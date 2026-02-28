"""
Quality Gate module — multi-layered validation for rules WITHOUT reference samples.

This is the core challenge identified by mentors: "how does the agent ensure
the generated rule matches as expected and maintains high quality when no
representative sample is provided?"

Architecture:
    Layer 1: Structural Validation   — YAML, schema, lint, format (validator.py)
    Layer 2: Sibling Rule Analysis   — compare against rules in same namespace
    Layer 3: Negative Testing        — must NOT match known-benign binaries
    Layer 4: Semantic Coherence      — name ↔ features ↔ ATT&CK alignment
    Layer 5: Confidence Scoring      — aggregate signals → route to rules/ vs nursery/

Design constraint: "the agent should never silently degrade confidence —
the HITL reviewer needs structured metadata showing exactly what was and
wasn't verified, and why."
"""

from __future__ import annotations

import re
import logging
from enum import Enum
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

import yaml

from .trigger import IssueContext, ATTCK_TECHNIQUE_MAP
from .grounding import RuleIndex, RuleEntry
from .validator import ValidationResult, validate_rule

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Confidence model
# ---------------------------------------------------------------------------


class ConfidenceLevel(Enum):
    """Confidence in a generated rule's quality."""
    HIGH = "high"        # Route to rules/ — strong evidence of correctness
    MEDIUM = "medium"    # Route to nursery/ — plausible but unverified by sample
    LOW = "low"          # Flag for human review — significant concerns
    REJECT = "reject"    # Do not submit — structural or semantic failures


class VerificationStatus(Enum):
    """Status of a single verification check."""
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"     # Check couldn't run (missing data)
    WARNING = "warning"     # Non-fatal concern


@dataclass
class VerificationCheck:
    """A single verification step and its result."""
    layer: str                          # e.g., "structural", "sibling", "negative", "semantic"
    check_name: str                     # e.g., "yaml_syntax", "namespace_coverage"
    status: VerificationStatus
    detail: str                         # Human-readable explanation
    evidence: Optional[str] = None      # Supporting data (e.g., matched rule names)

    def to_row(self) -> str:
        """Format as a PR description table row."""
        icon = {
            VerificationStatus.PASSED: "✅",
            VerificationStatus.FAILED: "❌",
            VerificationStatus.SKIPPED: "⏭️",
            VerificationStatus.WARNING: "⚠️",
        }[self.status]
        return f"| {icon} | {self.layer} | {self.check_name} | {self.detail} |"


@dataclass
class QualityReport:
    """
    Complete quality assessment for a generated rule.

    This is the structured HITL metadata the mentor asked for:
    "the HITL reviewer needs structured metadata showing exactly
    what was and wasn't verified, and why."
    """
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    target_directory: str = "nursery"   # "rules/" or "nursery/"
    checks: list[VerificationCheck] = field(default_factory=list)
    score: float = 0.0                  # 0.0 - 1.0

    # Context flags — what WAS available for verification
    had_sample: bool = False
    had_decompilation: bool = False
    had_sibling_rules: bool = False
    had_benign_corpus: bool = False
    had_attck_context: bool = False

    # Summary statistics
    passed_count: int = 0
    failed_count: int = 0
    warning_count: int = 0
    skipped_count: int = 0

    def add_check(self, check: VerificationCheck):
        """Add a check and update statistics."""
        self.checks.append(check)
        if check.status == VerificationStatus.PASSED:
            self.passed_count += 1
        elif check.status == VerificationStatus.FAILED:
            self.failed_count += 1
        elif check.status == VerificationStatus.WARNING:
            self.warning_count += 1
        else:
            self.skipped_count += 1

    def compute_confidence(self):
        """
        Compute overall confidence from individual checks.

        Scoring:
        - PASSED checks add to score
        - FAILED structural/semantic checks → REJECT
        - FAILED sibling/negative checks → cap at MEDIUM
        - All checks passed → HIGH (even without sample)
        """
        if self.failed_count == 0 and self.passed_count > 0:
            total = self.passed_count + self.warning_count + self.skipped_count
            self.score = self.passed_count / max(total, 1)
        else:
            total = self.passed_count + self.failed_count + self.warning_count
            self.score = self.passed_count / max(total, 1)

        # Check for hard failures
        hard_failures = [
            c for c in self.checks
            if c.status == VerificationStatus.FAILED
            and c.layer in ("structural", "semantic")
        ]
        if hard_failures:
            self.confidence = ConfidenceLevel.REJECT
            self.target_directory = ""
            return

        # Any failure caps confidence at MEDIUM
        if self.failed_count > 0:
            self.confidence = ConfidenceLevel.LOW
            self.target_directory = "nursery"
            return

        # Score-based routing.
        # Thresholds are educated guesses, not empirically tuned:
        #   0.8 chosen as "most checks passed" -- needs validation against
        #   real capa-rules PRs to see if this correlates with merge rate.
        #   0.7 is a softer bar for nursery/ placement.
        if self.score >= 0.8 and self.had_sample:
            # Only HIGH if we tested against a real sample
            self.confidence = ConfidenceLevel.HIGH
            self.target_directory = "rules"
        elif self.score >= 0.7:
            self.confidence = ConfidenceLevel.MEDIUM
            self.target_directory = "nursery"
        else:
            self.confidence = ConfidenceLevel.LOW
            self.target_directory = "nursery"

    def to_pr_section(self) -> str:
        """
        Format as a PR description section showing verification details.

        This is the structured metadata for the HITL reviewer.
        """
        parts = [
            "### Quality Gate Report",
            "",
            f"**Confidence:** {self.confidence.value.upper()} "
            f"(score: {self.score:.0%})",
            f"**Target directory:** `{self.target_directory}/`",
            "",
            "| Status | Layer | Check | Detail |",
            "|--------|-------|-------|--------|",
        ]

        for check in self.checks:
            parts.append(check.to_row())

        parts.append("")

        # Explain what WASN'T verified and why
        not_verified = []
        if not self.had_sample:
            not_verified.append(
                "**No reference sample available** — rule was NOT tested against "
                "a real binary. Routing to `nursery/` until sample-based testing "
                "confirms detection."
            )
        if not self.had_benign_corpus:
            not_verified.append(
                "**No benign corpus available** — negative testing (false positive "
                "check) was skipped. Provide `--testfiles-dir` to enable."
            )
        if not self.had_sibling_rules:
            not_verified.append(
                "**No sibling rules found** — could not compare against existing "
                "rules in the same namespace for over-generalization detection."
            )

        if not_verified:
            parts.append("<details>")
            parts.append("<summary>What was NOT verified (and why)</summary>")
            parts.append("")
            for item in not_verified:
                parts.append(f"- {item}")
            parts.append("")
            parts.append("</details>")
            parts.append("")

        return "\n".join(parts)

    def summary(self) -> str:
        """One-line summary."""
        return (
            f"[{self.confidence.value.upper()}] score={self.score:.0%} "
            f"passed={self.passed_count} failed={self.failed_count} "
            f"warnings={self.warning_count} skipped={self.skipped_count} "
            f"→ {self.target_directory}/"
        )


# ---------------------------------------------------------------------------
# Layer 2: Sibling Rule Analysis
# ---------------------------------------------------------------------------


@dataclass
class SiblingAnalysis:
    """Result of comparing a rule against its namespace siblings."""
    sibling_count: int = 0
    feature_overlap_scores: list[tuple[str, float]] = field(default_factory=list)
    over_generalization_risk: bool = False
    under_specification_risk: bool = False
    unique_features: list[str] = field(default_factory=list)
    shared_features: list[str] = field(default_factory=list)


def analyze_siblings(
    rule_text: str,
    rule_index: RuleIndex,
    namespace: Optional[str] = None,
) -> SiblingAnalysis:
    """
    Compare a generated rule against existing rules in the same namespace.

    This catches the over-generalization problem (like issue #1100 where
    persist-via-windows-service matched too broadly within registry keys).
    The existing rule corpus is "an underutilized validation signal,
    especially sibling rules within the same namespace."

    Checks:
    1. Feature overlap — how much does this rule's features overlap with siblings?
    2. Over-generalization — does this rule match a superset of what siblings match?
    3. Under-specification — is this rule too narrow compared to siblings?
    4. Unique features — what does this rule detect that siblings don't?
    """
    analysis = SiblingAnalysis()

    if not rule_index or not namespace:
        return analysis

    # Parse the generated rule's features
    try:
        data = yaml.safe_load(rule_text)
        if not data or "rule" not in data:
            return analysis
    except yaml.YAMLError:
        return analysis

    rule_features = _extract_feature_set(data["rule"].get("features", []))

    # Find sibling rules (same namespace or parent namespace)
    siblings = _find_siblings(rule_index, namespace)
    analysis.sibling_count = len(siblings)

    if not siblings:
        return analysis

    # Compare features with each sibling
    all_sibling_features: set[str] = set()
    for sibling in siblings:
        try:
            sib_data = yaml.safe_load(sibling.raw_text)
            if sib_data and "rule" in sib_data:
                sib_features = _extract_feature_set(sib_data["rule"].get("features", []))
                all_sibling_features.update(sib_features)

                # Compute pairwise overlap
                if rule_features and sib_features:
                    overlap = len(rule_features & sib_features) / max(
                        len(rule_features | sib_features), 1
                    )
                    analysis.feature_overlap_scores.append((sibling.name, overlap))
        except yaml.YAMLError:
            continue

    # Unique vs shared features
    analysis.unique_features = sorted(rule_features - all_sibling_features)
    analysis.shared_features = sorted(rule_features & all_sibling_features)

    # Over-generalization check: if the rule has very few unique features
    # and many shared features, it might be too broad.
    # 0.2 ratio and >2 shared: chosen by inspection of capa-rules#1100
    # where the FP rule shared nearly all features with siblings.
    # Needs tuning against more real FP cases.
    if rule_features:
        unique_ratio = len(analysis.unique_features) / len(rule_features)
        if unique_ratio < 0.2 and len(analysis.shared_features) > 2:
            analysis.over_generalization_risk = True

    # Under-specification check: if siblings are much more specific.
    # 0.3x multiplier is a rough heuristic: "less than a third of the
    # average sibling's feature count is suspiciously simple."
    # Not validated at scale yet.
    if rule_features and all_sibling_features:
        avg_sibling_size = len(all_sibling_features) / max(len(siblings), 1)
        if len(rule_features) < avg_sibling_size * 0.3:
            analysis.under_specification_risk = True

    return analysis


def _find_siblings(rule_index: RuleIndex, namespace: str) -> list[RuleEntry]:
    """Find rules in the same namespace or parent namespace."""
    siblings = []

    # Exact namespace match
    indices = rule_index._by_namespace.get(namespace, [])
    for idx in indices:
        siblings.append(rule_index.rules[idx])

    # If no exact matches, try parent namespace
    if not siblings and "/" in namespace:
        parent = namespace.rsplit("/", 1)[0]
        indices = rule_index._by_namespace.get(parent, [])
        for idx in indices:
            siblings.append(rule_index.rules[idx])

    # Cap at 20 siblings to keep comparison fast. Most namespaces have
    # fewer than 20 rules; if this becomes a bottleneck we can sample.
    return siblings[:20]


def _extract_feature_set(features: list | dict, depth: int = 0) -> set[str]:
    """
    Extract a normalized set of feature identifiers from a features tree.

    Returns set of strings like:
    - "api:CreateService"
    - "string:Software\\Microsoft\\..."
    - "number:0x80000002"
    - "match:set registry value"
    """
    result: set[str] = set()
    if depth > 10:
        return result

    if isinstance(features, list):
        for item in features:
            result.update(_extract_feature_set(item, depth + 1))
    elif isinstance(features, dict):
        for key, val in features.items():
            if key in ("api", "string", "substring", "match"):
                result.add(f"{key}:{val}")
            elif key == "number":
                # Normalize: extract just the number part
                num_str = str(val).split("=")[0].strip()
                result.add(f"number:{num_str}")
            elif key in ("and", "or", "not", "optional", "basic block", "call"):
                result.update(_extract_feature_set(val, depth + 1))
            elif isinstance(val, (list, dict)):
                result.update(_extract_feature_set(val, depth + 1))

    return result


# ---------------------------------------------------------------------------
# Layer 3: Negative Testing (False Positive Check)
# ---------------------------------------------------------------------------


def run_negative_tests(
    rule_text: str,
    testfiles_dir: Optional[str] = None,
    capa_path: str = "capa",
    timeout: int = 120,
) -> list[VerificationCheck]:
    """
    Test a rule against known-benign binaries to check for false positives.

    Uses the capa-testfiles repository which contains benign PE files
    for testing. If the rule matches any of these, it's likely too broad.

    Args:
        rule_text: The YAML rule to test
        testfiles_dir: Path to capa-testfiles or directory with benign samples
        capa_path: Path to capa executable
        timeout: Execution timeout per sample

    Returns:
        List of VerificationCheck results
    """
    import tempfile
    import subprocess

    checks = []

    if not testfiles_dir:
        checks.append(VerificationCheck(
            layer="negative",
            check_name="benign_corpus_test",
            status=VerificationStatus.SKIPPED,
            detail="No benign corpus provided (--testfiles-dir). "
                   "Cannot verify rule doesn't match benign software.",
        ))
        return checks

    testfiles_path = Path(testfiles_dir)
    if not testfiles_path.exists():
        checks.append(VerificationCheck(
            layer="negative",
            check_name="benign_corpus_test",
            status=VerificationStatus.SKIPPED,
            detail=f"Test files directory not found: {testfiles_dir}",
        ))
        return checks

    # Find PE files in the testfiles directory
    benign_files = []
    for ext in ("*.exe_", "*.dll_", "*.sys_", "*.exe", "*.dll"):
        benign_files.extend(testfiles_path.rglob(ext))

    if not benign_files:
        checks.append(VerificationCheck(
            layer="negative",
            check_name="benign_corpus_test",
            status=VerificationStatus.SKIPPED,
            detail=f"No PE files found in {testfiles_dir}",
        ))
        return checks

    # Write rule to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write(rule_text)
        rule_path = f.name

    false_positive_matches = []

    try:
        # Cap at 30 benign files to keep runtime under a few minutes.
        # capa-testfiles has ~50 benign PEs; 30 gives decent coverage
        # without blocking the pipeline.
        for sample_path in benign_files[:30]:
            try:
                result = subprocess.run(
                    [capa_path, "--rules", rule_path, "--json", str(sample_path)],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )

                if result.returncode == 0:
                    import json
                    try:
                        output = json.loads(result.stdout)
                        if output.get("rules"):
                            false_positive_matches.append(sample_path.name)
                    except (json.JSONDecodeError, KeyError):
                        pass

            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

    finally:
        Path(rule_path).unlink(missing_ok=True)

    if false_positive_matches:
        checks.append(VerificationCheck(
            layer="negative",
            check_name="benign_corpus_test",
            status=VerificationStatus.FAILED,
            detail=f"Rule matched {len(false_positive_matches)} benign file(s) — "
                   f"likely false positive",
            evidence=f"Matched: {', '.join(false_positive_matches[:5])}",
        ))
    else:
        checks.append(VerificationCheck(
            layer="negative",
            check_name="benign_corpus_test",
            status=VerificationStatus.PASSED,
            detail=f"Rule did NOT match any of {len(benign_files[:30])} "
                   f"benign test files",
        ))

    return checks


# ---------------------------------------------------------------------------
# Layer 4: Semantic Coherence
# ---------------------------------------------------------------------------


def check_semantic_coherence(
    rule_text: str,
    context: Optional[IssueContext] = None,
) -> list[VerificationCheck]:
    """
    Verify that the rule is semantically coherent:
    - Rule name matches what the features actually detect
    - ATT&CK technique IDs are appropriate for the feature set
    - API calls are real Win32 APIs (not hallucinated)
    - Feature tree is not degenerate (e.g., single OR with one child)

    This catches issues where the LLM generates a syntactically valid
    rule that doesn't actually make sense.
    """
    checks = []

    try:
        data = yaml.safe_load(rule_text)
        if not data or "rule" not in data:
            checks.append(VerificationCheck(
                layer="semantic",
                check_name="parseable",
                status=VerificationStatus.FAILED,
                detail="Rule is not parseable as a capa rule",
            ))
            return checks
    except yaml.YAMLError:
        checks.append(VerificationCheck(
            layer="semantic",
            check_name="parseable",
            status=VerificationStatus.FAILED,
            detail="Rule is not valid YAML",
        ))
        return checks

    rule = data["rule"]
    meta = rule.get("meta", {})
    features = rule.get("features", [])

    # --- Check 1: Feature tree depth ---
    feature_set = _extract_feature_set(features)
    # "< 2 features" threshold: a rule with only one feature is almost
    # certainly too broad for production use. This is the lowest bar;
    # real capa rules typically have 3-8 features.
    if len(feature_set) < 2:
        checks.append(VerificationCheck(
            layer="semantic",
            check_name="feature_depth",
            status=VerificationStatus.WARNING,
            detail=f"Rule has only {len(feature_set)} unique feature(s) -- "
                   f"may be too simple to avoid false positives",
        ))
    else:
        checks.append(VerificationCheck(
            layer="semantic",
            check_name="feature_depth",
            status=VerificationStatus.PASSED,
            detail=f"Rule has {len(feature_set)} unique features — sufficient depth",
        ))

    # --- Check 2: Name ↔ features alignment ---
    name = meta.get("name", "")
    namespace = meta.get("namespace", "")
    name_tokens = set(re.split(r"[^a-zA-Z0-9]+", name.lower())) - {"", "via", "the", "a", "and", "or"}

    # Check if key name tokens appear in features or are semantically related
    feature_str = " ".join(str(f) for f in feature_set).lower()
    name_feature_matches = sum(1 for t in name_tokens if t in feature_str)
    if name_tokens and name_feature_matches == 0:
        checks.append(VerificationCheck(
            layer="semantic",
            check_name="name_feature_alignment",
            status=VerificationStatus.WARNING,
            detail=f"Rule name '{name}' does not appear related to its features. "
                   f"Name tokens: {name_tokens}",
        ))
    else:
        checks.append(VerificationCheck(
            layer="semantic",
            check_name="name_feature_alignment",
            status=VerificationStatus.PASSED,
            detail=f"Rule name '{name}' aligns with detected features",
        ))

    # --- Check 3: ATT&CK technique coherence ---
    attck_entries = meta.get("att&ck", [])
    if attck_entries:
        # Extract technique IDs from the att&ck field
        rule_attck_ids = []
        for entry in attck_entries:
            ids = re.findall(r"T\d{4}(?:\.\d{3})?", str(entry))
            rule_attck_ids.extend(ids)

        # Cross-check with namespace
        namespace_lower = namespace.lower()
        attck_namespace_aligned = False
        for tid in rule_attck_ids:
            # Check if ATT&CK technique maps to the right tactic
            technique_str = ATTCK_TECHNIQUE_MAP.get(tid, "").lower()
            if technique_str:
                tactic = technique_str.split("::")[0].lower()
                if tactic in namespace_lower or namespace_lower in tactic:
                    attck_namespace_aligned = True
                    break

        if attck_namespace_aligned:
            checks.append(VerificationCheck(
                layer="semantic",
                check_name="attck_namespace_alignment",
                status=VerificationStatus.PASSED,
                detail=f"ATT&CK techniques {rule_attck_ids} align with namespace '{namespace}'",
            ))
        elif rule_attck_ids:
            checks.append(VerificationCheck(
                layer="semantic",
                check_name="attck_namespace_alignment",
                status=VerificationStatus.WARNING,
                detail=f"ATT&CK techniques {rule_attck_ids} may not align with namespace '{namespace}'",
            ))
    else:
        checks.append(VerificationCheck(
            layer="semantic",
            check_name="attck_namespace_alignment",
            status=VerificationStatus.SKIPPED,
            detail="No ATT&CK techniques specified — cannot verify alignment",
        ))

    # --- Check 4: API hallucination check ---
    apis_in_rule = [f.split(":", 1)[1] for f in feature_set if f.startswith("api:")]
    if apis_in_rule:
        # Check against known Win32 API patterns
        suspicious_apis = []
        for api in apis_in_rule:
            api_name = api.split(".")[-1] if "." in api else api
            # Heuristic: Win32 APIs typically follow naming conventions
            if not re.match(r"^[A-Z][a-zA-Z0-9]+[A-Z][a-zA-Z0-9]*$|^[a-z_]+$", api_name):
                # Doesn't match CamelCase (Win32) or snake_case (C runtime)
                if not api_name.startswith("_") and len(api_name) > 3:
                    suspicious_apis.append(api)

        if suspicious_apis:
            checks.append(VerificationCheck(
                layer="semantic",
                check_name="api_validity",
                status=VerificationStatus.WARNING,
                detail=f"Potentially hallucinated API name(s): {suspicious_apis}. "
                       f"Verify these are real Win32/CRT functions.",
                evidence=f"APIs: {', '.join(apis_in_rule)}",
            ))
        else:
            checks.append(VerificationCheck(
                layer="semantic",
                check_name="api_validity",
                status=VerificationStatus.PASSED,
                detail=f"All {len(apis_in_rule)} API name(s) follow valid naming conventions",
            ))

    # --- Check 5: Degenerate logic tree ---
    _check_degenerate_tree(features, checks)

    return checks


def _check_degenerate_tree(
    features: list | dict,
    checks: list[VerificationCheck],
    depth: int = 0,
):
    """Check for degenerate logic patterns (e.g., OR with single child)."""
    if depth > 0:
        return  # Only check top level

    if isinstance(features, list):
        for item in features:
            if isinstance(item, dict):
                for key, val in item.items():
                    if key in ("or", "and") and isinstance(val, list):
                        if len(val) <= 1:
                            checks.append(VerificationCheck(
                                layer="semantic",
                                check_name="logic_tree_structure",
                                status=VerificationStatus.WARNING,
                                detail=f"'{key}:' block has only {len(val)} child — "
                                       f"redundant logic operator",
                            ))
                            return

    checks.append(VerificationCheck(
        layer="semantic",
        check_name="logic_tree_structure",
        status=VerificationStatus.PASSED,
        detail="Logic tree structure is well-formed",
    ))


# ---------------------------------------------------------------------------
# Main quality gate entry point
# ---------------------------------------------------------------------------


def run_quality_gate(
    rule_text: str,
    context: Optional[IssueContext] = None,
    rule_index: Optional[RuleIndex] = None,
    namespace: Optional[str] = None,
    testfiles_dir: Optional[str] = None,
    capa_path: str = "capa",
    validation_result: Optional[ValidationResult] = None,
    sample_tested: bool = False,
) -> QualityReport:
    """
    Run the complete no-sample quality gate.

    This is the multi-layered approach described in the proposal:
    1. Structural validation (from validator.py, passed in)
    2. Sibling rule analysis (namespace comparison)
    3. Negative testing (benign corpus false-positive check)
    4. Semantic coherence (name/features/ATT&CK alignment)
    5. Confidence scoring and routing

    Args:
        rule_text: The generated YAML rule
        context: Issue context (for semantic checks)
        rule_index: Indexed capa-rules corpus (for sibling analysis)
        namespace: Rule's target namespace
        testfiles_dir: Path to benign test files
        capa_path: Path to capa executable
        validation_result: Pre-computed validation result from validator.py
        sample_tested: Whether the rule was already tested on a real sample

    Returns:
        QualityReport with structured HITL metadata
    """
    report = QualityReport()
    report.had_sample = sample_tested

    # --- Layer 1: Structural Validation ---
    if validation_result:
        report.add_check(VerificationCheck(
            layer="structural",
            check_name="yaml_syntax",
            status=VerificationStatus.PASSED if validation_result.yaml_valid
                   else VerificationStatus.FAILED,
            detail="YAML syntax is valid" if validation_result.yaml_valid
                   else "YAML syntax errors detected",
        ))
        report.add_check(VerificationCheck(
            layer="structural",
            check_name="schema",
            status=VerificationStatus.PASSED if validation_result.schema_valid
                   else VerificationStatus.FAILED,
            detail="Rule follows capa schema" if validation_result.schema_valid
                   else "Schema validation failed",
        ))
        report.add_check(VerificationCheck(
            layer="structural",
            check_name="lint",
            status=VerificationStatus.PASSED if validation_result.lint_passed
                   else VerificationStatus.FAILED,
            detail="capa linter passed" if validation_result.lint_passed
                   else f"Lint errors: {'; '.join(validation_result.errors[:3])}",
        ))
    else:
        # Run validation ourselves
        vresult = validate_rule(rule_text)
        report.add_check(VerificationCheck(
            layer="structural",
            check_name="yaml_syntax",
            status=VerificationStatus.PASSED if vresult.yaml_valid
                   else VerificationStatus.FAILED,
            detail="YAML syntax is valid" if vresult.yaml_valid
                   else "YAML syntax errors detected",
        ))
        report.add_check(VerificationCheck(
            layer="structural",
            check_name="schema",
            status=VerificationStatus.PASSED if vresult.schema_valid
                   else VerificationStatus.FAILED,
            detail="Rule follows capa schema" if vresult.schema_valid
                   else "Schema validation failed",
        ))
        report.add_check(VerificationCheck(
            layer="structural",
            check_name="lint",
            status=VerificationStatus.PASSED if vresult.lint_passed
                   else VerificationStatus.FAILED,
            detail="capa linter passed" if vresult.lint_passed
                   else f"Lint errors: {'; '.join(vresult.errors[:3])}",
        ))

    # --- Layer 2: Sibling Rule Analysis ---
    if rule_index and namespace:
        report.had_sibling_rules = True
        sibling_result = analyze_siblings(rule_text, rule_index, namespace)

        if sibling_result.sibling_count == 0:
            report.had_sibling_rules = False
            report.add_check(VerificationCheck(
                layer="sibling",
                check_name="namespace_coverage",
                status=VerificationStatus.SKIPPED,
                detail=f"No existing rules found in namespace '{namespace}'",
            ))
        else:
            # Over-generalization check
            if sibling_result.over_generalization_risk:
                report.add_check(VerificationCheck(
                    layer="sibling",
                    check_name="over_generalization",
                    status=VerificationStatus.FAILED,
                    detail=(
                        f"Rule may be over-generalized — shares most features with "
                        f"{sibling_result.sibling_count} sibling(s) but has few unique features. "
                        f"This is the same pattern that caused FP in capa-rules#1100."
                    ),
                    evidence=(
                        f"Shared: {sibling_result.shared_features[:5]}, "
                        f"Unique: {sibling_result.unique_features[:5]}"
                    ),
                ))
            else:
                report.add_check(VerificationCheck(
                    layer="sibling",
                    check_name="over_generalization",
                    status=VerificationStatus.PASSED,
                    detail=f"Rule has {len(sibling_result.unique_features)} unique feature(s) "
                           f"vs {sibling_result.sibling_count} sibling(s) — "
                           f"sufficient differentiation",
                ))

            # Feature overlap summary
            if sibling_result.feature_overlap_scores:
                max_overlap = max(score for _, score in sibling_result.feature_overlap_scores)
                closest_name = next(
                    name for name, score in sibling_result.feature_overlap_scores
                    if score == max_overlap
                )
                status = (VerificationStatus.WARNING
                          if max_overlap > 0.8
                          else VerificationStatus.PASSED)
                report.add_check(VerificationCheck(
                    layer="sibling",
                    check_name="feature_overlap",
                    status=status,
                    detail=(
                        f"Highest feature overlap: {max_overlap:.0%} with "
                        f"'{closest_name}'"
                    ) + (" — possible duplicate" if max_overlap > 0.8 else ""),
                ))

            # Under-specification check
            if sibling_result.under_specification_risk:
                report.add_check(VerificationCheck(
                    layer="sibling",
                    check_name="under_specification",
                    status=VerificationStatus.WARNING,
                    detail=f"Rule has fewer features than typical sibling rules — "
                           f"may be under-specified",
                ))
    else:
        if not rule_index:
            report.add_check(VerificationCheck(
                layer="sibling",
                check_name="namespace_coverage",
                status=VerificationStatus.SKIPPED,
                detail="No rule index available for sibling analysis. "
                       "Provide --rules-dir to enable.",
            ))

    # --- Layer 3: Negative Testing ---
    negative_checks = run_negative_tests(
        rule_text,
        testfiles_dir=testfiles_dir,
        capa_path=capa_path,
    )
    for check in negative_checks:
        report.add_check(check)
    report.had_benign_corpus = any(
        c.status != VerificationStatus.SKIPPED for c in negative_checks
    )

    # --- Layer 4: Semantic Coherence ---
    semantic_checks = check_semantic_coherence(rule_text, context)
    for check in semantic_checks:
        report.add_check(check)
    report.had_attck_context = any(
        c.check_name == "attck_namespace_alignment"
        and c.status != VerificationStatus.SKIPPED
        for c in semantic_checks
    )

    # --- Layer 5: Confidence Scoring ---
    report.compute_confidence()

    logger.info(f"Quality gate: {report.summary()}")
    return report
