"""
Backlog module — fetches and categorizes the capa-rules issue backlog
for automated processing.

This addresses the mentor's primary focus: "processing the existing backlog
of capa-rules issues" and "automating the transition from behavioral
descriptions and sample references into validated rules."

Categorizes each issue by what context is available:
- has_sample: SHA256/MD5 hashes → enables ground-truth testing
- has_decompilation: Code blocks → enables API/string extraction
- has_iocs: Registry paths, filenames → enables feature-based generation
- behavioral_only: Just a text description → requires the no-sample quality gate
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

import requests

from .trigger import IssueContext, _parse_issue_data, ATTCK_PATTERN

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class IssueTractability(Enum):
    """How tractable an issue is for automated rule generation."""

    HIGH = "high"        # Has sample + decompilation → full pipeline
    MEDIUM = "medium"    # Has IOCs or ATT&CK context → guided generation
    LOW = "low"          # Behavioral description only → needs quality gate
    SKIP = "skip"        # Bug report, meta-issue, already has PR


@dataclass
class IssueClassification:
    """Classification of a capa-rules issue for agent processing."""

    issue_number: int
    title: str
    url: str
    tractability: IssueTractability

    # Context availability flags
    has_sample: bool = False
    has_decompilation: bool = False
    has_iocs: bool = False          # registry paths, filenames, IPs
    has_attck: bool = False
    has_references: bool = False
    is_rule_request: bool = True    # vs bug report / question
    has_existing_pr: bool = False

    # Extracted metadata
    sample_count: int = 0
    attck_ids: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)

    # Agent processing state
    context: Optional[IssueContext] = None

    def summary(self) -> str:
        """One-line summary for display."""
        flags = []
        if self.has_sample:
            flags.append(f"samples={self.sample_count}")
        if self.has_decompilation:
            flags.append("decomp")
        if self.has_iocs:
            flags.append("iocs")
        if self.has_attck:
            flags.append(f"att&ck={','.join(self.attck_ids)}")
        if self.has_existing_pr:
            flags.append("HAS_PR")
        context = " | ".join(flags) if flags else "behavioral_only"
        return f"[{self.tractability.value:6s}] #{self.issue_number}: {self.title} ({context})"


# ---------------------------------------------------------------------------
# IOC detection patterns
# ---------------------------------------------------------------------------

# Registry path patterns (common persistence locations)
REGISTRY_PATTERN = re.compile(
    r"(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)"
    r"[\\\/][^\s\)\"']+",
    re.IGNORECASE,
)

# File path patterns (Windows paths)
FILE_PATH_PATTERN = re.compile(
    r"[A-Z]:\\[^\s\)\"']{5,}|"
    r"%(?:SystemRoot|APPDATA|ProgramFiles|TEMP|windir)%[\\\/][^\s\)\"']+",
    re.IGNORECASE,
)

# SHA256 and MD5 hash patterns
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")

# Code block detection (decompilation / pseudocode)
CODE_BLOCK_PATTERN = re.compile(r"```(?:\w+)?\n(.*?)```", re.DOTALL)
DECOMPILATION_KEYWORDS = {
    "void ", "int ", "HKEY", "LSTATUS", "undefined", "FUN_",
    "DWORD", "HANDLE", "LPCSTR", "BOOL ", "HRESULT",
    "CreateFile", "RegOpenKey", "LoadLibrary", "GetProcAddress",
    "push ", "mov ", "call ", "lea ",  # assembly patterns
}

# Labels that indicate non-rule-request issues
SKIP_LABELS = {
    "bug", "question", "documentation", "duplicate", "wontfix",
    "invalid", "false positive", "fixed", "meta",
}

# Labels that indicate rule requests
RULE_LABELS = {
    "rule idea", "enhancement", "new rule", "feature request",
    "rule request", "nursery",
}


# ---------------------------------------------------------------------------
# Issue classification
# ---------------------------------------------------------------------------


def classify_issue(issue_data: dict) -> IssueClassification:
    """
    Classify a single GitHub issue by tractability for agent processing.

    Examines the issue body for context signals: sample hashes,
    decompilation blocks, IOCs, ATT&CK references, etc.

    Args:
        issue_data: GitHub API issue response dict

    Returns:
        IssueClassification with all context flags set
    """
    number = issue_data.get("number", 0)
    title = issue_data.get("title", "")
    body = issue_data.get("body", "") or ""
    labels = [l["name"] for l in issue_data.get("labels", [])]
    html_url = issue_data.get("html_url", "")

    classification = IssueClassification(
        issue_number=number,
        title=title,
        url=html_url,
        tractability=IssueTractability.MEDIUM,  # default, will be refined
        labels=labels,
    )

    # Check if this is a rule request (vs bug/question/meta)
    label_set = {l.lower() for l in labels}
    if label_set & SKIP_LABELS:
        classification.is_rule_request = False
        classification.tractability = IssueTractability.SKIP
        return classification

    # Check for linked PRs (issue already addressed)
    if _has_linked_pr(issue_data):
        classification.has_existing_pr = True
        classification.tractability = IssueTractability.SKIP
        return classification

    # --- Context detection ---

    # 1. Sample hashes
    sha256_hashes = SHA256_PATTERN.findall(body)
    md5_hashes = MD5_PATTERN.findall(body)
    all_hashes = sha256_hashes + md5_hashes
    if all_hashes:
        classification.has_sample = True
        classification.sample_count = len(all_hashes)

    # 2. Decompilation / code blocks
    code_blocks = CODE_BLOCK_PATTERN.findall(body)
    for block in code_blocks:
        if any(kw in block for kw in DECOMPILATION_KEYWORDS):
            classification.has_decompilation = True
            break

    # 3. IOCs (registry paths, file paths)
    if REGISTRY_PATTERN.search(body) or FILE_PATH_PATTERN.search(body):
        classification.has_iocs = True

    # 4. ATT&CK technique references
    combined_text = f"{title} {body}"
    attck_ids = list(set(ATTCK_PATTERN.findall(combined_text)))
    if attck_ids:
        classification.has_attck = True
        classification.attck_ids = attck_ids

    # 5. References (URLs)
    url_pattern = re.compile(r"https?://[^\s\)\"']+")
    if url_pattern.search(body):
        classification.has_references = True

    # --- Tractability scoring ---
    classification.tractability = _score_tractability(classification)

    return classification


def _score_tractability(c: IssueClassification) -> IssueTractability:
    """
    Determine issue tractability based on available context.

    HIGH:   Has sample hashes (enables ground-truth testing)
    MEDIUM: Has IOCs or decompilation or ATT&CK (enables guided generation)
    LOW:    Behavioral description only (needs no-sample quality gate)
    SKIP:   Bug report, has PR, etc.
    """
    if not c.is_rule_request:
        return IssueTractability.SKIP

    if c.has_sample:
        return IssueTractability.HIGH

    if c.has_decompilation or c.has_iocs:
        return IssueTractability.MEDIUM

    if c.has_attck or c.has_references:
        return IssueTractability.MEDIUM

    return IssueTractability.LOW


def _has_linked_pr(issue_data: dict) -> bool:
    """
    Check if an issue has a linked PR (indicating it's already being addressed).

    Heuristic: check timeline events for cross-references from PRs.
    Falls back to checking if issue body mentions a PR.
    """
    body = issue_data.get("body", "") or ""
    # Check for common PR reference patterns
    if re.search(r"(?:PR|pull request|pull)\s*#?\d+", body, re.IGNORECASE):
        return True

    # Check pull_request field (for issues that are also PRs)
    if issue_data.get("pull_request"):
        return True

    return False


# ---------------------------------------------------------------------------
# Backlog fetching and processing
# ---------------------------------------------------------------------------


@dataclass
class BacklogReport:
    """Summary of the issue backlog analysis."""

    total_issues: int = 0
    high_tractability: list[IssueClassification] = field(default_factory=list)
    medium_tractability: list[IssueClassification] = field(default_factory=list)
    low_tractability: list[IssueClassification] = field(default_factory=list)
    skipped: list[IssueClassification] = field(default_factory=list)

    def summary(self) -> str:
        """Format as a summary string."""
        parts = [
            f"Backlog Analysis: {self.total_issues} issues",
            f"  HIGH   tractability (has sample):     {len(self.high_tractability)}",
            f"  MEDIUM tractability (IOCs/decomp):    {len(self.medium_tractability)}",
            f"  LOW    tractability (description only): {len(self.low_tractability)}",
            f"  SKIPPED (bugs/has PR/meta):           {len(self.skipped)}",
            "",
        ]

        if self.high_tractability:
            parts.append("=== HIGH (ready for full pipeline) ===")
            for c in self.high_tractability[:10]:
                parts.append(f"  {c.summary()}")
            parts.append("")

        if self.medium_tractability:
            parts.append("=== MEDIUM (guided generation) ===")
            for c in self.medium_tractability[:10]:
                parts.append(f"  {c.summary()}")
            parts.append("")

        if self.low_tractability:
            parts.append("=== LOW (needs quality gate) ===")
            for c in self.low_tractability[:10]:
                parts.append(f"  {c.summary()}")

        return "\n".join(parts)

    @property
    def processable(self) -> list[IssueClassification]:
        """All processable issues, sorted by tractability (high first)."""
        return self.high_tractability + self.medium_tractability + self.low_tractability


def fetch_backlog(
    owner: str = "mandiant",
    repo: str = "capa-rules",
    state: str = "open",
    max_issues: int = 100,
    token: Optional[str] = None,
) -> BacklogReport:
    """
    Fetch and classify all open issues from the capa-rules repository.

    This is the primary entry point for the issue backlog processor.
    The mentor's instruction: "processing the existing backlog of capa-rules
    issues" — this function implements that capability.

    Args:
        owner: GitHub repository owner
        repo: GitHub repository name
        state: Issue state filter ("open", "closed", "all")
        max_issues: Maximum number of issues to fetch
        token: GitHub personal access token (optional, for rate limits)

    Returns:
        BacklogReport with classified issues sorted by tractability
    """
    report = BacklogReport()
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    page = 1
    per_page = min(max_issues, 100)
    fetched = 0

    while fetched < max_issues:
        url = (
            f"https://api.github.com/repos/{owner}/{repo}/issues"
            f"?state={state}&per_page={per_page}&page={page}&sort=created&direction=desc"
        )

        logger.info(f"Fetching issues page {page} from {owner}/{repo}...")
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
        except requests.RequestException as e:
            logger.error(f"Failed to fetch issues: {e}")
            break

        issues = resp.json()
        if not issues:
            break

        for issue_data in issues:
            # Skip pull requests (GitHub API returns them as issues too)
            if issue_data.get("pull_request"):
                continue

            classification = classify_issue(issue_data)
            report.total_issues += 1

            if classification.tractability == IssueTractability.HIGH:
                report.high_tractability.append(classification)
            elif classification.tractability == IssueTractability.MEDIUM:
                report.medium_tractability.append(classification)
            elif classification.tractability == IssueTractability.LOW:
                report.low_tractability.append(classification)
            else:
                report.skipped.append(classification)

            # Also parse the full IssueContext for processable issues
            if classification.tractability != IssueTractability.SKIP:
                try:
                    classification.context = _parse_issue_data(issue_data)
                except Exception as e:
                    logger.debug(f"Failed to parse issue #{issue_data.get('number')}: {e}")

            fetched += 1
            if fetched >= max_issues:
                break

        page += 1

    logger.info(f"Backlog: {report.total_issues} issues classified "
                f"({len(report.high_tractability)} HIGH, "
                f"{len(report.medium_tractability)} MEDIUM, "
                f"{len(report.low_tractability)} LOW, "
                f"{len(report.skipped)} SKIP)")

    return report


def process_backlog_batch(
    report: BacklogReport,
    max_batch: int = 5,
    include_low: bool = False,
) -> list[IssueClassification]:
    """
    Select a batch of issues from the backlog for processing.

    Prioritizes HIGH tractability (has samples) since those can be
    fully validated. Then MEDIUM. LOW only if include_low=True.

    Args:
        report: BacklogReport from fetch_backlog()
        max_batch: Maximum number of issues to include
        include_low: Whether to include LOW tractability issues

    Returns:
        List of IssueClassification objects ready for pipeline processing
    """
    batch = []

    # First: HIGH tractability
    for c in report.high_tractability:
        if len(batch) >= max_batch:
            break
        if not c.has_existing_pr:
            batch.append(c)

    # Then: MEDIUM tractability
    for c in report.medium_tractability:
        if len(batch) >= max_batch:
            break
        if not c.has_existing_pr:
            batch.append(c)

    # Finally: LOW tractability (only if requested)
    if include_low:
        for c in report.low_tractability:
            if len(batch) >= max_batch:
                break
            if not c.has_existing_pr:
                batch.append(c)

    logger.info(f"Selected {len(batch)} issues for processing batch")
    return batch
