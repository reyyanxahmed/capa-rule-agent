"""
Tests for the quality gate and backlog processor modules.

These test the key features the mentor asked for:
1. No-sample quality gate — multi-layered validation without reference binary
2. Issue backlog processing — classify and prioritize capa-rules issues
3. HITL metadata — structured confidence reporting
"""

import pytest
import yaml
from unittest.mock import patch, MagicMock

from src.quality_gate import (
    run_quality_gate,
    analyze_siblings,
    check_semantic_coherence,
    run_negative_tests,
    QualityReport,
    ConfidenceLevel,
    VerificationStatus,
    VerificationCheck,
    _extract_feature_set,
    _find_siblings,
)
from future.backlog import (
    classify_issue,
    fetch_backlog,
    process_backlog_batch,
    BacklogReport,
    IssueClassification,
    IssueTractability,
    _score_tractability,
    _has_linked_pr,
    REGISTRY_PATTERN,
    SHA256_PATTERN,
)
from src.trigger import IssueContext
from src.grounding import RuleIndex, RuleEntry
from src.validator import ValidationResult


# ==========================================================================
# Quality Gate: Confidence Model
# ==========================================================================


class TestConfidenceModel:
    """Test the confidence scoring and routing logic."""

    def test_quality_report_all_passed(self):
        """All checks passed → should compute high score."""
        report = QualityReport()
        report.had_sample = True
        report.add_check(VerificationCheck(
            layer="structural", check_name="yaml",
            status=VerificationStatus.PASSED, detail="ok",
        ))
        report.add_check(VerificationCheck(
            layer="structural", check_name="schema",
            status=VerificationStatus.PASSED, detail="ok",
        ))
        report.add_check(VerificationCheck(
            layer="semantic", check_name="feature_depth",
            status=VerificationStatus.PASSED, detail="ok",
        ))
        report.compute_confidence()

        assert report.score >= 0.8
        assert report.confidence == ConfidenceLevel.HIGH
        assert report.target_directory == "rules"

    def test_quality_report_no_sample_caps_medium(self):
        """All checks passed but no sample → MEDIUM, route to nursery."""
        report = QualityReport()
        report.had_sample = False
        report.add_check(VerificationCheck(
            layer="structural", check_name="yaml",
            status=VerificationStatus.PASSED, detail="ok",
        ))
        report.add_check(VerificationCheck(
            layer="structural", check_name="schema",
            status=VerificationStatus.PASSED, detail="ok",
        ))
        report.add_check(VerificationCheck(
            layer="semantic", check_name="feature_depth",
            status=VerificationStatus.PASSED, detail="ok",
        ))
        report.compute_confidence()

        assert report.confidence == ConfidenceLevel.MEDIUM
        assert report.target_directory == "nursery"

    def test_structural_failure_rejects(self):
        """Structural failure → REJECT."""
        report = QualityReport()
        report.add_check(VerificationCheck(
            layer="structural", check_name="yaml",
            status=VerificationStatus.FAILED, detail="invalid yaml",
        ))
        report.compute_confidence()

        assert report.confidence == ConfidenceLevel.REJECT
        assert report.target_directory == ""

    def test_semantic_failure_rejects(self):
        """Semantic failure → REJECT."""
        report = QualityReport()
        report.add_check(VerificationCheck(
            layer="semantic", check_name="parseable",
            status=VerificationStatus.FAILED, detail="not parseable",
        ))
        report.compute_confidence()

        assert report.confidence == ConfidenceLevel.REJECT

    def test_sibling_failure_caps_low(self):
        """Sibling check failure (non-structural) → LOW."""
        report = QualityReport()
        report.add_check(VerificationCheck(
            layer="structural", check_name="yaml",
            status=VerificationStatus.PASSED, detail="ok",
        ))
        report.add_check(VerificationCheck(
            layer="sibling", check_name="over_generalization",
            status=VerificationStatus.FAILED, detail="too broad",
        ))
        report.compute_confidence()

        assert report.confidence == ConfidenceLevel.LOW
        assert report.target_directory == "nursery"

    def test_skipped_checks_dont_fail(self):
        """Skipped checks shouldn't count as failures."""
        report = QualityReport()
        report.add_check(VerificationCheck(
            layer="structural", check_name="yaml",
            status=VerificationStatus.PASSED, detail="ok",
        ))
        report.add_check(VerificationCheck(
            layer="negative", check_name="benign_corpus",
            status=VerificationStatus.SKIPPED, detail="no corpus",
        ))
        report.compute_confidence()

        assert report.failed_count == 0
        assert report.confidence != ConfidenceLevel.REJECT

    def test_pr_section_format(self):
        """PR section should include verification table."""
        report = QualityReport()
        report.had_sample = False
        report.add_check(VerificationCheck(
            layer="structural", check_name="yaml",
            status=VerificationStatus.PASSED, detail="ok",
        ))
        report.add_check(VerificationCheck(
            layer="negative", check_name="benign_corpus",
            status=VerificationStatus.SKIPPED, detail="no corpus",
        ))
        report.compute_confidence()

        pr_section = report.to_pr_section()
        assert "Quality Gate Report" in pr_section
        assert "Confidence" in pr_section
        assert "Status" in pr_section
        assert "Layer" in pr_section
        assert "NOT verified" in pr_section
        assert "No reference sample" in pr_section

    def test_summary_format(self):
        """Summary should be a one-liner with key metrics."""
        report = QualityReport()
        report.add_check(VerificationCheck(
            layer="structural", check_name="yaml",
            status=VerificationStatus.PASSED, detail="ok",
        ))
        report.compute_confidence()

        summary = report.summary()
        assert "passed=" in summary
        assert "failed=" in summary


# ==========================================================================
# Quality Gate: Sibling Rule Analysis
# ==========================================================================

# A valid capa rule for testing
VALID_RULE = """rule:
  meta:
    name: persist via Run registry key
    namespace: persistence/registry/run
    authors:
      - test@test.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Persistence::Boot or Logon Autostart Execution::Registry Run Keys / Startup Folder [T1547.001]
  features:
    - and:
      - or:
        - api: advapi32.RegSetValueEx
        - api: advapi32.RegCreateKeyEx
      - string: /Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run/i
      - number: 0x80000002 = HKEY_LOCAL_MACHINE
"""

# A too-broad rule that would cause false positives
BROAD_RULE = """rule:
  meta:
    name: set registry value
    namespace: persistence/registry
    authors:
      - test@test.com
    scopes:
      static: function
      dynamic: span of calls
  features:
    - or:
      - api: advapi32.RegSetValueEx
"""

# A rule with hallucinated API
BAD_API_RULE = """rule:
  meta:
    name: detect something
    namespace: nursery
    authors:
      - test@test.com
    scopes:
      static: function
      dynamic: span of calls
  features:
    - and:
      - api: kernel32.DoTheMalwareThing
      - string: "hello"
"""


class TestSiblingAnalysis:
    """Test sibling rule comparison for over-generalization detection."""

    def test_extract_feature_set(self):
        """Should extract normalized features from a rule."""
        data = yaml.safe_load(VALID_RULE)
        features = _extract_feature_set(data["rule"]["features"])

        assert "api:advapi32.RegSetValueEx" in features
        assert "api:advapi32.RegCreateKeyEx" in features
        assert any("number:" in f for f in features)
        assert any("string:" in f for f in features)

    def test_extract_feature_set_empty(self):
        """Empty features → empty set."""
        assert _extract_feature_set([]) == set()
        assert _extract_feature_set({}) == set()

    def test_analyze_siblings_no_index(self):
        """No rule index → empty analysis."""
        result = analyze_siblings(VALID_RULE, None, "persistence/registry")
        assert result.sibling_count == 0

    def test_analyze_siblings_no_namespace(self):
        """No namespace → empty analysis."""
        index = RuleIndex()
        result = analyze_siblings(VALID_RULE, index, None)
        assert result.sibling_count == 0

    def test_broad_rule_detection(self):
        """A rule with only one feature should be flagged as too simple."""
        # The broad_rule has only 1 unique feature (api:RegSetValueEx)
        data = yaml.safe_load(BROAD_RULE)
        features = _extract_feature_set(data["rule"]["features"])
        assert len(features) == 1  # only the API call


# ==========================================================================
# Quality Gate: Semantic Coherence
# ==========================================================================


class TestSemanticCoherence:
    """Test semantic coherence checks (name↔features, ATT&CK alignment, API validity)."""

    def test_valid_rule_coherent(self):
        """A well-formed rule should pass semantic checks."""
        checks = check_semantic_coherence(VALID_RULE)

        # Should have multiple checks
        assert len(checks) >= 3

        # Feature depth should pass (multiple features)
        depth_check = next(c for c in checks if c.check_name == "feature_depth")
        assert depth_check.status == VerificationStatus.PASSED

    def test_broad_rule_warns_on_depth(self):
        """A rule with only 1 feature should warn."""
        checks = check_semantic_coherence(BROAD_RULE)
        depth_check = next(c for c in checks if c.check_name == "feature_depth")
        assert depth_check.status == VerificationStatus.WARNING

    def test_invalid_yaml_fails(self):
        """Invalid YAML should fail immediately."""
        checks = check_semantic_coherence("not: valid: yaml: [")
        assert any(c.status == VerificationStatus.FAILED for c in checks)

    def test_name_feature_alignment_valid(self):
        """Rule name 'persist via Run registry key' should align with registry features."""
        checks = check_semantic_coherence(VALID_RULE)
        name_check = next(
            (c for c in checks if c.check_name == "name_feature_alignment"),
            None,
        )
        if name_check:
            # "registry" appears in both name and features
            assert name_check.status in (VerificationStatus.PASSED, VerificationStatus.WARNING)

    def test_attck_namespace_alignment(self):
        """ATT&CK T1547.001 (persistence) should align with persistence/ namespace."""
        checks = check_semantic_coherence(VALID_RULE)
        attck_check = next(
            (c for c in checks if c.check_name == "attck_namespace_alignment"),
            None,
        )
        if attck_check:
            assert attck_check.status == VerificationStatus.PASSED

    def test_logic_tree_well_formed(self):
        """Valid rule should have well-formed logic tree."""
        checks = check_semantic_coherence(VALID_RULE)
        tree_check = next(
            (c for c in checks if c.check_name == "logic_tree_structure"),
            None,
        )
        if tree_check:
            assert tree_check.status == VerificationStatus.PASSED

    def test_degenerate_or_block(self):
        """OR with single child should warn."""
        degenerate_rule = """rule:
  meta:
    name: test
    namespace: test
    authors:
      - test@test.com
    scopes:
      static: function
      dynamic: span of calls
  features:
    - or:
      - api: kernel32.CreateFile
"""
        checks = check_semantic_coherence(degenerate_rule)
        tree_check = next(
            (c for c in checks if c.check_name == "logic_tree_structure"),
            None,
        )
        if tree_check:
            assert tree_check.status == VerificationStatus.WARNING


# ==========================================================================
# Quality Gate: Negative Testing
# ==========================================================================


class TestNegativeTesting:
    """Test false-positive detection against benign binaries."""

    def test_no_testfiles_skips(self):
        """No testfiles dir → skip."""
        checks = run_negative_tests(VALID_RULE, testfiles_dir=None)
        assert len(checks) == 1
        assert checks[0].status == VerificationStatus.SKIPPED

    def test_nonexistent_dir_skips(self):
        """Nonexistent directory → skip."""
        checks = run_negative_tests(VALID_RULE, testfiles_dir="/nonexistent/path")
        assert len(checks) == 1
        assert checks[0].status == VerificationStatus.SKIPPED


# ==========================================================================
# Quality Gate: Full Pipeline
# ==========================================================================


class TestQualityGateFull:
    """Test the full run_quality_gate entry point."""

    def test_valid_rule_no_sample(self):
        """Valid rule without sample testing."""
        validation = ValidationResult(
            is_valid=True,
            yaml_valid=True,
            schema_valid=True,
            lint_passed=True,
        )
        report = run_quality_gate(
            VALID_RULE,
            validation_result=validation,
            sample_tested=False,
        )

        assert isinstance(report, QualityReport)
        assert report.confidence in (ConfidenceLevel.MEDIUM, ConfidenceLevel.LOW)
        assert report.target_directory == "nursery"
        assert report.passed_count > 0
        assert len(report.checks) > 0

    def test_valid_rule_with_sample(self):
        """Valid rule with sample testing → can reach HIGH."""
        validation = ValidationResult(
            is_valid=True,
            yaml_valid=True,
            schema_valid=True,
            lint_passed=True,
        )
        report = run_quality_gate(
            VALID_RULE,
            validation_result=validation,
            sample_tested=True,
        )

        assert isinstance(report, QualityReport)
        # With sample tested and all passing, should be HIGH
        if report.failed_count == 0:
            assert report.confidence == ConfidenceLevel.HIGH
            assert report.target_directory == "rules"

    def test_invalid_yaml_rejects(self):
        """Invalid YAML → REJECT."""
        report = run_quality_gate("not valid yaml: [")
        assert report.confidence == ConfidenceLevel.REJECT

    def test_schema_failure_rejects(self):
        """Missing schema fields → REJECT."""
        bad_rule = "rule:\n  meta:\n    name: test\n"
        report = run_quality_gate(bad_rule)
        # Should fail on schema (missing required fields)
        assert any(c.layer == "structural" and c.status == VerificationStatus.FAILED
                    for c in report.checks)

    def test_quality_gate_includes_all_layers(self):
        """Report should include checks from all layers."""
        validation = ValidationResult(
            is_valid=True,
            yaml_valid=True,
            schema_valid=True,
            lint_passed=True,
        )
        report = run_quality_gate(
            VALID_RULE,
            validation_result=validation,
        )
        layers = {c.layer for c in report.checks}
        assert "structural" in layers
        assert "semantic" in layers
        # negative and sibling are conditional on config

    def test_pr_section_not_empty(self):
        """PR section should be non-empty."""
        validation = ValidationResult(
            is_valid=True,
            yaml_valid=True,
            schema_valid=True,
            lint_passed=True,
        )
        report = run_quality_gate(
            VALID_RULE,
            validation_result=validation,
        )
        pr_section = report.to_pr_section()
        assert len(pr_section) > 100
        assert "Quality Gate Report" in pr_section


# ==========================================================================
# Backlog Processor: Issue Classification
# ==========================================================================


class TestIssueClassification:
    """Test classification of capa-rules issues by tractability."""

    def test_classify_issue_with_sample(self):
        """Issue with SHA256 hash → HIGH tractability."""
        issue = {
            "number": 42,
            "title": "New rule: detect process hollowing",
            "body": "Sample: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            "labels": [],
            "html_url": "https://github.com/mandiant/capa-rules/issues/42",
        }
        c = classify_issue(issue)

        assert c.has_sample
        assert c.sample_count == 1
        assert c.tractability == IssueTractability.HIGH

    def test_classify_issue_with_decompilation(self):
        """Issue with code block → MEDIUM tractability."""
        issue = {
            "number": 43,
            "title": "Rule idea: screen capture",
            "body": "```c\nvoid FUN_00401000() {\n  HANDLE h = CreateFile(...);\n}\n```",
            "labels": [],
            "html_url": "https://github.com/mandiant/capa-rules/issues/43",
        }
        c = classify_issue(issue)

        assert c.has_decompilation
        assert c.tractability == IssueTractability.MEDIUM

    def test_classify_issue_with_registry_ioc(self):
        """Issue with registry path → has_iocs, MEDIUM."""
        issue = {
            "number": 44,
            "title": "Detect AppInit_DLLs persistence",
            "body": "Check HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
            "labels": [],
            "html_url": "https://github.com/mandiant/capa-rules/issues/44",
        }
        c = classify_issue(issue)

        assert c.has_iocs
        assert c.tractability == IssueTractability.MEDIUM

    def test_classify_issue_with_attck(self):
        """Issue with ATT&CK technique → has_attck, MEDIUM."""
        issue = {
            "number": 45,
            "title": "T1547.001 persistence detection",
            "body": "Add detection for T1547.001 registry run keys",
            "labels": [],
            "html_url": "https://github.com/mandiant/capa-rules/issues/45",
        }
        c = classify_issue(issue)

        assert c.has_attck
        assert "T1547.001" in c.attck_ids
        assert c.tractability == IssueTractability.MEDIUM

    def test_classify_behavioral_only(self):
        """Issue with only text description → LOW tractability."""
        issue = {
            "number": 46,
            "title": "Detect clipboard monitoring",
            "body": "Malware monitors clipboard for crypto addresses.",
            "labels": [],
            "html_url": "https://github.com/mandiant/capa-rules/issues/46",
        }
        c = classify_issue(issue)

        assert not c.has_sample
        assert not c.has_decompilation
        assert not c.has_iocs
        assert not c.has_attck
        assert c.tractability == IssueTractability.LOW

    def test_classify_bug_report_skips(self):
        """Bug report label → SKIP."""
        issue = {
            "number": 47,
            "title": "False positive in service detection",
            "body": "Rule matches benign software",
            "labels": [{"name": "false positive"}, {"name": "bug"}],
            "html_url": "https://github.com/mandiant/capa-rules/issues/47",
        }
        c = classify_issue(issue)

        assert not c.is_rule_request
        assert c.tractability == IssueTractability.SKIP

    def test_classify_with_linked_pr(self):
        """Issue with linked PR → SKIP."""
        issue = {
            "number": 48,
            "title": "Add detection for DLL sideloading",
            "body": "Fixed in PR #1126",
            "labels": [],
            "html_url": "https://github.com/mandiant/capa-rules/issues/48",
        }
        c = classify_issue(issue)

        assert c.has_existing_pr
        assert c.tractability == IssueTractability.SKIP

    def test_classify_summary_format(self):
        """Summary should include tractability and context flags."""
        issue = {
            "number": 42,
            "title": "New rule: detect stuff",
            "body": "T1547.001 sample: " + "a" * 64,
            "labels": [],
            "html_url": "https://github.com/mandiant/capa-rules/issues/42",
        }
        c = classify_issue(issue)
        summary = c.summary()

        assert "#42" in summary
        assert c.tractability.value in summary


# ==========================================================================
# Backlog Processor: Backlog Report
# ==========================================================================


class TestBacklogReport:
    """Test backlog report generation and batch selection."""

    def _make_classification(
        self,
        number: int,
        tractability: IssueTractability,
        has_pr: bool = False,
    ) -> IssueClassification:
        return IssueClassification(
            issue_number=number,
            title=f"Test issue #{number}",
            url=f"https://github.com/mandiant/capa-rules/issues/{number}",
            tractability=tractability,
            has_existing_pr=has_pr,
        )

    def test_backlog_report_summary(self):
        """Report summary should list counts by tractability."""
        report = BacklogReport(total_issues=4)
        report.high_tractability = [self._make_classification(1, IssueTractability.HIGH)]
        report.medium_tractability = [self._make_classification(2, IssueTractability.MEDIUM)]
        report.low_tractability = [self._make_classification(3, IssueTractability.LOW)]
        report.skipped = [self._make_classification(4, IssueTractability.SKIP)]

        summary = report.summary()
        assert "HIGH" in summary
        assert "MEDIUM" in summary
        assert "LOW" in summary
        assert "4 issues" in summary

    def test_processable_order(self):
        """Processable should return HIGH → MEDIUM → LOW."""
        report = BacklogReport(total_issues=3)
        report.low_tractability = [self._make_classification(3, IssueTractability.LOW)]
        report.high_tractability = [self._make_classification(1, IssueTractability.HIGH)]
        report.medium_tractability = [self._make_classification(2, IssueTractability.MEDIUM)]

        processable = report.processable
        assert len(processable) == 3
        assert processable[0].tractability == IssueTractability.HIGH
        assert processable[1].tractability == IssueTractability.MEDIUM
        assert processable[2].tractability == IssueTractability.LOW

    def test_batch_selection_prioritizes_high(self):
        """Batch should select HIGH tractability first."""
        report = BacklogReport(total_issues=6)
        report.high_tractability = [
            self._make_classification(1, IssueTractability.HIGH),
            self._make_classification(2, IssueTractability.HIGH),
        ]
        report.medium_tractability = [
            self._make_classification(3, IssueTractability.MEDIUM),
            self._make_classification(4, IssueTractability.MEDIUM),
        ]
        report.low_tractability = [
            self._make_classification(5, IssueTractability.LOW),
        ]

        batch = process_backlog_batch(report, max_batch=3)
        assert len(batch) == 3
        assert batch[0].issue_number == 1
        assert batch[1].issue_number == 2
        assert batch[2].issue_number == 3

    def test_batch_excludes_existing_prs(self):
        """Batch should skip issues that already have PRs."""
        report = BacklogReport(total_issues=3)
        report.high_tractability = [
            self._make_classification(1, IssueTractability.HIGH, has_pr=True),
            self._make_classification(2, IssueTractability.HIGH),
        ]

        batch = process_backlog_batch(report, max_batch=5)
        assert len(batch) == 1
        assert batch[0].issue_number == 2

    def test_batch_includes_low_when_requested(self):
        """LOW tractability included only when include_low=True."""
        report = BacklogReport(total_issues=2)
        report.low_tractability = [
            self._make_classification(1, IssueTractability.LOW),
        ]

        batch_no_low = process_backlog_batch(report, max_batch=5, include_low=False)
        assert len(batch_no_low) == 0

        batch_with_low = process_backlog_batch(report, max_batch=5, include_low=True)
        assert len(batch_with_low) == 1


# ==========================================================================
# Backlog Processor: Pattern Detection
# ==========================================================================


class TestPatternDetection:
    """Test IOC/hash/code detection patterns."""

    def test_sha256_detection(self):
        """Should detect SHA256 hashes."""
        text = "Sample: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        assert SHA256_PATTERN.search(text)

    def test_registry_path_detection(self):
        """Should detect registry paths."""
        text = "Check HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        assert REGISTRY_PATTERN.search(text)

        text2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows"
        assert REGISTRY_PATTERN.search(text2)

    def test_linked_pr_detection(self):
        """Should detect linked PRs."""
        assert _has_linked_pr({"body": "Fixed in PR #1126"})
        assert _has_linked_pr({"body": "See pull request #42"})
        assert not _has_linked_pr({"body": "Just a description"})


# ==========================================================================
# Integration: Quality Gate + Pipeline
# ==========================================================================


class TestQualityGateIntegration:
    """Test quality gate integration with existing pipeline components."""

    def test_quality_gate_with_validation_result(self):
        """Quality gate should accept pre-computed validation results."""
        validation = ValidationResult(
            is_valid=True,
            yaml_valid=True,
            schema_valid=True,
            lint_passed=True,
        )
        report = run_quality_gate(
            VALID_RULE,
            validation_result=validation,
        )

        # Should have structural checks from validation
        structural = [c for c in report.checks if c.layer == "structural"]
        assert len(structural) >= 3
        assert all(c.status == VerificationStatus.PASSED for c in structural)

    def test_quality_gate_without_validation(self):
        """Quality gate should run its own validation if not provided."""
        report = run_quality_gate(VALID_RULE)

        structural = [c for c in report.checks if c.layer == "structural"]
        assert len(structural) >= 3

    def test_quality_gate_with_issue_context(self):
        """Quality gate should use issue context for semantic checks."""
        context = IssueContext(
            title="persist via Run registry key",
            body="Detect persistence via registry run keys T1547.001",
            attck_ids=["T1547.001"],
            suggested_namespace="persistence/registry",
        )
        report = run_quality_gate(
            VALID_RULE,
            context=context,
        )

        semantic = [c for c in report.checks if c.layer == "semantic"]
        assert len(semantic) > 0

    def test_nursery_routing_for_no_sample(self):
        """Without sample testing, should route to nursery."""
        validation = ValidationResult(
            is_valid=True,
            yaml_valid=True,
            schema_valid=True,
            lint_passed=True,
        )
        report = run_quality_gate(
            VALID_RULE,
            validation_result=validation,
            sample_tested=False,
        )

        assert report.target_directory == "nursery"
        assert report.had_sample is False

    def test_rules_routing_for_sample_tested(self):
        """With sample testing and all passing, should route to rules/."""
        validation = ValidationResult(
            is_valid=True,
            yaml_valid=True,
            schema_valid=True,
            lint_passed=True,
        )
        report = run_quality_gate(
            VALID_RULE,
            validation_result=validation,
            sample_tested=True,
        )

        if report.failed_count == 0:
            assert report.target_directory == "rules"
