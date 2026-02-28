"""
Tests for the expanded architecture modules:
- Proactive triggers (feed scanners, coverage analysis)
- Search grounding (API doc verification)
- PR workflow (branch naming, file paths, PR formatting)
- Test runner (capa execution, result parsing)
- ADK agent (tool declarations, tool handlers)
"""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from src.trigger import IssueContext
from src.validator import ValidationResult


# ===================================================================
# Proactive Trigger Tests
# ===================================================================

class TestProactiveTrigger:
    """Tests for proactive threat intel feed scanning."""

    def test_threat_report_to_issue_context(self):
        from src.proactive import ThreatReport
        report = ThreatReport(
            source="malpedia",
            title="Emotet persistence module",
            description="Emotet uses service creation for persistence",
            attck_ids=["T1543.003"],
            sample_hashes=["abc123"],
            references=["https://example.com/report"],
            malware_family="Emotet",
        )
        ctx = report.to_issue_context()
        assert isinstance(ctx, IssueContext)
        assert "T1543.003" in ctx.attck_ids
        assert ctx.suggested_namespace is not None

    def test_coverage_gap_no_coverage(self):
        from src.proactive import CoverageGap
        gap = CoverageGap(
            technique_id="T1547.001",
            technique_name="Registry Run Keys",
            source_reports=[],
            existing_rules=[],
            gap_type="no_coverage",
            priority=10.0,
        )
        summary = gap.summary()
        assert "no_coverage" in summary
        assert "T1547.001" in summary
        assert gap.priority == 10.0

    def test_coverage_gap_partial(self):
        from src.proactive import CoverageGap
        gap = CoverageGap(
            technique_id="T1543.003",
            technique_name="Windows Service",
            source_reports=[],
            existing_rules=["persist via Windows service"],
            gap_type="partial_coverage",
            priority=5.0,
        )
        assert gap.gap_type == "partial_coverage"
        assert len(gap.existing_rules) == 1

    def test_coverage_analyzer_no_coverage(self):
        from src.proactive import CoverageAnalyzer, ThreatReport
        from src.grounding import RuleIndex, RuleEntry

        # Create a minimal index with no rules for T9999
        index = RuleIndex()
        index.rules = [RuleEntry(
            path="test.yml",
            name="test rule",
            namespace="test",
            raw_text="",
            attck_ids=["T1234"],
        )]
        index._index_entry(0, index.rules[0])

        analyzer = CoverageAnalyzer(index)
        reports = [ThreatReport(
            source="test",
            title="Test",
            description="Test",
            attck_ids=["T9999"],
        )]
        gaps = analyzer.analyze_reports(reports)
        assert len(gaps) == 1
        assert gaps[0].gap_type == "no_coverage"

    def test_coverage_analyzer_existing_coverage(self):
        from src.proactive import CoverageAnalyzer, ThreatReport
        from src.grounding import RuleIndex, RuleEntry

        index = RuleIndex()
        for i in range(3):
            entry = RuleEntry(
                path=f"test{i}.yml",
                name=f"rule {i}",
                namespace="persistence/service",
                raw_text="",
                attck_ids=["T1543.003"],
            )
            index.rules.append(entry)
            index._index_entry(i, entry)

        analyzer = CoverageAnalyzer(index)
        reports = [ThreatReport(
            source="test",
            title="Test",
            description="Test",
            attck_ids=["T1543.003"],
        )]
        gaps = analyzer.analyze_reports(reports)
        assert len(gaps) == 1
        assert gaps[0].gap_type == "variant"  # Already well-covered

    def test_infer_namespace_from_attck(self):
        from src.proactive import _infer_namespace_from_attck
        assert _infer_namespace_from_attck(["T1543.003"]) == "persistence/service"
        assert _infer_namespace_from_attck(["T1547.001"]) == "persistence/registry"
        assert _infer_namespace_from_attck(["T1197"]) == "defense-evasion/bits"
        assert _infer_namespace_from_attck([]) is None


# ===================================================================
# Search Grounding Tests
# ===================================================================

class TestSearchGrounding:
    """Tests for the web search grounding module."""

    def test_grounding_context_empty(self):
        from src.search_grounding import GroundingContext
        ctx = GroundingContext()
        assert not ctx.has_content()
        assert ctx.to_prompt() == ""

    def test_grounding_context_with_api(self):
        from src.search_grounding import GroundingContext, SearchResult
        ctx = GroundingContext(
            api_definitions=[SearchResult(
                title="RegSetValueEx — MSDN",
                url="https://learn.microsoft.com/...",
                snippet="Sets the data and type of a specified value under a registry key.",
                source_type="msdn",
            )],
        )
        assert ctx.has_content()
        prompt = ctx.to_prompt()
        assert "Verified API Definitions" in prompt
        assert "RegSetValueEx" in prompt

    def test_grounding_context_full(self):
        from src.search_grounding import GroundingContext, SearchResult
        ctx = GroundingContext(
            api_definitions=[SearchResult("API", "http://msdn", "desc", "msdn")],
            registry_paths=[SearchResult("Reg", "http://msdn", "desc", "msdn")],
            technique_descriptions=[SearchResult("ATT&CK", "http://mitre", "desc", "mitre")],
            threat_reports=[SearchResult("Report", "http://blog", "desc", "blog")],
        )
        prompt = ctx.to_prompt()
        assert "Verified API Definitions" in prompt
        assert "Registry Key Documentation" in prompt
        assert "MITRE ATT&CK Technique Details" in prompt
        assert "Related Threat Intelligence" in prompt

    def test_classify_source(self):
        from src.search_grounding import _classify_source
        assert _classify_source("https://learn.microsoft.com/en-us/windows/...") == "msdn"
        assert _classify_source("https://attack.mitre.org/techniques/T1543/") == "mitre"
        assert _classify_source("https://www.mandiant.com/blog/...") == "blog"
        assert _classify_source("https://example.com") == "web"

    def test_fallback_search_api(self):
        from src.search_grounding import GoogleSearchClient
        client = GoogleSearchClient()  # No API key → fallback mode
        results = client._fallback_search("RegSetValueEx Win32 API", 3)
        assert len(results) >= 1
        assert any("microsoft" in r.url.lower() for r in results)

    def test_fallback_search_attck(self):
        from src.search_grounding import GoogleSearchClient
        client = GoogleSearchClient()
        results = client._fallback_search("T1543.003 persistence", 3)
        assert any(r.source_type == "mitre" for r in results)

    def test_fallback_search_registry(self):
        from src.search_grounding import GoogleSearchClient
        client = GoogleSearchClient()
        results = client._fallback_search("HKEY_LOCAL_MACHINE registry", 3)
        assert len(results) >= 1


# ===================================================================
# PR Workflow Tests
# ===================================================================

class TestPRWorkflow:
    """Tests for the automated PR creation module."""

    def test_derive_branch_name(self):
        from src.pr_workflow import derive_branch_name
        assert derive_branch_name("persist via Windows service", 1114) == "agent/persist-via-windows-service-1114"
        assert derive_branch_name("detect BITS usage") == "agent/detect-bits-usage"

    def test_derive_branch_name_long(self):
        from src.pr_workflow import derive_branch_name
        long_name = "a very long rule name that exceeds the reasonable length for a git branch"
        branch = derive_branch_name(long_name, 42)
        assert len(branch) < 100
        assert branch.startswith("agent/")
        assert branch.endswith("-42")

    def test_derive_file_path(self):
        from src.pr_workflow import derive_file_path
        path = derive_file_path("persistence/service", "persist via Windows service")
        assert path.endswith(".yml")
        assert "persistence" in path
        assert "service" in path
        assert "persist-via-windows-service" in path

    def test_derive_file_path_nested(self):
        from src.pr_workflow import derive_file_path
        path = derive_file_path("persistence/registry/run", "persist via Run key")
        assert "persistence" in path
        assert "run" in path

    def test_format_pr_description(self):
        from src.pr_workflow import format_pr_description, PRContext
        ctx = PRContext(
            rule_text="rule:\n  meta:\n    name: test",
            rule_name="test rule",
            namespace="test",
            issue_number=42,
            attck_ids=["T1543.003"],
            validation_result=ValidationResult(
                is_valid=True,
                yaml_valid=True,
                schema_valid=True,
                lint_passed=True,
            ),
        )
        desc = format_pr_description(ctx)
        assert "Automated capa rule submission" in desc
        assert "#42" in desc
        assert "T1543.003" in desc
        assert "✅ Pass" in desc
        assert "capa-rule-agent" in desc

    def test_format_pr_description_with_errors(self):
        from src.pr_workflow import format_pr_description, PRContext
        ctx = PRContext(
            rule_text="rule:\n  meta:\n    name: test",
            rule_name="test",
            namespace="test",
            validation_result=ValidationResult(
                is_valid=False,
                yaml_valid=True,
                schema_valid=True,
                lint_passed=False,
                errors=["missing namespace"],
            ),
        )
        desc = format_pr_description(ctx)
        assert "NEEDS REVIEW" in desc
        assert "missing namespace" in desc


# ===================================================================
# Test Runner Tests
# ===================================================================

class TestTestRunner:
    """Tests for the capa test runner module."""

    def test_test_result_summary_match(self):
        from src.test_runner import TestResult
        result = TestResult(
            matched=True,
            match_count=3,
            matched_addresses=["0x401000", "0x402000", "0x403000"],
            sample_hash="abcdef1234567890" * 4,
        )
        summary = result.summary()
        assert "MATCH" in summary
        assert "3 match(es)" in summary

    def test_test_result_summary_no_match(self):
        from src.test_runner import TestResult
        result = TestResult(matched=False, sample_hash="abc")
        assert "NO MATCH" in result.summary()

    def test_test_result_summary_error(self):
        from src.test_runner import TestResult
        result = TestResult(error="timeout", sample_hash="abc")
        assert "ERROR" in result.summary()

    def test_test_result_to_examples(self):
        from src.test_runner import TestResult
        result = TestResult(
            matched=True,
            match_count=2,
            matched_addresses=["0x401000", "0x402000"],
            sample_hash="aabbccdd" * 8,
        )
        examples = result.to_examples_field()
        assert len(examples) == 2
        assert "0x401000" in examples[0]
        assert "aabbccdd" in examples[0]

    def test_inject_examples_into_rule(self):
        from src.test_runner import inject_examples_into_rule, TestResult
        rule = """rule:
  meta:
    name: test rule
    namespace: test
    authors:
      - test@test.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Persistence::Windows Service [T1543.003]
  features:
    - and:
      - api: CreateService
"""
        results = [TestResult(
            matched=True,
            matched_addresses=["0x401000"],
            sample_hash="aabbccdd" * 8,
        )]
        updated = inject_examples_into_rule(rule, results)
        assert "examples:" in updated
        assert "0x401000" in updated

    def test_sample_manager_verify_hash(self):
        import tempfile
        import hashlib
        from src.test_runner import SampleManager

        manager = SampleManager()

        # Create a temp file with known content
        content = b"test content for hashing"
        expected = hashlib.sha256(content).hexdigest()

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            assert manager.verify_hash(temp_path, expected)
            assert not manager.verify_hash(temp_path, "0000" * 16)
        finally:
            Path(temp_path).unlink(missing_ok=True)


# ===================================================================
# ADK Agent Tests
# ===================================================================

class TestADKAgent:
    """Tests for the Google ADK agent module."""

    def test_tool_result_success(self):
        from src.adk_agent import ToolResult
        result = ToolResult(success=True, data={"key": "value"})
        d = result.to_dict()
        assert d["success"] is True
        assert d["data"]["key"] == "value"

    def test_tool_result_error(self):
        from src.adk_agent import ToolResult
        result = ToolResult(success=False, error="Something failed")
        d = result.to_dict()
        assert d["success"] is False
        assert "Something failed" in d["error"]

    def test_tool_declarations_complete(self):
        from src.adk_agent import TOOL_DECLARATIONS
        tool_names = {t.name for t in TOOL_DECLARATIONS}
        assert "parse_issue" in tool_names
        assert "search_similar_rules" in tool_names
        assert "search_api_docs" in tool_names
        assert "validate_rule" in tool_names
        assert "run_capa_test" in tool_names
        assert "create_pr" in tool_names

    def test_tool_handlers_complete(self):
        from src.adk_agent import TOOL_HANDLERS, TOOL_DECLARATIONS
        for decl in TOOL_DECLARATIONS:
            assert decl.name in TOOL_HANDLERS, f"Missing handler for tool: {decl.name}"

    def test_agent_config_defaults(self):
        from src.adk_agent import AgentConfig
        config = AgentConfig()
        assert config.model_name == "gemini-3.1-pro"
        assert config.max_tool_rounds == 10
        assert config.auto_submit_pr is False

    def test_tool_validate_rule_handler(self):
        from src.adk_agent import tool_validate_rule
        valid_rule = """rule:
  meta:
    name: test rule
    namespace: test
    authors:
      - test@test.com
    scopes:
      static: function
      dynamic: span of calls
  features:
    - and:
      - api: CreateFile
"""
        result = tool_validate_rule(valid_rule)
        assert result["success"] is True
        assert result["data"]["yaml_valid"] is True
        assert result["data"]["schema_valid"] is True

    def test_tool_validate_rule_invalid(self):
        from src.adk_agent import tool_validate_rule
        result = tool_validate_rule("not: valid: yaml: [")
        assert result["success"] is True
        assert result["data"]["yaml_valid"] is False

    def test_tool_search_api_docs(self):
        from src.adk_agent import tool_search_api_docs
        result = tool_search_api_docs("RegSetValueEx MSDN")
        assert result["success"] is True


# ===================================================================
# Pipeline Integration Tests (expanded)
# ===================================================================

class TestExpandedPipeline:
    """Tests for the expanded pipeline with new modules."""

    def test_format_pr_description_basic(self):
        from src.pipeline import format_pr_description
        ctx = IssueContext(
            title="Test rule",
            body="test body",
            attck_ids=["T1543.003"],
        )
        result = ValidationResult(is_valid=True, yaml_valid=True, schema_valid=True, lint_passed=True)
        desc = format_pr_description(ctx, "rule: test", result)
        assert "PASSED" in desc
        assert "T1543.003" in desc

    def test_offline_pipeline_still_works(self):
        """Ensure the original offline pipeline isn't broken by new imports."""
        from src.pipeline import run_pipeline
        ctx = IssueContext(
            title="Test rule",
            body="Detect persistence via test",
            attck_ids=["T1547.001"],
            suggested_name="test rule",
            suggested_namespace="persistence/registry",
        )
        rule_text, result, pr_desc, quality_report = run_pipeline(
            ctx,
            max_attempts=1,
            offline=True,
        )
        assert len(rule_text) > 0
        assert "rule:" in rule_text
