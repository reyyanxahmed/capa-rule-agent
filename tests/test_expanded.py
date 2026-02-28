"""
Tests for the expanded architecture modules:
- PR workflow (branch naming, file paths, PR formatting)
- Test runner (capa execution, result parsing)
- Pipeline integration (offline mode, PR descriptions)
"""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from src.trigger import IssueContext
from src.validator import ValidationResult


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
