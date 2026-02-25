"""
Tests for the capa rule generation agent.
"""

import pytest
from src.trigger import parse_description, parse_github_issue, IssueContext, _infer_rule_metadata
from src.validator import validate_yaml_syntax, validate_schema, validate_rule
from src.generator import generate_rule_offline


class TestTrigger:
    """Tests for the issue parsing / trigger module."""

    def test_parse_description_basic(self):
        ctx = parse_description("Detect persistence via ShellServiceObjectDelayLoad registry key")
        assert ctx.title is not None
        assert "ShellServiceObjectDelayLoad" in ctx.body
        assert ctx.suggested_namespace is not None

    def test_parse_description_with_attck(self):
        ctx = parse_description("Detect T1547.001 registry run key persistence")
        assert "T1547.001" in ctx.attck_ids
        assert len(ctx.attck_references) > 0

    def test_parse_description_multiple_attck(self):
        ctx = parse_description("Detect T1543.003 and T1569.002 service-based persistence")
        assert "T1543.003" in ctx.attck_ids
        assert "T1569.002" in ctx.attck_ids

    def test_infer_metadata_persistence(self):
        name, namespace = _infer_rule_metadata("persist via ShellServiceObjectDelayLoad", [])
        assert namespace is not None
        assert "persistence" in namespace

    def test_infer_metadata_service(self):
        name, namespace = _infer_rule_metadata("persist via Windows service", [])
        assert namespace == "persistence/service"

    def test_infer_metadata_registry(self):
        name, namespace = _infer_rule_metadata("persist via registry ShellServiceObjectDelayLoad", [])
        assert namespace == "persistence/registry"

    def test_prompt_context_format(self):
        ctx = parse_description("Detect T1547.001 persistence via Run registry key")
        prompt = ctx.to_prompt_context()
        assert "## Issue:" in prompt
        assert "T1547.001" in prompt
        assert "### ATT&CK Techniques" in prompt


class TestValidator:
    """Tests for the validation module."""

    VALID_RULE = """rule:
  meta:
    name: test rule
    namespace: test
    authors:
      - test@test.com
    scopes:
      static: function
      dynamic: call
  features:
    - api: kernel32.CreateFileA
"""

    INVALID_YAML = """rule:
  meta:
    name: bad yaml
    features:
  - this is: [broken
"""

    MISSING_FEATURES = """rule:
  meta:
    name: no features
    authors:
      - test@test.com
    scopes:
      static: function
      dynamic: call
"""

    MISSING_META = """rule:
  features:
    - api: kernel32.CreateFileA
"""

    def test_valid_yaml(self):
        ok, errors = validate_yaml_syntax(self.VALID_RULE)
        assert ok
        assert len(errors) == 0

    def test_invalid_yaml(self):
        ok, errors = validate_yaml_syntax(self.INVALID_YAML)
        assert not ok
        assert len(errors) > 0

    def test_valid_schema(self):
        ok, errors = validate_schema(self.VALID_RULE)
        assert ok
        assert len(errors) == 0

    def test_missing_features(self):
        ok, errors = validate_schema(self.MISSING_FEATURES)
        assert not ok
        assert any("features" in e for e in errors)

    def test_missing_meta(self):
        ok, errors = validate_schema(self.MISSING_META)
        assert not ok
        assert any("meta" in e for e in errors)

    def test_full_validation_valid(self):
        result = validate_rule(self.VALID_RULE)
        assert result.yaml_valid
        assert result.schema_valid

    def test_full_validation_invalid_yaml(self):
        result = validate_rule(self.INVALID_YAML)
        assert not result.yaml_valid
        assert not result.is_valid

    def test_error_summary(self):
        result = validate_rule(self.MISSING_META)
        summary = result.error_summary()
        assert "SCHEMA ERROR" in summary


class TestGenerator:
    """Tests for the offline rule generator."""

    def test_offline_generates_valid_yaml(self):
        ctx = parse_description("Detect persistence via Run registry key T1547.001")
        rule = generate_rule_offline(ctx)
        ok, errors = validate_yaml_syntax(rule)
        assert ok, f"Generated rule has YAML errors: {errors}"

    def test_offline_includes_attck(self):
        ctx = parse_description("Detect T1543.003 service persistence")
        rule = generate_rule_offline(ctx)
        assert "T1543.003" in rule

    def test_offline_includes_namespace(self):
        ctx = parse_description("Detect persistence via Windows service")
        rule = generate_rule_offline(ctx)
        assert "persistence" in rule

    def test_offline_schema_valid(self):
        ctx = parse_description("Detect persistence via registry key")
        rule = generate_rule_offline(ctx)
        ok, errors = validate_schema(rule)
        assert ok, f"Generated rule has schema errors: {errors}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
