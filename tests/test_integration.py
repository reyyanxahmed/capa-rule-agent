"""
Integration tests — end-to-end pipeline tests that require the capa-rules corpus.

These tests validate the full pipeline flow including RAG grounding.
Skipped if the capa-rules directory is not available.
"""

import os
import pytest
from pathlib import Path

from src.trigger import parse_description, parse_github_issue, IssueContext
from src.generator import generate_rule_offline
from src.grounding import RuleIndex, format_grounding_context
from src.validator import validate_rule, validate_yaml_syntax, validate_schema
from src.pipeline import run_pipeline, DEFAULT_RULES_DIR

# Skip if capa-rules not available
RULES_AVAILABLE = Path(DEFAULT_RULES_DIR).exists() or Path(
    os.environ.get("CAPA_RULES_DIR", "/nonexistent")
).exists()


def get_rules_dir():
    """Get the capa-rules directory path."""
    if Path(DEFAULT_RULES_DIR).exists():
        return str(DEFAULT_RULES_DIR)
    return os.environ.get("CAPA_RULES_DIR", str(DEFAULT_RULES_DIR))


@pytest.mark.skipif(not RULES_AVAILABLE, reason="capa-rules directory not available")
class TestGroundingIntegration:
    """Integration tests for RAG grounding over the real capa-rules corpus."""

    @pytest.fixture(scope="class")
    def rule_index(self):
        index = RuleIndex()
        index.index_directory(get_rules_dir())
        return index

    def test_index_has_rules(self, rule_index):
        assert len(rule_index) > 100, f"Expected 100+ rules, got {len(rule_index)}"

    def test_retrieve_persistence_service(self, rule_index):
        ctx = parse_description("Detect persistence via Windows service creation T1543.003")
        results = rule_index.retrieve(ctx, top_k=5)
        assert len(results) >= 1
        namespaces = [e.namespace for e, _ in results]
        assert any("persistence" in ns for ns in namespaces), f"No persistence rules found: {namespaces}"

    def test_retrieve_registry_persistence(self, rule_index):
        ctx = parse_description("Detect persistence via Run registry key T1547.001")
        results = rule_index.retrieve(ctx, top_k=5)
        assert len(results) >= 1
        attck_ids = [tid for e, _ in results for tid in e.attck_ids]
        assert "T1547.001" in attck_ids, f"T1547.001 not in results: {attck_ids}"

    def test_retrieve_encryption(self, rule_index):
        ctx = parse_description("Detect AES encryption in malware")
        results = rule_index.retrieve(ctx, top_k=5)
        assert len(results) >= 1
        namespaces = [e.namespace for e, _ in results]
        assert any("encrypt" in ns for ns in namespaces), f"No encryption rules: {namespaces}"

    def test_grounding_context_quality(self, rule_index):
        ctx = parse_description("Detect BITS Jobs for persistence T1197")
        results = rule_index.retrieve(ctx, top_k=5)
        grounding = format_grounding_context(results, max_rules=3)
        assert "Reference Rule" in grounding
        assert "```yaml" in grounding
        assert "rule:" in grounding


@pytest.mark.skipif(not RULES_AVAILABLE, reason="capa-rules directory not available")
class TestPipelineIntegration:
    """Integration tests for the full pipeline."""

    def test_offline_pipeline_description(self):
        ctx = parse_description("Detect persistence via ShellServiceObjectDelayLoad registry key")
        rule_text, result, pr_desc, quality_report = run_pipeline(
            ctx,
            max_attempts=1,
            offline=True,
            rules_dir=get_rules_dir(),
        )
        assert result.yaml_valid
        assert result.schema_valid
        assert "rule:" in rule_text
        assert "persistence" in rule_text

    def test_offline_pipeline_generates_pr_desc(self):
        ctx = parse_description("Detect service persistence T1543.003")
        rule_text, result, pr_desc, quality_report = run_pipeline(
            ctx,
            max_attempts=1,
            offline=True,
            rules_dir=get_rules_dir(),
        )
        assert "Auto-generated capa rule" in pr_desc
        assert "Validation status" in pr_desc

    def test_offline_pipeline_with_attck(self):
        ctx = parse_description("Detect T1547.001 autostart registry persistence")
        rule_text, result, pr_desc, quality_report = run_pipeline(
            ctx,
            max_attempts=1,
            offline=True,
            rules_dir=get_rules_dir(),
        )
        assert "T1547.001" in rule_text
