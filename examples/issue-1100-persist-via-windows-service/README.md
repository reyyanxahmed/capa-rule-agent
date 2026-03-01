# Issue #1100: persist via Windows service

**Source:** [https://github.com/mandiant/capa-rules/issues/1100](https://github.com/mandiant/capa-rules/issues/1100)
**Confidence:** LOW (80%)
**Validation:** Failed on attempt 1/3
**Sample available:** Yes (not locally available)

## What the agent did

This is a false-positive report on the existing persist-via-windows-service rule. The agent generated a replacement rule with three detection paths: CreateService API with SERVICE_AUTO_START constant, sc.exe command-line creation, and registry-based service installation. Quality gate scored 80% but flagged 1 failure (sibling analysis found significant overlap with existing service-related rules in the same namespace). This overlap is expected since the rule is meant to replace an existing one. Sample hash was referenced but not locally available.

## Files

- `input.json`: Issue metadata passed to the pipeline
- `generated_rule.yml`: Gemini 3.1 Pro output (not a template)
- `quality_report.md`: Quality gate layer-by-layer results
