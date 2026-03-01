# Issue #1050: detect mouse movement analysis for sandbox evasion

**Source:** [https://github.com/mandiant/capa-rules/issues/1050](https://github.com/mandiant/capa-rules/issues/1050)
**Confidence:** LOW (67%)
**Validation:** Passed on attempt 1/3
**Sample available:** Yes (not locally available)

## What the agent did

The issue describes mouse movement analysis as a sandbox evasion technique with a sample hash and decompiled code. The agent generated three detection variants: advanced pattern analysis (GetCursorPos + math functions), cursor polling in loops, and mouse-with-key-state correlation. The rule correctly preserved the original issue author in meta.authors. Sample hash was referenced but not locally available for testing.

## Files

- `input.json`: Issue metadata passed to the pipeline
- `generated_rule.yml`: Gemini 3.1 Pro output (not a template)
- `quality_report.md`: Quality gate layer-by-layer results
