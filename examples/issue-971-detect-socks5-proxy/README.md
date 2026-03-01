# Issue #971: detect socks5 proxy capabilities

**Source:** [https://github.com/mandiant/capa-rules/issues/971](https://github.com/mandiant/capa-rules/issues/971)
**Confidence:** LOW (67%)
**Validation:** Passed on attempt 1/3
**Sample available:** No

## What the agent did

The issue describes SOCKS5 proxy detection based on protocol constants (address types 0x1/0x3/0x4 and command codes 0x1/0x2/0x3). The agent extracted these constants and paired them with socket API calls. Confidence is LOW because SOCKS5 constant values (1-5) are extremely common integers that would cause false positives in static analysis. No sample binary was referenced in the issue.

## Files

- `input.json`: Issue metadata passed to the pipeline
- `generated_rule.yml`: Gemini 3.1 Pro output (not a template)
- `quality_report.md`: Quality gate layer-by-layer results
