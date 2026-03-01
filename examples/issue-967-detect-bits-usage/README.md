# Issue #967: detect BITS usage in general

**Source:** [https://github.com/mandiant/capa-rules/issues/967](https://github.com/mandiant/capa-rules/issues/967)
**Confidence:** MEDIUM (75%)
**Validation:** Passed on attempt 1/3
**Sample available:** No

## What the agent did

The agent generated a rule covering three BITS access vectors: COM interface strings (IBackgroundCopyManager), command-line tools (bitsadmin, Start-BitsTransfer), and raw COM CLSIDs as byte patterns. The CLSID bytes are a strong detection signal. MEDIUM confidence because BITS is a legitimate Windows service, so the rule will match benign software that uses BITS for updates. No sample was referenced.

## Files

- `input.json`: Issue metadata passed to the pipeline
- `generated_rule.yml`: Gemini 3.1 Pro output (not a template)
- `quality_report.md`: Quality gate layer-by-layer results
