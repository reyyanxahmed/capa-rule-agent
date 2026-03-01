# Issue #915: delay execution: add Beep WinAPI

**Source:** [https://github.com/mandiant/capa-rules/issues/915](https://github.com/mandiant/capa-rules/issues/915)
**Confidence:** LOW (67%)
**Validation:** Passed on attempt 2/3
**Sample available:** No

**Self-correction:** Attempt 1 failed validation. The error was fed back to Gemini 3.1 Pro, which corrected the issue on attempt 2.

## What the agent did

Attempt 1 failed lint because the MBC entry B0003 was malformed (missing sub-technique). The self-correction loop fed this error back to Gemini, which corrected it to B0003.003 on attempt 2. The generated rule targets kernel32.Beep as a delay mechanism. Confidence is LOW because calling Beep alone is a weak signal without additional context like loop patterns. No sample was provided in the issue.

## Files

- `input.json`: Issue metadata passed to the pipeline
- `generated_rule.yml`: Gemini 3.1 Pro output (not a template)
- `quality_report.md`: Quality gate layer-by-layer results
