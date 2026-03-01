# Issue #1095: Document shellcode execution via ReadDirectoryChanges

**Source:** [https://github.com/mandiant/capa-rules/issues/1095](https://github.com/mandiant/capa-rules/issues/1095)
**Confidence:** MEDIUM (78%)
**Validation:** Passed on attempt 1/3
**Sample available:** No

## What the agent did

The issue describes a technique where ReadDirectoryChangesW's lpCompletionRoutine callback is abused to execute shellcode. The agent correctly paired RWX memory allocation with ReadDirectoryChangesW/ExW and alertable wait functions (SleepEx, WaitForSingleObjectEx). This is the strongest generated rule in this batch: specific API combination, low false-positive surface, and correct ATT&CK mapping (T1620). MEDIUM confidence because no sample binary was available to verify.

## Files

- `input.json`: Issue metadata passed to the pipeline
- `generated_rule.yml`: Gemini 3.1 Pro output (not a template)
- `quality_report.md`: Quality gate layer-by-layer results
