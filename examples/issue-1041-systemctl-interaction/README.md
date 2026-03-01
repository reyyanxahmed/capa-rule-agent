# Issue #1041: detect journalctl/systemctl/systemd interactions on Linux

**Source:** [https://github.com/mandiant/capa-rules/issues/1041](https://github.com/mandiant/capa-rules/issues/1041)
**Confidence:** LOW (62%)
**Validation:** Passed on attempt 2/3
**Sample available:** Yes (not locally available)

**Self-correction:** Attempt 1 failed validation. The error was fed back to Gemini 3.1 Pro, which corrected the issue on attempt 2.

## What the agent did

Attempt 1 failed lint because a string feature was too short (capa requires strings >= 4 chars). The self-correction loop fixed this on attempt 2, switching to regex patterns. The issue provided a sample hash (6a5bda...) and 4 ATT&CK IDs, all of which the agent extracted. Sample testing was attempted but the binary was not locally available. The rule uses os: linux scope and targets systemctl/journalctl commands.

## Files

- `input.json`: Issue metadata passed to the pipeline
- `generated_rule.yml`: Gemini 3.1 Pro output (not a template)
- `quality_report.md`: Quality gate layer-by-layer results
