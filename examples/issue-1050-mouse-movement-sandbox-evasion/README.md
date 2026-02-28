# Issue #1050: detect mouse movement analysis for sandbox evasion

Source: https://github.com/mandiant/capa-rules/issues/1050

## What this issue asks for

A new rule to detect advanced mouse movement analysis used by malware to
identify sandbox environments. Unlike the existing `check for unmoving mouse
cursor` rule (which only looks for multiple `GetCursorPos` calls), this
targets vector math APIs like `acos`, `sqrt`, `atan2` combined with cursor
position sampling and timing functions.

ATT&CK: T1497.002 (Virtualization/Sandbox Evasion: User Activity Based Checks)

## No-sample quality gate path

This example demonstrates the quality gate when the issue provides a sample
hash but the binary is not available locally. The gate still runs:
- Structural validation (YAML, schema, lint): all pass
- Sibling analysis: 22% overlap with existing mouse cursor rule (low, good)
- Negative testing: skipped (no benign corpus)
- Semantic coherence: name/feature/ATT&CK alignment checks pass

Result: MEDIUM confidence, routed to `nursery/`. This is the correct
outcome: the rule is structurally sound and semantically coherent, but
without sample testing we cannot confirm it actually detects the behavior.

## Files

- `input.json`: structured issue context
- `generated_rule.yml`: offline template output (with Gemini, features would
  include GetCursorPos, math APIs, Sleep/GetTickCount)
- `quality_report.md`: full quality gate output
