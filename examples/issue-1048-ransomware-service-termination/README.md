# Issue #1048: detect opening of services often referenced by ransomware

Source: https://github.com/mandiant/capa-rules/issues/1048

## What this issue asks for

A rule to detect ransomware that opens and stops critical services (backup,
database, antivirus) before encrypting files. The issue provides a reference
list of ~36 service names from BlackMatter ransomware IOCs.

ATT&CK: T1489 (Service Stop)

## What makes this interesting for the agent

This is the ideal case for automated rule generation:
- Clear behavioral description with specific APIs (`OpenService`,
  `ControlService`)
- Concrete feature list (service name strings)
- No ambiguity about what the rule should detect
- No existing rules in this namespace (new coverage)

With Gemini enabled (not offline), the agent would generate a rule with
`api: OpenServiceA` or `api: OpenServiceW` combined with string matches
for service names like `vss`, `sql`, `sophos`, `backup`.

## Limitations visible in this example

The offline template generates a skeleton with TODO placeholders instead of
real API/string features. With a GOOGLE_API_KEY, the generator produces
concrete features, but the quality is bounded by the issue's specificity.

The quality gate shows three SKIPPED checks: no siblings (new namespace),
no benign corpus, no sample. This is honest: we cannot guarantee correctness
without at least one of those signals.

## Files

- `input.json`: structured issue context
- `generated_rule.yml`: offline template output
- `quality_report.md`: full quality gate output (3 skipped checks)
