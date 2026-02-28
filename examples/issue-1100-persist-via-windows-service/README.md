# Issue #1100: persist via Windows service (false positive)

Source: https://github.com/mandiant/capa-rules/issues/1100

## What happened

The existing `persist via Windows service` rule matched a function at `0x404427`
that modifies NetBT parameters (`NetbiosOptions`) under
`SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces`. The function
uses `RegOpenKeyExA` and `RegSetValueExA` on a Services subkey, which triggers
the rule, but it does not create or modify a service binary path.

## What the agent does

1. Parses the issue to extract ATT&CK ID (T1543.003), sample hash, and
   decompilation
2. Grounds the generation in the existing `persistence/service` namespace rules
   via RAG retrieval
3. Generates a candidate rule with the offline template (or Gemini with API key)
4. Runs the quality gate, which flags over-generalization risk because the
   generated rule shares features with existing siblings

## What the agent cannot do yet

The quality gate correctly identifies the risk, but the actual fix is narrowing
an existing rule's features, not generating a new rule. This requires understanding
which registry value names (`ImagePath`, `Start`) indicate real service persistence
vs. benign configuration (`NetbiosOptions`). That judgment still needs a human
reviewer.

## Files

- `input.json`: structured issue context fed into the pipeline
- `generated_rule.yml`: offline-generated candidate rule (template, no LLM)
- `quality_report.md`: quality gate output showing sibling analysis warning
