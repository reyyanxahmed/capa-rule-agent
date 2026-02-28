### Quality Gate Report

**Confidence:** MEDIUM (score: 71%)
**Target directory:** `nursery/`

| Status | Layer | Check | Detail |
|--------|-------|-------|--------|
| ✅ | structural | yaml_syntax | YAML syntax is valid |
| ✅ | structural | schema | Rule follows capa schema |
| ✅ | structural | lint | capa linter passed |
| ⚠️ | sibling | over_generalization | Rule shares most features with 4 sibling(s) in persistence/service but has few unique features. This is the same pattern that caused FP in capa-rules#1100. |
| ✅ | sibling | feature_overlap | Highest feature overlap: 45% with 'persist via Windows service' |
| ⏭️ | negative | benign_corpus_test | No benign corpus provided (--testfiles-dir). Cannot verify rule doesn't match benign software. |
| ✅ | semantic | feature_depth | Rule has 4 unique features: sufficient depth |
| ✅ | semantic | name_feature_alignment | Rule name 'persist via Windows service' aligns with detected features |
| ✅ | semantic | attck_namespace_alignment | ATT&CK techniques ['T1543.003'] align with namespace 'persistence/service' |
| ✅ | semantic | logic_tree_structure | Logic tree structure is well-formed |

<details>
<summary>What was NOT verified (and why)</summary>

- **No reference sample available**: rule was NOT tested against a real binary. Routing to `nursery/` until sample-based testing confirms detection.
- **No benign corpus available**: negative testing (false positive check) was skipped. Provide `--testfiles-dir` to enable.

</details>

### Notes

This issue is a false positive report, not a new rule request. The existing
`persist via Windows service` rule matches a function that only modifies
NetBT parameters (NetbiosOptions), not service binary paths. The fix
requires narrowing the rule's feature set, not generating a new rule.

This example demonstrates a limitation: the agent's quality gate can flag
over-generalization risk via sibling analysis, but the actual fix (modifying
an existing rule's features) requires human judgment about which registry
paths constitute real service persistence vs. benign configuration.
