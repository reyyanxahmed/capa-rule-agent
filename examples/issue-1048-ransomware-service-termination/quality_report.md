### Quality Gate Report

**Confidence:** MEDIUM (score: 78%)
**Target directory:** `nursery/`

| Status | Layer | Check | Detail |
|--------|-------|-------|--------|
| ✅ | structural | yaml_syntax | YAML syntax is valid |
| ✅ | structural | schema | Rule follows capa schema |
| ✅ | structural | lint | capa linter passed |
| ⏭️ | sibling | namespace_coverage | No existing rules found in namespace 'impact/service-stop' |
| ⏭️ | negative | benign_corpus_test | No benign corpus provided (--testfiles-dir). Cannot verify rule doesn't match benign software. |
| ✅ | semantic | feature_depth | Rule has 5 unique features: sufficient depth |
| ✅ | semantic | name_feature_alignment | Rule name aligns with detected features |
| ⏭️ | semantic | attck_namespace_alignment | ATT&CK technique T1489 not in technique map: cannot verify alignment |
| ✅ | semantic | logic_tree_structure | Logic tree structure is well-formed |

<details>
<summary>What was NOT verified (and why)</summary>

- **No reference sample available**: rule was NOT tested against a real binary. Routing to `nursery/` until sample-based testing confirms detection.
- **No sibling rules found**: could not compare against existing rules in the same namespace for over-generalization detection. This is a new namespace.
- **No benign corpus available**: negative testing (false positive check) was skipped. Provide `--testfiles-dir` to enable.

</details>

### Notes

This issue has no sample hash and targets a namespace (impact/service-stop)
that does not exist in the current capa-rules corpus. The quality gate
correctly identifies three gaps:

1. No sample testing possible
2. No sibling rules for comparison (new namespace)
3. No benign corpus for FP checking

Despite these gaps, structural and semantic checks pass. The rule is
routed to `nursery/` at MEDIUM confidence, which is the right call:
a human reviewer needs to verify the service name list covers real
ransomware targets without being so broad it matches legitimate
service management tools.
