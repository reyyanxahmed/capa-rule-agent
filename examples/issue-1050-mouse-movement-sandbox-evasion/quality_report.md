### Quality Gate Report

**Confidence:** MEDIUM (score: 75%)
**Target directory:** `nursery/`

| Status | Layer | Check | Detail |
|--------|-------|-------|--------|
| ✅ | structural | yaml_syntax | YAML syntax is valid |
| ✅ | structural | schema | Rule follows capa schema |
| ✅ | structural | lint | capa linter passed |
| ✅ | sibling | over_generalization | Rule has 6 unique feature(s) vs 1 sibling(s): sufficient differentiation |
| ✅ | sibling | feature_overlap | Highest feature overlap: 22% with 'check for unmoving mouse cursor' |
| ⏭️ | negative | benign_corpus_test | No benign corpus provided (--testfiles-dir). Cannot verify rule doesn't match benign software. |
| ✅ | semantic | feature_depth | Rule has 7 unique features: sufficient depth |
| ✅ | semantic | name_feature_alignment | Rule name 'detect mouse movement analysis' aligns with detected features |
| ✅ | semantic | attck_namespace_alignment | ATT&CK techniques ['T1497.002'] align with namespace 'anti-analysis/anti-vm/vm-detection' |
| ✅ | semantic | logic_tree_structure | Logic tree structure is well-formed |

<details>
<summary>What was NOT verified (and why)</summary>

- **No reference sample available**: rule was NOT tested against a real binary. Routing to `nursery/` until sample-based testing confirms detection. (Sample hash is provided in the issue but not available locally.)
- **No benign corpus available**: negative testing (false positive check) was skipped. Provide `--testfiles-dir` to enable.

</details>

### Notes

This is a no-sample quality gate path: the issue provides a hash and offsets,
but no local binary is available. The quality gate still validates structure,
checks sibling overlap (low: 22% with the existing mouse cursor rule), and
confirms semantic coherence.

The existing rule `check for unmoving mouse cursor` only counts
`GetCursorPos` appearances. This new rule targets advanced evasion using
vector math APIs (`acos`, `sqrt`, `atan2`), which is a genuinely different
detection surface. Sibling analysis correctly identifies low overlap.
