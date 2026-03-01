# Issue #1048: detect opening of services often referenced by ransomware

**Source:** [https://github.com/mandiant/capa-rules/issues/1048](https://github.com/mandiant/capa-rules/issues/1048)
**Confidence:** MEDIUM (73%)
**Validation:** Passed on attempt 1/3
**Sample available:** No

## What the agent did

The issue lists specific Windows service names commonly targeted by ransomware for termination (VSS, SQL, backup services, AV products). The agent grouped these into semantic categories (backup, database, security, Commvault, QuickBooks) using regex patterns with OpenService API. MEDIUM confidence: the service name patterns are specific enough to be meaningful, though benign uninstallers may also stop these services.

## Files

- `input.json`: Issue metadata passed to the pipeline
- `generated_rule.yml`: Gemini 3.1 Pro output (not a template)
- `quality_report.md`: Quality gate layer-by-layer results
