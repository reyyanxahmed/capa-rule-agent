"""
Pipeline module: orchestrates issue -> rule -> validate -> quality gate.

Two modes:
  --offline    Template generation, no API calls (for testing).
  (default)    Gemini 3.1 Pro generation with RAG grounding + quality gate.
"""

from __future__ import annotations

import os
import sys
import re
import logging
import argparse
from pathlib import Path
from typing import Optional

from .trigger import IssueContext, parse_github_issue, parse_description
from .generator import generate_rule, generate_rule_offline
from .validator import validate_rule, ValidationResult
from .grounding import RuleIndex, format_grounding_context
from .test_runner import run_capa_tests, inject_examples_into_rule
from .pr_workflow import PRContext, create_pull_request
from .quality_gate import run_quality_gate, QualityReport, ConfidenceLevel

logger = logging.getLogger(__name__)

# Default paths (relative to workspace)
DEFAULT_CAPA_DIR = Path(__file__).parent.parent.parent / "capa"
DEFAULT_RULES_DIR = Path(__file__).parent.parent.parent / "capa-rules"
DEFAULT_LINT_SCRIPT = DEFAULT_CAPA_DIR / "scripts" / "lint.py"
DEFAULT_FORMAT_SCRIPT = DEFAULT_CAPA_DIR / "scripts" / "capafmt.py"


def run_pipeline(
    context: IssueContext,
    max_attempts: int = 3,
    offline: bool = False,
    output_path: Optional[str] = None,
    lint_script: Optional[str] = None,
    format_script: Optional[str] = None,
    rules_dir: Optional[str] = None,
    capa_path: str = "capa",
    sample_dir: Optional[str] = None,
    testfiles_dir: Optional[str] = None,
) -> tuple[str, ValidationResult, str, Optional[QualityReport]]:
    """
    Run the agent pipeline: ground -> generate -> validate -> quality gate.

    Returns:
        (rule_text, validation_result, pr_description, quality_report)
    """
    lint_script = lint_script or str(DEFAULT_LINT_SCRIPT)
    format_script = format_script or str(DEFAULT_FORMAT_SCRIPT)
    rules_dir = rules_dir or str(DEFAULT_RULES_DIR)

    # Step 1: RAG grounding over existing capa rules
    grounding_ctx = ""
    index = None
    if not offline and Path(rules_dir).exists():
        logger.info("Building rule index for RAG grounding...")
        index = RuleIndex()
        n = index.index_directory(rules_dir)
        if n > 0:
            retrieved = index.retrieve(context, top_k=5)
            grounding_ctx = format_grounding_context(retrieved, max_rules=3)
            logger.info(f"Retrieved {len(retrieved)} similar rules for grounding")

    # Step 2: Generate -> validate -> self-correct loop
    validation_errors: list[str] = []
    best_rule = ""
    best_result = ValidationResult(is_valid=False)

    for attempt in range(1, max_attempts + 1):
        logger.info(f"Attempt {attempt}/{max_attempts}")

        if offline:
            rule_text = generate_rule_offline(context)
        else:
            rule_text = generate_rule(
                context,
                validation_errors=validation_errors if attempt > 1 else None,
                grounding_context=grounding_ctx,
            )

        result = validate_rule(
            rule_text,
            rules_dir=rules_dir,
            lint_script=lint_script,
            format_script=format_script,
        )

        if result.formatted_rule:
            rule_text = result.formatted_rule

        if result.is_valid or (not best_result.is_valid and result.schema_valid):
            best_rule = rule_text
            best_result = result

        if result.is_valid:
            logger.info(f"Rule passed validation on attempt {attempt}")
            break
        else:
            logger.warning(f"Validation failed: {result.error_summary()}")
            validation_errors = result.errors

    # Step 3: Sample testing (if hashes available and samples exist locally)
    sample_tested = False
    if not offline and context.sample_hashes and best_result.is_valid:
        logger.info(f"Testing against {len(context.sample_hashes)} sample(s)...")
        test_results = run_capa_tests(
            best_rule,
            sample_hashes=context.sample_hashes,
            sample_dir=sample_dir,
            capa_path=capa_path,
        )
        matched = [tr for tr in test_results if tr.matched]
        if matched:
            best_rule = inject_examples_into_rule(best_rule, matched)
            sample_tested = True
            logger.info(f"Injected {len(matched)} example(s) into rule")

    # Step 4: Quality gate
    quality_report = None
    if not offline:
        logger.info("Running quality gate...")
        quality_report = run_quality_gate(
            best_rule,
            context=context,
            rule_index=index,
            namespace=context.suggested_namespace,
            testfiles_dir=testfiles_dir,
            capa_path=capa_path,
            validation_result=best_result,
            sample_tested=sample_tested,
        )
        logger.info(f"Quality gate: {quality_report.summary()}")

    # Step 5: Write output
    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(best_rule)
        logger.info(f"Rule written to {output_path}")

    pr_desc = format_pr_description(context, best_rule, best_result)
    if quality_report:
        pr_desc += "\n" + quality_report.to_pr_section()

    return best_rule, best_result, pr_desc, quality_report


def format_pr_description(
    context: IssueContext,
    rule_text: str,
    result: ValidationResult,
) -> str:
    """Format a PR description for the generated rule."""
    status = "PASSED" if result.is_valid else "NEEDS REVIEW"

    desc = f"""## Auto-generated capa rule

**Source issue:** {context.title}
**Validation status:** {status}

### Rule preview

```yaml
{rule_text.strip()}
```

### Validation details

- YAML syntax: {'pass' if result.yaml_valid else 'fail'}
- Schema: {'pass' if result.schema_valid else 'fail'}
- Lint: {'pass' if result.lint_passed else 'fail'}
"""

    if result.errors:
        desc += "\n### Errors\n"
        for e in result.errors:
            desc += f"- {e}\n"

    if context.attck_ids:
        desc += f"\n### ATT&CK Coverage\n"
        for tid in context.attck_ids:
            desc += f"- {tid}\n"

    desc += "\n---\n*Generated by capa-rule-agent (GSoC 2026 PoC)*\n"
    return desc


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="capa Rule Generation Agent: generate capa rules from GitHub issues"
    )
    parser.add_argument("--issue-url", help="GitHub issue URL to generate a rule for")
    parser.add_argument("--description", help="Plain text description of the technique to detect")
    parser.add_argument("--output", "-o", help="Output path for the generated rule YAML")
    parser.add_argument("--offline", action="store_true", help="Template generation, no LLM API call")
    parser.add_argument("--submit-pr", action="store_true", help="Submit validated rule as PR")
    parser.add_argument("--dry-run", action="store_true", help="Prepare PR but don't push")
    parser.add_argument("--max-attempts", type=int, default=3, help="Max generation attempts (default: 3)")
    parser.add_argument("--rules-dir", default=str(DEFAULT_RULES_DIR), help="Path to capa-rules directory")
    parser.add_argument("--lint-script", default=str(DEFAULT_LINT_SCRIPT))
    parser.add_argument("--format-script", default=str(DEFAULT_FORMAT_SCRIPT))
    parser.add_argument("--capa-path", default="capa", help="Path to capa executable")
    parser.add_argument("--sample-dir", help="Directory containing malware samples")
    parser.add_argument("--testfiles-dir", help="Path to capa-testfiles (benign binaries for FP testing)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-8s %(name)s: %(message)s",
    )

    # Parse input
    if args.issue_url:
        context = parse_github_issue(args.issue_url)
    elif args.description:
        context = parse_description(args.description)
    else:
        parser.error("Must provide --issue-url or --description")

    logger.info(f"Issue: {context.title}")
    if context.attck_ids:
        logger.info(f"ATT&CK: {context.attck_ids}")

    if not args.offline and not os.environ.get("GOOGLE_API_KEY"):
        logger.warning("GOOGLE_API_KEY not set, falling back to offline mode")
        args.offline = True

    # Run pipeline
    rule_text, result, pr_desc, quality_report = run_pipeline(
        context,
        max_attempts=args.max_attempts,
        offline=args.offline,
        output_path=args.output,
        lint_script=args.lint_script,
        format_script=args.format_script,
        rules_dir=args.rules_dir,
        capa_path=args.capa_path,
        sample_dir=args.sample_dir,
        testfiles_dir=args.testfiles_dir,
    )

    # Submit PR if requested
    if args.submit_pr and result.is_valid:
        if quality_report and quality_report.confidence == ConfidenceLevel.REJECT:
            logger.warning("Quality gate REJECTED rule, skipping PR submission")
        else:
            target_dir = quality_report.target_directory if quality_report else "nursery"
            issue_number = None
            for ref in context.references:
                m = re.search(r"/issues/(\d+)", ref)
                if m:
                    issue_number = int(m.group(1))
                    break

            pr_ctx = PRContext(
                rule_text=rule_text,
                rule_name=context.suggested_name or context.title.lower()[:60],
                namespace=context.suggested_namespace or target_dir,
                issue_number=issue_number,
                attck_ids=context.attck_ids,
                validation_result=result,
                references=context.references,
                sample_hashes=context.sample_hashes,
            )
            pr_result = create_pull_request(pr_ctx, rules_repo_dir=args.rules_dir, dry_run=args.dry_run)
            if pr_result.get("success"):
                print(f"PR created: {pr_result.get('pr_url', 'N/A')}")
            else:
                print(f"PR creation failed: {pr_result.get('error', 'unknown')}")

    # Print results
    print(f"\n{'=' * 60}")
    print("GENERATED RULE")
    print(f"{'=' * 60}")
    print(rule_text)
    print(f"Valid: {result.is_valid}")

    if quality_report:
        print(f"\n{quality_report.summary()}")

    return 0 if result.is_valid else 1


if __name__ == "__main__":
    sys.exit(main())
