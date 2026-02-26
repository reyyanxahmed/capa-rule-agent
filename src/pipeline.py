"""
Pipeline module — orchestrates the end-to-end rule generation flow.

Supports two execution modes:

1. **Standard pipeline** (original):
   Trigger → Ground → Generate → Validate → Self-Correct → Output

2. **Full agent pipeline** (expanded):
   Trigger → Search Ground → RAG Ground → Generate → Validate → Test → PR

The full pipeline integrates:
- Proactive triggers (threat intel feeds for coverage gap detection)
- Google Search grounding (API doc verification)
- capa test runner (sample-based validation)
- Automated PR workflow (GitHub PR submission)
- Google ADK agent (tool-use orchestration)
"""

from __future__ import annotations

import os
import sys
import json
import logging
import argparse
from pathlib import Path
from typing import Optional

from .trigger import IssueContext, parse_github_issue, parse_description
from .generator import generate_rule, generate_rule_offline
from .validator import validate_rule, ValidationResult
from .grounding import RuleIndex, format_grounding_context
from .search_grounding import build_grounding_context, GroundingContext
from .test_runner import run_capa_on_sample, run_capa_tests, inject_examples_into_rule, TestResult
from .pr_workflow import PRContext, create_pull_request, format_pr_description as format_pr_body

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
) -> tuple[str, ValidationResult]:
    """
    Run the full agent pipeline: generate → validate → self-correct.

    Args:
        context: Structured issue context
        max_attempts: Maximum generation/correction attempts
        offline: Use offline template generation (no LLM)
        output_path: Path to write the final rule
        lint_script: Path to capa lint.py
        format_script: Path to capa capafmt.py
        rules_dir: Path to capa-rules directory

    Returns:
        Tuple of (final_rule_text, validation_result)
    """
    lint_script = lint_script or str(DEFAULT_LINT_SCRIPT)
    format_script = format_script or str(DEFAULT_FORMAT_SCRIPT)
    rules_dir = rules_dir or str(DEFAULT_RULES_DIR)

    # Build grounding context via RAG over existing rules
    grounding_ctx = ""
    if not offline and Path(rules_dir).exists():
        logger.info("Building rule index for RAG grounding...")
        index = RuleIndex()
        n = index.index_directory(rules_dir)
        if n > 0:
            retrieved = index.retrieve(context, top_k=5)
            grounding_ctx = format_grounding_context(retrieved, max_rules=3)
            logger.info(f"Retrieved {len(retrieved)} similar rules for grounding")

    validation_errors: list[str] = []
    best_rule = ""
    best_result = ValidationResult(is_valid=False)

    for attempt in range(1, max_attempts + 1):
        logger.info(f"=== Attempt {attempt}/{max_attempts} ===")

        # Step 1: Generate
        if offline:
            rule_text = generate_rule_offline(context)
        else:
            rule_text = generate_rule(
                context,
                validation_errors=validation_errors if attempt > 1 else None,
                grounding_context=grounding_ctx,
            )

        logger.info(f"Generated rule ({len(rule_text)} chars)")

        # Step 2: Validate
        result = validate_rule(
            rule_text,
            rules_dir=rules_dir,
            lint_script=lint_script,
            format_script=format_script,
        )

        # Use formatted version if available
        if result.formatted_rule:
            rule_text = result.formatted_rule

        # Track best attempt
        if result.is_valid or (not best_result.is_valid and result.schema_valid):
            best_rule = rule_text
            best_result = result

        if result.is_valid:
            logger.info(f"✓ Rule passed validation on attempt {attempt}")
            break
        else:
            logger.warning(f"✗ Validation failed on attempt {attempt}:")
            logger.warning(result.error_summary())
            validation_errors = result.errors

    # Step 3: Output
    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(best_rule)
        logger.info(f"Rule written to {output_path}")

    # Generate PR description
    pr_desc = format_pr_description(context, best_rule, best_result)

    return best_rule, best_result, pr_desc


def format_pr_description(
    context: IssueContext,
    rule_text: str,
    result: ValidationResult,
) -> str:
    """Format a PR description for the generated rule."""
    status = "✅ PASSED" if result.is_valid else "⚠️ NEEDS REVIEW"

    desc = f"""## Auto-generated capa rule

**Source issue:** {context.title}
**Validation status:** {status}

### Rule preview

```yaml
{rule_text.strip()}
```

### Validation details

- YAML syntax: {'✅' if result.yaml_valid else '❌'}
- Schema: {'✅' if result.schema_valid else '❌'}
- Lint: {'✅' if result.lint_passed else '❌'}
"""

    if result.warnings:
        desc += "\n### Warnings\n"
        for w in result.warnings:
            desc += f"- {w}\n"

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


# ---------------------------------------------------------------------------
# Full pipeline — integrates all expanded modules
# ---------------------------------------------------------------------------

def run_full_pipeline(
    context: IssueContext,
    max_attempts: int = 3,
    output_path: Optional[str] = None,
    lint_script: Optional[str] = None,
    format_script: Optional[str] = None,
    rules_dir: Optional[str] = None,
    capa_path: str = "capa",
    sample_dir: Optional[str] = None,
    submit_pr: bool = False,
    dry_run: bool = False,
) -> dict:
    """
    Run the full expanded pipeline with all modules.

    Pipeline stages:
    1. RAG Grounding — retrieve similar capa rules
    2. Search Grounding — verify APIs/registry paths via Google Search
    3. Generation — LLM-powered rule creation with grounding context
    4. Validation — YAML → schema → lint → format
    5. Self-correction — re-prompt on errors (up to max_attempts)
    6. Testing — run capa on samples (if hashes available)
    7. PR Submission — create Pull Request (if submit_pr=True)

    Returns:
        Dict with rule_text, validation, test_results, pr_result
    """
    lint_script = lint_script or str(DEFAULT_LINT_SCRIPT)
    format_script = format_script or str(DEFAULT_FORMAT_SCRIPT)
    rules_dir = rules_dir or str(DEFAULT_RULES_DIR)

    result = {
        "rule_text": None,
        "validation": None,
        "test_results": [],
        "pr_result": None,
        "stages_completed": [],
    }

    # --- Stage 1: RAG Grounding ---
    grounding_ctx = ""
    if Path(rules_dir).exists():
        logger.info("Stage 1: Building RAG grounding index...")
        index = RuleIndex()
        n = index.index_directory(rules_dir)
        if n > 0:
            retrieved = index.retrieve(context, top_k=5)
            grounding_ctx = format_grounding_context(retrieved, max_rules=3)
            logger.info(f"  Retrieved {len(retrieved)} similar rules")
        result["stages_completed"].append("rag_grounding")

    # --- Stage 2: Search Grounding ---
    search_ctx = ""
    if context.attck_ids or context.body:
        logger.info("Stage 2: Search grounding (API docs + ATT&CK)...")
        try:
            search_grounding = build_grounding_context(context)
            if search_grounding.has_content():
                search_ctx = search_grounding.to_prompt()
                logger.info(f"  Found {len(search_grounding.api_definitions)} API docs, "
                          f"{len(search_grounding.technique_descriptions)} ATT&CK details")
        except Exception as e:
            logger.warning(f"  Search grounding failed (non-fatal): {e}")
        result["stages_completed"].append("search_grounding")

    # Combine grounding contexts
    full_grounding = "\n\n".join(filter(None, [grounding_ctx, search_ctx]))

    # --- Stages 3-5: Generate → Validate → Self-correct ---
    validation_errors: list[str] = []
    best_rule = ""
    best_validation = ValidationResult(is_valid=False)

    for attempt in range(1, max_attempts + 1):
        logger.info(f"Stage 3: Generation attempt {attempt}/{max_attempts}...")

        rule_text = generate_rule(
            context,
            validation_errors=validation_errors if attempt > 1 else None,
            grounding_context=full_grounding,
        )
        logger.info(f"  Generated rule ({len(rule_text)} chars)")

        logger.info(f"Stage 4: Validation attempt {attempt}...")
        vresult = validate_rule(
            rule_text,
            rules_dir=rules_dir,
            lint_script=lint_script,
            format_script=format_script,
        )

        if vresult.formatted_rule:
            rule_text = vresult.formatted_rule

        if vresult.is_valid or (not best_validation.is_valid and vresult.schema_valid):
            best_rule = rule_text
            best_validation = vresult

        if vresult.is_valid:
            logger.info(f"  ✓ Validation passed on attempt {attempt}")
            break
        else:
            logger.warning(f"  ✗ Validation failed: {vresult.error_summary()}")
            validation_errors = vresult.errors

    result["rule_text"] = best_rule
    result["validation"] = {
        "is_valid": best_validation.is_valid,
        "yaml_valid": best_validation.yaml_valid,
        "schema_valid": best_validation.schema_valid,
        "lint_passed": best_validation.lint_passed,
        "errors": best_validation.errors,
        "warnings": best_validation.warnings,
    }
    result["stages_completed"].append("generation")
    result["stages_completed"].append("validation")

    # --- Stage 6: Testing ---
    if context.sample_hashes and best_validation.is_valid:
        logger.info(f"Stage 5: Testing against {len(context.sample_hashes)} sample(s)...")
        test_results = run_capa_tests(
            best_rule,
            sample_hashes=context.sample_hashes,
            sample_dir=sample_dir,
            capa_path=capa_path,
        )
        result["test_results"] = [
            {
                "hash": tr.sample_hash[:16] + "...",
                "matched": tr.matched,
                "match_count": tr.match_count,
                "addresses": tr.matched_addresses,
                "error": tr.error,
            }
            for tr in test_results
        ]

        # Inject examples into rule if tests passed
        matched_results = [tr for tr in test_results if tr.matched]
        if matched_results:
            best_rule = inject_examples_into_rule(best_rule, matched_results)
            result["rule_text"] = best_rule
            logger.info(f"  Injected {len(matched_results)} example(s) into rule")

        result["stages_completed"].append("testing")

    # --- Stage 7: PR Submission ---
    if submit_pr and best_validation.is_valid:
        logger.info("Stage 6: Creating Pull Request...")

        # Parse issue number if available
        issue_number = None
        for ref in context.references:
            import re
            match = re.search(r"/issues/(\d+)", ref)
            if match:
                issue_number = int(match.group(1))
                break

        pr_ctx = PRContext(
            rule_text=best_rule,
            rule_name=context.suggested_name or context.title.lower()[:60],
            namespace=context.suggested_namespace or "nursery",
            issue_number=issue_number,
            attck_ids=context.attck_ids,
            validation_result=best_validation,
            test_results="\n".join(
                f"  {tr.sample_hash[:16]}... → {'MATCH' if tr.matched else 'NO MATCH'}"
                for tr in (test_results if context.sample_hashes else [])
            ) or None,
            references=context.references,
            sample_hashes=context.sample_hashes,
        )

        pr_result = create_pull_request(
            pr_ctx,
            rules_repo_dir=rules_dir,
            dry_run=dry_run,
        )
        result["pr_result"] = pr_result
        result["stages_completed"].append("pr_submission")

    # Write output
    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(best_rule)
        logger.info(f"Rule written to {output_path}")

    return result


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="capa Rule Generation Agent — generate capa rules from GitHub issues"
    )

    # Input source
    input_group = parser.add_argument_group("input")
    input_group.add_argument(
        "--issue-url",
        help="GitHub issue URL to generate a rule for",
    )
    input_group.add_argument(
        "--description",
        help="Plain text description of the technique to detect",
    )
    input_group.add_argument(
        "--scan-feeds",
        action="store_true",
        help="Run proactive trigger: scan threat intel feeds for coverage gaps",
    )

    # Output
    output_group = parser.add_argument_group("output")
    output_group.add_argument(
        "--output", "-o",
        help="Output path for the generated rule YAML",
    )
    output_group.add_argument(
        "--submit-pr",
        action="store_true",
        help="Submit the validated rule as a PR to mandiant/capa-rules",
    )
    output_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Prepare PR but don't push or create it",
    )

    # Pipeline mode
    mode_group = parser.add_argument_group("mode")
    mode_group.add_argument(
        "--offline",
        action="store_true",
        help="Use offline template generation (no LLM API call)",
    )
    mode_group.add_argument(
        "--agent",
        action="store_true",
        help="Use the full ADK agent with tool-use reasoning",
    )

    # Configuration
    config_group = parser.add_argument_group("configuration")
    config_group.add_argument(
        "--max-attempts",
        type=int,
        default=3,
        help="Maximum generation attempts (default: 3)",
    )
    config_group.add_argument(
        "--lint-script",
        default=str(DEFAULT_LINT_SCRIPT),
        help="Path to capa lint.py script",
    )
    config_group.add_argument(
        "--format-script",
        default=str(DEFAULT_FORMAT_SCRIPT),
        help="Path to capa capafmt.py script",
    )
    config_group.add_argument(
        "--rules-dir",
        default=str(DEFAULT_RULES_DIR),
        help="Path to capa-rules directory",
    )
    config_group.add_argument(
        "--capa-path",
        default="capa",
        help="Path to capa executable (for testing)",
    )
    config_group.add_argument(
        "--sample-dir",
        help="Directory containing malware samples for testing",
    )
    config_group.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    # Set up logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(levelname)-8s %(name)s: %(message)s",
    )

    # --- Proactive feed scan mode ---
    if args.scan_feeds:
        from .proactive import scan_feeds
        logger.info("Running proactive feed scan...")
        gaps = scan_feeds(
            rules_dir=args.rules_dir,
            max_gaps=20,
        )
        print(f"\n{'='*60}")
        print(f"COVERAGE GAPS ({len(gaps)} found)")
        print(f"{'='*60}")
        for gap in gaps:
            print(f"  {gap.summary()}")
        return 0

    # --- ADK Agent mode ---
    if args.agent:
        if not os.environ.get("GOOGLE_API_KEY"):
            logger.error("GOOGLE_API_KEY required for agent mode")
            return 1

        from .adk_agent import CapaRuleAgent, AgentConfig
        config = AgentConfig(
            rules_dir=args.rules_dir,
            lint_script=args.lint_script,
            format_script=args.format_script,
            auto_submit_pr=args.submit_pr,
        )
        agent = CapaRuleAgent(config)

        if args.issue_url:
            result = agent.process_issue(args.issue_url)
        elif args.description:
            result = agent.process_description(args.description)
        else:
            parser.error("Agent mode requires --issue-url or --description")

        print(json.dumps(result, indent=2, default=str))
        return 0

    # --- Standard pipeline mode ---

    # Parse input
    if args.issue_url:
        context = parse_github_issue(args.issue_url)
    elif args.description:
        context = parse_description(args.description)
    else:
        parser.error("Must provide one of: --issue-url, --description, --scan-feeds, --agent")

    logger.info(f"Issue context: {context.title}")
    logger.info(f"ATT&CK IDs: {context.attck_ids}")
    logger.info(f"References: {len(context.references)} URLs")

    # Check for API key
    if not args.offline and not os.environ.get("GOOGLE_API_KEY"):
        logger.warning("GOOGLE_API_KEY not set — falling back to offline mode")
        args.offline = True

    if args.offline:
        # Lightweight pipeline (no LLM, no search)
        rule_text, result, pr_desc = run_pipeline(
            context,
            max_attempts=args.max_attempts,
            offline=True,
            output_path=args.output,
            lint_script=args.lint_script,
            format_script=args.format_script,
            rules_dir=args.rules_dir,
        )
    else:
        # Full pipeline with all stages
        pipeline_result = run_full_pipeline(
            context,
            max_attempts=args.max_attempts,
            output_path=args.output,
            lint_script=args.lint_script,
            format_script=args.format_script,
            rules_dir=args.rules_dir,
            capa_path=args.capa_path,
            sample_dir=args.sample_dir,
            submit_pr=args.submit_pr,
            dry_run=args.dry_run,
        )
        rule_text = pipeline_result["rule_text"] or ""
        result = ValidationResult(
            is_valid=pipeline_result["validation"]["is_valid"] if pipeline_result["validation"] else False,
        )
        pr_desc = format_pr_description(context, rule_text, result)

        # Print stages completed
        stages = pipeline_result.get("stages_completed", [])
        logger.info(f"Stages completed: {' → '.join(stages)}")

        # Print test results if any
        if pipeline_result.get("test_results"):
            print("\n" + "=" * 60)
            print("TEST RESULTS")
            print("=" * 60)
            for tr in pipeline_result["test_results"]:
                status = "✓ MATCH" if tr["matched"] else "✗ NO MATCH"
                print(f"  {tr['hash']} → {status}")

        # Print PR result if submitted
        if pipeline_result.get("pr_result"):
            pr = pipeline_result["pr_result"]
            if pr.get("success"):
                print(f"\n✓ PR created: {pr.get('pr_url', 'N/A')}")
            else:
                print(f"\n✗ PR creation failed: {pr.get('error', 'unknown')}")

    # Print results
    print("\n" + "=" * 60)
    print("GENERATED RULE")
    print("=" * 60)
    print(rule_text)
    print("=" * 60)
    print(f"Valid: {result.is_valid}")
    if hasattr(result, 'errors') and result.errors:
        print(f"Errors: {result.errors}")
    if hasattr(result, 'warnings') and result.warnings:
        print(f"Warnings: {result.warnings}")

    print("\n" + "=" * 60)
    print("PR DESCRIPTION")
    print("=" * 60)
    print(pr_desc)

    return 0 if result.is_valid else 1


if __name__ == "__main__":
    sys.exit(main())
