"""
ADK Agent module — wraps the capa rule generation pipeline as a Google ADK agent
with tool-use capabilities and multi-step reasoning.

Google Agent Development Kit (ADK) provides a framework for building agents
that can use tools, maintain state, and reason over multi-step tasks.

This module defines:
- Tool functions the agent can invoke (search_rules, validate_rule, create_pr, etc.)
- The agent configuration with system instruction and tool bindings
- Session management for stateful multi-turn conversations
"""

from __future__ import annotations

import os
import json
import logging
from typing import Optional, Any
from dataclasses import dataclass, field

from google import genai
from google.genai import types

from src.trigger import IssueContext, parse_github_issue, parse_description
from src.grounding import RuleIndex, format_grounding_context
from src.generator import generate_rule, generate_rule_offline
from src.validator import validate_rule, ValidationResult
from future.search_grounding import search_api_docs, search_threat_intel
from src.pr_workflow import create_pull_request, PRContext
from src.test_runner import run_capa_on_sample, TestResult
from src.quality_gate import run_quality_gate, QualityReport, ConfidenceLevel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Agent system instruction — defines the agent's persona and capabilities
# ---------------------------------------------------------------------------

AGENT_SYSTEM_INSTRUCTION = """\
You are the **capa Rule Generation Agent**, an autonomous contributor to Mandiant FLARE's
capa project. Your purpose is to generate, validate, and submit high-quality capa YAML rules
that detect malware capabilities in executable files.

## Your Capabilities (Tools)

You have access to these tools:
1. **parse_issue** — Parse a GitHub issue URL into structured context (technique, ATT&CK IDs, samples, references)
2. **search_similar_rules** — RAG retrieval over 650+ existing capa rules to find style/syntax references
3. **search_api_docs** — Google Search for Win32 API documentation, shell command syntax, or threat intel
4. **generate_rule** — Generate a capa YAML rule from issue context + grounding
5. **validate_rule** — Run YAML syntax check → schema validation → capa linter → capa formatter
6. **run_capa_test** — Run capa against a real malware sample to verify the rule matches
7. **run_quality_gate** — Multi-layered validation for when no sample is available (sibling analysis, negative testing, semantic coherence)
8. **create_pr** — Package the validated rule and submit it as a Pull Request to mandiant/capa-rules

## Workflow

For each issue/request, follow this reasoning loop:

1. **Understand** — Parse the issue, extract ATT&CK IDs, references, decompilation context
2. **Research** — Search for similar existing rules AND API documentation for referenced functions
3. **Generate** — Write a capa rule grounded in real examples and verified API names
4. **Validate** — Run the full linter pipeline. If errors → fix and re-validate (up to 3 attempts)
5. **Quality Gate** — If no sample available, run the no-sample quality gate (sibling analysis, semantic checks)
6. **Test** — If a sample hash is available, run capa against it to verify detection
7. **Submit** — Create a formatted PR with rule, quality report, and coverage summary

Never submit a rule that fails validation. If you cannot fix all errors, flag it for human review.
Always run the quality gate when no sample is available — this ensures the HITL reviewer knows exactly
what was and wasn't verified.
"""


# ---------------------------------------------------------------------------
# Tool definitions — each maps to a function the agent can invoke
# ---------------------------------------------------------------------------

@dataclass
class ToolResult:
    """Standardized tool invocation result."""
    success: bool
    data: Any = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        result = {"success": self.success}
        if self.data is not None:
            result["data"] = self.data
        if self.error:
            result["error"] = self.error
        return result


def tool_parse_issue(issue_url: str) -> dict:
    """
    ADK Tool: Parse a GitHub issue into structured context.

    Args:
        issue_url: Full GitHub issue URL

    Returns:
        Dict with extracted issue fields
    """
    try:
        ctx = parse_github_issue(issue_url)
        return ToolResult(
            success=True,
            data={
                "title": ctx.title,
                "attck_ids": ctx.attck_ids,
                "attck_references": ctx.attck_references,
                "references": ctx.references[:5],
                "sample_hashes": ctx.sample_hashes,
                "has_decompilation": ctx.decompilation is not None,
                "suggested_name": ctx.suggested_name,
                "suggested_namespace": ctx.suggested_namespace,
                "body_preview": ctx.body[:500],
            },
        ).to_dict()
    except Exception as e:
        return ToolResult(success=False, error=str(e)).to_dict()


def tool_search_similar_rules(
    query: str,
    attck_ids: Optional[list[str]] = None,
    namespace: Optional[str] = None,
    top_k: int = 5,
    rules_dir: str = "",
) -> dict:
    """
    ADK Tool: Search the capa-rules corpus for similar existing rules.

    Uses inverted indices over namespace, ATT&CK IDs, and keywords
    to find the most relevant rules as few-shot examples.

    Args:
        query: Natural language query (e.g., "persistence via Windows service")
        attck_ids: Optional ATT&CK technique IDs to boost
        namespace: Optional namespace to prefer
        top_k: Number of rules to return

    Returns:
        Dict with retrieved rules and scores
    """
    try:
        index = RuleIndex()
        n = index.index_directory(rules_dir)
        if n == 0:
            return ToolResult(success=False, error="No rules indexed").to_dict()

        # Create a lightweight IssueContext for retrieval
        ctx = IssueContext(
            title=query,
            body=query,
            attck_ids=attck_ids or [],
            suggested_namespace=namespace,
        )

        retrieved = index.retrieve(ctx, top_k=top_k)
        results = []
        for entry, score in retrieved:
            results.append({
                "name": entry.name,
                "namespace": entry.namespace,
                "attck_ids": entry.attck_ids,
                "score": round(score, 1),
                "rule_text": entry.raw_text[:1500],
            })

        return ToolResult(success=True, data={"count": len(results), "rules": results}).to_dict()
    except Exception as e:
        return ToolResult(success=False, error=str(e)).to_dict()


def tool_search_api_docs(query: str) -> dict:
    """
    ADK Tool: Search the web for API documentation or threat intelligence.

    Uses Google Search to verify Win32 API function signatures, registry
    key paths, shell commands, or threat reports.

    Args:
        query: Search query (e.g., "RegSetValueEx MSDN parameters")

    Returns:
        Dict with search results
    """
    try:
        results = search_api_docs(query)
        return ToolResult(success=True, data=results).to_dict()
    except Exception as e:
        return ToolResult(success=False, error=str(e)).to_dict()


def tool_validate_rule(
    rule_text: str,
    rules_dir: str = "",
    lint_script: str = "",
    format_script: str = "",
) -> dict:
    """
    ADK Tool: Validate a generated capa rule through the full pipeline.

    Runs: YAML syntax → schema check → capa linter → capa formatter.

    Args:
        rule_text: The YAML rule content to validate

    Returns:
        Dict with validation results and errors
    """
    try:
        result = validate_rule(
            rule_text,
            rules_dir=rules_dir or None,
            lint_script=lint_script or None,
            format_script=format_script or None,
        )
        return ToolResult(
            success=True,
            data={
                "is_valid": result.is_valid,
                "yaml_valid": result.yaml_valid,
                "schema_valid": result.schema_valid,
                "lint_passed": result.lint_passed,
                "errors": result.errors,
                "warnings": result.warnings,
                "formatted_rule": result.formatted_rule,
            },
        ).to_dict()
    except Exception as e:
        return ToolResult(success=False, error=str(e)).to_dict()


def tool_run_capa_test(
    rule_text: str,
    sample_hash: str,
    sample_path: Optional[str] = None,
) -> dict:
    """
    ADK Tool: Run capa with a generated rule against a malware sample.

    Downloads sample if needed, runs capa, checks if the rule matches.

    Args:
        rule_text: The YAML rule to test
        sample_hash: SHA256 hash of the sample
        sample_path: Optional local path to the sample

    Returns:
        Dict with test results (matched, function addresses, etc.)
    """
    try:
        result = run_capa_on_sample(rule_text, sample_hash, sample_path)
        return ToolResult(
            success=True,
            data={
                "matched": result.matched,
                "match_count": result.match_count,
                "matched_addresses": result.matched_addresses,
                "error": result.error,
            },
        ).to_dict()
    except Exception as e:
        return ToolResult(success=False, error=str(e)).to_dict()


def tool_create_pr(
    rule_text: str,
    rule_name: str,
    namespace: str,
    issue_number: Optional[int] = None,
    test_results: Optional[str] = None,
) -> dict:
    """
    ADK Tool: Create a Pull Request on mandiant/capa-rules.

    Packages the validated rule into a properly structured PR with:
    - Correctly named file in the right directory
    - Formatted PR description with validation results
    - ATT&CK coverage summary
    - Reference to source issue

    Args:
        rule_text: The validated YAML rule
        rule_name: The rule name (for file naming)
        namespace: The rule namespace (for directory placement)
        issue_number: Optional GitHub issue number to reference
        test_results: Optional test runner output to include

    Returns:
        Dict with PR URL and details
    """
    try:
        pr_ctx = PRContext(
            rule_text=rule_text,
            rule_name=rule_name,
            namespace=namespace,
            issue_number=issue_number,
            test_results=test_results,
        )
        result = create_pull_request(pr_ctx)
        return ToolResult(success=True, data=result).to_dict()
    except Exception as e:
        return ToolResult(success=False, error=str(e)).to_dict()


# ---------------------------------------------------------------------------
# Tool schema declarations for ADK (function declarations)
# ---------------------------------------------------------------------------

def tool_run_quality_gate(
    rule_text: str,
    namespace: str = "",
    rules_dir: str = "",
    sample_tested: bool = False,
) -> dict:
    """
    ADK Tool: Run the no-sample quality gate on a generated rule.

    Multi-layered validation that checks sibling rule analysis,
    semantic coherence, and negative testing — the key challenge
    identified by mentors for issues without reference samples.

    Args:
        rule_text: The YAML rule to assess
        namespace: Rule's target namespace
        rules_dir: Path to capa-rules for sibling analysis
        sample_tested: Whether the rule was already tested on a sample

    Returns:
        Dict with confidence level, score, target directory, and check details
    """
    try:
        rule_index = None
        if rules_dir:
            rule_index = RuleIndex()
            rule_index.index_directory(rules_dir)

        report = run_quality_gate(
            rule_text,
            rule_index=rule_index,
            namespace=namespace or None,
            sample_tested=sample_tested,
        )
        return ToolResult(
            success=True,
            data={
                "confidence": report.confidence.value,
                "score": report.score,
                "target_directory": report.target_directory,
                "passed": report.passed_count,
                "failed": report.failed_count,
                "warnings": report.warning_count,
                "checks": [
                    {
                        "layer": c.layer,
                        "check": c.check_name,
                        "status": c.status.value,
                        "detail": c.detail,
                    }
                    for c in report.checks
                ],
                "pr_section": report.to_pr_section(),
            },
        ).to_dict()
    except Exception as e:
        return ToolResult(success=False, error=str(e)).to_dict()


TOOL_DECLARATIONS = [
    types.FunctionDeclaration(
        name="parse_issue",
        description="Parse a capa-rules GitHub issue URL into structured context with ATT&CK IDs, sample hashes, references, and decompilation context.",
        parameters=types.Schema(
            type="OBJECT",
            properties={
                "issue_url": types.Schema(
                    type="STRING",
                    description="Full GitHub issue URL (e.g. https://github.com/mandiant/capa-rules/issues/1114)",
                ),
            },
            required=["issue_url"],
        ),
    ),
    types.FunctionDeclaration(
        name="search_similar_rules",
        description="Search the capa-rules corpus for similar existing rules using RAG retrieval. Returns top-K matching rules as few-shot context.",
        parameters=types.Schema(
            type="OBJECT",
            properties={
                "query": types.Schema(
                    type="STRING",
                    description="Natural language description of the technique to search for",
                ),
                "attck_ids": types.Schema(
                    type="ARRAY",
                    items=types.Schema(type="STRING"),
                    description="ATT&CK technique IDs to boost matches (e.g. ['T1543.003'])",
                ),
                "namespace": types.Schema(
                    type="STRING",
                    description="Preferred namespace to search in (e.g. 'persistence/service')",
                ),
                "top_k": types.Schema(
                    type="INTEGER",
                    description="Number of results to return (default: 5)",
                ),
            },
            required=["query"],
        ),
    ),
    types.FunctionDeclaration(
        name="search_api_docs",
        description="Search the web for Win32 API documentation, registry path details, or threat intelligence reports to verify technical details.",
        parameters=types.Schema(
            type="OBJECT",
            properties={
                "query": types.Schema(
                    type="STRING",
                    description="Search query (e.g. 'RegSetValueEx MSDN parameters' or 'T1543.003 MITRE ATT&CK')",
                ),
            },
            required=["query"],
        ),
    ),
    types.FunctionDeclaration(
        name="validate_rule",
        description="Validate a generated capa rule through YAML syntax check, schema validation, capa linter, and formatter.",
        parameters=types.Schema(
            type="OBJECT",
            properties={
                "rule_text": types.Schema(
                    type="STRING",
                    description="The complete YAML rule content to validate",
                ),
            },
            required=["rule_text"],
        ),
    ),
    types.FunctionDeclaration(
        name="run_capa_test",
        description="Run capa with a rule against a real malware sample to verify detection. Requires sample hash.",
        parameters=types.Schema(
            type="OBJECT",
            properties={
                "rule_text": types.Schema(
                    type="STRING",
                    description="The YAML rule to test",
                ),
                "sample_hash": types.Schema(
                    type="STRING",
                    description="SHA256 hash of the malware sample",
                ),
                "sample_path": types.Schema(
                    type="STRING",
                    description="Optional local path to the sample file",
                ),
            },
            required=["rule_text", "sample_hash"],
        ),
    ),
    types.FunctionDeclaration(
        name="create_pr",
        description="Create a Pull Request on mandiant/capa-rules with the validated rule, test results, and PR description.",
        parameters=types.Schema(
            type="OBJECT",
            properties={
                "rule_text": types.Schema(
                    type="STRING",
                    description="The validated YAML rule content",
                ),
                "rule_name": types.Schema(
                    type="STRING",
                    description="Rule name for file naming (e.g. 'persist via Windows service')",
                ),
                "namespace": types.Schema(
                    type="STRING",
                    description="Rule namespace for directory placement (e.g. 'persistence/service')",
                ),
                "issue_number": types.Schema(
                    type="INTEGER",
                    description="GitHub issue number to reference (e.g. 1114)",
                ),
                "test_results": types.Schema(
                    type="STRING",
                    description="Test runner output to include in PR description",
                ),
            },
            required=["rule_text", "rule_name", "namespace"],
        ),
    ),
    types.FunctionDeclaration(
        name="run_quality_gate",
        description="Run the multi-layered no-sample quality gate. Checks sibling rule analysis, semantic coherence, and negative testing. Returns confidence level and structured HITL metadata showing what was and wasn't verified.",
        parameters=types.Schema(
            type="OBJECT",
            properties={
                "rule_text": types.Schema(
                    type="STRING",
                    description="The YAML rule to assess",
                ),
                "namespace": types.Schema(
                    type="STRING",
                    description="Rule's target namespace (e.g. 'persistence/service')",
                ),
                "sample_tested": types.Schema(
                    type="BOOLEAN",
                    description="Whether the rule was already tested on a real sample",
                ),
            },
            required=["rule_text"],
        ),
    ),
]

# Map tool names to handler functions
TOOL_HANDLERS = {
    "parse_issue": lambda args: tool_parse_issue(**args),
    "search_similar_rules": lambda args: tool_search_similar_rules(**args),
    "search_api_docs": lambda args: tool_search_api_docs(**args),
    "validate_rule": lambda args: tool_validate_rule(**args),
    "run_capa_test": lambda args: tool_run_capa_test(**args),
    "create_pr": lambda args: tool_create_pr(**args),
    "run_quality_gate": lambda args: tool_run_quality_gate(**args),
}


# ---------------------------------------------------------------------------
# Agent session — manages multi-turn interaction with tool use
# ---------------------------------------------------------------------------

@dataclass
class AgentConfig:
    """Configuration for the ADK agent."""
    model_name: str = "gemini-3.1-pro"
    api_key: Optional[str] = None
    rules_dir: str = ""
    lint_script: str = ""
    format_script: str = ""
    max_tool_rounds: int = 10
    auto_submit_pr: bool = False


class CapaRuleAgent:
    """
    Google ADK-powered agent for automated capa rule generation.

    Implements the full agentic loop:
    1. Receive task (issue URL or description)
    2. Reason about what tools to call
    3. Execute tools (search, validate, test, etc.)
    4. Iterate until rule is valid or max rounds exceeded
    5. Optionally submit PR

    The agent uses Gemini's function calling to decide which tools
    to invoke at each step, maintaining conversation history.
    """

    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or AgentConfig()
        self.client = genai.Client(api_key=self.config.api_key)
        self.history: list[types.Content] = []
        self._rule_index: Optional[RuleIndex] = None

    @property
    def rule_index(self) -> RuleIndex:
        """Lazily build and cache the rule index."""
        if self._rule_index is None:
            self._rule_index = RuleIndex()
            if self.config.rules_dir:
                self._rule_index.index_directory(self.config.rules_dir)
        return self._rule_index

    def process_issue(self, issue_url: str) -> dict:
        """
        Process a GitHub issue end-to-end using the agentic loop.

        Args:
            issue_url: GitHub issue URL to process

        Returns:
            Dict with generated rule, validation results, and PR URL if submitted
        """
        user_message = (
            f"Generate a capa rule for this GitHub issue: {issue_url}\n\n"
            "Follow these steps:\n"
            "1. Parse the issue to understand the technique\n"
            "2. Search for similar existing rules as reference\n"
            "3. Search API docs for any referenced Win32 functions\n"
            "4. Generate the rule\n"
            "5. Validate it with the linter\n"
            "6. If a sample hash is available, test against it\n"
            "7. Submit as a PR if validation passes"
        )
        return self._run_agent_loop(user_message)

    def process_description(self, description: str) -> dict:
        """
        Generate a rule from a plain text description.

        Args:
            description: Natural language description of the technique

        Returns:
            Dict with generated rule and validation results
        """
        user_message = (
            f"Generate a capa rule for: {description}\n\n"
            "Search for similar rules, generate, and validate."
        )
        return self._run_agent_loop(user_message)

    def _run_agent_loop(self, user_message: str) -> dict:
        """
        Core agentic loop — send message, handle tool calls, iterate.

        The agent decides which tools to call based on the conversation
        context. Each tool call result is fed back as a function response,
        and the agent continues reasoning until it produces a final text
        response or reaches the max rounds limit.
        """
        self.history.append(
            types.Content(role="user", parts=[types.Part(text=user_message)])
        )

        final_result = {
            "rule_text": None,
            "validation": None,
            "pr_url": None,
            "tool_calls": [],
            "reasoning_steps": [],
        }

        for round_num in range(1, self.config.max_tool_rounds + 1):
            logger.info(f"Agent round {round_num}/{self.config.max_tool_rounds}")

            # Call Gemini with tool declarations
            response = self.client.models.generate_content(
                model=self.config.model_name,
                contents=self.history,
                config=types.GenerateContentConfig(
                    system_instruction=AGENT_SYSTEM_INSTRUCTION,
                    tools=[types.Tool(function_declarations=TOOL_DECLARATIONS)],
                    temperature=0.1,
                    max_output_tokens=4096,
                ),
            )

            # Check if the model wants to call tools
            candidate = response.candidates[0]
            response_parts = candidate.content.parts

            # Add model response to history
            self.history.append(candidate.content)

            # Check for function calls
            function_calls = [p for p in response_parts if p.function_call]

            if not function_calls:
                # Model produced a text response — agent loop complete
                text_parts = [p.text for p in response_parts if p.text]
                final_text = "\n".join(text_parts)
                final_result["reasoning_steps"].append({
                    "round": round_num,
                    "type": "final_response",
                    "text": final_text[:1000],
                })
                logger.info(f"Agent completed after {round_num} rounds")
                break

            # Execute each tool call
            function_responses = []
            for part in function_calls:
                fc = part.function_call
                tool_name = fc.name
                tool_args = dict(fc.args) if fc.args else {}

                logger.info(f"  Tool call: {tool_name}({list(tool_args.keys())})")

                # Inject config paths into tool args
                if tool_name == "search_similar_rules":
                    tool_args["rules_dir"] = self.config.rules_dir
                elif tool_name == "validate_rule":
                    tool_args["rules_dir"] = self.config.rules_dir
                    tool_args["lint_script"] = self.config.lint_script
                    tool_args["format_script"] = self.config.format_script
                elif tool_name == "run_quality_gate":
                    tool_args["rules_dir"] = self.config.rules_dir

                # Execute the tool
                handler = TOOL_HANDLERS.get(tool_name)
                if handler:
                    result = handler(tool_args)
                else:
                    result = {"success": False, "error": f"Unknown tool: {tool_name}"}

                final_result["tool_calls"].append({
                    "round": round_num,
                    "tool": tool_name,
                    "args": {k: str(v)[:200] for k, v in tool_args.items()},
                    "success": result.get("success", False),
                })

                # Extract rule text if validation returned it
                if tool_name == "validate_rule" and result.get("success"):
                    data = result.get("data", {})
                    if data.get("is_valid"):
                        final_result["validation"] = data
                        if data.get("formatted_rule"):
                            final_result["rule_text"] = data["formatted_rule"]

                # Extract PR URL if created
                if tool_name == "create_pr" and result.get("success"):
                    pr_data = result.get("data", {})
                    final_result["pr_url"] = pr_data.get("pr_url")

                function_responses.append(
                    types.Part(
                        function_response=types.FunctionResponse(
                            name=tool_name,
                            response=result,
                        )
                    )
                )

            # Add function responses to history
            self.history.append(
                types.Content(role="user", parts=function_responses)
            )

        return final_result

    def reset(self):
        """Clear conversation history for a new task."""
        self.history.clear()
        logger.info("Agent history cleared")
