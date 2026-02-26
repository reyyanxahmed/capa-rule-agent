"""
Generator module — uses Gemini to generate valid capa YAML rules from issue context.

Implements:
- Structured prompt engineering with capa rule format constraints
- Few-shot examples from existing rules
- Grounding via references and API documentation context
"""

from __future__ import annotations

import logging
from typing import Optional

from google import genai
from google.genai import types

from .trigger import IssueContext
from .grounding import RuleIndex, format_grounding_context

logger = logging.getLogger(__name__)

# System prompt that teaches the model the capa rule format
SYSTEM_PROMPT = """You are an expert capa rule author for Mandiant FLARE. You generate valid capa YAML rules
that detect malware capabilities in executable files.

## capa Rule Format

A capa rule is a YAML file with this structure:

```yaml
rule:
  meta:
    name: <descriptive lowercase name>
    namespace: <hierarchical/namespace/path>
    authors:
      - <author email>
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - <Tactic>::<Technique>::<Sub-technique> [T####.###]
    references:
      - <url>
    examples:
      - <sample_hash:function_address>
  features:
    - <logic tree using and/or/not/optional>
```

## Feature Types Available

### API calls
- `api: <library>.<function>` — e.g., `api: advapi32.RegSetValueEx`
- `api: <function>` — without library prefix

### Strings
- `string: "exact string"` — exact match
- `string: /regex pattern/i` — regex match (i = case insensitive)
- `substring: "partial"` — substring match

### Numbers
- `number: 0x80000002 = HKEY_LOCAL_MACHINE` — numeric constant with description
- `number: 2 = SERVICE_AUTO_START`

### Matching other rules
- `match: <namespace>` — matches if another rule in that namespace fires
- `match: set registry value` — matches a specific rule by name

### Logic operators
- `and:` — all children must match
- `or:` — at least one child must match
- `not:` — child must NOT match
- `optional:` — child may or may not match (doesn't affect overall result)

### Scope qualifiers
- `basic block:` — features within a single basic block
- `call:` — features within a single API call (dynamic analysis)

## Rules for Rule Writing

1. **Use the correct scopes**: Most rules use `static: function` and `dynamic: span of calls`
2. **Be specific with API calls**: Include the library prefix when known (e.g., `advapi32.CreateService`)
3. **Use regex for flexibility**: Registry paths and command strings should use regex to handle variations
4. **Add descriptions to numbers**: Always annotate magic numbers (e.g., `number: 2 = SERVICE_AUTO_START`)
5. **Follow naming conventions**: Rule names are lowercase, descriptive, use natural language
6. **Namespace correctly**: Use hierarchical paths like `persistence/registry`, `communication/http`
7. **Include ATT&CK mapping**: Use the format `Tactic::Technique::Sub-technique [T####.###]`
8. **Don't be overly broad**: Rules should have enough conditions to avoid false positives
9. **Examples field**: Use `<hash>:<address>` format if available, otherwise omit

## Output Format

Return ONLY the YAML rule content. Do not include markdown code fences or explanations.
Start directly with `rule:` and ensure proper YAML indentation (2 spaces).
"""

# Few-shot examples of well-written capa rules
FEW_SHOT_EXAMPLES = [
    {
        "issue": "Detect persistence via Run registry key",
        "rule": """rule:
  meta:
    name: persist via Run registry key
    namespace: persistence/registry/run
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Persistence::Boot or Logon Autostart Execution::Registry Run Keys / Startup Folder [T1547.001]
    examples:
      - Practical Malware Analysis Lab 06-03.exe_:0x401130
  features:
    - and:
      - or:
        - match: set registry value
        - number: 0x80000001 = HKEY_CURRENT_USER
        - number: 0x80000002 = HKEY_LOCAL_MACHINE
      - or:
        - string: /Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run/i
        - string: /Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServices/i"""
    },
    {
        "issue": "Detect persistence via Windows service creation using CreateService API",
        "rule": """rule:
  meta:
    name: persist via Windows service
    namespace: persistence/service
    authors:
      - moritz.raabe@mandiant.com
    scopes:
      static: function
      dynamic: span of calls
    att&ck:
      - Persistence::Create or Modify System Process::Windows Service [T1543.003]
    examples:
      - Practical Malware Analysis Lab 03-02.dll_:0x10004706
  features:
    - or:
      - and:
        - or:
          - basic block:
            - and:
              - number: 2 = SERVICE_AUTO_START
              - api: advapi32.CreateService
          - call:
            - and:
              - number: 2 = SERVICE_AUTO_START
              - api: advapi32.CreateService
        - optional:
          - or:
            - api: advapi32.OpenService
            - api: advapi32.StartService"""
    },
]


def generate_rule(
    context: IssueContext,
    api_key: Optional[str] = None,
    model_name: str = "gemini-2.0-flash",
    max_retries: int = 3,
    validation_errors: Optional[list[str]] = None,
    grounding_context: Optional[str] = None,
) -> str:
    """
    Generate a capa rule from issue context using Gemini.

    Args:
        context: Structured issue context
        api_key: Google API key (falls back to GOOGLE_API_KEY env var)
        model_name: Gemini model to use
        max_retries: Number of generation attempts
        validation_errors: Previous validation errors to correct
        grounding_context: RAG-retrieved similar rules as context

    Returns:
        Generated YAML rule as string
    """
    client = genai.Client(api_key=api_key)

    # Build the prompt
    prompt_parts = []

    # Add RAG-retrieved grounding context first (if available)
    if grounding_context:
        prompt_parts.append(grounding_context)
        prompt_parts.append("")

    # Add few-shot examples
    prompt_parts.append("## Examples of well-written capa rules\n")
    for i, example in enumerate(FEW_SHOT_EXAMPLES, 1):
        prompt_parts.append(f"### Example {i}: {example['issue']}\n```yaml\n{example['rule']}\n```\n")

    # Add the issue context
    prompt_parts.append("## Your Task\n")
    prompt_parts.append("Generate a capa rule for the following issue:\n")
    prompt_parts.append(context.to_prompt_context())

    # Add correction context if this is a retry
    if validation_errors:
        prompt_parts.append("\n## IMPORTANT: Previous attempt had validation errors\n")
        prompt_parts.append("Fix the following issues in your generated rule:\n")
        for error in validation_errors:
            prompt_parts.append(f"- {error}")
        prompt_parts.append("\nGenerate a corrected version that addresses ALL of these errors.")

    # Add author placeholder
    prompt_parts.append(f"\n## Metadata\n- Author email: gsoc-agent@mandiant.com")
    if context.suggested_namespace:
        prompt_parts.append(f"- Suggested namespace: {context.suggested_namespace}")
    if context.suggested_name:
        prompt_parts.append(f"- Suggested rule name: {context.suggested_name}")

    prompt = "\n".join(prompt_parts)

    logger.info(f"Generating rule with {model_name} (prompt length: {len(prompt)} chars)")

    response = client.models.generate_content(
        model=model_name,
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            temperature=0.2,
            max_output_tokens=2048,
        ),
    )

    raw_output = response.text.strip()

    # Clean up output — remove code fences if present
    if raw_output.startswith("```"):
        lines = raw_output.split("\n")
        # Remove first line (```yaml) and last line (```)
        lines = [l for l in lines if not l.strip().startswith("```")]
        raw_output = "\n".join(lines)

    # Ensure it starts with "rule:"
    if not raw_output.startswith("rule:"):
        # Try to find "rule:" in the output
        idx = raw_output.find("rule:")
        if idx >= 0:
            raw_output = raw_output[idx:]
        else:
            logger.warning("Generated output does not contain 'rule:' — returning as-is")

    return raw_output


def generate_rule_offline(context: IssueContext) -> str:
    """
    Generate a template capa rule without LLM (for testing/offline use).

    Produces a syntactically valid rule skeleton based on the issue context.
    """
    attck_section = ""
    if context.attck_references:
        attck_lines = "\n".join(f"      - {ref}" for ref in context.attck_references)
        attck_section = f"    att&ck:\n{attck_lines}"
    elif context.attck_ids:
        attck_lines = "\n".join(f"      - {tid}" for tid in context.attck_ids)
        attck_section = f"    att&ck:\n{attck_lines}"

    references_section = ""
    if context.references:
        ref_lines = "\n".join(f"      - {ref}" for ref in context.references[:3])
        references_section = f"    references:\n{ref_lines}"

    name = context.suggested_name or context.title.lower()[:60]
    namespace = context.suggested_namespace or "nursery"

    sections = [
        "rule:",
        "  meta:",
        f"    name: {name}",
        f"    namespace: {namespace}",
        "    authors:",
        "      - gsoc-agent@mandiant.com",
        "    scopes:",
        "      static: function",
        "      dynamic: span of calls",
    ]

    if attck_section:
        sections.append(attck_section)
    if references_section:
        sections.append(references_section)

    sections.extend([
        "  features:",
        "    - and:",
        "      - or:",
        "        - match: set registry value",
        '      - string: "TODO: add detection logic"',
    ])

    rule = "\n".join(sections) + "\n"
    return rule
