"""
Trigger module — parses capa-rules GitHub issues to extract structured context
for rule generation.

Handles both "reactive" triggers (parsing existing issues) and provides
the data model for future "proactive" triggers (threat intel feeds).
"""

from __future__ import annotations

import re
import json
import logging
from dataclasses import dataclass, field
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ATT&CK technique pattern: T1234 or T1234.567
ATTCK_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")

# Common ATT&CK tactic/technique names for matching
ATTCK_TACTICS = {
    "persistence", "execution", "defense evasion", "credential access",
    "discovery", "lateral movement", "collection", "command and control",
    "exfiltration", "impact", "initial access", "privilege escalation",
    "resource development", "reconnaissance",
}

# MITRE ATT&CK technique ID to full name mapping (common persistence techniques)
ATTCK_TECHNIQUE_MAP = {
    "T1543.003": "Persistence::Create or Modify System Process::Windows Service [T1543.003]",
    "T1547.001": "Persistence::Boot or Logon Autostart Execution::Registry Run Keys / Startup Folder [T1547.001]",
    "T1547.004": "Persistence::Boot or Logon Autostart Execution::Winlogon Helper DLL [T1547.004]",
    "T1547.012": "Persistence::Boot or Logon Autostart Execution::Print Processors [T1547.012]",
    "T1546.015": "Persistence::Event Triggered Execution::Component Object Model Hijacking [T1546.015]",
    "T1546.010": "Persistence::Event Triggered Execution::AppInit DLLs [T1546.010]",
    "T1053.005": "Persistence::Scheduled Task/Job::Scheduled Task [T1053.005]",
    "T1574.001": "Persistence::Hijack Execution Flow::DLL Search Order Hijacking [T1574.001]",
    "T1569.002": "Execution::System Services::Service Execution [T1569.002]",
    "T1197": "Defense Evasion::BITS Jobs [T1197]",
}


@dataclass
class IssueContext:
    """Structured context extracted from a capa-rules GitHub issue."""

    title: str
    body: str
    labels: list[str] = field(default_factory=list)
    attck_ids: list[str] = field(default_factory=list)
    attck_references: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    sample_hashes: list[str] = field(default_factory=list)
    decompilation: Optional[str] = None
    verdict: Optional[str] = None
    suggested_namespace: Optional[str] = None
    suggested_name: Optional[str] = None

    def to_prompt_context(self) -> str:
        """Format as context string for LLM prompt."""
        parts = [
            f"## Issue: {self.title}",
            f"\n### Description\n{self.body}",
        ]
        if self.attck_ids:
            parts.append(f"\n### ATT&CK Techniques\n" + "\n".join(
                f"- {tid}: {ATTCK_TECHNIQUE_MAP.get(tid, tid)}"
                for tid in self.attck_ids
            ))
        if self.references:
            parts.append(f"\n### References\n" + "\n".join(f"- {r}" for r in self.references))
        if self.sample_hashes:
            parts.append(f"\n### Sample Hashes\n" + "\n".join(f"- {h}" for h in self.sample_hashes))
        if self.decompilation:
            parts.append(f"\n### Decompilation\n```c\n{self.decompilation}\n```")
        if self.verdict:
            parts.append(f"\n### Verdict/Notes\n{self.verdict}")
        if self.suggested_namespace:
            parts.append(f"\n### Suggested Namespace: {self.suggested_namespace}")
        if self.suggested_name:
            parts.append(f"\n### Suggested Rule Name: {self.suggested_name}")
        return "\n".join(parts)


def parse_github_issue(issue_url: str) -> IssueContext:
    """
    Parse a capa-rules GitHub issue URL into structured context.

    Args:
        issue_url: Full GitHub issue URL (e.g., https://github.com/mandiant/capa-rules/issues/1114)

    Returns:
        IssueContext with extracted fields
    """
    # Extract owner/repo/number from URL
    match = re.match(
        r"https?://github\.com/([^/]+)/([^/]+)/issues/(\d+)",
        issue_url
    )
    if not match:
        raise ValueError(f"Invalid GitHub issue URL: {issue_url}")

    owner, repo, number = match.groups()
    api_url = f"https://api.github.com/repos/{owner}/{repo}/issues/{number}"

    logger.info(f"Fetching issue {owner}/{repo}#{number}")

    response = requests.get(api_url, headers={"Accept": "application/vnd.github.v3+json"})
    response.raise_for_status()
    data = response.json()

    return _parse_issue_data(data)


def _parse_issue_data(data: dict) -> IssueContext:
    """Parse GitHub API issue response into IssueContext."""
    title = data.get("title", "")
    body = data.get("body", "")
    labels = [label["name"] for label in data.get("labels", [])]

    # Extract ATT&CK technique IDs
    attck_ids = list(set(ATTCK_PATTERN.findall(title + " " + body)))
    attck_references = [
        ATTCK_TECHNIQUE_MAP[tid] for tid in attck_ids
        if tid in ATTCK_TECHNIQUE_MAP
    ]

    # Extract URLs as references
    url_pattern = re.compile(r"https?://[^\s\)\"']+")
    references = url_pattern.findall(body)

    # Extract sample hashes (SHA256, MD5)
    sha256_pattern = re.compile(r"\b[a-fA-F0-9]{64}\b")
    md5_pattern = re.compile(r"\b[a-fA-F0-9]{32}\b")
    sample_hashes = sha256_pattern.findall(body) + md5_pattern.findall(body)

    # Extract decompilation blocks (code fences)
    decompilation = None
    code_blocks = re.findall(r"```(?:\w+)?\n(.*?)```", body, re.DOTALL)
    for block in code_blocks:
        # Heuristic: if it contains C-like code patterns, it's likely decompilation
        if any(kw in block for kw in ["void ", "int ", "HKEY", "LSTATUS", "undefined", "FUN_"]):
            decompilation = block.strip()
            break

    # Extract verdict lines
    verdict = None
    verdict_match = re.search(r"verdict[:\s]*\n(.*?)(?:\n\n|\ndecompilation)", body, re.DOTALL | re.IGNORECASE)
    if verdict_match:
        verdict = verdict_match.group(1).strip()

    # Infer namespace and name from title
    suggested_name, suggested_namespace = _infer_rule_metadata(title, labels)

    return IssueContext(
        title=title,
        body=body,
        labels=labels,
        attck_ids=attck_ids,
        attck_references=attck_references,
        references=references,
        sample_hashes=sample_hashes,
        decompilation=decompilation,
        verdict=verdict,
        suggested_namespace=suggested_namespace,
        suggested_name=suggested_name,
    )


def _infer_rule_metadata(title: str, labels: list[str]) -> tuple[Optional[str], Optional[str]]:
    """Infer rule name and namespace from issue title and labels."""
    name = None
    namespace = None

    # Clean up title to make a rule name
    title_lower = title.lower().strip()

    # Remove common prefixes
    for prefix in ["rule idea:", "rule:", "detect", "add rule for", "add rule to"]:
        if title_lower.startswith(prefix):
            title_lower = title_lower[len(prefix):].strip()

    # Check for persistence patterns
    if any(kw in title_lower for kw in ["persist", "autostart", "startup", "run key", "service"]):
        namespace = "persistence"
        if "registry" in title_lower or "shellservice" in title_lower.replace(" ", ""):
            namespace = "persistence/registry"
        elif "service" in title_lower:
            namespace = "persistence/service"
        elif "scheduled" in title_lower or "task" in title_lower:
            namespace = "persistence/scheduled-tasks"

    # Convert title to kebab-case rule name
    name = re.sub(r"[^a-z0-9\s]", "", title_lower)
    name = re.sub(r"\s+", " ", name).strip()

    return name, namespace


def parse_description(description: str, technique_name: Optional[str] = None) -> IssueContext:
    """
    Create an IssueContext from a plain text description (for local/manual use).

    Args:
        description: Plain text description of the technique to detect
        technique_name: Optional technique name for rule naming

    Returns:
        IssueContext with inferred fields
    """
    attck_ids = list(set(ATTCK_PATTERN.findall(description)))
    attck_references = [
        ATTCK_TECHNIQUE_MAP[tid] for tid in attck_ids
        if tid in ATTCK_TECHNIQUE_MAP
    ]

    name = technique_name or description[:80]
    suggested_name, suggested_namespace = _infer_rule_metadata(name, [])

    return IssueContext(
        title=name,
        body=description,
        attck_ids=attck_ids,
        attck_references=attck_references,
        suggested_name=suggested_name,
        suggested_namespace=suggested_namespace,
    )
