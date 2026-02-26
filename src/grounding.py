"""
Grounding module — retrieves relevant existing capa rules as few-shot examples
for the generator via lightweight semantic similarity.

Implements a local RAG pipeline over the capa-rules corpus:
1. Index all rules by namespace, ATT&CK IDs, and keyword tokens
2. Retrieve top-K rules most relevant to a given IssueContext
3. Format retrieved rules as grounding context for the LLM prompt

This avoids hallucinated rule syntax by grounding generation in real examples.
"""

from __future__ import annotations

import re
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from collections import Counter

import yaml

from .trigger import IssueContext

logger = logging.getLogger(__name__)

# Stopwords to filter out from keyword matching
STOPWORDS = {
    "the", "a", "an", "and", "or", "not", "is", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "as", "via", "using", "that", "this", "it",
    "be", "are", "was", "were", "will", "can", "may", "has", "have", "do",
    "does", "did", "if", "else", "when", "data", "file", "function", "rule",
}


@dataclass
class RuleEntry:
    """A parsed capa rule with extracted metadata for indexing."""
    path: str
    name: str
    namespace: str
    raw_text: str
    attck_ids: list[str] = field(default_factory=list)
    keywords: set[str] = field(default_factory=set)
    apis: list[str] = field(default_factory=list)
    authors: list[str] = field(default_factory=list)


class RuleIndex:
    """
    In-memory index over the capa-rules corpus for fast retrieval.

    Supports retrieval by:
    - Namespace prefix matching
    - ATT&CK technique ID
    - Keyword overlap (TF-based scoring)
    - API call overlap
    """

    def __init__(self):
        self.rules: list[RuleEntry] = []
        self._by_namespace: dict[str, list[int]] = {}
        self._by_attck: dict[str, list[int]] = {}
        self._by_keyword: dict[str, list[int]] = {}
        self._by_api: dict[str, list[int]] = {}

    def index_directory(self, rules_dir: str | Path, max_rules: int = 2000) -> int:
        """
        Index all YAML rules in a directory tree.

        Args:
            rules_dir: Root directory of capa-rules repository
            max_rules: Maximum rules to index (safety limit)

        Returns:
            Number of rules indexed
        """
        rules_path = Path(rules_dir)
        if not rules_path.exists():
            logger.warning(f"Rules directory not found: {rules_dir}")
            return 0

        count = 0
        for yml_path in sorted(rules_path.rglob("*.yml")):
            if count >= max_rules:
                break

            # Skip non-rule files
            rel_path = str(yml_path.relative_to(rules_path))
            if rel_path.startswith(".") or rel_path.startswith("nursery"):
                continue

            try:
                entry = self._parse_rule_file(yml_path, rel_path)
                if entry:
                    idx = len(self.rules)
                    self.rules.append(entry)
                    self._index_entry(idx, entry)
                    count += 1
            except Exception as e:
                logger.debug(f"Skipping {rel_path}: {e}")

        logger.info(f"Indexed {count} rules from {rules_dir}")
        return count

    def _parse_rule_file(self, path: Path, rel_path: str) -> Optional[RuleEntry]:
        """Parse a single rule YAML file into a RuleEntry."""
        raw = path.read_text(encoding="utf-8", errors="replace")
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError:
            return None

        if not isinstance(data, dict) or "rule" not in data:
            return None

        rule = data["rule"]
        meta = rule.get("meta", {})

        name = meta.get("name", "")
        namespace = meta.get("namespace", "")
        authors = meta.get("authors", [])

        # Extract ATT&CK IDs
        attck_ids = []
        for entry in meta.get("att&ck", []):
            ids = re.findall(r"T\d{4}(?:\.\d{3})?", str(entry))
            attck_ids.extend(ids)

        # Extract keywords from name and namespace
        keywords = set()
        for token in re.split(r"[^a-zA-Z0-9]+", f"{name} {namespace}"):
            token_lower = token.lower()
            if token_lower and token_lower not in STOPWORDS and len(token_lower) > 2:
                keywords.add(token_lower)

        # Extract API calls from features
        apis = self._extract_apis(rule.get("features", []))

        return RuleEntry(
            path=rel_path,
            name=name,
            namespace=namespace,
            raw_text=raw,
            attck_ids=attck_ids,
            keywords=keywords,
            apis=apis,
            authors=authors,
        )

    def _extract_apis(self, features: list | dict, depth: int = 0) -> list[str]:
        """Recursively extract API calls from a features tree."""
        apis = []
        if depth > 10:
            return apis

        if isinstance(features, list):
            for item in features:
                apis.extend(self._extract_apis(item, depth + 1))
        elif isinstance(features, dict):
            for key, val in features.items():
                if key == "api":
                    apis.append(str(val))
                elif isinstance(val, (list, dict)):
                    apis.extend(self._extract_apis(val, depth + 1))
        return apis

    def _index_entry(self, idx: int, entry: RuleEntry):
        """Add a rule entry to all inverted indices."""
        # Index by namespace (including all prefixes)
        parts = entry.namespace.split("/")
        for i in range(1, len(parts) + 1):
            prefix = "/".join(parts[:i])
            self._by_namespace.setdefault(prefix, []).append(idx)

        # Index by ATT&CK ID
        for tid in entry.attck_ids:
            self._by_attck.setdefault(tid, []).append(idx)

        # Index by keyword
        for kw in entry.keywords:
            self._by_keyword.setdefault(kw, []).append(idx)

        # Index by API
        for api in entry.apis:
            api_name = api.split(".")[-1].lower() if "." in api else api.lower()
            self._by_api.setdefault(api_name, []).append(idx)

    def retrieve(
        self,
        context: IssueContext,
        top_k: int = 5,
        namespace_boost: float = 3.0,
        attck_boost: float = 5.0,
        keyword_boost: float = 1.0,
    ) -> list[tuple[RuleEntry, float]]:
        """
        Retrieve the most relevant rules for a given issue context.

        Scoring:
        - ATT&CK ID match: attck_boost per matching ID
        - Namespace prefix match: namespace_boost
        - Keyword overlap: keyword_boost per matching keyword

        Args:
            context: The issue context to match against
            top_k: Number of rules to return
            namespace_boost: Score boost for namespace matches
            attck_boost: Score boost for ATT&CK ID matches
            keyword_boost: Score boost per keyword match

        Returns:
            List of (RuleEntry, score) tuples sorted by score descending
        """
        scores: Counter = Counter()

        # Score by ATT&CK IDs
        for tid in context.attck_ids:
            for idx in self._by_attck.get(tid, []):
                scores[idx] += attck_boost

        # Score by namespace
        if context.suggested_namespace:
            parts = context.suggested_namespace.split("/")
            for i in range(1, len(parts) + 1):
                prefix = "/".join(parts[:i])
                for idx in self._by_namespace.get(prefix, []):
                    scores[idx] += namespace_boost * (i / len(parts))

        # Score by keyword overlap
        query_keywords = set()
        text = f"{context.title} {context.body}"
        for token in re.split(r"[^a-zA-Z0-9]+", text):
            token_lower = token.lower()
            if token_lower and token_lower not in STOPWORDS and len(token_lower) > 2:
                query_keywords.add(token_lower)

        for kw in query_keywords:
            for idx in self._by_keyword.get(kw, []):
                scores[idx] += keyword_boost

        if not scores:
            logger.warning("No matching rules found in index")
            return []

        # Get top-K
        top_entries = scores.most_common(top_k)
        return [(self.rules[idx], score) for idx, score in top_entries]

    def __len__(self) -> int:
        return len(self.rules)


def format_grounding_context(
    retrieved: list[tuple[RuleEntry, float]],
    max_rules: int = 3,
    max_chars_per_rule: int = 2000,
) -> str:
    """
    Format retrieved rules as grounding context for the LLM prompt.

    Args:
        retrieved: List of (RuleEntry, score) tuples
        max_rules: Maximum rules to include
        max_chars_per_rule: Maximum characters per rule text

    Returns:
        Formatted context string
    """
    if not retrieved:
        return ""

    parts = ["## Similar existing capa rules (for reference)\n"]
    parts.append("Use these as style and syntax references. Do NOT copy them directly.\n")

    for i, (entry, score) in enumerate(retrieved[:max_rules], 1):
        text = entry.raw_text.strip()
        if len(text) > max_chars_per_rule:
            text = text[:max_chars_per_rule] + "\n# ... (truncated)"

        parts.append(f"### Reference Rule {i}: {entry.name}")
        parts.append(f"Namespace: {entry.namespace} | ATT&CK: {', '.join(entry.attck_ids) or 'N/A'}")
        parts.append(f"Relevance score: {score:.1f}\n")
        parts.append(f"```yaml\n{text}\n```\n")

    return "\n".join(parts)
