"""
Proactive Trigger module — monitors threat intelligence feeds to identify
malware techniques that lack capa rule coverage.

Implements two trigger modes:
1. **Reactive** — Parse existing GitHub issues (handled by trigger.py)
2. **Proactive** — Scan threat intel feeds for new techniques, cross-reference
   with existing capa rules, and create issues/rules for uncovered gaps.

Supported feeds:
- MALPEDIA — malware family profiles with ATT&CK mappings
- MalwareBazaar — recent samples with tags and signatures
- MITRE ATT&CK — technique updates and new sub-techniques
- VirusTotal Livehunt — (future) real-time YARA-based alerting
"""

from __future__ import annotations

import re
import json
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

import requests

from src.trigger import IssueContext, ATTCK_TECHNIQUE_MAP, ATTCK_PATTERN
from src.grounding import RuleIndex

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ThreatReport:
    """A threat intelligence report that may indicate uncovered techniques."""
    source: str                           # "malpedia", "malwarebazaar", "mitre"
    title: str
    description: str
    attck_ids: list[str] = field(default_factory=list)
    sample_hashes: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    malware_family: Optional[str] = None
    timestamp: Optional[str] = None
    tags: list[str] = field(default_factory=list)

    def to_issue_context(self) -> IssueContext:
        """Convert to IssueContext for pipeline consumption."""
        attck_refs = [
            ATTCK_TECHNIQUE_MAP.get(tid, tid) for tid in self.attck_ids
        ]
        name = self.title.lower()
        namespace = _infer_namespace_from_attck(self.attck_ids)

        return IssueContext(
            title=self.title,
            body=self.description,
            attck_ids=self.attck_ids,
            attck_references=attck_refs,
            references=self.references,
            sample_hashes=self.sample_hashes,
            suggested_name=name,
            suggested_namespace=namespace,
        )


@dataclass
class CoverageGap:
    """An identified gap between threat intel and existing capa rules."""
    technique_id: str
    technique_name: str
    source_reports: list[ThreatReport]
    existing_rules: list[str]             # names of partially matching rules
    gap_type: str                         # "no_coverage", "partial_coverage", "variant"
    priority: float                       # higher = more urgent

    def summary(self) -> str:
        return (
            f"[{self.gap_type}] {self.technique_id}: {self.technique_name} "
            f"(priority: {self.priority:.1f}, sources: {len(self.source_reports)}, "
            f"existing_rules: {len(self.existing_rules)})"
        )


# ---------------------------------------------------------------------------
# Feed scanners
# ---------------------------------------------------------------------------

class MalpediaScanner:
    """
    Scan MALPEDIA for malware families with ATT&CK technique mappings.

    MALPEDIA provides structured threat actor and malware family profiles,
    each mapped to ATT&CK techniques. We cross-reference these with
    existing capa rules to find coverage gaps.
    """

    BASE_URL = "https://malpedia.caad.fkie.fraunhofer.de/api"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.session = requests.Session()
        if api_key:
            self.session.headers["Authorization"] = f"apitoken {api_key}"

    def get_recent_families(self, limit: int = 50) -> list[ThreatReport]:
        """
        Fetch recently updated malware families from MALPEDIA.

        Returns:
            List of ThreatReports with ATT&CK mappings
        """
        reports = []
        try:
            resp = self.session.get(
                f"{self.BASE_URL}/list/families",
                timeout=30,
            )
            resp.raise_for_status()
            families = resp.json()

            for family_name, family_data in list(families.items())[:limit]:
                attck_ids = []
                refs = []

                # Extract ATT&CK techniques if available
                for technique in family_data.get("attribution", []):
                    ids = ATTCK_PATTERN.findall(str(technique))
                    attck_ids.extend(ids)

                # Extract references
                for url in family_data.get("urls", []):
                    refs.append(url)

                if attck_ids:  # Only include families with ATT&CK mappings
                    reports.append(ThreatReport(
                        source="malpedia",
                        title=f"Malware family: {family_name}",
                        description=family_data.get("description", ""),
                        attck_ids=list(set(attck_ids)),
                        references=refs[:5],
                        malware_family=family_name,
                        tags=family_data.get("alt_names", []),
                    ))

        except requests.RequestException as e:
            logger.warning(f"MALPEDIA API error: {e}")

        logger.info(f"Fetched {len(reports)} MALPEDIA families with ATT&CK mappings")
        return reports


class MalwareBazaarScanner:
    """
    Scan MalwareBazaar for recent malware samples with signatures/tags.

    MalwareBazaar (abuse.ch) provides daily sample uploads with:
    - SHA256 hashes for downloading
    - Signature names (family identification)
    - Tags for technique identification
    """

    BASE_URL = "https://mb-api.abuse.ch/api/v1/"

    def get_recent_samples(
        self,
        hours: int = 24,
        limit: int = 100,
        tag: Optional[str] = None,
    ) -> list[ThreatReport]:
        """
        Query MalwareBazaar for recently uploaded samples.

        Args:
            hours: Look back window in hours
            limit: Maximum samples to fetch
            tag: Optional tag filter (e.g., "Emotet", "Cobalt Strike")

        Returns:
            List of ThreatReports with sample hashes
        """
        reports = []
        try:
            payload = {"query": "get_recent", "selector": str(hours)}
            if tag:
                payload = {"query": "get_taginfo", "tag": tag, "limit": limit}

            resp = requests.post(self.BASE_URL, data=payload, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            if data.get("query_status") != "ok":
                logger.warning(f"MalwareBazaar query failed: {data.get('query_status')}")
                return reports

            for sample in data.get("data", [])[:limit]:
                sha256 = sample.get("sha256_hash", "")
                signature = sample.get("signature") or "unknown"
                tags = sample.get("tags") or []

                # Infer ATT&CK IDs from tags
                attck_ids = []
                for t in tags:
                    ids = ATTCK_PATTERN.findall(t)
                    attck_ids.extend(ids)

                reports.append(ThreatReport(
                    source="malwarebazaar",
                    title=f"Sample: {signature} ({sha256[:16]}...)",
                    description=f"MalwareBazaar sample, signature: {signature}, tags: {', '.join(tags)}",
                    attck_ids=attck_ids,
                    sample_hashes=[sha256] if sha256 else [],
                    malware_family=signature if signature != "unknown" else None,
                    timestamp=sample.get("first_seen"),
                    tags=tags,
                ))

        except requests.RequestException as e:
            logger.warning(f"MalwareBazaar API error: {e}")

        logger.info(f"Fetched {len(reports)} MalwareBazaar samples")
        return reports


class MitreAttckScanner:
    """
    Monitor MITRE ATT&CK for technique updates via the ATT&CK STIX data.

    Cross-references the full ATT&CK technique catalog with existing capa
    rules to identify techniques with zero or low rule coverage.
    """

    STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    def get_techniques(self, limit: int = 500) -> list[dict]:
        """
        Fetch ATT&CK Enterprise techniques from the STIX bundle.

        Returns:
            List of technique dicts with id, name, description, tactic
        """
        techniques = []
        try:
            resp = requests.get(self.STIX_URL, timeout=60)
            resp.raise_for_status()
            bundle = resp.json()

            for obj in bundle.get("objects", []):
                if obj.get("type") != "attack-pattern":
                    continue
                if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                    continue

                # Extract technique ID
                external_refs = obj.get("external_references", [])
                tid = None
                for ref in external_refs:
                    if ref.get("source_name") == "mitre-attack":
                        tid = ref.get("external_id")
                        break

                if not tid:
                    continue

                # Extract kill chain phase (tactic)
                tactics = []
                for phase in obj.get("kill_chain_phases", []):
                    if phase.get("kill_chain_name") == "mitre-attack":
                        tactics.append(phase["phase_name"])

                techniques.append({
                    "id": tid,
                    "name": obj.get("name", ""),
                    "description": obj.get("description", "")[:500],
                    "tactics": tactics,
                    "platforms": obj.get("x_mitre_platforms", []),
                })

                if len(techniques) >= limit:
                    break

        except requests.RequestException as e:
            logger.warning(f"MITRE ATT&CK fetch error: {e}")

        logger.info(f"Fetched {len(techniques)} ATT&CK techniques")
        return techniques


# ---------------------------------------------------------------------------
# Coverage gap analysis
# ---------------------------------------------------------------------------

class CoverageAnalyzer:
    """
    Cross-references threat intel with existing capa rules to find gaps.

    The analyzer produces a prioritized list of CoverageGap objects,
    each describing a technique that either lacks capa rules entirely
    or only has partial coverage.
    """

    def __init__(self, rule_index: RuleIndex):
        self.rule_index = rule_index
        # Build a reverse map: ATT&CK ID → list of rule names
        self._attck_to_rules: dict[str, list[str]] = {}
        for entry in rule_index.rules:
            for tid in entry.attck_ids:
                self._attck_to_rules.setdefault(tid, []).append(entry.name)

    def analyze_reports(self, reports: list[ThreatReport]) -> list[CoverageGap]:
        """
        Analyze threat reports to find coverage gaps.

        Args:
            reports: Threat intel reports with ATT&CK mappings

        Returns:
            Prioritized list of coverage gaps
        """
        # Aggregate reports by technique
        technique_reports: dict[str, list[ThreatReport]] = {}
        for report in reports:
            for tid in report.attck_ids:
                technique_reports.setdefault(tid, []).append(report)

        gaps = []
        for tid, reports_for_technique in technique_reports.items():
            existing = self._attck_to_rules.get(tid, [])

            if not existing:
                gap_type = "no_coverage"
                priority = 10.0 + len(reports_for_technique)  # High priority
            elif len(existing) < 2:
                gap_type = "partial_coverage"
                priority = 5.0 + len(reports_for_technique) * 0.5
            else:
                # Check if any reports mention specific variants not covered
                gap_type = "variant"
                priority = 2.0

            # Look up technique name
            technique_name = ATTCK_TECHNIQUE_MAP.get(tid, tid)

            gaps.append(CoverageGap(
                technique_id=tid,
                technique_name=technique_name,
                source_reports=reports_for_technique,
                existing_rules=existing,
                gap_type=gap_type,
                priority=priority,
            ))

        # Sort by priority (descending)
        gaps.sort(key=lambda g: g.priority, reverse=True)
        return gaps

    def analyze_attck_coverage(
        self,
        techniques: list[dict],
        windows_only: bool = True,
    ) -> list[CoverageGap]:
        """
        Compare full ATT&CK matrix against existing capa rules.

        Args:
            techniques: ATT&CK technique list from MitreAttckScanner
            windows_only: Only analyze Windows-relevant techniques

        Returns:
            List of techniques with no capa rule coverage
        """
        gaps = []
        for tech in techniques:
            tid = tech["id"]

            if windows_only and "Windows" not in tech.get("platforms", []):
                continue

            existing = self._attck_to_rules.get(tid, [])
            if not existing:
                gaps.append(CoverageGap(
                    technique_id=tid,
                    technique_name=tech["name"],
                    source_reports=[],
                    existing_rules=[],
                    gap_type="no_coverage",
                    priority=8.0,  # BASE priority for uncovered techniques
                ))

        gaps.sort(key=lambda g: g.priority, reverse=True)
        logger.info(
            f"ATT&CK coverage analysis: {len(gaps)} techniques with zero capa rules "
            f"(out of {len(techniques)} analyzed)"
        )
        return gaps


# ---------------------------------------------------------------------------
# Proactive trigger entrypoint
# ---------------------------------------------------------------------------

def scan_feeds(
    rules_dir: str,
    malpedia_key: Optional[str] = None,
    include_bazaar: bool = True,
    include_attck: bool = True,
    max_gaps: int = 20,
) -> list[CoverageGap]:
    """
    Run a full proactive scan: fetch feeds → analyze coverage → return gaps.

    This is the main entry point for the proactive trigger, designed to
    run on a schedule (e.g., daily cron) or as an ADK tool call.

    Args:
        rules_dir: Path to capa-rules directory for coverage baseline
        malpedia_key: Optional MALPEDIA API key
        include_bazaar: Include MalwareBazaar recent samples
        include_attck: Include MITRE ATT&CK full coverage analysis
        max_gaps: Maximum gaps to return

    Returns:
        Prioritized list of coverage gaps to address
    """
    # Step 1: Build rule index
    index = RuleIndex()
    n = index.index_directory(rules_dir)
    logger.info(f"Indexed {n} existing rules for coverage baseline")

    analyzer = CoverageAnalyzer(index)
    all_gaps: list[CoverageGap] = []

    # Step 2: Scan MALPEDIA
    malpedia = MalpediaScanner(api_key=malpedia_key)
    malpedia_reports = malpedia.get_recent_families(limit=50)
    if malpedia_reports:
        malpedia_gaps = analyzer.analyze_reports(malpedia_reports)
        all_gaps.extend(malpedia_gaps)
        logger.info(f"MALPEDIA: {len(malpedia_gaps)} coverage gaps found")

    # Step 3: Scan MalwareBazaar
    if include_bazaar:
        bazaar = MalwareBazaarScanner()
        bazaar_reports = bazaar.get_recent_samples(hours=24, limit=100)
        if bazaar_reports:
            bazaar_gaps = analyzer.analyze_reports(bazaar_reports)
            all_gaps.extend(bazaar_gaps)
            logger.info(f"MalwareBazaar: {len(bazaar_gaps)} coverage gaps found")

    # Step 4: Full ATT&CK matrix coverage
    if include_attck:
        mitre = MitreAttckScanner()
        techniques = mitre.get_techniques()
        if techniques:
            attck_gaps = analyzer.analyze_attck_coverage(techniques, windows_only=True)
            all_gaps.extend(attck_gaps)
            logger.info(f"ATT&CK matrix: {len(attck_gaps)} uncovered techniques")

    # Deduplicate by technique ID and keep highest priority
    seen: dict[str, CoverageGap] = {}
    for gap in all_gaps:
        if gap.technique_id not in seen or gap.priority > seen[gap.technique_id].priority:
            seen[gap.technique_id] = gap

    final_gaps = sorted(seen.values(), key=lambda g: g.priority, reverse=True)[:max_gaps]
    logger.info(f"Final prioritized gaps: {len(final_gaps)}")
    return final_gaps


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _infer_namespace_from_attck(attck_ids: list[str]) -> Optional[str]:
    """Infer a capa namespace from ATT&CK technique IDs using tactic patterns."""
    TACTIC_NAMESPACE_MAP = {
        "T1543": "persistence/service",
        "T1547": "persistence/registry",
        "T1546": "persistence/registry",
        "T1053": "persistence/scheduled-tasks",
        "T1574": "persistence",
        "T1197": "defense-evasion/bits",
        "T1569": "execution/service",
        "T1059": "execution/command-line",
        "T1106": "execution",
        "T1055": "host-interaction/process/inject",
        "T1112": "host-interaction/registry",
        "T1082": "host-interaction/os/info",
        "T1071": "communication/http",
        "T1095": "communication/socket",
    }

    for tid in attck_ids:
        # Try full ID first (e.g., T1547.001), then base (e.g., T1547)
        if tid in TACTIC_NAMESPACE_MAP:
            return TACTIC_NAMESPACE_MAP[tid]
        base = tid.split(".")[0]
        if base in TACTIC_NAMESPACE_MAP:
            return TACTIC_NAMESPACE_MAP[base]

    return None
