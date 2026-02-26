"""
Test Runner module — runs capa with generated rules against malware samples
to verify that rules actually detect the intended capabilities.

This is the critical "ground truth" validation step: a rule might pass
schema checks and linting, but does it actually match on real samples?

Supports:
1. **Local samples** — run capa against a sample on disk
2. **Sample download** — fetch samples from MalwareBazaar or VirusTotal
3. **Result parsing** — extract match addresses and function names
4. **Examples field** — generate the `examples:` metadata field from test results
"""

from __future__ import annotations

import os
import json
import logging
import tempfile
import subprocess
import hashlib
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class TestResult:
    """Result of running capa with a rule against a sample."""
    matched: bool = False
    match_count: int = 0
    matched_addresses: list[str] = field(default_factory=list)
    matched_functions: list[str] = field(default_factory=list)
    sample_hash: str = ""
    sample_path: Optional[str] = None
    capa_version: Optional[str] = None
    error: Optional[str] = None
    raw_output: Optional[str] = None

    def to_examples_field(self) -> list[str]:
        """
        Generate the capa rule `examples:` field from match results.

        Format: <hash>:<address>
        """
        examples = []
        for addr in self.matched_addresses[:3]:
            examples.append(f"{self.sample_hash}:{addr}")
        return examples

    def summary(self) -> str:
        if self.error:
            return f"ERROR: {self.error}"
        if self.matched:
            return (
                f"MATCH: {self.match_count} match(es) at "
                f"{', '.join(self.matched_addresses[:3])}"
            )
        return "NO MATCH: Rule did not fire on this sample"


@dataclass
class SampleInfo:
    """Information about a malware sample."""
    sha256: str
    local_path: Optional[str] = None
    file_size: Optional[int] = None
    file_type: Optional[str] = None
    source: Optional[str] = None  # "local", "malwarebazaar", "virustotal"


# ---------------------------------------------------------------------------
# Sample acquisition
# ---------------------------------------------------------------------------

class SampleManager:
    """
    Manages sample acquisition from local storage or remote sources.

    Security note: Downloaded samples are stored in a designated quarantine
    directory with restricted permissions. The agent never executes samples —
    it only passes them to capa for static analysis.
    """

    def __init__(self, quarantine_dir: Optional[str] = None):
        self.quarantine_dir = Path(quarantine_dir or tempfile.mkdtemp(prefix="capa-samples-"))
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    def get_sample(self, sha256: str, local_path: Optional[str] = None) -> Optional[SampleInfo]:
        """
        Get a sample by hash, checking local storage first then remote sources.

        Args:
            sha256: SHA256 hash of the sample
            local_path: Optional known local path

        Returns:
            SampleInfo if found, None otherwise
        """
        # Check local path first
        if local_path and Path(local_path).exists():
            return SampleInfo(
                sha256=sha256,
                local_path=local_path,
                file_size=Path(local_path).stat().st_size,
                source="local",
            )

        # Check quarantine directory
        quarantine_path = self.quarantine_dir / sha256
        if quarantine_path.exists():
            return SampleInfo(
                sha256=sha256,
                local_path=str(quarantine_path),
                file_size=quarantine_path.stat().st_size,
                source="local",
            )

        # Try MalwareBazaar download
        sample = self._download_from_malwarebazaar(sha256)
        if sample:
            return sample

        logger.warning(f"Sample {sha256[:16]}... not available from any source")
        return None

    def _download_from_malwarebazaar(self, sha256: str) -> Optional[SampleInfo]:
        """
        Download a sample from MalwareBazaar (abuse.ch).

        Note: MalwareBazaar returns samples in a password-protected ZIP (password: "infected").
        We extract the sample and store it in the quarantine directory.
        """
        url = "https://mb-api.abuse.ch/api/v1/"
        try:
            resp = requests.post(
                url,
                data={"query": "get_file", "sha256_hash": sha256},
                timeout=60,
            )

            if resp.status_code == 200 and resp.headers.get("Content-Type", "").startswith("application/"):
                # Save the ZIP
                zip_path = self.quarantine_dir / f"{sha256}.zip"
                zip_path.write_bytes(resp.content)

                # Extract (requires 'unzip' with password)
                sample_path = self.quarantine_dir / sha256
                try:
                    subprocess.run(
                        ["unzip", "-P", "infected", "-o", str(zip_path), "-d", str(self.quarantine_dir)],
                        capture_output=True,
                        timeout=30,
                    )
                    # Find the extracted file
                    for f in self.quarantine_dir.iterdir():
                        if f.name != f"{sha256}.zip" and f.is_file():
                            # Verify hash
                            actual_hash = hashlib.sha256(f.read_bytes()).hexdigest()
                            if actual_hash.lower() == sha256.lower():
                                f.rename(sample_path)
                                zip_path.unlink(missing_ok=True)
                                return SampleInfo(
                                    sha256=sha256,
                                    local_path=str(sample_path),
                                    file_size=sample_path.stat().st_size,
                                    source="malwarebazaar",
                                )
                except subprocess.TimeoutExpired:
                    logger.warning("Unzip timed out")
                finally:
                    zip_path.unlink(missing_ok=True)

            else:
                logger.debug(f"MalwareBazaar: sample not found ({resp.status_code})")

        except requests.RequestException as e:
            logger.warning(f"MalwareBazaar download error: {e}")

        return None

    def verify_hash(self, file_path: str, expected_sha256: str) -> bool:
        """Verify a file's SHA256 hash matches the expected value."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest().lower() == expected_sha256.lower()


# ---------------------------------------------------------------------------
# capa test execution
# ---------------------------------------------------------------------------

def run_capa_on_sample(
    rule_text: str,
    sample_hash: str,
    sample_path: Optional[str] = None,
    capa_path: str = "capa",
    timeout: int = 120,
) -> TestResult:
    """
    Run capa with a single rule against a malware sample.

    This is the ground-truth validation: does the rule actually detect
    the intended capability in the sample?

    Args:
        rule_text: The YAML rule to test
        sample_hash: SHA256 hash of the sample
        sample_path: Local path to the sample (or None to attempt download)
        capa_path: Path to the capa executable
        timeout: Execution timeout in seconds

    Returns:
        TestResult with match details
    """
    result = TestResult(sample_hash=sample_hash)

    # Get sample
    manager = SampleManager()
    sample = manager.get_sample(sample_hash, sample_path)

    if not sample or not sample.local_path:
        result.error = f"Sample {sample_hash[:16]}... not available"
        return result

    result.sample_path = sample.local_path

    # Write rule to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write(rule_text)
        rule_path = f.name

    try:
        # Run capa with JSON output for structured parsing
        cmd = [
            capa_path,
            "--rules", rule_path,
            "--json",
            sample.local_path,
        ]

        logger.info(f"Running: capa --rules {rule_path} --json {sample.local_path}")

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        result.raw_output = proc.stdout[:5000]

        if proc.returncode == 0:
            # Parse JSON output
            try:
                data = json.loads(proc.stdout)
                result.capa_version = data.get("meta", {}).get("version", "unknown")

                # Check for matches
                rules_matched = data.get("rules", {})
                if rules_matched:
                    result.matched = True
                    for rule_name, rule_data in rules_matched.items():
                        matches = rule_data.get("matches", {})
                        result.match_count += len(matches)
                        for addr, match_info in matches.items():
                            result.matched_addresses.append(str(addr))
                else:
                    result.matched = False

            except json.JSONDecodeError as e:
                # capa might not have JSON output in all versions
                result.error = f"Failed to parse capa JSON output: {e}"
                # Fall back to checking exit code
                result.matched = proc.returncode == 0
        else:
            # Non-zero exit could mean no matches or error
            if "no capabilities found" in proc.stderr.lower():
                result.matched = False
            else:
                result.error = f"capa exited with code {proc.returncode}: {proc.stderr[:500]}"

    except subprocess.TimeoutExpired:
        result.error = f"capa timed out after {timeout}s"
    except FileNotFoundError:
        result.error = f"capa executable not found at: {capa_path}"
    finally:
        Path(rule_path).unlink(missing_ok=True)

    return result


def run_capa_tests(
    rule_text: str,
    sample_hashes: list[str],
    sample_dir: Optional[str] = None,
    capa_path: str = "capa",
) -> list[TestResult]:
    """
    Run capa with a rule against multiple samples.

    Args:
        rule_text: The YAML rule to test
        sample_hashes: List of SHA256 hashes
        sample_dir: Optional directory to search for local samples
        capa_path: Path to capa executable

    Returns:
        List of TestResult objects
    """
    results = []
    for sha256 in sample_hashes:
        # Check if sample exists in sample_dir
        local_path = None
        if sample_dir:
            candidate = Path(sample_dir) / sha256
            if candidate.exists():
                local_path = str(candidate)

        result = run_capa_on_sample(
            rule_text,
            sample_hash=sha256,
            sample_path=local_path,
            capa_path=capa_path,
        )
        results.append(result)
        logger.info(f"  {sha256[:16]}... → {result.summary()}")

    matched_count = sum(1 for r in results if r.matched)
    logger.info(f"Test results: {matched_count}/{len(results)} samples matched")
    return results


def inject_examples_into_rule(rule_text: str, test_results: list[TestResult]) -> str:
    """
    Add the `examples:` field to a rule based on test results.

    This populates the rule's meta.examples field with actual sample:address
    pairs, which is a quality indicator for capa rules.

    Args:
        rule_text: Original rule YAML text
        test_results: List of test results with match addresses

    Returns:
        Updated rule text with examples field
    """
    examples = []
    for result in test_results:
        if result.matched:
            examples.extend(result.to_examples_field())

    if not examples:
        return rule_text

    # Build examples YAML block
    examples_block = "    examples:\n"
    for ex in examples[:5]:  # Limit to 5 examples
        examples_block += f"      - {ex}\n"

    # Insert after att&ck or references section, before features
    import re
    # Find the right insertion point
    insert_pattern = re.compile(
        r"((?:    att&ck:.*?(?:\n      - .*)*\n)|(?:    references:.*?(?:\n      - .*)*\n))",
        re.DOTALL,
    )

    matches = list(insert_pattern.finditer(rule_text))
    if matches:
        last_match = matches[-1]
        insert_pos = last_match.end()
        return rule_text[:insert_pos] + examples_block + rule_text[insert_pos:]
    else:
        # Fallback: insert before features
        features_pos = rule_text.find("  features:")
        if features_pos > 0:
            return rule_text[:features_pos] + examples_block + rule_text[features_pos:]

    return rule_text
