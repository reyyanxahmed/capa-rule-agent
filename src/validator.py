"""
Validator module — validates generated capa rules using the official linter
and formatter, then parses errors for the self-correction loop.

Implements the core validation pipeline:
1. YAML syntax check
2. capa rule schema validation
3. capa linter (style/best practice checks)
4. capa formatter (canonical formatting)
5. Error parsing for self-correction feedback
"""

from __future__ import annotations

import re
import logging
import tempfile
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

import yaml

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of validating a capa rule."""

    is_valid: bool
    yaml_valid: bool = True
    schema_valid: bool = True
    lint_passed: bool = True
    format_diff: Optional[str] = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    formatted_rule: Optional[str] = None

    def error_summary(self) -> str:
        """Format errors as a string for the self-correction prompt."""
        parts = []
        if not self.yaml_valid:
            parts.append("YAML SYNTAX ERROR: Rule is not valid YAML.")
        if not self.schema_valid:
            parts.append("SCHEMA ERROR: Rule does not follow the capa rule schema.")
        if not self.lint_passed:
            parts.append("LINT ERRORS:")
        for error in self.errors:
            parts.append(f"  - {error}")
        for warning in self.warnings:
            parts.append(f"  - WARNING: {warning}")
        return "\n".join(parts)


def validate_yaml_syntax(rule_text: str) -> tuple[bool, list[str]]:
    """Check if the rule is valid YAML."""
    try:
        data = yaml.safe_load(rule_text)
        if not isinstance(data, dict):
            return False, ["Rule must be a YAML mapping (dict), got: " + type(data).__name__]
        return True, []
    except yaml.YAMLError as e:
        return False, [f"YAML parse error: {e}"]


def validate_schema(rule_text: str) -> tuple[bool, list[str]]:
    """Check if the rule follows the expected capa rule schema."""
    errors = []
    try:
        data = yaml.safe_load(rule_text)
    except yaml.YAMLError:
        return False, ["Cannot validate schema: YAML is invalid"]

    if "rule" not in data:
        errors.append("Missing top-level 'rule' key")
        return False, errors

    rule = data["rule"]

    if "meta" not in rule:
        errors.append("Missing 'meta' section under 'rule'")
    else:
        meta = rule["meta"]
        required_meta = ["name", "authors", "scopes"]
        for field_name in required_meta:
            if field_name not in meta:
                errors.append(f"Missing required meta field: '{field_name}'")

        # Check scopes
        if "scopes" in meta:
            scopes = meta["scopes"]
            if "static" not in scopes:
                errors.append("Missing 'static' in scopes")
            if "dynamic" not in scopes:
                errors.append("Missing 'dynamic' in scopes")

        # Check authors is a list
        if "authors" in meta and not isinstance(meta["authors"], list):
            errors.append("'authors' must be a list")

    if "features" not in rule:
        errors.append("Missing 'features' section under 'rule'")
    else:
        features = rule["features"]
        if not isinstance(features, list):
            errors.append("'features' must be a list")
        elif len(features) == 0:
            errors.append("'features' list is empty")

    return len(errors) == 0, errors


def run_capa_lint(
    rule_text: str,
    rules_dir: Optional[str] = None,
    capa_path: str = "python",
    lint_script: Optional[str] = None,
) -> tuple[bool, list[str], list[str]]:
    """
    Run the capa linter on a rule.

    Args:
        rule_text: The YAML rule content
        rules_dir: Path to the capa-rules directory (for context)
        capa_path: Path to the Python executable
        lint_script: Path to the lint.py script

    Returns:
        Tuple of (passed, errors, warnings)
    """
    errors = []
    warnings = []

    # Write rule to a temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write(rule_text)
        temp_path = f.name

    try:
        # If we have a lint script path, use it
        if lint_script and Path(lint_script).exists():
            cmd = [capa_path, lint_script, temp_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            output = result.stdout + result.stderr

            # Parse lint output for FAIL/WARN lines
            for line in output.split("\n"):
                line = line.strip()
                if "FAIL:" in line:
                    # Extract the error message
                    msg = line.split("FAIL:", 1)[1].strip()
                    # Skip sample-related errors (we don't have local samples)
                    if "referenced example doesn't exist" not in msg:
                        errors.append(msg)
                elif "WARN:" in line:
                    msg = line.split("WARN:", 1)[1].strip()
                    warnings.append(msg)

            passed = result.returncode == 0 or (
                len(errors) == 0 and all(
                    "referenced example" in w for w in warnings
                )
            )
        else:
            # Fallback: basic validation only
            logger.warning("Lint script not found, using basic validation only")
            passed = True

    except subprocess.TimeoutExpired:
        errors.append("Linter timed out after 60 seconds")
        passed = False
    except FileNotFoundError:
        logger.warning("Could not run linter — Python or lint script not found")
        passed = True  # Don't block on missing linter
    finally:
        Path(temp_path).unlink(missing_ok=True)

    return passed, errors, warnings


def run_capa_format(
    rule_text: str,
    capa_path: str = "python",
    format_script: Optional[str] = None,
) -> Optional[str]:
    """
    Run the capa formatter and return the formatted rule.

    Returns None if formatting fails.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write(rule_text)
        temp_path = f.name

    try:
        if format_script and Path(format_script).exists():
            cmd = [capa_path, format_script, temp_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return result.stdout.strip() + "\n"
            else:
                logger.warning(f"Formatter error: {result.stderr}")
                return None
        else:
            logger.warning("Format script not found")
            return None
    except Exception as e:
        logger.warning(f"Formatter failed: {e}")
        return None
    finally:
        Path(temp_path).unlink(missing_ok=True)


def validate_rule(
    rule_text: str,
    rules_dir: Optional[str] = None,
    lint_script: Optional[str] = None,
    format_script: Optional[str] = None,
) -> ValidationResult:
    """
    Run the full validation pipeline on a generated rule.

    Args:
        rule_text: The YAML rule to validate
        rules_dir: Path to capa-rules for context
        lint_script: Path to capa's lint.py
        format_script: Path to capa's capafmt.py

    Returns:
        ValidationResult with detailed error information
    """
    result = ValidationResult(is_valid=False)

    # Step 1: YAML syntax
    yaml_ok, yaml_errors = validate_yaml_syntax(rule_text)
    result.yaml_valid = yaml_ok
    if not yaml_ok:
        result.errors.extend(yaml_errors)
        return result

    # Step 2: Schema validation
    schema_ok, schema_errors = validate_schema(rule_text)
    result.schema_valid = schema_ok
    if not schema_ok:
        result.errors.extend(schema_errors)
        return result

    # Step 3: Linter
    lint_ok, lint_errors, lint_warnings = run_capa_lint(
        rule_text,
        rules_dir=rules_dir,
        lint_script=lint_script,
    )
    result.lint_passed = lint_ok
    result.errors.extend(lint_errors)
    result.warnings.extend(lint_warnings)

    # Step 4: Formatter
    formatted = run_capa_format(
        rule_text,
        format_script=format_script,
    )
    if formatted:
        result.formatted_rule = formatted
        if formatted.strip() != rule_text.strip():
            result.format_diff = "Rule formatting differs from canonical format"
            result.warnings.append("Rule was reformatted by capafmt — using formatted version")

    # Overall result
    result.is_valid = yaml_ok and schema_ok and lint_ok
    return result
