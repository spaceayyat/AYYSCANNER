"""Security baseline rule engine.

A baseline is a small JSON document describing organizational security
expectations (e.g. "HTTPS required", "SSH must not be exposed publicly").
Each rule is evaluated against a `ScanResult` by looking for the presence
(or absence) of specific finding IDs / patterns, and produces PASS, WARN,
or FAIL.

The engine is intentionally simple and declarative so that new rules can be
added by editing a JSON file, not by writing new Python.
"""

from __future__ import annotations

import json
from typing import Any

from ayyscanner.models import BaselineResult, BaselineStatus, ScanResult
import logging

logger = logging.getLogger("ayyscanner.baseline")


def load_baseline(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _finding_ids(result: ScanResult) -> set[str]:
    return {f.id for f in result.findings}


def _has_any_finding_matching(result: ScanResult, id_prefix: str) -> bool:
    return any(f.id.startswith(id_prefix) for f in result.findings)


def evaluate_rule(rule: dict[str, Any], result: ScanResult) -> BaselineResult:
    """Evaluate one baseline rule.

    Supported rule "type" values:
      - "forbid_finding_prefix": FAIL if any finding ID starts with the given
        prefix (e.g. externally-exposed SSH/Telnet/RDP findings).
      - "require_absence_of_id": FAIL if the exact finding ID is present
        (e.g. WEB-TLS-NOHTTPS meaning HTTPS is required but missing).
      - "require_no_high_or_above_in_category": WARN/FAIL if any High or
        Critical finding exists in a given category.
    """
    rule_id = rule["id"]
    description = rule["description"]
    rule_type = rule["type"]
    fail_status = BaselineStatus(rule.get("fail_status", "FAIL"))

    if rule_type == "forbid_finding_prefix":
        prefix = rule["prefix"]
        if _has_any_finding_matching(result, prefix):
            matches = [f.title for f in result.findings if f.id.startswith(prefix)]
            return BaselineResult(
                rule_id=rule_id,
                description=description,
                status=fail_status,
                detail=f"Matched: {'; '.join(matches)}",
            )
        return BaselineResult(
            rule_id=rule_id, description=description, status=BaselineStatus.PASS, detail="No matching findings."
        )

    if rule_type == "require_absence_of_id":
        target_id = rule["finding_id"]
        if target_id in _finding_ids(result):
            return BaselineResult(
                rule_id=rule_id,
                description=description,
                status=fail_status,
                detail=f"Required condition failed: finding {target_id} is present.",
            )
        return BaselineResult(
            rule_id=rule_id,
            description=description,
            status=BaselineStatus.PASS,
            detail=f"Finding {target_id} not present.",
        )

    if rule_type == "require_no_high_or_above_in_category":
        category = rule["category"]
        offenders = [
            f for f in result.findings
            if f.category == category and f.severity.rank >= 3  # HIGH or CRITICAL
        ]
        if offenders:
            return BaselineResult(
                rule_id=rule_id,
                description=description,
                status=fail_status,
                detail=f"{len(offenders)} High/Critical finding(s) in category '{category}'.",
            )
        return BaselineResult(
            rule_id=rule_id,
            description=description,
            status=BaselineStatus.PASS,
            detail=f"No High/Critical findings in category '{category}'.",
        )

    logger.warning("Unknown baseline rule type: %s", rule_type)
    return BaselineResult(
        rule_id=rule_id,
        description=description,
        status=BaselineStatus.NOT_APPLICABLE,
        detail=f"Unknown rule type '{rule_type}'.",
    )


def evaluate_baseline(baseline: dict[str, Any], result: ScanResult) -> None:
    """Evaluate every rule in the baseline and attach results to `result`."""
    for rule in baseline.get("rules", []):
        try:
            result.baseline_results.append(evaluate_rule(rule, result))
        except KeyError as exc:
            logger.error("Malformed baseline rule %s: missing %s", rule.get("id"), exc)
