"""Overall security score (0-100), calculated only from a scan's actual findings.

The score is a pure function of the findings (and, for the coverage note, the list of checks
that ran): the same findings always give the same score. No randomness, no clock, no network.

How it works
------------
Start at 100 and subtract a penalty for every *security* finding:

    penalty = SEVERITY_POINTS[severity] x STATUS_WEIGHT[status] x repeat multiplier

* Severity points: Critical 30, High 18, Medium 8, Low 3, Informational 0.
* Status weight: a Confirmed finding counts in full, a Potential one (indicators only) counts half,
  an Informational one counts nothing.
* Repeats: the same issue found in several places (for example three cookies without HttpOnly)
  adds 25% per extra instance, up to double the single-instance penalty, so one noisy rule
  cannot sink the score on its own.

Two guard rails stop many small things from hiding one big thing:

* a Confirmed Critical finding caps the score at 39;
* a Confirmed High finding caps the score at 74.

Site-quality notes (SEO, link health, page facts) are never part of the security score.
A scan that failed outright has no score. A scan that stopped early is scored on the checks that
ran and is flagged as partial. A score is *not* a proof of security: it only measures what
this scanner looked for.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from ayyscanner.models import Finding, FindingStatus, Severity

SCORE_VERSION = 1

SEVERITY_POINTS = {
    Severity.CRITICAL: 30.0,
    Severity.HIGH: 18.0,
    Severity.MEDIUM: 8.0,
    Severity.LOW: 3.0,
    Severity.INFO: 0.0,
}
STATUS_WEIGHT = {
    FindingStatus.CONFIRMED: 1.0,
    FindingStatus.POTENTIAL: 0.5,
    FindingStatus.INFORMATIONAL: 0.0,
}
REPEAT_STEP = 0.25  # each extra instance of the same finding id adds this fraction ...
REPEAT_MAX = 2.0  # ... up to this multiple of the single-instance penalty

# (severity, status) -> highest score allowed while such a finding exists
CAPS = (
    (Severity.CRITICAL, 39, "a confirmed Critical finding"),
    (Severity.HIGH, 74, "a confirmed High finding"),
)

# (minimum score, key, label, one-line meaning). Keys are used as CSS classes.
BANDS = (
    (90, "excellent", "Excellent", "No significant weaknesses were found by the checks that ran."),
    (75, "good", "Good", "Only minor weaknesses were found. Fix them when convenient."),
    (50, "fair", "Needs improvement", "Several weaknesses were found. Plan fixes soon."),
    (25, "poor", "Poor", "Serious weaknesses were found. Fix them promptly."),
    (0, "critical", "Critical", "Severe weaknesses were found. Fix these first."),
)

MAX_FACTORS = 12


def band_for(score: int) -> tuple[str, str, str]:
    for minimum, key, label, meaning in BANDS:
        if score >= minimum:
            return key, label, meaning
    return BANDS[-1][1:]  # pragma: no cover - score is clamped to 0..100


def _coverage(checks: Iterable[dict[str, Any]]) -> dict[str, int]:
    ran = skipped = failed = 0
    for c in checks:
        state = c.get("status")
        if state == "ran":
            ran += 1
        elif state == "failed":
            failed += 1
        else:
            skipped += 1
    return {"ran": ran, "skipped": skipped, "failed": failed, "total": ran + skipped + failed}


def compute_score(findings: Iterable[Finding], outcome: str = "complete",
                  checks: Optional[Iterable[dict[str, Any]]] = None) -> dict[str, Any]:
    """Return the score and everything that explains it (JSON-serializable)."""
    security = [f for f in findings if f.domain == "security"]
    checks = list(checks or [])
    coverage = _coverage(checks)
    base: dict[str, Any] = {
        "version": SCORE_VERSION,
        "scale": {"min": 0, "max": 100},
        "coverage": coverage,
        "method": ("Start at 100. Each security finding subtracts points by severity (Critical 30, High 18, Medium 8, "
                   "Low 3), counted in full if Confirmed and half if Potential. Repeats of the same issue add 25% each "
                   "(up to double). A confirmed Critical finding caps the score at 39, a confirmed High at 74. "
                   "Informational notes and SEO/link-quality notes never lower it."),
        "bands": [{"min": m, "max": (100 if i == 0 else BANDS[i - 1][0] - 1), "key": k, "label": lbl, "meaning": mean}
                  for i, (m, k, lbl, mean) in enumerate(BANDS)],
    }
    # A dependency scan whose vulnerability lookup did not run has no data to judge: scoring it would
    # report a flattering 100 for packages nobody checked.
    lookup_missing = any(c.get("name") == "OSV.dev vulnerability lookup" and c.get("status") != "ran" for c in (checks or []))
    if outcome == "failed" or lookup_missing:
        meaning = ("The scan failed, so there is nothing to score." if outcome == "failed" else
                   "The OSV.dev vulnerability lookup did not run, so the packages were not checked and there is nothing to score.")
        return {**base, "score": None, "rated": False, "partial": False, "band": "unrated", "label": "Not rated",
                "meaning": meaning, "total_penalty": 0.0,
                "caps_applied": [], "factors": [], "factors_total": 0, "finding_count": 0}

    # Group by (rule id, severity, status). The repeat multiplier depends on how many instances of one
    # rule id were found, whatever their status, so it is computed per rule id.
    per_rule: dict[str, int] = {}
    groups: dict[tuple[str, Severity, FindingStatus], list[Finding]] = {}
    for f in security:
        per_rule[f.id] = per_rule.get(f.id, 0) + 1
        groups.setdefault((f.id, f.severity, f.status or FindingStatus.CONFIRMED), []).append(f)

    factors = []
    for (fid, sev, status), items in groups.items():
        multiplier = min(1.0 + REPEAT_STEP * (per_rule[fid] - 1), REPEAT_MAX)
        penalty = SEVERITY_POINTS[sev] * STATUS_WEIGHT[status] * len(items) / per_rule[fid] * multiplier
        factors.append({
            "id": fid, "title": items[0].title, "severity": sev.value, "status": status.value,
            "count": len(items), "penalty": round(penalty, 2),
        })
    factors = [x for x in factors if x["penalty"] > 0]  # informational notes cost nothing, so they are not "factors"
    factors.sort(key=lambda x: (-x["penalty"], -Severity(x["severity"]).rank, x["id"], x["status"]))

    total_penalty = sum(x["penalty"] for x in factors)
    score = max(0, min(100, int(round(100 - total_penalty))))
    caps_applied = []
    for sev, cap, why in CAPS:
        if any(f.severity == sev and f.status == FindingStatus.CONFIRMED for f in security) and score > cap:
            score = cap
            caps_applied.append({"cap": cap, "reason": why[0].upper() + why[1:] + f" limits the score to {cap}."})
    key, label, meaning = band_for(score)
    return {
        **base, "score": score, "rated": True, "partial": outcome != "complete", "band": key, "label": label,
        "meaning": meaning, "total_penalty": round(total_penalty, 2), "caps_applied": caps_applied,
        "factors": factors[:MAX_FACTORS], "factors_total": len(factors),
        "finding_count": len(security),
    }


def passed_checks(findings: Iterable[Finding], outcome: str, checks: Optional[Iterable[dict[str, Any]]],
                  metadata: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """What went right: security check groups that ran and found nothing (web and system scans), or
    pinned packages with no known vulnerability (dependency scans). Only real results are counted."""
    metadata = metadata or {}
    deps = metadata.get("dependency_summary")
    if isinstance(deps, dict):
        total = int(deps.get("checked", 0))
        return {"count": int(deps.get("clean", 0)), "total": total, "unit": "packages", "items": [],
                "note": ("Pinned packages with no known vulnerability in OSV.dev." if deps.get("osv_checked")
                         else "The OSV.dev lookup did not run, so no package could be confirmed clean.")}
    if outcome == "failed":
        return {"count": 0, "total": 0, "unit": "checks", "items": [], "note": "The scan failed."}
    ran = [c for c in (checks or []) if c.get("status") == "ran" and c.get("domain", "security") == "security"]
    passed = [c["name"] for c in ran if c.get("issues", 1) == 0]
    return {"count": len(passed), "total": len(ran), "unit": "checks", "items": passed,
            "note": "Check groups that ran and found nothing to report."}
