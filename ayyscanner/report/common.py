"""Data preparation shared by every report format, so HTML, Markdown, PDF,
CSV and JSON can never disagree about what a scan found."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ayyscanner.models import FindingStatus, ScanResult, Severity

ASSETS = Path(__file__).resolve().parent.parent / "assets"
SEVERITY_ORDER = [s.value for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)]
STATUS_ORDER = [s.value for s in FindingStatus]

STATUS_HELP = {
    "Confirmed": "The scanner directly observed the problem (for example a header is absent from the response, or a cookie has no Secure flag).",
    "Potential": "The scanner saw indicators, but whether it is a real vulnerability depends on context it cannot see. Verify manually.",
    "Informational": "An observation with no direct security impact on its own, provided for completeness.",
}

OUTCOME_LABELS = {
    "complete": "Completed",
    "partial": "Partial: the scan was stopped or a stage failed, so results are incomplete",
    "failed": "Failed: nothing could be scanned",
}


def read_asset(name: str) -> str:
    return (ASSETS / name).read_text(encoding="utf-8")


def safe_http_url(value: str) -> str | None:
    """Return `value` only if it is a plain http(s) URL. Anything else
    (javascript:, data:, file: ...) must never become a clickable link."""
    try:
        parts = urlsplit(value.strip())
    except ValueError:
        return None
    return value.strip() if parts.scheme in ("http", "https") and parts.netloc else None


def csv_safe(value: Any) -> str:
    """Neutralize spreadsheet formula injection: cells starting with = + - @ or
    a control character are prefixed so Excel/Sheets treat them as text."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def fmt_time(iso: str | None) -> str:
    if not iso:
        return "-"
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return iso


def filename_for(result: ScanResult, ext: str) -> str:
    host = re.sub(r"[^A-Za-z0-9.-]+", "-", urlsplit(result.target).hostname or result.scan_type or "scan").strip("-.") or "scan"
    stamp = (result.started_at or "")[:16].replace("-", "").replace(":", "").replace("T", "-")
    return f"ayyscanner-{host}-{stamp}.{ext}"


def key_observations(result: ScanResult) -> list[str]:
    """Plain-language facts taken from what was actually measured. Nothing is
    stated unless the scan produced the data for it."""
    tech: dict[str, Any] = result.metadata.get("technical", {})
    out: list[str] = []
    if "is_https" in tech:
        out.append("The page was served over HTTPS." if tech["is_https"] else "The page was served over plain HTTP (no encryption).")
    headers = tech.get("security_headers")
    if headers:
        have = sum(1 for v in headers.values() if v)
        out.append(f"{have} of {len(headers)} recommended security headers are present.")
    tls = tech.get("tls")
    if tls and tls.get("days_remaining") is not None:
        out.append(f"The TLS certificate is valid and expires in {tls['days_remaining']} day(s).")
    elif tls and tls.get("verify_error"):
        out.append(f"The TLS certificate could not be verified: {tls['verify_error']}.")
    cookies = tech.get("cookies")
    if cookies:
        weak = sum(1 for c in cookies if not c.get("httponly") or not c.get("secure") or c.get("samesite") is None)
        out.append(f"{len(cookies)} cookie(s) were set; {weak} lack at least one of Secure, HttpOnly or SameSite.")
    if tech.get("exposed_files"):
        out.append("Sensitive files are publicly readable: " + ", ".join(tech["exposed_files"]) + ".")
    return out


def score_headline(score: dict[str, Any]) -> str:
    """One line such as '82/100 - Good', or 'Not rated'."""
    return f"{score['score']}/100 - {score['label']}" if score.get("rated") else str(score.get("label", "Not rated"))


def score_notes(score: dict[str, Any]) -> list[str]:
    """Caveats that belong next to the number, in plain language."""
    notes: list[str] = []
    cov = score.get("coverage", {})
    if score.get("partial") and score.get("rated"):
        notes.append("The scan stopped early, so the score only reflects the checks that ran.")
    if cov.get("failed"):
        notes.append(f"{cov['failed']} check(s) failed to run and could not count toward the score.")
    notes += [c["reason"] for c in score.get("caps_applied", [])]
    if score.get("rated") and score.get("score") == 100:
        notes.append("100 means the checks that ran found nothing to deduct; it does not prove the site is secure.")
    return notes


def factor_text(f: dict[str, Any]) -> str:
    times = f" x{f['count']}" if f["count"] > 1 else ""
    return f"-{f['penalty']:g}  {f['title']}{times} ({f['severity']}, {f['status'].lower()})"
