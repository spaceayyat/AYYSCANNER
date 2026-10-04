"""Dependency / third-party library scanner.

Parses common manifest/lockfile formats to extract package name + pinned
version, then looks each one up in the public OSV.dev database. This is a
read-only lookup: nothing is exercised or exploited.

OSV's batch endpoint returns only advisory IDs, so the details of each
advisory (summary, severity) are fetched separately (bounded by MAX_DETAIL_LOOKUPS).
A match on the exact pinned version is a Confirmed finding; a dependency
without a pinned version is only an Informational note, because it cannot be
audited at all.
"""

from __future__ import annotations

import json
import logging
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

import requests

from ayyscanner.models import Confidence, Finding, FindingStatus, OUTCOME_PARTIAL, ScanResult, Severity
from ayyscanner.web_scan.http import RateLimiter

logger = logging.getLogger("ayyscanner.dependencies")

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_API = "https://api.osv.dev/v1/vulns/{id}"
OSV_VULN_PAGE = "https://osv.dev/vulnerability/{id}"
MAX_DETAIL_LOOKUPS = 60


@dataclass
class Dependency:
    name: str
    version: Optional[str]
    ecosystem: str  # "PyPI", "npm"
    manifest_file: str


# --------------------------------------------------------------------------
# Manifest parsing
# --------------------------------------------------------------------------


def parse_requirements_txt(path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    pinned = re.compile(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+]+)")
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except OSError as exc:
        logger.warning("Could not read %s: %s", path, exc)
        return deps
    for line in lines:
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        match = pinned.match(line)
        if match:
            deps.append(Dependency(match.group(1), match.group(2), "PyPI", str(path)))
        else:
            name = re.split(r"[<>=~!\[; ]", line)[0].strip()  # unpinned: version unknown
            if name:
                deps.append(Dependency(name, None, "PyPI", str(path)))
    return deps


def parse_package_lock_json(path: Path) -> list[Dependency]:
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Could not parse %s: %s", path, exc)
        return []
    deps: list[Dependency] = []
    packages = data.get("packages") or data.get("dependencies") or {}
    for pkg_path, meta in packages.items():
        if not isinstance(meta, dict):
            continue
        name = pkg_path.split("node_modules/")[-1] if pkg_path else meta.get("name")
        version = meta.get("version")
        if name and version:
            deps.append(Dependency(name, version, "npm", str(path)))
    return deps


def parse_pyproject_toml(path: Path) -> list[Dependency]:
    """Best-effort: only picks up PEP 621 style `"name==x.y.z"` pins."""
    try:
        content = path.read_text(errors="ignore")
    except OSError as exc:
        logger.warning("Could not read %s: %s", path, exc)
        return []
    return [
        Dependency(m.group(1), m.group(2), "PyPI", str(path))
        for m in re.finditer(r'"([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+]+)"', content)
    ]


MANIFEST_PARSERS = {
    "requirements.txt": parse_requirements_txt,
    "package-lock.json": parse_package_lock_json,
    "pyproject.toml": parse_pyproject_toml,
}


def discover_manifests(project_dir: Path) -> list[Path]:
    return [project_dir / name for name in MANIFEST_PARSERS if (project_dir / name).exists()]


def collect_dependencies(project_dir: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    for manifest in discover_manifests(project_dir):
        deps.extend(MANIFEST_PARSERS[manifest.name](manifest))
    return deps


# --------------------------------------------------------------------------
# Severity: computed from the advisory itself, never guessed from digits
# --------------------------------------------------------------------------

_CVSS3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    """CVSS v3.1 'Roundup': smallest one-decimal number >= x (float-safe)."""
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> Optional[float]:
    """Base score for a CVSS v3.0/v3.1 vector string, or None if it is not one."""
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    try:
        m = dict(part.split(":", 1) for part in vector.split("/")[1:])
        scope_changed = m["S"] == "C"
        pr_weights = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}
        iss = 1 - (1 - _CVSS3_WEIGHTS["C"][m["C"]]) * (1 - _CVSS3_WEIGHTS["I"][m["I"]]) * (1 - _CVSS3_WEIGHTS["A"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        exploitability = 8.22 * _CVSS3_WEIGHTS["AV"][m["AV"]] * _CVSS3_WEIGHTS["AC"][m["AC"]] * pr_weights[m["PR"]] * _CVSS3_WEIGHTS["UI"][m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    return _roundup(min((1.08 if scope_changed else 1.0) * (impact + exploitability), 10.0))


def _severity_from_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW if score > 0 else Severity.INFO


_LABELS = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


def severity_from_osv(vuln: dict[str, Any]) -> tuple[Severity, str]:
    """Return (severity, how it was determined). Falls back to Medium, and says so."""
    label = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    if label in _LABELS:
        return _LABELS[label], f"advisory severity label '{label}'"
    for entry in vuln.get("severity") or []:
        raw = str(entry.get("score", "")).strip()
        score = cvss3_base_score(raw)
        if score is None:
            try:
                score = float(raw)
            except ValueError:
                continue
        return _severity_from_score(score), f"CVSS score {score:g}"
    return Severity.MEDIUM, "not provided by OSV; Medium assumed"


# --------------------------------------------------------------------------
# OSV lookups
# --------------------------------------------------------------------------


def query_osv(deps: list[Dependency], session: requests.Session, limiter: RateLimiter, timeout: float) -> dict[str, list[str]]:
    """Batch lookup. Returns {'name@version': [advisory ids]}. Raises requests.RequestException."""
    queryable = [d for d in deps if d.version]
    if not queryable:
        return {}
    queries = [{"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version} for d in queryable]
    limiter.acquire()
    resp = session.post(OSV_BATCH_URL, json={"queries": queries}, timeout=timeout)
    resp.raise_for_status()
    found: dict[str, list[str]] = {}
    for dep, entry in zip(queryable, resp.json().get("results", [])):
        ids = [v["id"] for v in entry.get("vulns", []) if "id" in v]
        if ids:
            found[f"{dep.name}@{dep.version}"] = ids
    return found


def fetch_vuln_details(vuln_id: str, session: requests.Session, limiter: RateLimiter, timeout: float) -> Optional[dict[str, Any]]:
    limiter.acquire()
    try:
        resp = session.get(OSV_VULN_API.format(id=vuln_id), timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.warning("Could not fetch OSV details for %s: %s", vuln_id, exc)
        return None


def _finding(fid: str, title: str, severity: Severity, confidence: Confidence, description: str, evidence: str,
             impact: str, remediation: str, target: str, references: Optional[list[str]] = None,
             status: Optional[FindingStatus] = None, detection: str = "") -> Finding:
    return Finding(id=fid, title=title, category="dependencies", severity=severity, confidence=confidence,
                   description=description, evidence=evidence, impact=impact, remediation=remediation,
                   references=references or [], target=target, detection_method=detection, status=status)


def run_dependency_scan(project_dir: str, timeout: float = 10.0, rate_limit: float = 5.0, offline: bool = False,
                        session: Optional[requests.Session] = None,
                        progress_cb: Optional[Callable[[int, str, str], None]] = None) -> ScanResult:
    def report(percent: int, stage: str, message: str) -> None:
        if progress_cb:
            progress_cb(percent, stage, message)

    logger.info("Starting dependency scan for %s", project_dir)
    report(5, "manifests", "Reading dependency files …")
    path = Path(project_dir)
    result = ScanResult(scan_type="dependencies", target=str(path))

    def finish() -> ScanResult:
        result.mark_finished()
        return result

    if not path.is_dir():
        result.errors.append(f"Project directory not found: {project_dir}")
        result.outcome = "failed"
        return finish()
    manifests = discover_manifests(path)
    if not manifests:
        result.errors.append("No recognized dependency manifest files found (looked for requirements.txt, package-lock.json, pyproject.toml).")
        result.outcome = "failed"
        return finish()

    deps = collect_dependencies(path)
    result.metadata.update(manifests_found=[str(m) for m in manifests], dependencies_found=len(deps))
    pinned = [d for d in deps if d.version]
    result.metadata["dependency_summary"] = {"total": len(deps), "checked": len(pinned), "vulnerable": 0,
                                             "clean": 0, "osv_checked": False}
    checks = [{"name": "Dependency files read", "status": "ran", "note": f"{len(manifests)} file(s), {len(deps)} package(s)", "domain": "security", "issues": 0}]
    result.metadata["checks"] = checks

    for dep in (d for d in deps if not d.version):
        result.add(_finding(
            f"DEP-UNRESOLVED-{dep.name}", f"Could not determine pinned version for '{dep.name}'", Severity.INFO, Confidence.LOW,
            "Dependency is declared without a pinned/locked version.", f"manifest={dep.manifest_file}",
            "This dependency cannot be checked against vulnerability databases without a version.",
            "Pin an exact version so it can be reliably audited and reproduced.", str(path),
            detection="Manifest parsing found no exact version pin (==)."))

    if offline:
        checks.append({"name": "OSV.dev vulnerability lookup", "status": "skipped", "note": "offline mode", "domain": "security", "issues": 0})
        result.errors.append("Offline mode: the OSV.dev vulnerability lookup was skipped, so known vulnerabilities were NOT checked.")
        result.outcome = OUTCOME_PARTIAL
        return finish()

    session = session or requests.Session()
    limiter = RateLimiter(rate_limit)
    report(25, "osv", f"Checking {len(pinned)} package(s) against OSV.dev …")
    try:
        matches = query_osv(deps, session, limiter, timeout)
    except (requests.RequestException, ValueError) as exc:
        logger.warning("OSV.dev query failed: %s", exc)
        checks.append({"name": "OSV.dev vulnerability lookup", "status": "failed", "note": type(exc).__name__, "domain": "security", "issues": 0})
        result.errors.append(f"OSV.dev could not be reached ({type(exc).__name__}). Dependency vulnerability results may be unavailable: known vulnerabilities were NOT checked. Check your internet connection and try again.")
        result.outcome = OUTCOME_PARTIAL
        return finish()

    report(60, "details", "Reading vulnerability details …")
    vulnerable = sum(1 for ids in matches.values() if ids)
    result.metadata["dependency_summary"].update(osv_checked=True, vulnerable=vulnerable, clean=max(len(pinned) - vulnerable, 0))
    checks.append({"name": "OSV.dev vulnerability lookup", "status": "ran", "note": "", "domain": "security", "issues": vulnerable})
    details_cache: dict[str, Optional[dict[str, Any]]] = {}
    for key, ids in matches.items():
        name, version = key.rsplit("@", 1)
        for vuln_id in ids:
            if vuln_id not in details_cache:
                details_cache[vuln_id] = fetch_vuln_details(vuln_id, session, limiter, timeout) if len(details_cache) < MAX_DETAIL_LOOKUPS else None
            detail = details_cache[vuln_id] or {}
            severity, basis = severity_from_osv(detail) if detail else (Severity.MEDIUM, "advisory details unavailable; Medium assumed")
            summary = detail.get("summary") or (detail.get("details") or "")[:300] or "No summary available (see the advisory)."
            result.add(_finding(
                f"DEP-VULN-{name}-{vuln_id}", f"Known vulnerability in {name}=={version}: {vuln_id}", severity, Confidence.HIGH,
                summary, f"OSV ID {vuln_id} matches {name}=={version}. Severity basis: {basis}.",
                "This dependency version has a publicly documented vulnerability. Whether it is reachable in your code needs review.",
                f"Upgrade '{name}' to a patched version listed in the advisory.", str(path),
                references=[OSV_VULN_PAGE.format(id=vuln_id)], status=FindingStatus.CONFIRMED,
                detection="Exact name and pinned version were looked up in the OSV.dev vulnerability database."))

    report(95, "score", "Calculating the score …")
    logger.info("Dependency scan complete: %d findings", len(result.findings))
    return finish()
