"""Core data models shared by every scanner and every report format.

Every scanner produces `Finding` objects inside a `ScanResult`; every report
renderer consumes a `ScanResult`. Keeping this contract narrow is what lets a
new scanner or a new report format be added without touching the other side.

Findings carry two independent judgements, on purpose:

* `severity`   - how bad the issue is *if it is real* (Critical ... Informational).
* `status`     - how sure the scanner is that it is real:
    Confirmed      the scanner directly observed the problem (e.g. a header is
                   absent from the response, a cookie has no Secure flag).
    Potential      the scanner saw indicators, but whether it is a genuine
                   vulnerability depends on context it cannot see.
    Informational  an observation with no direct security impact on its own.

On top of the per-finding judgements, `ScanResult.score()` derives one overall 0-100 security
score from the findings (see ayyscanner/scoring.py for exactly how).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from ayyscanner import __version__


class Severity(str, Enum):
    INFO = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class FindingStatus(str, Enum):
    CONFIRMED = "Confirmed"
    POTENTIAL = "Potential"
    INFORMATIONAL = "Informational"

    @property
    def order(self) -> int:
        return list(FindingStatus).index(self)


class BaselineStatus(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"


# Categories whose findings are about site quality (SEO, link health, page
# facts) rather than security. They are reported, but never mixed into the
# headline security severity counts.
QUALITY_CATEGORIES = frozenset({"seo", "links", "page"})

# Values of ScanResult.outcome.
OUTCOME_COMPLETE = "complete"
OUTCOME_PARTIAL = "partial"  # stopped early or a stage failed; results are incomplete
OUTCOME_FAILED = "failed"  # nothing could be scanned


@dataclass
class Finding:
    """A single, self-contained observation."""

    id: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    description: str
    evidence: str
    impact: str
    remediation: str
    references: list[str] = field(default_factory=list)
    target: str = ""  # the affected URL / endpoint / host
    parameter: str = ""  # header, cookie, form field... when applicable
    detection_method: str = ""
    cwe: str = ""  # e.g. "CWE-693"
    owasp: str = ""  # e.g. "A05:2021 Security Misconfiguration"
    status: Optional[FindingStatus] = None

    def __post_init__(self) -> None:
        if self.status is None:
            if self.severity == Severity.INFO:
                self.status = FindingStatus.INFORMATIONAL
            elif self.confidence == Confidence.LOW:
                self.status = FindingStatus.POTENTIAL
            else:
                self.status = FindingStatus.CONFIRMED

    @property
    def domain(self) -> str:
        return "quality" if self.category in QUALITY_CATEGORIES else "security"

    @property
    def dedupe_key(self) -> tuple[str, str, str]:
        return (self.id, self.target, self.parameter)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["status"] = self.status.value if self.status else ""
        d["domain"] = self.domain
        return d

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Finding":
        status = data.get("status")
        return Finding(
            id=data["id"],
            title=data["title"],
            category=data["category"],
            severity=Severity(data["severity"]),
            confidence=Confidence(data["confidence"]),
            description=data["description"],
            evidence=data.get("evidence", ""),
            impact=data.get("impact", ""),
            remediation=data.get("remediation", ""),
            references=list(data.get("references", [])),
            target=data.get("target", ""),
            parameter=data.get("parameter", ""),
            detection_method=data.get("detection_method", ""),
            cwe=data.get("cwe", ""),
            owasp=data.get("owasp", ""),
            status=FindingStatus(status) if status else None,
        )


@dataclass
class BaselineResult:
    """The outcome of evaluating one baseline rule against a scan."""

    rule_id: str
    description: str
    status: BaselineStatus
    detail: str

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ScanResult:
    """The full output of one scan."""

    tool: str = "AYYSCANNER"
    tool_version: str = __version__
    scan_type: str = ""
    target: str = ""
    started_at: str = field(default_factory=_now)
    finished_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    outcome: str = OUTCOME_COMPLETE
    requests_made: int = 0
    findings: list[Finding] = field(default_factory=list)
    baseline_results: list[BaselineResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)  # user-facing warnings / failures
    metadata: dict[str, Any] = field(default_factory=dict)  # scan facts, options, sections

    # -- building -----------------------------------------------------------

    def add(self, finding: Finding) -> bool:
        """Add a finding unless an identical one (same id, target, parameter)
        is already present. Returns True if it was added."""
        if any(f.dedupe_key == finding.dedupe_key for f in self.findings):
            return False
        self.findings.append(finding)
        return True

    def mark_finished(self) -> None:
        self.finished_at = _now()
        try:
            start = datetime.fromisoformat(self.started_at)
            end = datetime.fromisoformat(self.finished_at)
            self.duration_seconds = round((end - start).total_seconds(), 2)
        except (ValueError, TypeError):
            self.duration_seconds = None

    # -- querying -----------------------------------------------------------

    def _select(self, domain: Optional[str]) -> list[Finding]:
        return [f for f in self.findings if domain is None or f.domain == domain]

    def sorted_findings(self, domain: Optional[str] = None) -> list[Finding]:
        return sorted(
            self._select(domain),
            key=lambda f: (-f.severity.rank, f.status.order, f.id, f.target, f.parameter),
        )

    def severity_breakdown(self, domain: Optional[str] = None) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self._select(domain):
            counts[f.severity.value] += 1
        return counts

    def status_breakdown(self, domain: Optional[str] = None) -> dict[str, int]:
        counts = {s.value: 0 for s in FindingStatus}
        for f in self._select(domain):
            counts[f.status.value] += 1
        return counts

    def baseline_breakdown(self) -> dict[str, int]:
        counts = {s.value: 0 for s in BaselineStatus}
        for b in self.baseline_results:
            counts[b.status.value] += 1
        return counts

    def has_serious_findings(self) -> bool:
        """True if there is a High/Critical security finding that is not merely
        informational. Used for CLI exit codes."""
        return any(
            f.severity.rank >= Severity.HIGH.rank and f.status != FindingStatus.INFORMATIONAL
            for f in self._select("security")
        )

    def score(self) -> dict[str, Any]:
        """The overall security score and the factors behind it. Deterministic: derived only from the findings."""
        from ayyscanner.scoring import compute_score  # local import: scoring imports this module

        return compute_score(self.findings, self.outcome, self.metadata.get("checks"))

    # -- (de)serialization --------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        def group(domain: str) -> dict[str, Any]:
            return {
                "total": len(self._select(domain)),
                "severity_breakdown": self.severity_breakdown(domain),
                "status_breakdown": self.status_breakdown(domain),
            }

        return {
            "schema_version": 2,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "scan_type": self.scan_type,
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "outcome": self.outcome,
            "requests_made": self.requests_made,
            "summary": {
                "total_findings": len(self.findings),
                "security": group("security"),
                "quality": group("quality"),
                "baseline_breakdown": self.baseline_breakdown(),
            },
            "score": self.score(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "baseline_results": [b.to_dict() for b in self.baseline_results],
            "errors": self.errors,
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "ScanResult":
        result = ScanResult(
            tool=data.get("tool", "AYYSCANNER"),
            tool_version=data.get("tool_version", __version__),
            scan_type=data.get("scan_type", ""),
            target=data.get("target", ""),
            started_at=data.get("started_at") or _now(),
            finished_at=data.get("finished_at"),
            duration_seconds=data.get("duration_seconds"),
            outcome=data.get("outcome", OUTCOME_COMPLETE),
            requests_made=int(data.get("requests_made", 0) or 0),
            errors=list(data.get("errors", [])),
            metadata=dict(data.get("metadata", {})),
        )
        result.findings = [Finding.from_dict(f) for f in data.get("findings", [])]
        result.baseline_results = [
            BaselineResult(
                rule_id=b["rule_id"],
                description=b["description"],
                status=BaselineStatus(b["status"]),
                detail=b["detail"],
            )
            for b in data.get("baseline_results", [])
        ]
        return result
