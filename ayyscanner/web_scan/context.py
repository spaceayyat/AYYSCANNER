"""Shared state passed to every check of one scan."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from ayyscanner.models import ScanResult
from ayyscanner.web_scan.http import HttpClient
from ayyscanner.web_scan.options import ScanOptions
from ayyscanner.web_scan.rules import make_finding


@dataclass
class ScanContext:
    result: ScanResult
    client: HttpClient
    options: ScanOptions
    url: str  # URL of the page being analysed (after redirects)
    facts: dict[str, Any] = field(default_factory=dict)  # becomes result.metadata sections
    checks: list[dict[str, str]] = field(default_factory=list)  # what ran / was skipped

    def add(self, rule_id: str, *, evidence: str, target: Optional[str] = None, **kwargs: Any) -> None:
        """Create a finding from the rule catalog and add it (duplicates are dropped)."""
        self.result.add(make_finding(rule_id, evidence=evidence, target=target or self.url, **kwargs))

    def warn(self, message: str) -> None:
        if message not in self.result.errors:
            self.result.errors.append(message)

    def note_check(self, name: str, status: str, note: str = "") -> None:
        """Record a check as 'ran', 'skipped' or 'failed', so reports never imply
        something was tested when it was not."""
        self.checks.append({"name": name, "status": status, "note": note})
