"""User-configurable scan behaviour, with strict validation.

Invalid values are rejected with a message per field. They are never silently
replaced by defaults, so a scan never runs with settings the user did not ask for.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from typing import Any

from ayyscanner import __version__

DEFAULT_USER_AGENT = f"AYYSCANNER/{__version__} (security scanner; authorized testing)"

# name -> (minimum, maximum, label)
_NUMERIC_LIMITS: dict[str, tuple[float, float, str]] = {
    "timeout": (1, 60, "Request timeout (seconds)"),
    "rate_limit_per_second": (0.5, 20, "Rate limit (requests/second)"),
    "max_links_to_check": (0, 500, "Max links to check"),
    "link_check_concurrency": (1, 20, "Link check concurrency"),
}


class OptionsError(ValueError):
    """Raised when scan options are invalid. `.fields` maps option -> message."""

    def __init__(self, problems: dict[str, str]) -> None:
        self.fields = problems
        super().__init__("; ".join(f"{k}: {v}" for k, v in problems.items()))


@dataclass
class ScanOptions:
    timeout: float = 10.0
    rate_limit_per_second: float = 5.0
    user_agent: str = DEFAULT_USER_AGENT
    max_body_bytes: int = 2_000_000
    check_internal_links: bool = True
    check_external_links: bool = True
    max_links_to_check: int = 100
    link_check_concurrency: int = 5
    check_tls: bool = True
    check_http_to_https_redirect: bool = True
    check_cors: bool = True
    check_well_known_files: bool = True  # robots.txt, sitemap.xml, security.txt
    check_sensitive_files: bool = True  # /.git/HEAD, /.env, /phpinfo.php

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "ScanOptions":
        """Build options from untrusted input. Unknown keys are ignored (so
        settings saved by an older version keep working); bad values raise."""
        data = data or {}
        defaults = cls()
        problems: dict[str, str] = {}
        values: dict[str, Any] = {}
        for f in fields(cls):
            if f.name not in data:
                continue
            raw = data[f.name]
            default = getattr(defaults, f.name)
            if f.name in _NUMERIC_LIMITS:
                lo, hi, label = _NUMERIC_LIMITS[f.name]
                if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                    problems[f.name] = f"{label} must be a number."
                elif not lo <= raw <= hi:
                    problems[f.name] = f"{label} must be between {lo:g} and {hi:g}."
                else:
                    values[f.name] = type(default)(raw)
            elif f.name == "user_agent":
                ua = raw.strip() if isinstance(raw, str) else ""
                if not 1 <= len(ua) <= 200 or not ua.isascii() or not ua.isprintable():
                    problems[f.name] = "User agent must be 1-200 printable ASCII characters."
                else:
                    values[f.name] = ua
            elif f.name == "max_body_bytes":
                if isinstance(raw, bool) or not isinstance(raw, int) or not 10_000 <= raw <= 20_000_000:
                    problems[f.name] = "Body size limit must be between 10,000 and 20,000,000 bytes."
                else:
                    values[f.name] = raw
            elif isinstance(default, bool):
                if not isinstance(raw, bool):
                    problems[f.name] = "Must be true or false."
                else:
                    values[f.name] = raw
        if problems:
            raise OptionsError(problems)
        return cls(**values)
