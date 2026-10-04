"""User preferences (Settings page), stored locally as one small JSON file.

Validation is strict, like scan options: bad values are rejected with a message per field and
never silently replaced. Unknown keys from a newer/older version are ignored on load. Writes are
atomic. Nothing here is ever sent anywhere.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("ayyscanner")

DEFAULTS: dict[str, Any] = {
    "theme": "system",            # system | light | dark
    "ui_scale": 100,              # percent
    "scan_timeout": 300,          # seconds: the whole scan is stopped (results kept, marked partial) after this
    "request_timeout": 10,        # seconds per request (website scans)
    "show_informational": True,   # include informational findings in results
    "sort_findings": "severity",  # severity | name
    "result_view": "detailed",    # detailed | compact
    "auto_save_history": True,    # keep finished scans on this computer
}
_CHOICES = {"theme": ("system", "light", "dark"), "sort_findings": ("severity", "name"), "result_view": ("detailed", "compact")}
_RANGES = {"ui_scale": (80, 150, "UI size"), "scan_timeout": (30, 3600, "Scan time limit"), "request_timeout": (1, 60, "Request timeout")}
_BOOLS = ("show_informational", "auto_save_history")


class PrefsError(ValueError):
    def __init__(self, problems: dict[str, str]) -> None:
        self.fields = problems
        super().__init__("; ".join(problems.values()))


def validate(data: Any, base: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Return base (or defaults) updated with the valid keys of `data`; raise PrefsError for bad values."""
    out = dict(base or DEFAULTS)
    if not isinstance(data, dict):
        raise PrefsError({"_": "Settings must be a JSON object."})
    problems: dict[str, str] = {}
    for key, value in data.items():
        if key in _CHOICES:
            if value in _CHOICES[key]:
                out[key] = value
            else:
                problems[key] = f"{key.replace('_', ' ').capitalize()} must be one of: {', '.join(_CHOICES[key])}."
        elif key in _RANGES:
            lo, hi, label = _RANGES[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not lo <= value <= hi:
                problems[key] = f"{label} must be a number between {lo} and {hi}."
            else:
                out[key] = int(value)
        elif key in _BOOLS:
            if isinstance(value, bool):
                out[key] = value
            else:
                problems[key] = "Must be on or off."
        # unknown keys are ignored
    if problems:
        raise PrefsError(problems)
    return out


class PrefsStore:
    """In-memory when `path` is None; otherwise persisted to `path`."""

    def __init__(self, path: Optional[Path]) -> None:
        self.path = Path(path) if path else None
        self.values = dict(DEFAULTS)
        if self.path:
            try:
                self.values = validate(self._lenient(json.loads(self.path.read_text(encoding="utf-8"))))
            except FileNotFoundError:
                pass
            except (OSError, ValueError):
                log.warning("Could not read %s; using default settings.", self.path)

    @staticmethod
    def _lenient(data: Any) -> dict[str, Any]:
        """Keep only the individually valid keys of a saved file, so one bad value doesn't reset everything."""
        if not isinstance(data, dict):
            return {}
        good: dict[str, Any] = {}
        for key, value in data.items():
            try:
                validate({key: value})
                good[key] = value
            except PrefsError:
                pass
        return good

    def get(self) -> dict[str, Any]:
        return dict(self.values)

    def update(self, data: Any) -> dict[str, Any]:
        new = validate(data, self.values)
        self.values = new
        self._write()
        return dict(new)

    def reset(self) -> dict[str, Any]:
        self.values = dict(DEFAULTS)
        self._write()
        return dict(self.values)

    def _write(self) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".tmp-", suffix=".json")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(self.values, fh, indent=2)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, self.path)
            except BaseException:
                Path(tmp).unlink(missing_ok=True)
                raise
        except OSError as exc:
            log.warning("Could not save settings: %s", exc)
