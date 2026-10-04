"""Saves finished scans to disk so they survive a page reload or a server restart.

One JSON file per scan, written atomically (temp file + rename) so a crash or a
power cut can never leave a half-written file. Scan ids are validated before they
touch the filesystem. The folder holds scan results only, never credentials.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("ayyscanner")
_ID = re.compile(r"^[A-Za-z0-9_-]{4,64}$")


class ScanStore:
    def __init__(self, directory: Path, keep: int = 50) -> None:
        self.directory = Path(directory)
        self.keep = keep

    def _path(self, job_id: str) -> Path:
        if not _ID.match(job_id):
            raise ValueError("invalid scan id")
        return self.directory / f"{job_id}.json"

    def save(self, record: dict[str, Any]) -> bool:
        """Write one scan record. Returns False (and logs) instead of raising: a full disk must not break a scan."""
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            target = self._path(record["id"])
            fd, tmp = tempfile.mkstemp(dir=self.directory, prefix=".tmp-", suffix=".json")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(record, fh, ensure_ascii=False)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, target)
            except BaseException:
                Path(tmp).unlink(missing_ok=True)
                raise
            self._prune()
            return True
        except (OSError, ValueError, TypeError) as exc:
            log.warning("Could not save scan %s: %s", record.get("id"), exc)
            return False

    def load_all(self) -> list[dict[str, Any]]:
        """Newest first. Unreadable or corrupt files are skipped, never fatal."""
        records = []
        try:
            files = [p for p in self.directory.glob("*.json") if _ID.match(p.stem)]
        except OSError:
            return []
        for path in files:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict) and data.get("id") == path.stem and isinstance(data.get("result"), dict):
                    records.append((path.stat().st_mtime, data))
            except (OSError, ValueError):
                log.warning("Skipping unreadable saved scan %s", path.name)
        return [d for _, d in sorted(records, key=lambda x: x[0], reverse=True)]

    def delete(self, job_id: str) -> None:
        try:
            self._path(job_id).unlink(missing_ok=True)
        except (OSError, ValueError):
            pass

    def _prune(self) -> None:
        files = sorted((p for p in self.directory.glob("*.json") if _ID.match(p.stem)), key=lambda p: p.stat().st_mtime, reverse=True)
        for old in files[self.keep:]:
            old.unlink(missing_ok=True)
