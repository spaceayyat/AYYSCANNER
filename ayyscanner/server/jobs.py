"""Background scan jobs for the web UI.

Each scan runs on its own thread so the UI never blocks. Jobs live in memory
only: finished results are kept for a while (bounded) so reports can be
downloaded, and disappear when the server stops.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from ayyscanner.models import OUTCOME_FAILED, ScanResult
from ayyscanner.report.common import key_observations
from ayyscanner.server.store import ScanStore
from ayyscanner.web_scan import ScanOptions, run_web_scan

log = logging.getLogger("ayyscanner")

MAX_KEPT_JOBS = 25
MAX_JOB_AGE_SECONDS = 6 * 3600  # in-memory only
MAX_SAVED_JOB_AGE_SECONDS = 30 * 24 * 3600  # when scans are saved to disk


class TooManyScans(Exception):
    pass


@dataclass
class Job:
    id: str
    url: str
    options: ScanOptions
    created: float = field(default_factory=time.time)
    started: Optional[float] = None
    finished: Optional[float] = None
    state: str = "queued"  # queued | running | done | failed | cancelled
    percent: int = 0
    stage: str = ""
    message: str = ""
    result: Optional[ScanResult] = None
    error: Optional[str] = None
    cancel_event: threading.Event = field(default_factory=threading.Event)

    @property
    def is_finished(self) -> bool:
        return self.state in ("done", "failed", "cancelled")

    def snapshot(self, include_result: bool = True) -> dict[str, Any]:
        end = self.finished or time.time()
        data: dict[str, Any] = {
            "id": self.id,
            "state": self.state,
            "target": self.url,
            "progress": {
                "percent": self.percent,
                "stage": self.stage,
                "message": self.message,
                "elapsed_seconds": round(end - self.started, 1) if self.started else 0,
            },
            "error": self.error,
        }
        if include_result and self.result is not None:
            data["result"] = self.result.to_dict()
            data["observations"] = key_observations(self.result)
        return data

    def summary(self) -> dict[str, Any]:
        """Small description for the 'recent scans' list (no findings)."""
        return {
            "id": self.id, "state": self.state, "target": self.url, "created": self.created, "finished": self.finished,
            "percent": self.percent, "outcome": self.result.outcome if self.result else None,
            "findings": self.result.to_dict()["summary"]["security"]["total"] if self.result else None,
            "score": self.result.score()["score"] if self.result else None,
        }

    def to_record(self) -> dict[str, Any]:
        return {"id": self.id, "url": self.url, "state": self.state, "created": self.created, "started": self.started,
                "finished": self.finished, "error": self.error, "result": self.result.to_dict() if self.result else None}

    @staticmethod
    def from_record(rec: dict[str, Any]) -> "Job":
        job = Job(id=rec["id"], url=str(rec.get("url", "")), options=ScanOptions(), created=rec.get("created") or time.time(),
                  started=rec.get("started"), finished=rec.get("finished") or time.time(), state=rec.get("state", "done"),
                  error=rec.get("error"), result=ScanResult.from_dict(rec["result"]))
        job.percent = 100 if job.state == "done" else 0
        return job


class JobManager:
    def __init__(self, max_concurrent: int = 2, store: Optional[ScanStore] = None) -> None:
        self.max_concurrent = max_concurrent
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._store = store
        if store is not None:  # restore scans saved by an earlier run
            for rec in reversed(store.load_all()):
                try:
                    job = Job.from_record(rec)
                except Exception:  # noqa: BLE001 - one bad file must not stop the server
                    log.warning("Skipping saved scan %s: unreadable format", rec.get("id"))
                    continue
                self._jobs[job.id] = job

    def list(self) -> list[dict[str, Any]]:
        """Newest first, running scans included."""
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda j: j.created, reverse=True)
        return [j.summary() for j in jobs]

    def submit(self, url: str, options: ScanOptions) -> Job:
        with self._lock:
            self._prune()
            if sum(1 for j in self._jobs.values() if not j.is_finished) >= self.max_concurrent:
                raise TooManyScans(
                    f"{self.max_concurrent} scan(s) are already running. Wait for one to finish or stop it, then try again."
                )
            job = Job(id=secrets.token_urlsafe(9), url=url, options=options)
            self._jobs[job.id] = job
        threading.Thread(target=self._run, args=(job,), name=f"scan-{job.id}", daemon=True).start()
        return job

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def cancel(self, job_id: str) -> Optional[Job]:
        job = self.get(job_id)
        if job and not job.is_finished:
            job.cancel_event.set()
            job.message = "Stopping …"
        return job

    def _run(self, job: Job) -> None:
        def progress(percent: int, stage: str, message: str) -> None:
            job.percent, job.stage, job.message = percent, stage, message

        job.state, job.started = "running", time.time()
        try:
            job.result = run_web_scan(job.url, job.options, progress_cb=progress, cancel_event=job.cancel_event)
            if job.cancel_event.is_set():
                job.state = "cancelled"
            elif job.result.outcome == OUTCOME_FAILED:
                job.state = "failed"
                job.error = job.result.errors[0] if job.result.errors else "The scan failed."
            else:
                job.state, job.percent = "done", 100
        except Exception:  # noqa: BLE001 - a scanner bug must not kill the server
            log.exception("Scan %s crashed", job.id)
            job.state = "failed"
            job.error = "The scan stopped because of an internal error. Details were written to the server log."
        finally:
            job.finished = time.time()
            if self._store is not None and job.result is not None:
                self._store.save(job.to_record())  # saved the moment the scan ends: nothing to remember to save

    def _prune(self) -> None:
        """Called with the lock held. Drops expired jobs, then the oldest finished ones."""
        now = time.time()
        for jid in [j.id for j in self._jobs.values() if j.is_finished and now - (j.finished or now) > (MAX_SAVED_JOB_AGE_SECONDS if self._store else MAX_JOB_AGE_SECONDS)]:
            del self._jobs[jid]
            if self._store is not None:
                self._store.delete(jid)
        finished = sorted((j for j in self._jobs.values() if j.is_finished), key=lambda j: j.finished or 0)
        for job in finished[: max(0, len(finished) - MAX_KEPT_JOBS + 1)]:
            del self._jobs[job.id]
            if self._store is not None:
                self._store.delete(job.id)
