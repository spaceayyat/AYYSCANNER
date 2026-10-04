"""Background scan jobs for the web UI (website, system and project scans).

Each scan runs on its own thread so the UI never blocks. Finished scans are kept in memory and,
unless the user turned history off, saved to disk (see store.py) so they survive restarts.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ayyscanner.errors import explain, explain_notice
from ayyscanner.models import OUTCOME_FAILED, OUTCOME_PARTIAL, ScanResult
from ayyscanner.report.common import key_observations
from ayyscanner.server.store import ScanStore
from ayyscanner.userprefs import PrefsStore
from ayyscanner.web_scan import ScanOptions, run_web_scan

log = logging.getLogger("ayyscanner")

MAX_KEPT_JOBS = 50
MAX_JOB_AGE_SECONDS = 6 * 3600  # in-memory only
MAX_SAVED_JOB_AGE_SECONDS = 30 * 24 * 3600  # when scans are saved to disk
KINDS = ("web", "system", "project")


class TooManyScans(Exception):
    pass


@dataclass
class Job:
    id: str
    url: str  # the target: a URL, this computer's name, or a project folder
    options: ScanOptions
    kind: str = "web"  # web | system | project
    created: float = field(default_factory=time.time)
    started: Optional[float] = None
    finished: Optional[float] = None
    state: str = "queued"  # queued | running | done | failed | cancelled
    percent: int = 0
    stage: str = ""
    message: str = ""
    result: Optional[ScanResult] = None
    error: Optional[str] = None
    error_info: Optional[dict[str, Any]] = None  # {title, message, details} for friendly errors
    cancel_event: threading.Event = field(default_factory=threading.Event)
    _stats: Optional[dict[str, Any]] = field(default=None, repr=False)

    @property
    def is_finished(self) -> bool:
        return self.state in ("done", "failed", "cancelled")

    def snapshot(self, include_result: bool = True) -> dict[str, Any]:
        end = self.finished or time.time()
        data: dict[str, Any] = {
            "id": self.id,
            "kind": self.kind,
            "state": self.state,
            "target": self.url,
            "progress": {
                "percent": self.percent,
                "stage": self.stage,
                "message": self.message,
                "elapsed_seconds": round(end - self.started, 1) if self.started else 0,
            },
            "error": self.error,
            "error_info": self.error_info,
        }
        if include_result and self.result is not None:
            data["result"] = self.result.to_dict()
            data["observations"] = key_observations(self.result)
            data["notices"] = [explain_notice(e) for e in self.result.errors]  # friendly headline + original text
        return data

    def stats(self) -> dict[str, Any]:
        """Score and counts for the history list; computed once, after the scan ends."""
        if self._stats is None and self.result is not None:
            d = self.result.to_dict()
            sec = d["summary"]["security"]
            failed = self.result.outcome == OUTCOME_FAILED  # nothing was scanned: no score, no counts
            self._stats = {"score": d["score"]["score"], "findings": None if failed else sec["total"],
                           "severity": None if failed else sec["severity_breakdown"], "outcome": self.result.outcome}
        return self._stats or {"score": None, "findings": None, "severity": None, "outcome": None}

    def summary(self) -> dict[str, Any]:
        """Small description for the history list (no findings)."""
        return {"id": self.id, "kind": self.kind, "state": self.state, "target": self.url, "created": self.created,
                "finished": self.finished, "percent": self.percent, **self.stats()}

    def to_record(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "url": self.url, "state": self.state, "created": self.created,
                "started": self.started, "finished": self.finished, "error": self.error, "error_info": self.error_info,
                "result": self.result.to_dict() if self.result else None}

    @staticmethod
    def from_record(rec: dict[str, Any]) -> "Job":
        job = Job(id=rec["id"], url=str(rec.get("url", "")), options=ScanOptions(), kind=rec.get("kind") or "web",
                  created=rec.get("created") or time.time(), started=rec.get("started"),
                  finished=rec.get("finished") or time.time(), state=rec.get("state", "done"), error=rec.get("error"),
                  error_info=rec.get("error_info"), result=ScanResult.from_dict(rec["result"]))
        job.percent = 100 if job.state == "done" else 0
        return job


class JobManager:
    def __init__(self, max_concurrent: int = 2, store: Optional[ScanStore] = None, prefs: Optional[PrefsStore] = None) -> None:
        self.max_concurrent = max_concurrent
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._store = store
        self._prefs = prefs
        if store is not None:  # restore scans saved by an earlier run
            for rec in reversed(store.load_all()):
                try:
                    job = Job.from_record(rec)
                except Exception:  # noqa: BLE001 - one bad file must not stop the server
                    log.warning("Skipping saved scan %s: unreadable format", rec.get("id"))
                    continue
                self._jobs[job.id] = job

    # -- settings the user can change while the server runs ---------------------------

    def _pref(self, key: str, default: Any) -> Any:
        return self._prefs.get().get(key, default) if self._prefs else default

    # -- queries ---------------------------------------------------------------------

    def list(self) -> list[dict[str, Any]]:
        """Newest first, running scans included."""
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda j: j.created, reverse=True)
        return [j.summary() for j in jobs]

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    # -- actions ---------------------------------------------------------------------

    def submit(self, url: str, options: Optional[ScanOptions] = None, *, kind: str = "web") -> Job:
        if kind not in KINDS:
            raise ValueError(f"Unknown scan type '{kind}'.")
        with self._lock:
            self._prune()
            if sum(1 for j in self._jobs.values() if not j.is_finished) >= self.max_concurrent:
                raise TooManyScans(
                    f"{self.max_concurrent} scan(s) are already running. Wait for one to finish or stop it, then try again."
                )
            job = Job(id=secrets.token_urlsafe(9), url=url, options=options or ScanOptions(), kind=kind)
            self._jobs[job.id] = job
        threading.Thread(target=self._run, args=(job,), name=f"scan-{job.id}", daemon=True).start()
        return job

    def cancel(self, job_id: str) -> Optional[Job]:
        job = self.get(job_id)
        if job and not job.is_finished:
            job.cancel_event.set()
            job.message = "Stopping …"
        return job

    def delete(self, job_id: str) -> bool:
        """Remove one finished scan from history (memory and disk). A running scan is never deleted."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or not job.is_finished:
                return False
            del self._jobs[job_id]
        if self._store is not None:
            self._store.delete(job_id)
        return True

    def clear(self) -> int:
        """Remove every finished scan from history. Returns how many were removed."""
        with self._lock:
            ids = [j.id for j in self._jobs.values() if j.is_finished]
            for jid in ids:
                del self._jobs[jid]
        if self._store is not None:
            for jid in ids:
                self._store.delete(jid)
        return len(ids)

    # -- running ---------------------------------------------------------------------

    def _execute(self, job: Job, progress: Callable[[int, str, str], None]) -> ScanResult:
        if job.kind == "system":
            from ayyscanner.scanners.system import run_system_scan

            return run_system_scan(progress_cb=progress)
        if job.kind == "project":
            from ayyscanner.scanners.dependencies import run_dependency_scan

            return run_dependency_scan(job.url, timeout=float(self._pref("request_timeout", 10)), progress_cb=progress)
        return run_web_scan(job.url, job.options, progress_cb=progress, cancel_event=job.cancel_event)

    def _run(self, job: Job) -> None:
        def progress(percent: int, stage: str, message: str) -> None:
            job.percent, job.stage, job.message = percent, stage, message

        timed_out = threading.Event()

        def on_time_limit() -> None:
            timed_out.set()
            job.cancel_event.set()

        limit = float(self._pref("scan_timeout", 300))
        timer = threading.Timer(limit, on_time_limit)
        timer.daemon = True
        timer.start()
        job.state, job.started = "running", time.time()
        try:
            job.result = self._execute(job, progress)
            if timed_out.is_set() and job.result.outcome != OUTCOME_FAILED:
                job.result.outcome = OUTCOME_PARTIAL
                job.result.errors.append(f"The scan reached the time limit ({limit:g} s, see Settings) and was stopped. Results are partial.")
                job.state, job.percent = "done", 100
            elif job.cancel_event.is_set():
                job.state = "cancelled"
            elif job.result.outcome == OUTCOME_FAILED:
                job.state = "failed"
                raw = job.result.errors[0] if job.result.errors else "The scan failed."
                job.error_info = explain(job.kind, raw, "\n".join(job.result.errors))
                job.error = job.error_info["title"] + " " + job.error_info["message"]
            else:
                job.state, job.percent = "done", 100
        except Exception as exc:  # noqa: BLE001 - a scanner bug must not kill the server
            log.exception("Scan %s crashed", job.id)
            job.state = "failed"
            job.error_info = explain("internal", "", f"{type(exc).__name__}: {str(exc)[:300]}")
            job.error = job.error_info["title"] + " " + job.error_info["message"]
        finally:
            timer.cancel()
            job.finished = time.time()
            if job.result is not None:
                job.stats()  # cache the score and counts
                if self._store is not None and self._pref("auto_save_history", True):
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
