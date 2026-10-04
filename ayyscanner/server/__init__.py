"""Local web UI and JSON API.

This server can start scans from the machine it runs on, so it is guarded like
a security-sensitive service:

* listens on localhost only by default (see settings.py),
* only answers to allow-listed Host headers (defeats DNS rebinding),
* the API requires a SameSite=Strict session cookie that only pages served by
  this server receive (defeats cross-site requests),
* state-changing requests must be JSON and, if they carry an Origin header,
  it must be this server's own origin,
* every response carries strict security headers,
* clients never supply file paths; report filenames are generated server-side.
"""

from __future__ import annotations

import hmac
import logging
import platform
import secrets
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any, Optional

from flask import Flask, Response, abort, jsonify, make_response, request, send_from_directory
from werkzeug.exceptions import HTTPException
from werkzeug.serving import make_server

from ayyscanner import __version__
from ayyscanner.instance import reuse_running
from ayyscanner.models import ScanResult
from ayyscanner.report import FORMATS, filename_for
from ayyscanner.report.common import ASSETS
from ayyscanner.server.jobs import KINDS, JobManager, TooManyScans
from ayyscanner.server.store import ScanStore
from ayyscanner.userprefs import DEFAULTS as PREF_DEFAULTS, PrefsError, PrefsStore
from ayyscanner.settings import Settings
from ayyscanner.web_scan.options import _NUMERIC_LIMITS, OptionsError, ScanOptions
from ayyscanner.web_scan.urls import InvalidUrlError, parse_target

log = logging.getLogger("ayyscanner")

COOKIE_NAME = "ayy_session"
APP_CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; "
    "object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
_PUBLIC_ASSETS = {"tokens.css", "logo.svg"}
TAB_TIMEOUT_SECONDS = 15  # the page pings every 5 s


def _hostname(host_header: str) -> str:
    h = host_header.strip().lower()
    if h.startswith("["):
        return h[1 : h.index("]")] if "]" in h else h
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h


def _error(status: int, code: str, message: str, **extra: Any) -> Response:
    response = jsonify({"error": {"code": code, "message": message, **extra}})
    response.status_code = status
    return response


def create_app(settings: Optional[Settings] = None, manager: Optional[JobManager] = None) -> Flask:
    settings = settings or Settings()
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    session_secret = secrets.token_urlsafe(32)
    store = ScanStore(settings.data_dir / "scans") if settings.data_dir else None
    prefs = PrefsStore(settings.data_dir / "settings.json" if settings.data_dir else None)
    jobs = manager or JobManager(settings.max_concurrent_scans, store, prefs)
    allowed_hosts = settings.allowed_hosts
    open_tabs: dict[str, float] = {}  # browser tab id -> last heartbeat; lets a second launch see the UI is already open
    tabs_lock = threading.Lock()

    # -- guards ---------------------------------------------------------------

    @app.before_request
    def guard() -> Optional[Response]:
        if _hostname(request.host) not in allowed_hosts:
            return _error(403, "bad_host", "This request used a host name the scanner is not configured to answer to.")
        if not request.path.startswith("/api/"):
            return None
        supplied = request.cookies.get(COOKIE_NAME, "")
        if not hmac.compare_digest(supplied.encode(), session_secret.encode()):
            return _error(403, "no_session", "Missing or invalid session. Reload the AYYSCANNER page and try again.")
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("Origin")
            if origin and origin.rstrip("/") != request.host_url.rstrip("/"):
                return _error(403, "bad_origin", "Cross-origin requests are not allowed.")
            if request.method in ("POST", "PUT") and not request.is_json:
                return _error(415, "json_required", "Send the request body as JSON (Content-Type: application/json).")
        return None

    @app.after_request
    def secure_headers(response: Response) -> Response:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if "Content-Security-Policy" not in response.headers:
            response.headers["Content-Security-Policy"] = APP_CSP
            response.headers.setdefault("X-Frame-Options", "DENY")
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    # -- pages and assets -----------------------------------------------------

    @app.get("/")
    def index() -> Response:
        response = make_response(send_from_directory(app.static_folder, "index.html"))
        response.set_cookie(COOKIE_NAME, session_secret, httponly=True, samesite="Strict", path="/")
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/assets/<name>")
    def asset(name: str) -> Response:
        if name not in _PUBLIC_ASSETS:  # explicit allow-list: no filesystem paths from the client
            abort(404)
        return send_from_directory(ASSETS, name)

    def _ui_open() -> bool:
        now = time.time()
        with tabs_lock:
            for tab in [t for t, seen in open_tabs.items() if now - seen > TAB_TIMEOUT_SECONDS]:
                del open_tabs[tab]
            return bool(open_tabs)

    @app.get("/healthz")
    def healthz() -> Response:
        """Unauthenticated identity check used by the launcher to find a running instance. Reveals nothing sensitive."""
        return jsonify({"app": "ayyscanner", "version": __version__, "ui_open": _ui_open()})

    # -- API ------------------------------------------------------------------

    def _tab_id() -> str:
        body = request.get_json(silent=True)
        tab = body.get("tab") if isinstance(body, dict) else None
        return tab if isinstance(tab, str) and 0 < len(tab) <= 64 else ""

    @app.post("/api/ui/ping")
    def ui_ping() -> Response:
        tab = _tab_id()
        if tab:
            with tabs_lock:
                if len(open_tabs) < 50 or tab in open_tabs:
                    open_tabs[tab] = time.time()
        return jsonify({"ok": True})

    @app.post("/api/ui/closed")
    def ui_closed() -> Response:
        with tabs_lock:
            open_tabs.pop(_tab_id(), None)
        return jsonify({"ok": True})

    @app.get("/api/scans")
    def list_scans() -> Response:
        return jsonify({"scans": jobs.list(), "saved": store is not None})

    @app.get("/api/health")
    def health() -> Response:
        return jsonify({"ok": True, "version": __version__})

    @app.get("/api/config")
    def config() -> Response:
        return jsonify({
            "version": __version__,
            "defaults": ScanOptions().to_dict(),
            "settings": prefs.get(),
            "setting_defaults": PREF_DEFAULTS,
            "history_on_disk": store is not None,
            "data_dir": str(settings.data_dir) if settings.data_dir else None,
            "limits": {k: {"min": lo, "max": hi, "label": label} for k, (lo, hi, label) in _NUMERIC_LIMITS.items()},
            "formats": [{"key": f.key, "label": f.label} for f in FORMATS.values()],
        })

    def _project_dir(raw: Any) -> Path:
        """Validate a folder typed by the user. It is only read for dependency manifests."""
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError("Enter the folder of the project you want to scan.")
        if len(raw) > 1024 or "\x00" in raw:
            raise ValueError("That folder path is not valid.")
        path = Path(raw.strip()).expanduser()
        try:
            path = path.resolve(strict=True)
        except (OSError, RuntimeError):
            raise ValueError("That folder was not found on this computer. Check the path.") from None
        if not path.is_dir():
            raise ValueError("That path is a file. Choose the project's folder.")
        return path

    @app.post("/api/scans")
    def start_scan() -> Response:
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return _error(400, "invalid_body", "The request body must be a JSON object.")
        kind = body.get("kind", "web")
        if kind not in KINDS:
            return _error(400, "invalid_kind", "Unknown scan type. Choose website, system or project.")
        if body.get("authorized") is not True:
            what = {"web": "Confirm that you own this target or have permission to test it before scanning.",
                    "system": "Confirm that you want to check this computer before scanning.",
                    "project": "Confirm that you want to read this project's dependency files before scanning."}[kind]
            return _error(400, "authorization_required", what)
        options = None
        if kind == "web":
            try:
                parse_target(body.get("url") if isinstance(body.get("url"), str) else "")  # validate now for a fast, clear error
            except InvalidUrlError as exc:
                return _error(400, "invalid_url", str(exc))
            try:
                options = ScanOptions.from_dict(body.get("options") if isinstance(body.get("options"), dict) else {})
            except OptionsError as exc:
                return _error(400, "invalid_options", "Some scan options are invalid: " + "; ".join(exc.fields.values()), fields=exc.fields)
            target = body["url"].strip()  # raw input: the engine needs to know if no scheme was typed
        elif kind == "project":
            try:
                target = str(_project_dir(body.get("directory")))
            except ValueError as exc:
                return _error(400, "invalid_directory", str(exc))
        else:
            target = platform.node() or "this computer"
        try:
            job = jobs.submit(target, options, kind=kind)
        except TooManyScans as exc:
            return _error(429, "busy", str(exc))
        log.info("%s scan %s started for %s", kind, job.id, job.url)
        response = jsonify({"id": job.id, "state": job.state, "kind": kind})
        response.status_code = 202
        return response

    def _job_or_404(job_id: str):
        job = jobs.get(job_id)
        if job is None:
            abort(404, description="Unknown scan. It may have expired when the server restarted.")
        return job

    @app.delete("/api/scans/<job_id>")
    def delete_scan(job_id: str) -> Response:
        job = _job_or_404(job_id)
        if not job.is_finished:
            return _error(409, "still_running", "That scan is still running. Stop it first, then delete it.")
        jobs.delete(job_id)
        return jsonify({"ok": True})

    @app.delete("/api/scans")
    def clear_scans() -> Response:
        return jsonify({"ok": True, "removed": jobs.clear()})

    @app.get("/api/settings")
    def get_settings() -> Response:
        return jsonify({"settings": prefs.get(), "defaults": PREF_DEFAULTS})

    @app.put("/api/settings")
    def put_settings() -> Response:
        body = request.get_json(silent=True)
        try:
            return jsonify({"settings": prefs.update(body)})
        except PrefsError as exc:
            return _error(400, "invalid_settings", "Some settings are invalid: " + "; ".join(exc.fields.values()), fields=exc.fields)

    @app.post("/api/settings/reset")
    def reset_settings() -> Response:
        return jsonify({"settings": prefs.reset()})

    @app.post("/api/shortcut")
    def make_shortcut() -> Response:
        """Create (or repair) the desktop shortcut. Same code as `python run.py --create-shortcut`."""
        from ayyscanner import shortcut

        try:
            outcome = shortcut.ensure_shortcut(force=True)
        except Exception:  # noqa: BLE001 - never a stack trace in the UI
            log.exception("Creating the desktop shortcut failed")
            return _error(500, "shortcut_failed", "The shortcut could not be created. Details were written to the server log.")
        ok = outcome.status in (shortcut.CREATED, shortcut.UPDATED, shortcut.EXISTS)
        return jsonify({"ok": ok, "message": shortcut.describe(outcome) or outcome.message or "Nothing to do."})

    @app.get("/api/scans/<job_id>")
    def scan_status(job_id: str) -> Response:
        return jsonify(_job_or_404(job_id).snapshot())

    @app.post("/api/scans/<job_id>/cancel")
    def scan_cancel(job_id: str) -> Response:
        _job_or_404(job_id)
        jobs.cancel(job_id)
        return jsonify({"ok": True})

    @app.get("/api/scans/<job_id>/report")
    def scan_report(job_id: str) -> Response:
        job = _job_or_404(job_id)
        fmt = FORMATS.get(request.args.get("format", "html"))
        if fmt is None:
            return _error(400, "bad_format", "Unknown report format. Choose one of: " + ", ".join(FORMATS) + ".")
        if job.result is None:
            return _error(409, "not_ready", "This scan has no results yet.")
        result: ScanResult = job.result
        response = make_response(fmt.render(result))
        response.headers["Content-Type"] = fmt.mimetype
        inline = fmt.key == "html" and request.args.get("inline") == "1"
        response.headers["Content-Disposition"] = f'{"inline" if inline else "attachment"}; filename="{filename_for(result, fmt.extension)}"'
        if inline:
            # Render the report in an opaque origin so it can never touch the app's origin.
            response.headers["Content-Security-Policy"] = "sandbox allow-scripts allow-popups allow-popups-to-escape-sandbox"
        return response

    # -- errors ---------------------------------------------------------------

    @app.errorhandler(HTTPException)
    def http_error(exc: HTTPException) -> Response:
        if request.path.startswith("/api/"):
            return _error(exc.code or 500, (exc.name or "error").lower().replace(" ", "_"), exc.description or exc.name)
        return Response(f"{exc.code} {exc.name}", status=exc.code, mimetype="text/plain")

    @app.errorhandler(Exception)
    def unexpected(exc: Exception) -> Response:
        log.exception("Unhandled error on %s %s", request.method, request.path)
        message = "Something went wrong on the server. Details were written to the server log."
        if settings.debug:
            message += f" ({type(exc).__name__}: {exc})"
        return _error(500, "internal_error", message)

    return app


def run_server(settings: Settings) -> int:
    """Start the UI server and block until Ctrl+C. Returns a process exit code."""
    logging.basicConfig(level=getattr(logging, settings.log_level), format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    logging.getLogger("werkzeug").setLevel(logging.WARNING if not settings.debug else logging.INFO)
    if reuse_running(settings):  # Home/Run twice must not start a second server or a second tab
        return 0
    app = create_app(settings)
    try:
        server = make_server(settings.host, settings.port, app, threaded=True)
    except OSError as exc:
        reason = "is already in use" if isinstance(exc, OSError) and exc.errno in (98, 48, 10048) else f"could not be opened ({exc.strerror or exc})"
        print(f"Error: port {settings.port} {reason}.\n"
              f"Stop the other program, or choose another port with AYYSCANNER_PORT=<number> (or --port).")
        return 1
    print(f"AYYSCANNER {__version__} is running at {settings.url}\nPress Ctrl+C to stop.")
    if settings.data_dir:
        print(f"Scan history and settings are stored in {settings.data_dir}")
    if settings.open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(settings.url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping AYYSCANNER.")
    finally:
        server.server_close()
    return 0
