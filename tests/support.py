"""Test helpers: a tiny configurable local web site.

Tests scan real HTTP responses from 127.0.0.1, so no internet access is needed.
"""

from __future__ import annotations

import shutil
import ssl
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Optional, Union


@dataclass
class Route:
    status: int = 200
    body: Union[str, bytes] = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    content_type: str = "text/html; charset=utf-8"
    delay: float = 0.0


GOOD_HEADERS = [
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=()"),
]

PAGE = """<!doctype html><html lang="en"><head><title>A perfectly fine page title</title>
<meta name="description" content="A description that is comfortably long enough to be considered good by any sensible SEO guideline.">
<meta name="viewport" content="width=device-width, initial-scale=1"><link rel="canonical" href="{canonical}">
</head><body><h1>Hello</h1><p>Some words on the page.</p>{extra}</body></html>"""


def page(extra: str = "", canonical: str = "/") -> str:
    return PAGE.format(extra=extra, canonical=canonical)


HAVE_OPENSSL = shutil.which("openssl") is not None
_cert_cache: Optional[tuple[str, str]] = None


def self_signed_cert() -> tuple[str, str]:
    """(certfile, keyfile) for a throw-away self-signed cert for 127.0.0.1 (needs the openssl CLI)."""
    global _cert_cache
    if _cert_cache is None:
        d = Path(tempfile.mkdtemp(prefix="ayy-test-cert-"))
        cert, key = str(d / "cert.pem"), str(d / "key.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                        "-days", "2", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
                       check=True, capture_output=True)
        _cert_cache = (cert, key)
    return _cert_cache


class Site:
    """Serve `routes` (path -> Route or callable returning Route) on a free port.
    Pass tls=True for HTTPS with a self-signed certificate."""

    def __init__(self, routes: dict[str, Union[Route, Callable[[BaseHTTPRequestHandler], Route]]], tls: bool = False) -> None:
        self.routes = routes
        self.tls = tls
        self.requests: list[tuple[str, str, dict[str, str]]] = []  # (method, path, headers)
        site = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _serve(self) -> None:
                path = self.path.split("?")[0]
                site.requests.append((self.command, self.path, {k.lower(): v for k, v in self.headers.items()}))
                route = site.routes.get(path)
                if callable(route):
                    route = route(self)
                if route is None:
                    route = Route(404, "<html><title>Not found</title>Not found</html>")
                if route.delay:
                    time.sleep(route.delay)
                body = route.body.encode() if isinstance(route.body, str) else route.body
                self.send_response(route.status)
                self.send_header("Content-Type", route.content_type)
                self.send_header("Content-Length", str(len(body)))
                for k, v in route.headers:
                    self.send_header(k, v)
                self.end_headers()
                if self.command != "HEAD":
                    try:
                        self.wfile.write(body)
                    except (BrokenPipeError, ConnectionResetError):
                        pass

            do_GET = do_HEAD = _serve

            def log_message(self, *args) -> None:  # keep test output quiet
                pass

        class QuietServer(ThreadingHTTPServer):
            def handle_error(self, request, client_address) -> None:  # aborted TLS handshakes are expected in tests
                pass

        self._server = QuietServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*self_signed_cert())
            self._server.socket = ctx.wrap_socket(self._server.socket, server_side=True)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"{'https' if self.tls else 'http'}://127.0.0.1:{self._server.server_address[1]}"

    def __enter__(self) -> "Site":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()

    def paths_requested(self, method: str | None = None) -> list[str]:
        return [p for m, p, _ in self.requests if method is None or m == method]


# ---------------------------------------------------------------- unit-test helpers


def make_response(url: str = "https://example.test/", status: int = 200, headers: Optional[dict] = None,
                  cookies: Optional[list[str]] = None, body: Union[str, bytes] = b""):
    """A synthetic Response, for testing checks without any network."""
    from requests.structures import CaseInsensitiveDict

    from ayyscanner.web_scan.http import Response

    return Response(url=url, status=status, headers=CaseInsensitiveDict(headers or {}), set_cookies=cookies or [],
                    body=body.encode() if isinstance(body, str) else body, truncated=False, elapsed_ms=1.0, redirects=[])


def make_ctx(url: str = "https://example.test/", **options):
    """A ScanContext bound to `url` with a real (but unused) client."""
    from ayyscanner.models import ScanResult
    from ayyscanner.web_scan.context import ScanContext
    from ayyscanner.web_scan.http import HttpClient
    from ayyscanner.web_scan.options import ScanOptions

    opts = ScanOptions(**{"rate_limit_per_second": 20, **options})
    return ScanContext(result=ScanResult(scan_type="web", target=url), client=HttpClient(opts, allow_private=True), options=opts, url=url)
