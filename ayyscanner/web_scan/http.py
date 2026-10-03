"""The one HTTP client every request in a scan goes through.

Centralising requests means every request gets the same protections:

* a shared rate limiter and an honest request counter,
* per-request timeouts plus a wall-clock cap on reading the body,
* a hard cap on body size (a hostile server cannot exhaust memory),
* manual redirect following, so every hop is validated,
* an SSRF guard: unless the scan target itself is a private/local address,
  requests to private, loopback and link-local addresses are refused (this is
  what stops a malicious page from steering the link checker at your LAN or
  a cloud metadata endpoint),
* cooperative cancellation,
* no cookie jar, no ~/.netrc credentials.

`fetch()` never raises for network problems: it returns a `FetchResult` whose
`error` is written for humans. Only `ScanCancelled` propagates.
"""

from __future__ import annotations

import http.cookiejar
import ipaddress
import re
import socket
import threading
import time
import warnings
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import urljoin, urlsplit

import requests
import urllib3
from requests.adapters import HTTPAdapter
from requests.auth import AuthBase
from requests.structures import CaseInsensitiveDict

from ayyscanner.web_scan.options import ScanOptions

MAX_REDIRECTS = 10
CHUNK_SIZE = 16 * 1024
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class ScanCancelled(Exception):
    """Raised inside a scan when the user pressed Stop."""


@dataclass
class FetchError:
    kind: str  # dns | refused | timeout | tls | redirects | blocked | reset | other
    message: str  # human-readable and safe to show to the user
    detail: str = ""  # short technical detail for the report (never a stack trace)
    cert_error: bool = False  # True when the failure was TLS certificate verification
    url: str = ""  # the URL that was being requested when it failed


@dataclass
class Response:
    url: str
    status: int
    headers: CaseInsensitiveDict
    set_cookies: list[str]
    body: bytes
    truncated: bool
    elapsed_ms: float
    redirects: list[tuple[str, int]]  # (url, status) of each redirect hop taken
    encoding: Optional[str] = None

    @property
    def text(self) -> str:
        return self.body.decode(self.encoding or "utf-8", errors="replace")


@dataclass
class FetchResult:
    response: Optional[Response] = None
    error: Optional[FetchError] = None

    @property
    def ok(self) -> bool:
        return self.response is not None


class RateLimiter:
    """Thread-safe limiter shared by every worker thread of a scan."""

    def __init__(self, max_per_second: float) -> None:
        self._interval = 1.0 / max_per_second if max_per_second > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def acquire(self) -> None:
        if self._interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            wait = self._next - now
            self._next = max(now, self._next) + self._interval
        if wait > 0:
            time.sleep(wait)


class _NoAuth(AuthBase):
    """Stops requests from silently attaching credentials from ~/.netrc."""

    def __call__(self, r):  # noqa: D401
        return r


def _scrub(text: str) -> str:
    """Trim a library error message down to something safe and readable."""
    text = re.sub(r"<[^>]*object at 0x[0-9a-fA-F]+>", "", text)
    text = re.sub(r"\(Caused by [^)]*\)?", "", text)
    return " ".join(text.split())[:240]


def _describe_error(exc: Exception, url: str, timeout: float) -> FetchError:
    err = _classify_error(exc, url, timeout)
    err.url = url
    return err


def _classify_error(exc: Exception, url: str, timeout: float) -> FetchError:
    parts = urlsplit(url)
    host = parts.hostname or url
    port = parts.port or (443 if parts.scheme == "https" else 80)
    blob = f"{type(exc).__name__} {exc!r}"

    if isinstance(exc, requests.exceptions.TooManyRedirects):
        return FetchError("redirects", f"The site redirected more than {MAX_REDIRECTS} times. It may be stuck in a redirect loop.")
    if isinstance(exc, requests.exceptions.SSLError):
        m = re.search(r"certificate verify failed: ([^(\"']+?)\s*(?:\(|\"|'|$)", blob)
        reason = m.group(1).strip().rstrip(".") if m else ""
        if reason or "CERTIFICATE_VERIFY_FAILED" in blob:
            reason = reason or "certificate verification failed"
            return FetchError("tls", f"The TLS certificate for {host} could not be verified: {reason}.", reason, cert_error=True)
        return FetchError("tls", f"A TLS/SSL error occurred while connecting to {host}: {_scrub(str(exc))[:120]}", _scrub(str(exc)))
    if isinstance(exc, requests.exceptions.Timeout) or "timed out" in blob.lower():
        return FetchError("timeout", f"The connection timed out after {timeout:g} seconds. Verify that the URL is correct and the target is reachable.")
    lowered = blob.lower()
    if any(s in lowered for s in ("name or service not known", "nameresolutionerror", "getaddrinfo failed",
                                  "temporary failure in name resolution", "nodename nor servname", "no address associated")):
        return FetchError("dns", f"Could not resolve the hostname '{host}'. Check the address for typos and that your network/DNS is working.")
    if "connection refused" in lowered or "actively refused" in lowered:
        return FetchError("refused", f"The connection to {host}:{port} was refused. The site may be down, or nothing is listening on that port.")
    if "connection reset" in lowered or "connectionreseterror" in lowered or "connection aborted" in lowered:
        return FetchError("reset", f"The connection to {host} was reset by the server before a response was received.")
    if isinstance(exc, requests.exceptions.InvalidURL) or isinstance(exc, requests.exceptions.MissingSchema):
        return FetchError("other", "The URL is not valid.")
    return FetchError("other", f"The request to {host} failed: {_scrub(str(exc))[:160] or type(exc).__name__}.")


def resolve_is_public(host: str, resolver: Callable = socket.getaddrinfo) -> Optional[bool]:
    """True if every address `host` resolves to is globally routable, False if
    any is private/loopback/link-local/reserved, None if it can't be resolved.

    Note: this lookup and the later connect are separate, so a hostile DNS
    server could answer differently the second time (DNS rebinding). This
    narrows the SSRF surface; it is not a sandbox.
    """
    try:
        for info in resolver(host, None, proto=socket.IPPROTO_TCP):
            ip = ipaddress.ip_address(info[4][0].split("%")[0])
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            if not ip.is_global:
                return False
        return True
    except (OSError, ValueError):
        return None


class HttpClient:
    def __init__(
        self,
        options: ScanOptions,
        *,
        allow_private: bool,
        cancel_event: Optional[threading.Event] = None,
        resolver: Callable = socket.getaddrinfo,
    ) -> None:
        self.options = options
        self.allow_private = allow_private
        self.cancel_event = cancel_event
        self.insecure_hosts: set[str] = set()  # hosts whose bad certificate we already reported
        self._resolver = resolver
        self._limiter = RateLimiter(options.rate_limit_per_second)
        self._count = 0
        self._lock = threading.Lock()
        self._public_cache: dict[str, Optional[bool]] = {}
        self._session = self._build_session()

    # -- setup ----------------------------------------------------------------

    def _build_session(self) -> requests.Session:
        s = requests.Session()
        s.headers.update({
            "User-Agent": self.options.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })
        s.auth = _NoAuth()
        s.cookies.set_policy(http.cookiejar.DefaultCookiePolicy(allowed_domains=[]))  # accept no cookies
        size = max(self.options.link_check_concurrency + 2, 10)
        adapter = HTTPAdapter(pool_connections=size, pool_maxsize=size, max_retries=0)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        return s

    @property
    def requests_made(self) -> int:
        return self._count

    def close(self) -> None:
        self._session.close()

    # -- guards ---------------------------------------------------------------

    def check_cancelled(self) -> None:
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise ScanCancelled()

    def host_is_public(self, host: str) -> Optional[bool]:
        """Cached `resolve_is_public`. See that function for the caveats."""
        with self._lock:
            if host in self._public_cache:
                return self._public_cache[host]
        verdict = resolve_is_public(host, self._resolver)
        with self._lock:
            self._public_cache[host] = verdict
        return verdict

    def _blocked(self, url: str) -> Optional[FetchError]:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return FetchError("blocked", "Only http:// and https:// URLs can be requested.", url=url)
        if not self.allow_private and self.host_is_public(parts.hostname) is False:
            return FetchError(
                "blocked",
                f"'{parts.hostname}' resolves to a private or internal address. It was not requested, "
                "because the scan target is a public site.",
                url=url,
            )
        return None

    # -- requests -------------------------------------------------------------

    def fetch(
        self,
        url: str,
        method: str = "GET",
        *,
        follow_redirects: bool = True,
        max_bytes: Optional[int] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> FetchResult:
        """Perform one logical request (following redirects if asked).

        `max_bytes` caps the body that is read; 0 means "headers only".
        """
        limit = self.options.max_body_bytes if max_bytes is None else max_bytes
        timeout = self.options.timeout
        started = time.monotonic()
        deadline = started + max(timeout * 3, 15)
        redirects: list[tuple[str, int]] = []
        current = url

        for _ in range(MAX_REDIRECTS + 1):
            self.check_cancelled()
            blocked = self._blocked(current)
            if blocked:
                return FetchResult(error=blocked)

            self._limiter.acquire()
            self.check_cancelled()
            with self._lock:
                self._count += 1
            host = urlsplit(current).hostname
            if host in self.insecure_hosts:  # we knowingly skip verification here (and report it), so keep the log quiet
                warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
            try:
                r = self._session.request(
                    method, current, timeout=(timeout, timeout), allow_redirects=False, stream=True,
                    headers=headers, verify=host not in self.insecure_hosts,
                )
            except Exception as exc:  # noqa: BLE001 - every failure is converted to a FetchError
                return FetchResult(error=_describe_error(exc, current, timeout))

            location = r.headers.get("Location")
            if follow_redirects and r.status_code in _REDIRECT_STATUSES and location:
                redirects.append((current, r.status_code))
                r.close()
                current = urljoin(current, location)
                continue

            try:
                body, truncated = self._read_body(r, method, limit, deadline)
                cookies = self._set_cookies(r)
                return FetchResult(response=Response(
                    url=current, status=r.status_code, headers=r.headers, set_cookies=cookies,
                    body=body, truncated=truncated, elapsed_ms=(time.monotonic() - started) * 1000.0,
                    redirects=redirects, encoding=_charset(r.headers.get("Content-Type", "")),
                ))
            except ScanCancelled:
                raise
            except Exception as exc:  # noqa: BLE001
                return FetchResult(error=_describe_error(exc, current, timeout))
            finally:
                r.close()

        return FetchResult(error=_describe_error(requests.exceptions.TooManyRedirects(), current, timeout))

    def _read_body(self, r: requests.Response, method: str, limit: int, deadline: float) -> tuple[bytes, bool]:
        if method == "HEAD" or limit <= 0:
            return b"", False
        chunks: list[bytes] = []
        total = 0
        for chunk in r.iter_content(CHUNK_SIZE):
            self.check_cancelled()
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                return b"".join(chunks)[:limit], True
            if time.monotonic() > deadline:
                return b"".join(chunks), True
        return b"".join(chunks), False

    @staticmethod
    def _set_cookies(r: requests.Response) -> list[str]:
        try:
            return list(r.raw.headers.getlist("Set-Cookie"))
        except AttributeError:
            value = r.headers.get("Set-Cookie")
            return [value] if value else []


def _charset(content_type: str) -> Optional[str]:
    m = re.search(r"charset=([\w.-]+)", content_type, re.IGNORECASE)
    if not m:
        return None
    name = m.group(1).strip("\"'")
    try:
        "".encode(name)
    except LookupError:
        return None
    return name
