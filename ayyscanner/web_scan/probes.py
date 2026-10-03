"""Small, read-only probes of well-known locations.

Each probe is one or two plain GET requests. A file counts as present only if
its *content* has the expected format - an HTTP 200 alone is not enough,
because many sites answer every path with a 200 "not found" page.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from ayyscanner.models import Severity
from ayyscanner.web_scan.context import ScanContext
from ayyscanner.web_scan.urls import swap_scheme

_PROBE_BYTES = 64 * 1024
_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", re.M)
_SECRET_KEY = re.compile(r"PASS|SECRET|TOKEN|KEY|PRIVATE|CREDENTIAL", re.I)


def _looks_like_html(body: bytes, content_type: str) -> bool:
    return "html" in content_type.lower() or body.lstrip()[:1] == b"<" and b"<html" in body[:2048].lower()


def check_http_redirect(ctx: ScanContext) -> None:
    if not ctx.options.check_http_to_https_redirect:
        ctx.note_check("HTTP to HTTPS redirect", "skipped", "disabled in options")
        return
    if urlsplit(ctx.url).scheme != "https":
        ctx.note_check("HTTP to HTTPS redirect", "skipped", "target is not served over HTTPS")
        return
    http_url = swap_scheme(ctx.url, "http")
    if http_url is None:
        ctx.note_check("HTTP to HTTPS redirect", "skipped", "target uses a non-standard port")
        return
    res = ctx.client.fetch(http_url, "GET", max_bytes=0)
    if not res.ok:
        # Port 80 closed or filtered: nothing is served over HTTP, which is not a finding.
        ctx.facts["http_redirects_to_https"] = None
        ctx.note_check("HTTP to HTTPS redirect", "ran", f"plain HTTP not reachable ({res.error.kind if res.error else 'error'})")
        return
    redirects = urlsplit(res.response.url).scheme == "https"
    ctx.facts["http_redirects_to_https"] = redirects
    ctx.note_check("HTTP to HTTPS redirect", "ran")
    if not redirects:
        ctx.add("WEB-TLS-NOREDIRECT", target=http_url, parameter="scheme",
                evidence=f"GET {http_url} -> HTTP {res.response.status}; final URL: {res.response.url}")


def check_well_known(ctx: ScanContext) -> None:
    if not ctx.options.check_well_known_files:
        ctx.note_check("robots.txt / sitemap.xml / security.txt", "skipped", "disabled in options")
        return
    origin = urljoin(ctx.url, "/")

    def get(path: str):
        res = ctx.client.fetch(urljoin(origin, path), "GET", max_bytes=_PROBE_BYTES)
        if not res.ok:
            ctx.warn(f"Could not check {path}: {res.error.message if res.error else 'request failed'}")
            return None, None
        return res.response, res.response.status

    robots, status = get("/robots.txt")
    robots_ok = bool(robots and status == 200 and not _looks_like_html(robots.body, robots.headers.get("Content-Type", "")))
    sitemap_declared = bool(robots_ok and re.search(r"^\s*sitemap:", robots.text, re.I | re.M))
    ctx.facts["robots_txt"] = {"present": robots_ok if robots is not None else None, "url": urljoin(origin, "/robots.txt")}
    if robots is not None and not robots_ok and status in (404, 410, 200):
        ctx.add("SEO-ROBOTS-TXT-MISSING", target=urljoin(origin, "/robots.txt"), evidence=f"GET /robots.txt -> HTTP {status}")

    sitemap, status = get("/sitemap.xml")
    sitemap_ok = bool(sitemap and status == 200 and re.search(rb"<(urlset|sitemapindex)\b", sitemap.body[:4096]))
    ctx.facts["sitemap_xml"] = {"present": sitemap_ok if sitemap is not None else None, "declared_in_robots": sitemap_declared}
    if sitemap is not None and not sitemap_ok and not sitemap_declared and status in (404, 410, 200):
        ctx.add("SEO-SITEMAP-MISSING", target=urljoin(origin, "/sitemap.xml"),
                evidence=f"GET /sitemap.xml -> HTTP {status}; robots.txt does not declare a Sitemap either")

    sectxt, status = get("/.well-known/security.txt")
    present = bool(sectxt and status == 200 and re.search(rb"^\s*contact\s*:", sectxt.body, re.I | re.M))
    ctx.facts["security_txt"] = {"present": present if sectxt is not None else None}
    if sectxt is not None and not present and status in (404, 410, 200):
        ctx.add("WEB-SECURITY-TXT-MISSING", target=urljoin(origin, "/.well-known/security.txt"),
                evidence=f"GET /.well-known/security.txt -> HTTP {status}, no 'Contact:' field found")
    ctx.note_check("robots.txt / sitemap.xml / security.txt", "ran")


def check_sensitive_files(ctx: ScanContext) -> None:
    if not ctx.options.check_sensitive_files:
        ctx.note_check("Sensitive file exposure (.git, .env, phpinfo)", "skipped", "disabled in options")
        return
    origin = urljoin(ctx.url, "/")
    exposed: list[str] = []

    res = ctx.client.fetch(urljoin(origin, "/.git/HEAD"), "GET", max_bytes=1024, follow_redirects=False)
    if res.ok and res.response.status == 200 and re.match(rb"^ref:\s+refs/", res.response.body):
        head = res.response.text.strip().splitlines()[0][:80]
        exposed.append(".git/HEAD")
        ctx.add("WEB-EXPOSED-GIT", target=urljoin(origin, "/.git/HEAD"), parameter="/.git/HEAD",
                evidence=f"GET /.git/HEAD -> HTTP 200; content is a valid Git HEAD reference: '{head}'")

    res = ctx.client.fetch(urljoin(origin, "/.env"), "GET", max_bytes=_PROBE_BYTES, follow_redirects=False)
    if res.ok and res.response.status == 200 and not _looks_like_html(res.response.body, res.response.headers.get("Content-Type", "")):
        keys = _ENV_LINE.findall(res.response.text)
        if len(keys) >= 2:
            exposed.append(".env")
            secret_like = [k for k in keys if _SECRET_KEY.search(k)]
            overrides = {"severity": Severity.CRITICAL} if secret_like else {}
            ctx.add("WEB-EXPOSED-ENV", target=urljoin(origin, "/.env"), parameter="/.env", **overrides,
                    evidence=(f"GET /.env -> HTTP 200; {len(keys)} KEY=VALUE line(s). Keys: {', '.join(keys[:10])}"
                              f"{' …' if len(keys) > 10 else ''}. Values redacted."
                              + (f" {len(secret_like)} key name(s) look like secrets." if secret_like else "")))

    res = ctx.client.fetch(urljoin(origin, "/phpinfo.php"), "GET", max_bytes=_PROBE_BYTES, follow_redirects=False)
    if res.ok and res.response.status == 200 and re.search(r"<title>\s*phpinfo\(\)|PHP Version\s+\d", res.response.text, re.I):
        exposed.append("phpinfo.php")
        ctx.add("WEB-EXPOSED-PHPINFO", target=urljoin(origin, "/phpinfo.php"), parameter="/phpinfo.php",
                evidence="GET /phpinfo.php -> HTTP 200; body contains the phpinfo() page signature")

    ctx.facts["exposed_files"] = exposed
    ctx.note_check("Sensitive file exposure (.git, .env, phpinfo)", "ran")
