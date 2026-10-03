"""The web scanner.

    from ayyscanner.web_scan import run_web_scan
    result = run_web_scan("https://example.com")

`run_web_scan` is synchronous and blocking. Callers that need a responsive UI
run it on a worker thread and pass a `threading.Event` for cancellation and a
`progress_cb(percent, stage, message)` for status updates.

Scope: one page, analysed passively, plus a handful of plain GET requests to
well-known locations. JavaScript is not executed, nothing is submitted, and no
attack payloads are sent.
"""

from __future__ import annotations

import logging
import socket
import threading
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from ayyscanner.models import OUTCOME_FAILED, OUTCOME_PARTIAL, ScanResult
from ayyscanner.web_scan import probes, security, seo
from ayyscanner.web_scan.context import ScanContext
from ayyscanner.web_scan.http import HttpClient, ScanCancelled, resolve_is_public
from ayyscanner.web_scan.links import check_links, extract_links
from ayyscanner.web_scan.options import ScanOptions
from ayyscanner.web_scan.page import build_page_info
from ayyscanner.web_scan.urls import InvalidUrlError, host_key, parse_target, swap_scheme

log = logging.getLogger("ayyscanner")

ProgressCallback = Optional[Callable[[int, str, str], None]]

SCOPE_NOTES = [
    "One page (the target URL) is analysed; the site is not crawled.",
    "Analysis is passive: response headers, cookies, TLS and HTML are inspected, plus a few plain GET requests to well-known locations.",
    "JavaScript is not executed, so content rendered client-side is not seen.",
    "No forms are submitted, no logins are attempted and no attack payloads are sent.",
    "A clean report does not prove the site is secure; it only means these specific checks found nothing.",
]

__all__ = ["run_web_scan", "ScanOptions", "InvalidUrlError"]


def _fail(result: ScanResult, message: str) -> ScanResult:
    result.outcome = OUTCOME_FAILED
    result.errors.insert(0, message)
    result.mark_finished()
    return result


def _run_stage(ctx: ScanContext, name: str, fn: Callable[..., Any], *args: Any, notes: bool = True) -> None:
    """Run one group of checks. A bug or unexpected page structure in one stage
    is reported in the results, and the remaining stages still run."""
    try:
        fn(*args)
        if notes:
            ctx.note_check(name, "ran")
    except ScanCancelled:
        raise
    except Exception:  # noqa: BLE001
        log.exception("Stage %r failed while scanning %s", name, ctx.url)
        ctx.note_check(name, "failed", "unexpected internal error; see the server log")
        ctx.warn(f"The '{name}' checks hit an unexpected error and were skipped.")
        ctx.result.outcome = OUTCOME_PARTIAL


def _fetch_target(ctx: ScanContext, url: str, scheme_defaulted: bool):
    """Fetch the target, recovering from a bad certificate or a wrong guess of
    'https' when the user typed no scheme. Returns (FetchResult, url_used)."""
    client = ctx.client
    res = client.fetch(url)

    if not res.ok and res.error.cert_error:
        failed = res.error.url or url
        parts = urlsplit(failed)
        host, port = parts.hostname or "", parts.port or 443
        security.report_cert_problem(ctx, host, port, res.error.detail)
        client.insecure_hosts.add(host)
        ctx.warn(f"The TLS certificate for {host} could not be verified ({res.error.detail}). "
                 "The scan continued without certificate verification for this host.")
        res = client.fetch(url)

    if not res.ok and scheme_defaulted and res.error.kind != "dns" and urlsplit(url).scheme == "https":
        alt = swap_scheme(url, "http", any_port=True)
        if alt:
            retry = client.fetch(alt)
            if retry.ok:
                ctx.warn(f"https:// could not be reached ({res.error.message}) so http:// was scanned instead.")
                return retry, alt
    return res, url


def run_web_scan(
    raw_url: str,
    options: Optional[ScanOptions] = None,
    progress_cb: ProgressCallback = None,
    cancel_event: Optional[threading.Event] = None,
    resolver: Callable = socket.getaddrinfo,
) -> ScanResult:
    options = options or ScanOptions()

    def report(percent: int, stage: str, message: str) -> None:
        if progress_cb:
            progress_cb(percent, stage, message)

    result = ScanResult(scan_type="web", target=(raw_url or "").strip())
    try:
        target = parse_target(raw_url)
    except InvalidUrlError as exc:
        return _fail(result, str(exc))
    result.target = target.url

    # Scanning your own local/private site is a normal use, so a private *target*
    # is allowed. Links found on the page may then reach private addresses too;
    # for a public target they may not (see HttpClient).
    allow_private = resolve_is_public(urlsplit(target.url).hostname or "", resolver) is False
    client = HttpClient(options, allow_private=allow_private, cancel_event=cancel_event, resolver=resolver)
    ctx = ScanContext(result=result, client=client, options=options, url=target.url)

    try:
        report(4, "connecting", f"Connecting to {target.url} …")
        res, url = _fetch_target(ctx, target.url, target.scheme_defaulted)
        if not res.ok:
            return _fail(result, res.error.message)
        resp = res.response
        ctx.url = resp.url
        result.target = url
        is_https = urlsplit(resp.url).scheme == "https"
        if host_key(resp.url) != host_key(url):
            ctx.warn(f"The target redirected to a different host ({urlsplit(resp.url).hostname}); results describe that host.")

        report(18, "parsing", "Reading the response …")
        ctype = (resp.headers.get("Content-Type") or "").lower()
        is_html = "html" in ctype or (not ctype and resp.body.lstrip()[:1] == b"<")
        soup: Optional[BeautifulSoup] = None
        if is_html:
            try:
                soup = BeautifulSoup(resp.body, "html.parser")
            except Exception:  # noqa: BLE001 - malformed markup must not abort the scan
                log.exception("HTML parsing failed for %s", resp.url)
                ctx.warn("The page could not be parsed as HTML, so HTML-based checks were skipped.")
                is_html = False
        page = build_page_info(url, resp, soup, is_html)
        result.metadata["page"] = page.to_dict()

        if resp.status >= 400:
            ctx.add("PAGE-HTTP-ERROR", evidence=f"HTTP {resp.status} returned for {resp.url}")
            ctx.warn(f"The target returned HTTP {resp.status}. Findings describe that error response, which may differ from the real site.")
        if resp.truncated:
            ctx.add("PAGE-TRUNCATED", evidence=f"Only the first {len(resp.body):,} bytes of the response were analysed.")
        if not is_html:
            ctx.add("PAGE-NOT-HTML", evidence=f"Content-Type: {page.content_type or '(none)'}")
            ctx.note_check("HTML content checks (mixed content, forms, scripts, SEO, links)", "skipped", "response is not HTML")

        report(30, "headers", "Checking headers, cookies and TLS …")
        _run_stage(ctx, "HTTPS usage", security.check_https, ctx, is_https)
        _run_stage(ctx, "Security headers", security.check_headers, ctx, resp, is_https)
        _run_stage(ctx, "Server banners", security.check_banners, ctx, resp)
        _run_stage(ctx, "Cookie attributes", security.check_cookies, ctx, resp, is_https)
        _run_stage(ctx, "TLS certificate and protocol", security.check_tls, ctx, notes=False)
        report(42, "cors", "Checking CORS policy …")
        _run_stage(ctx, "CORS policy", security.check_cors, ctx, resp, notes=False)

        if soup is not None:
            report(50, "content", "Analysing page content …")
            _run_stage(ctx, "Mixed content", security.check_mixed_content, ctx, soup, is_https)
            _run_stage(ctx, "Forms", security.check_forms, ctx, soup, is_https)
            _run_stage(ctx, "Third-party scripts (SRI)", security.check_third_party_scripts, ctx, soup)
            _run_stage(ctx, "Error-message disclosure", security.check_info_disclosure, ctx, resp.text)

        report(58, "probes", "Probing well-known files …")
        _run_stage(ctx, "HTTP to HTTPS redirect", probes.check_http_redirect, ctx, notes=False)
        _run_stage(ctx, "robots.txt / sitemap.xml / security.txt", probes.check_well_known, ctx, notes=False)
        _run_stage(ctx, "Sensitive file exposure (.git, .env, phpinfo)", probes.check_sensitive_files, ctx, notes=False)

        seo_facts: dict[str, Any] = {}
        if soup is not None:
            report(68, "seo", "Running SEO checks …")

            def run_seo() -> None:
                seo_facts.update(seo.run_seo_checks(ctx, page, soup))

            _run_stage(ctx, "SEO and page quality", run_seo)

            report(72, "links", "Extracting links …")
            links = extract_links(page.final_url, soup)
            result.metadata["links"] = links.to_dict()
            if options.check_internal_links or options.check_external_links:
                def link_progress(done: int, total: int) -> None:
                    report(72 + int(24 * done / max(total, 1)), "links", f"Checking links ({done}/{total}) …")

                report(72, "links", f"Checking up to {options.max_links_to_check} links …")
                _run_stage(ctx, "Link status", check_links, ctx, links, link_progress)
                result.metadata["links"] = links.to_dict()
            else:
                ctx.note_check("Link status", "skipped", "disabled in options")

        result.metadata.update(seo=seo_facts, technical=ctx.facts, checks=ctx.checks,
                               options=options.to_dict(), scope=SCOPE_NOTES)
        report(98, "finalizing", "Finishing up …")
    except ScanCancelled:
        result.outcome = OUTCOME_PARTIAL
        ctx.warn("The scan was stopped before it finished. Results are partial.")
        result.metadata.update(seo=result.metadata.get("seo", {}), technical=ctx.facts, checks=ctx.checks,
                               options=options.to_dict(), scope=SCOPE_NOTES)
    finally:
        result.requests_made = client.requests_made
        client.close()
        result.mark_finished()
    report(100, "done", "Scan complete.")
    return result
