"""Link extraction and (optional) link status checking."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urldefrag, urljoin, urlsplit

from bs4 import BeautifulSoup

from ayyscanner.web_scan.context import ScanContext
from ayyscanner.web_scan.http import ScanCancelled
from ayyscanner.web_scan.urls import is_same_site

_NON_HTTP = ("mailto:", "tel:", "javascript:", "sms:", "fax:", "data:", "blob:")
# Statuses servers commonly return to automated clients on perfectly good pages.
_RESTRICTED = {401, 403, 429, 999}


@dataclass
class LinkRecord:
    url: str
    anchor_text: str
    link_type: str  # internal | external | other
    occurrences: int = 1
    checked: bool = False
    status_code: Optional[int] = None
    is_broken: bool = False
    is_redirect: bool = False
    redirect_target: Optional[str] = None
    note: Optional[str] = None  # why it was skipped / why it is not counted as broken
    error: Optional[str] = None


@dataclass
class LinksSummary:
    total_found: int = 0
    unique_count: int = 0
    duplicate_count: int = 0
    internal_count: int = 0
    external_count: int = 0
    other_count: int = 0
    checked_count: int = 0
    broken_count: int = 0
    redirect_count: int = 0
    items: list[LinkRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def extract_links(base_url: str, soup: BeautifulSoup) -> LinksSummary:
    """Collect every <a href>, resolved, classified and de-duplicated. No network."""
    summary = LinksSummary()
    seen: dict[str, LinkRecord] = {}
    base_tag = soup.find("base", href=True)
    base = urljoin(base_url, base_tag["href"]) if base_tag is not None else base_url

    for anchor in soup.find_all("a"):
        href = (anchor.get("href") or "").strip()
        if not href:
            continue
        summary.total_found += 1
        text = anchor.get_text(" ", strip=True) or "(no link text)"

        if href.startswith("#") or href.lower().startswith(_NON_HTTP):
            resolved, link_type = href, "other"
        else:
            resolved, _ = urldefrag(urljoin(base, href))
            scheme = urlsplit(resolved).scheme
            if scheme not in ("http", "https"):
                link_type = "other"
            else:
                link_type = "internal" if is_same_site(base_url, resolved) else "external"

        if resolved in seen:
            seen[resolved].occurrences += 1
            summary.duplicate_count += 1
            continue
        record = LinkRecord(url=resolved, anchor_text=text[:200], link_type=link_type)
        seen[resolved] = record
        summary.items.append(record)
        setattr(summary, f"{link_type}_count", getattr(summary, f"{link_type}_count") + 1)

    summary.unique_count = len(summary.items)
    return summary


def _check_one(ctx: ScanContext, record: LinkRecord) -> None:
    client = ctx.client
    try:
        res = client.fetch(record.url, "HEAD", max_bytes=0)
        blocked = res.error is not None and res.error.kind == "blocked"
        if not blocked and (not res.ok or res.response.status in (405, 501)):
            res = client.fetch(record.url, "GET", max_bytes=0)  # some servers reject HEAD
    except ScanCancelled:
        return

    if not res.ok:
        if res.error and res.error.kind == "blocked":
            record.note = "Skipped: " + res.error.message
            return
        record.checked, record.is_broken = True, True
        record.error = res.error.message if res.error else "Request failed"
        return

    resp = res.response
    record.checked = True
    record.status_code = resp.status
    if resp.redirects:
        record.is_redirect, record.redirect_target = True, resp.url
    if resp.status in _RESTRICTED:
        record.note = f"HTTP {resp.status}: the server refused or throttled an automated request; the link may still work in a browser."
    else:
        record.is_broken = resp.status >= 400


def check_links(
    ctx: ScanContext, summary: LinksSummary, progress: Optional[Callable[[int, int], None]] = None
) -> None:
    opts = ctx.options
    candidates = [
        r for r in summary.items
        if (r.link_type == "internal" and opts.check_internal_links) or (r.link_type == "external" and opts.check_external_links)
    ][: opts.max_links_to_check]
    skipped = sum(1 for r in summary.items if r.link_type in ("internal", "external")) - len(candidates)

    if candidates:
        done = 0
        with ThreadPoolExecutor(max_workers=opts.link_check_concurrency) as pool:
            futures = [pool.submit(_check_one, ctx, r) for r in candidates]
            for future in as_completed(futures):
                if future.cancelled():  # queued work dropped after Stop was pressed
                    continue
                future.result()
                done += 1
                if progress:
                    progress(done, len(candidates))
                if ctx.client.cancel_event is not None and ctx.client.cancel_event.is_set():
                    for f in futures:
                        f.cancel()
    ctx.client.check_cancelled()

    summary.checked_count = sum(r.checked for r in summary.items)
    summary.broken_count = sum(r.is_broken for r in summary.items)
    summary.redirect_count = sum(r.is_redirect for r in summary.items)
    if skipped > 0:
        ctx.warn(f"{skipped} link(s) were not checked because the limit is {opts.max_links_to_check} links per scan.")
    blocked = sum(1 for r in summary.items if r.note and r.note.startswith("Skipped"))
    if blocked:
        ctx.warn(f"{blocked} link(s) were not checked because they point to private/internal addresses.")

    broken = [r for r in summary.items if r.is_broken]
    if broken:
        ctx.add("LINK-BROKEN", parameter="a[href]", evidence="; ".join(
            f"{r.url} -> {('HTTP ' + str(r.status_code)) if r.status_code else (r.error or 'error')}" for r in broken[:10])
            + (f"; … and {len(broken) - 10} more" if len(broken) > 10 else ""),
            description=f"{len(broken)} link(s) on the page returned an error status or could not be reached.")
    redirects = [r for r in summary.items if r.is_redirect and not r.is_broken]
    if redirects:
        ctx.add("LINK-REDIRECT", parameter="a[href]", evidence="; ".join(f"{r.url} -> {r.redirect_target}" for r in redirects[:5])
                + (f"; … and {len(redirects) - 5} more" if len(redirects) > 5 else ""),
                description=f"{len(redirects)} link(s) on the page redirect to a different URL.")
