"""Builds the `PageInfo` record (facts about the one page that was fetched)."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Optional
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from ayyscanner.web_scan.http import Response

_SKIPPED_TEXT_PARENTS = {"script", "style", "noscript", "template", "head", "title"}
_WORD_RE = re.compile(r"[^\W_]+(?:'[^\W_]+)?", re.UNICODE)


def clean_text(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return re.sub(r"\s+", " ", value).strip()


def meta_content(soup: BeautifulSoup, attr: str, name: str) -> Optional[str]:
    tag = soup.find("meta", attrs={attr: re.compile(f"^{re.escape(name)}$", re.I)})
    if tag is not None and tag.get("content") is not None:
        return clean_text(tag.get("content"))
    return None


def count_words(soup: BeautifulSoup) -> int:
    """Count visible words WITHOUT modifying the tree (later checks still need
    the <script> and <style> elements)."""
    body = soup.body or soup
    total = 0
    for text in body.find_all(string=True):
        if text.parent is not None and text.parent.name in _SKIPPED_TEXT_PARENTS:
            continue
        total += len(_WORD_RE.findall(str(text)))
    return total


@dataclass
class PageInfo:
    requested_url: str
    final_url: str
    scheme: str
    is_https: bool
    status_code: int
    response_time_ms: float
    content_type: Optional[str]
    charset: Optional[str]
    page_size_bytes: int
    truncated: bool
    is_html: bool
    server: Optional[str]
    redirect_chain: list[dict[str, Any]] = field(default_factory=list)
    title: Optional[str] = None
    title_length: int = 0
    meta_description: Optional[str] = None
    meta_description_length: int = 0
    canonical_url: Optional[str] = None
    html_lang: Optional[str] = None
    word_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_page_info(requested_url: str, resp: Response, soup: Optional[BeautifulSoup], is_html: bool) -> PageInfo:
    ctype = resp.headers.get("Content-Type")
    page = PageInfo(
        requested_url=requested_url,
        final_url=resp.url,
        scheme=urlsplit(resp.url).scheme,
        is_https=urlsplit(resp.url).scheme == "https",
        status_code=resp.status,
        response_time_ms=round(resp.elapsed_ms, 1),
        content_type=ctype,
        charset=resp.encoding,
        page_size_bytes=len(resp.body),
        truncated=resp.truncated,
        is_html=is_html,
        server=resp.headers.get("Server"),
        redirect_chain=[{"url": u, "status": s} for u, s in resp.redirects],
    )
    if soup is None:
        return page

    if soup.title is not None:
        page.title = clean_text(soup.title.get_text()) or ""
        page.title_length = len(page.title)
    page.meta_description = meta_content(soup, "name", "description")
    page.meta_description_length = len(page.meta_description or "")

    canonical = soup.find("link", rel=lambda v: bool(v) and "canonical" in (v if isinstance(v, list) else [v]))
    if canonical is not None and canonical.get("href"):
        page.canonical_url = urljoin(resp.url, canonical["href"].strip())

    html_tag = soup.find("html")
    if html_tag is not None and html_tag.get("lang"):
        page.html_lang = html_tag["lang"].strip()

    if not page.charset:
        meta = soup.find("meta", charset=True)
        if meta is not None:
            page.charset = meta["charset"]
        else:
            ct_meta = soup.find("meta", attrs={"http-equiv": re.compile("^content-type$", re.I)})
            m = re.search(r"charset=([\w.-]+)", (ct_meta or {}).get("content", ""), re.I) if ct_meta else None
            page.charset = m.group(1) if m else None
    page.word_count = count_words(soup)
    return page
