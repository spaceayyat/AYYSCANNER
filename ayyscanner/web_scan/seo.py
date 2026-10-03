"""On-page SEO / quality checks. These are reported separately from security
findings and never count toward the headline security severity totals."""

from __future__ import annotations

import json
import re
from typing import Any

from bs4 import BeautifulSoup

from ayyscanner.web_scan.context import ScanContext
from ayyscanner.web_scan.page import PageInfo, meta_content

TITLE_MIN, TITLE_MAX = 10, 60
DESC_MIN, DESC_MAX = 50, 160
SAMPLE = 10


def _check_title(ctx: ScanContext, page: PageInfo, facts: dict[str, Any]) -> None:
    facts.update(title=page.title, title_length=page.title_length)
    if page.title is None:
        facts["title_status"] = "missing"
        ctx.add("SEO-TITLE-MISSING", evidence="No <title> element found in the document.")
    elif page.title == "":
        facts["title_status"] = "empty"
        ctx.add("SEO-TITLE-EMPTY", evidence="<title></title>")
    elif page.title_length < TITLE_MIN:
        facts["title_status"] = "too_short"
        ctx.add("SEO-TITLE-TOO-SHORT", evidence=f"Title is {page.title_length} characters: {page.title!r}")
    elif page.title_length > TITLE_MAX:
        facts["title_status"] = "too_long"
        ctx.add("SEO-TITLE-TOO-LONG", evidence=f"Title is {page.title_length} characters: {page.title!r}")
    else:
        facts["title_status"] = "ok"


def _check_description(ctx: ScanContext, page: PageInfo, facts: dict[str, Any]) -> None:
    desc = page.meta_description
    facts.update(meta_description=desc, meta_description_length=page.meta_description_length)
    if desc is None:
        facts["meta_description_status"] = "missing"
        ctx.add("SEO-METADESC-MISSING", evidence='No <meta name="description"> tag found.')
    elif desc == "":
        facts["meta_description_status"] = "empty"
        ctx.add("SEO-METADESC-EMPTY", evidence='<meta name="description" content="">')
    elif page.meta_description_length < DESC_MIN:
        facts["meta_description_status"] = "too_short"
        ctx.add("SEO-METADESC-TOO-SHORT", evidence=f"{page.meta_description_length} characters: {desc!r}")
    elif page.meta_description_length > DESC_MAX:
        facts["meta_description_status"] = "too_long"
        ctx.add("SEO-METADESC-TOO-LONG", evidence=f"{page.meta_description_length} characters")
    else:
        facts["meta_description_status"] = "ok"


def _check_headings(ctx: ScanContext, soup: BeautifulSoup, facts: dict[str, Any]) -> None:
    h1 = [t.get_text(" ", strip=True) for t in soup.find_all("h1")]
    facts.update(h1_count=len(h1), h1_texts=h1[:SAMPLE])
    if not h1:
        ctx.add("SEO-H1-MISSING", evidence="No <h1> element found in the document.")
    elif len(h1) > 1:
        ctx.add("SEO-H1-MULTIPLE", evidence=f"{len(h1)} <h1> elements: " + "; ".join(h1[:5])[:300])


def _check_images(ctx: ScanContext, soup: BeautifulSoup, facts: dict[str, Any]) -> None:
    images = soup.find_all("img")
    # alt="" is valid (marks a decorative image); only a *missing* attribute is a problem.
    missing = [i.get("src") or i.get("data-src") or "(no src)" for i in images if i.get("alt") is None]
    facts.update(images_total=len(images), images_missing_alt=len(missing), images_missing_alt_sample=missing[:SAMPLE])
    if missing:
        ctx.add("SEO-IMG-ALT-MISSING", parameter="img[alt]",
                evidence=f"{len(missing)} of {len(images)} <img> tag(s) have no alt attribute, e.g. " + "; ".join(missing[:5])[:300])


def _check_canonical(ctx: ScanContext, page: PageInfo, facts: dict[str, Any]) -> None:
    facts["canonical_url"] = page.canonical_url
    if not page.canonical_url:
        facts["canonical_status"] = "missing"
        ctx.add("SEO-CANONICAL-MISSING", evidence='No <link rel="canonical"> found.')
    elif page.canonical_url.rstrip("/") != page.final_url.rstrip("/"):
        facts["canonical_status"] = "points_elsewhere"
        ctx.add("SEO-CANONICAL-MISMATCH", evidence=f"canonical={page.canonical_url}  page={page.final_url}")
    else:
        facts["canonical_status"] = "present"


def _check_robots_meta(ctx: ScanContext, soup: BeautifulSoup, facts: dict[str, Any]) -> None:
    content = meta_content(soup, "name", "robots")
    directives = {d.strip().lower() for d in (content or "").split(",") if d.strip()}
    facts.update(robots_meta=content, robots_noindex="noindex" in directives, robots_nofollow="nofollow" in directives)
    if "noindex" in directives:
        ctx.add("SEO-ROBOTS-NOINDEX", parameter="meta[name=robots]", evidence=f'<meta name="robots" content="{content}">')


def _check_social_and_structured(soup: BeautifulSoup, facts: dict[str, Any]) -> None:
    og = {k: meta_content(soup, "property", f"og:{k}") for k in ("title", "description", "image", "url", "type")}
    tw = {k: meta_content(soup, "name", f"twitter:{k}") for k in ("card", "title", "description", "image")}
    facts.update(open_graph=og, open_graph_complete=all(og[k] for k in ("title", "description", "image")),
                 twitter_card=tw, twitter_card_complete=all(tw[k] for k in ("card", "title", "description")))

    types: list[str] = []
    blocks = 0
    for script in soup.find_all("script", attrs={"type": re.compile(r"^application/ld\+json$", re.I)}):
        try:
            data = json.loads(script.string or script.get_text() or "")
        except ValueError:
            continue
        blocks += 1
        for entry in data if isinstance(data, list) else [data]:
            if isinstance(entry, dict) and "@type" in entry:
                t = entry["@type"]
                types.extend(str(x) for x in (t if isinstance(t, list) else [t]))
    microdata = soup.find(attrs={"itemscope": True}) is not None
    facts.update(structured_data_blocks=blocks, structured_data_types=sorted(set(types)),
                 structured_data_present=blocks > 0 or microdata)


def run_seo_checks(ctx: ScanContext, page: PageInfo, soup: BeautifulSoup) -> dict[str, Any]:
    facts: dict[str, Any] = {}
    _check_title(ctx, page, facts)
    _check_description(ctx, page, facts)
    _check_headings(ctx, soup, facts)
    _check_images(ctx, soup, facts)
    _check_canonical(ctx, page, facts)
    _check_robots_meta(ctx, soup, facts)
    _check_social_and_structured(soup, facts)
    facts["viewport_present"] = soup.find("meta", attrs={"name": re.compile("^viewport$", re.I)}) is not None
    if not facts["viewport_present"]:
        ctx.add("SEO-VIEWPORT-MISSING", evidence='No <meta name="viewport"> tag found.')
    return facts
