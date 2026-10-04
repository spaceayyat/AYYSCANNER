"""Self-contained HTML report.

Everything is escaped, links are only emitted for http(s) URLs, and the page
carries a strict Content-Security-Policy that allows nothing except its own
inline stylesheet and script (pinned by hash). Content scraped from a scanned
site therefore cannot run code even if it slipped through escaping.
"""

from __future__ import annotations

import base64
import hashlib
import html as html_lib
import math
from typing import Any
from urllib.parse import urlsplit

from ayyscanner.models import Finding, ScanResult
from ayyscanner.report.common import (
    OUTCOME_LABELS,
    SEVERITY_ORDER,
    STATUS_HELP,
    STATUS_ORDER,
    fmt_time,
    key_observations,
    read_asset,
    safe_http_url,
    score_headline,
    score_notes,
)

REPORT_CSS = """
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 var(--font-sans)}
.wrap{max-width:1040px;margin:0 auto;padding:28px 20px 60px}
a{color:var(--brand)}
code,pre{font-family:var(--font-mono);font-size:12.5px}
h1,h2,h3,h4{line-height:1.25;margin:0}
h2{font-size:18px;margin:36px 0 14px;padding-bottom:8px;border-bottom:1px solid var(--border)}
.muted{color:var(--text-muted)}
.brand{display:flex;align-items:center;gap:14px}
.brand svg{width:44px;height:44px;flex:none}
.wordmark{font-weight:800;letter-spacing:.14em;font-size:13px}
.wordmark span{color:var(--brand)}
h1{font-size:26px;margin-top:2px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:18px 20px;box-shadow:var(--shadow)}
.hero{display:grid;gap:18px}
.target{font-family:var(--font-mono);font-size:14px;word-break:break-all}
.meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px 22px;margin-top:6px}
.meta-grid dt{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--text-faint)}
.meta-grid dd{margin:2px 0 0;font-weight:600;word-break:break-word}
.notice{border:1px solid var(--border-strong);border-left:4px solid var(--warn);border-radius:var(--radius-sm);padding:12px 16px;margin-top:18px;background:var(--surface)}
.notice.failed{border-left-color:var(--danger)}
.notice ul{margin:6px 0 0;padding-left:20px}
.tiles{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:8px 0 14px}
.tile{background:var(--surface);border:1px solid var(--border);border-top:3px solid var(--c);border-radius:var(--radius-sm);padding:10px 12px}
.tile b{display:block;font-size:28px;line-height:1.1;color:var(--c)}
.tile span{font-size:12px;color:var(--text-muted)}
.bar{width:100%;height:10px;border-radius:5px;background:var(--surface-3);display:block}
.bar rect{height:10px}
.bar-critical{fill:var(--sev-critical)}.bar-high{fill:var(--sev-high)}.bar-medium{fill:var(--sev-medium)}.bar-low{fill:var(--sev-low)}.bar-informational{fill:var(--sev-info)}
.sev-critical{--c:var(--sev-critical)}.sev-high{--c:var(--sev-high)}.sev-medium{--c:var(--sev-medium)}.sev-low{--c:var(--sev-low)}.sev-informational{--c:var(--sev-info)}
.statuses{display:flex;flex-wrap:wrap;gap:8px 22px;margin:14px 0 0;padding:0;list-style:none}
.statuses li{font-size:14px}
.obs{margin:10px 0 0;padding-left:20px}
.chip{display:inline-block;font-size:11.5px;font-weight:700;padding:2px 9px;border-radius:999px;border:1px solid var(--border-strong);color:var(--text-muted);white-space:nowrap}
.chip.sev{color:var(--c);background:color-mix(in srgb,var(--c) 13%,transparent);border-color:color-mix(in srgb,var(--c) 40%,transparent)}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px}
.filters button{font:inherit;font-size:13px;padding:5px 12px;border-radius:999px;border:1px solid var(--border-strong);background:var(--surface);color:var(--text);cursor:pointer}
.filters button[aria-pressed=true]{background:var(--brand-solid);border-color:var(--brand-solid);color:var(--on-brand)}
.finding{background:var(--surface);border:1px solid var(--border);border-left:5px solid var(--c);border-radius:var(--radius);padding:16px 20px;margin-bottom:14px;box-shadow:var(--shadow)}
.finding[hidden]{display:none}
.finding header{display:flex;flex-wrap:wrap;gap:6px 8px;align-items:center;margin-bottom:10px}
.finding h3{flex-basis:100%;font-size:17px;margin-top:4px}
.finding dl{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px 20px;margin:0 0 6px;padding:10px 12px;background:var(--surface-2);border-radius:var(--radius-sm)}
.finding dt{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--text-faint)}
.finding dd{margin:2px 0 0;word-break:break-word}
.finding h4{font-size:12px;text-transform:uppercase;letter-spacing:.07em;color:var(--text-muted);margin:14px 0 4px}
.finding p{margin:0}
pre{margin:6px 0 0;padding:10px 12px;background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm);white-space:pre-wrap;overflow-wrap:anywhere}
.finding ul{margin:0;padding-left:20px}
.finding footer{margin-top:14px;font-size:12px;color:var(--text-faint)}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top;word-break:break-word}
th{color:var(--text-muted);font-weight:600;width:1%;white-space:nowrap}
.scroll{overflow-x:auto}
.ok{color:var(--ok)}.bad{color:var(--danger)}.skip{color:var(--text-faint)}
details summary{cursor:pointer;color:var(--brand);font-weight:600}
.help{display:grid;gap:8px}
.foot{margin-top:40px;font-size:12.5px;color:var(--text-faint);text-align:center}
.score{border-top:4px solid var(--sc)}
.score-excellent{--sc:var(--score-excellent)}.score-good{--sc:var(--score-good)}.score-fair{--sc:var(--score-fair)}
.score-poor{--sc:var(--score-poor)}.score-critical{--sc:var(--score-critical)}.score-unrated{--sc:var(--score-unrated)}
.score-main{display:flex;gap:26px;align-items:center;flex-wrap:wrap}
.gauge{width:160px;height:160px;flex:none}
.gauge .track{fill:none;stroke:var(--surface-3);stroke-width:12}
.gauge .arc{fill:none;stroke:var(--sc);stroke-width:12;stroke-linecap:round}
.gauge .num{font:800 46px/1 var(--font-sans);fill:var(--text);text-anchor:middle}
.gauge .of{font:600 12px var(--font-sans);fill:var(--text-muted);text-anchor:middle;letter-spacing:.06em}
.score-text{flex:1 1 280px;min-width:0}
.score-text .verdict{font-size:22px;font-weight:800;color:var(--sc)}
.score-text p{color:var(--text-muted);margin:6px 0 0}
.score h3{font-size:15px;margin:20px 0 0}.score table{margin-top:10px}.score td.pts{font-family:var(--font-mono);font-weight:700;white-space:nowrap;color:var(--c)}
.score .note{border-left:3px solid var(--border-strong);padding-left:12px;color:var(--text-muted);font-size:13.5px;margin:10px 0 0}
@media print{.score{break-inside:avoid}}
@media (max-width:720px){.tiles{grid-template-columns:repeat(2,1fr)}}
@media print{:root{color-scheme:light}body{background:#fff}.filters{display:none}.finding{break-inside:avoid;box-shadow:none}.wrap{padding:0}}
"""

REPORT_JS = """
document.querySelectorAll('.filters button').forEach(function(btn){
  btn.addEventListener('click',function(){
    var f=btn.getAttribute('data-filter');
    document.querySelectorAll('.filters button').forEach(function(b){b.setAttribute('aria-pressed',b===btn?'true':'false')});
    document.querySelectorAll('article.finding[data-sev]').forEach(function(a){
      a.hidden=!(f==='all'||a.getAttribute('data-sev')===f||a.getAttribute('data-status')===f);
    });
  });
});
"""


def esc(value: Any) -> str:
    return html_lib.escape("" if value is None else str(value), quote=True)


def _ref_label(url: str) -> str:
    parts = urlsplit(url)
    if "cwe.mitre.org" in parts.netloc:
        return "MITRE CWE-" + parts.path.rsplit("/", 1)[-1].removesuffix(".html")
    if parts.netloc == "owasp.org" and parts.path.startswith("/Top10/"):
        return "OWASP Top 10: " + parts.path.strip("/").split("/")[-1].replace("_", " ").replace("-", " ")
    return parts.netloc + parts.path.rstrip("/")


def _slug(text: str) -> str:
    return text.lower().replace(" ", "-")


def _link_or_text(url: str) -> str:
    safe = safe_http_url(url)
    return f'<a href="{esc(safe)}" rel="noopener noreferrer" target="_blank">{esc(_ref_label(safe))}</a>' if safe else esc(url)


def _finding_card(f: Finding, result: ScanResult, index: int) -> str:
    meta: list[tuple[str, str]] = []
    if f.target:
        meta.append(("Affected URL / endpoint", f"<code>{esc(f.target)}</code>"))
    if f.parameter:
        meta.append(("Parameter", f"<code>{esc(f.parameter)}</code>"))
    class_bits = [b for b in (f.cwe, f.owasp) if b]
    if class_bits:
        meta.append(("Classification", esc(" · ".join(class_bits))))
    meta.append(("Finding ID", f"<code>{esc(f.id)}</code>"))
    meta_html = "".join(f"<div><dt>{k}</dt><dd>{v}</dd></div>" for k, v in meta)

    tech = ""
    if f.detection_method:
        tech += f"<p><strong>Detection method:</strong> {esc(f.detection_method)}</p>"
    if f.evidence:
        tech += f"<h4>Evidence</h4><pre>{esc(f.evidence)}</pre>"
    refs = "".join(f"<li>{_link_or_text(r)}</li>" for r in f.references)
    sev = _slug(f.severity.value)
    return f"""<article class="finding sev-{sev}" id="finding-{index}" data-sev="{esc(f.severity.value)}" data-status="{esc(f.status.value)}">
<header><span class="chip sev">{esc(f.severity.value)}</span><span class="chip">{esc(f.status.value)}</span>
<span class="chip">Confidence: {esc(f.confidence.value)}</span><h3>{esc(f.title)}</h3></header>
<dl>{meta_html}</dl>
<h4>Description</h4><p>{esc(f.description)}</p>
<h4>Technical details</h4>{tech or '<p class="muted">No additional technical detail recorded.</p>'}
<h4>Impact</h4><p>{esc(f.impact)}</p>
<h4>Remediation</h4><p>{esc(f.remediation)}</p>
{f'<h4>References</h4><ul>{refs}</ul>' if refs else ''}
<footer>Observed {esc(fmt_time(result.started_at))} · {esc(result.tool)} {esc(result.tool_version)}</footer>
</article>"""


def _score_card(result: ScanResult) -> str:
    sc = result.score()
    rated = bool(sc["rated"])
    circ = 2 * math.pi * 52
    arc = ""
    if rated and sc["score"] > 0:
        arc = (f'<circle class="arc" cx="60" cy="60" r="52" transform="rotate(-90 60 60)" '
               f'stroke-dasharray="{circ * sc["score"] / 100:.2f} {circ:.2f}"/>')
    num, of = (str(sc["score"]), "OUT OF 100") if rated else ("&ndash;", "NOT RATED")
    gauge = (f'<svg class="gauge" viewBox="0 0 120 120" role="img" aria-label="Security score {esc(score_headline(sc))}">'
             f'<circle class="track" cx="60" cy="60" r="52"/>{arc}<text class="num" x="60" y="69">{num}</text>'
             f'<text class="of" x="60" y="88">{of}</text></svg>')
    cov = sc["coverage"]
    about = (f"A summary of this scan's security findings out of 100 (higher is better). It starts at 100 and loses points "
             f"for each issue the scanner confirmed or suspected, weighted by severity. Based on {cov['ran']} of {cov['total']} checks that ran."
             if rated else "A score needs a scan that completed at least one check.")
    verdict = esc(score_headline(sc))
    rows = ""
    if rated and sc["factors"]:
        def row(f: dict[str, Any]) -> str:
            times = f' &times; {f["count"]}' if f["count"] > 1 else ""
            return (f'<tr><td class="pts sev-{_slug(f["severity"])}">-{f["penalty"]:g}</td><td>{esc(f["title"])}{times}</td>'
                    f'<td>{esc(f["severity"])}</td><td>{esc(f["status"])}</td></tr>')

        body = "".join(row(f) for f in sc["factors"])
        more = f'<p class="muted">Top {len(sc["factors"])} of {sc["factors_total"]} factors shown.</p>' if sc["factors_total"] > len(sc["factors"]) else ""
        rows = (f'<h3>What lowered the score</h3><div class="scroll"><table><tr><th>Points lost</th><th>Finding</th>'
                f'<th>Severity</th><th>Status</th></tr>{body}</table></div>{more}')
    elif rated:
        rows = '<h3>What lowered the score</h3><p class="muted">Nothing. No security findings were deducted.</p>'
    notes = "".join(f'<p class="note">{esc(n)}</p>' for n in score_notes(sc))
    return (f'<div class="card score score-{sc["band"]}"><div class="score-main">{gauge}<div class="score-text">'
            f'<div class="verdict">{verdict}</div><p>{esc(sc["meaning"])}</p><p>{esc(about)}</p></div></div>{rows}{notes}'
            f'<details><summary>How is this score calculated?</summary><p class="muted">{esc(sc["method"])} '
            f'The same findings always produce the same score.</p></details></div>')


def _summary(result: ScanResult) -> str:
    counts = result.severity_breakdown("security")
    total = sum(counts.values())
    tiles = "".join(
        f'<div class="tile sev-{_slug(s)}"><b>{counts[s]}</b><span>{s}</span></div>' for s in SEVERITY_ORDER
    )
    x, rects = 0.0, ""
    for s in SEVERITY_ORDER:
        if counts[s] and total:
            w = 100.0 * counts[s] / total
            rects += f'<rect class="bar-{_slug(s)}" x="{x:.2f}" y="0" width="{w:.2f}" height="10"/>'
            x += w
    bar = f'<svg class="bar" viewBox="0 0 100 10" preserveAspectRatio="none" role="img" aria-label="Severity distribution">{rects}</svg>'
    statuses = result.status_breakdown("security")
    status_list = "".join(f"<li><strong>{statuses[s]}</strong> {s.lower()}</li>" for s in STATUS_ORDER)
    obs = key_observations(result)
    obs_html = f'<ul class="obs">{"".join(f"<li>{esc(o)}</li>" for o in obs)}</ul>' if obs else ""
    quality = len(result.sorted_findings("quality"))
    q_html = f'<p class="muted">Plus {quality} site-quality / SEO note(s), listed separately below and not counted above.</p>' if quality else ""
    if total == 0 and result.outcome != "failed":
        headline = "<p><strong>No security findings were reported by the checks that ran.</strong> This does not prove the site is secure; see scope and limitations.</p>"
    else:
        headline = f"<p><strong>{total}</strong> security finding(s) reported.</p>" if result.outcome != "failed" else ""
    pc = result.passed_checks()
    passed = (f'<p><strong>{pc["count"]}</strong> of {pc["total"]} {pc["unit"]} passed. <span class="muted">{esc(pc["note"])}</span></p>'
              if pc["total"] and result.outcome != "failed" else "")
    return f'<div class="tiles">{tiles}</div>{bar}<ul class="statuses">{status_list}</ul>{headline}{passed}{obs_html}{q_html}'


def _kv_table(rows: list[tuple[str, Any]]) -> str:
    body = "".join(f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>" for k, v in rows if v not in (None, ""))
    return f'<div class="scroll"><table>{body}</table></div>'


def _facts(result: ScanResult) -> str:
    md = result.metadata
    out = []
    page = md.get("page")
    if page:
        out.append("<h2>Page information</h2><div class=\"card\">" + _kv_table([
            ("Requested URL", page["requested_url"]), ("Final URL", page["final_url"]), ("HTTP status", page["status_code"]),
            ("Response time", f"{page['response_time_ms']:.0f} ms"), ("Content type", page["content_type"]),
            ("Size analysed", f"{page['page_size_bytes']:,} bytes" + (" (truncated)" if page["truncated"] else "")),
            ("Title", page["title"]), ("Language", page["html_lang"]), ("Word count", page["word_count"]),
            ("Redirects followed", " → ".join(f"{h['url']} ({h['status']})" for h in page["redirect_chain"]) or "None"),
        ]) + "</div>")
    tech = md.get("technical", {})
    if tech.get("security_headers"):
        rows = "".join(
            f'<tr><th>{esc(k)}</th><td class="{"ok" if v else "bad"}">{"Present" if v else "Missing"}</td></tr>'
            for k, v in tech["security_headers"].items())
        out.append(f'<h2>Security headers</h2><div class="card scroll"><table>{rows}</table></div>')
    if tech.get("cookies"):
        rows = "".join(
            f"<tr><th>{esc(c['name'])}</th><td>Secure: {'yes' if c['secure'] else 'no'} · HttpOnly: {'yes' if c['httponly'] else 'no'} · SameSite: {esc(c['samesite'] or 'not set')}</td></tr>"
            for c in tech["cookies"])
        out.append(f'<h2>Cookies</h2><div class="card scroll"><table>{rows}</table><p class="muted">Cookie values are never recorded.</p></div>')
    tls = tech.get("tls")
    if tls:
        out.append("<h2>TLS</h2><div class=\"card\">" + _kv_table([
            ("Protocol", tls.get("version")), ("Cipher", tls.get("cipher")), ("Issuer", tls.get("issuer")),
            ("Expires", tls.get("not_after")), ("Days remaining", tls.get("days_remaining")),
            ("Verification error", tls.get("verify_error")), ("Handshake error", tls.get("error")),
        ]) + "</div>")
    links = md.get("links")
    if links:
        summary = (f"{links['unique_count']} unique links ({links['internal_count']} internal, {links['external_count']} external, "
                   f"{links['other_count']} other); {links['checked_count']} checked, {links['broken_count']} broken, {links['redirect_count']} redirecting.")
        rows = "".join(
            f"<tr><td>{esc(i['url'])}</td><td>{esc(i['link_type'])}</td><td>{esc(i['status_code'] if i['status_code'] else ('error' if i['checked'] else '-'))}</td>"
            f"<td>{'Broken' if i['is_broken'] else 'Redirect' if i['is_redirect'] else 'OK' if i['checked'] else esc(i['note'] or 'Not checked')}</td></tr>"
            for i in links["items"][:500])
        out.append(f'<h2>Links</h2><div class="card"><p>{esc(summary)}</p><details><summary>Show all links</summary>'
                   f'<div class="scroll"><table><tr><th>URL</th><th>Type</th><th>Status</th><th>Result</th></tr>{rows}</table></div></details></div>')
    return "".join(out)


def _checks(result: ScanResult) -> str:
    checks = result.metadata.get("checks")
    if not checks:
        return ""
    rows = "".join(
        f'<tr><th>{esc(c["name"])}</th><td class="{"ok" if c["status"] == "ran" else "bad" if c["status"] == "failed" else "skip"}">{esc(c["status"])}</td><td>{esc(c["note"])}</td></tr>'
        for c in checks)
    return f'<h2>Checks performed</h2><div class="card scroll"><table>{rows}</table></div>'


def render_html(result: ScanResult) -> str:
    security = result.sorted_findings("security")
    quality = result.sorted_findings("quality")
    md = result.metadata

    notices = ""
    if result.outcome != "complete" or result.errors:
        css_class = "notice failed" if result.outcome == "failed" else "notice"
        items = "".join(f"<li>{esc(e)}</li>" for e in result.errors)
        notices = f'<div class="{css_class}"><strong>{esc(OUTCOME_LABELS.get(result.outcome, result.outcome))}</strong>{f"<ul>{items}</ul>" if items else ""}</div>'

    filter_buttons = '<button type="button" data-filter="all" aria-pressed="true">All</button>' + "".join(
        f'<button type="button" data-filter="{s}" aria-pressed="false">{s}</button>'
        for s in SEVERITY_ORDER if any(f.severity.value == s for f in security)
    ) + "".join(
        f'<button type="button" data-filter="{s}" aria-pressed="false">{s} only</button>'
        for s in ("Potential",) if any(f.status.value == s for f in security)
    )
    findings_html = "".join(_finding_card(f, result, i) for i, f in enumerate(security, 1)) or \
        '<div class="card muted">No security findings were reported.</div>'
    quality_html = ""
    if quality:
        quality_html = "<h2>Site quality &amp; SEO notes</h2><p class=\"muted\">Not security issues; these do not count toward the totals above.</p>" + \
            "".join(_finding_card(f, result, 1000 + i) for i, f in enumerate(quality, 1))

    baseline = ""
    if result.baseline_results:
        rows = "".join(f"<tr><th>{esc(b.rule_id)}</th><td>{esc(b.description)}</td><td>{esc(b.status.value)}</td><td>{esc(b.detail)}</td></tr>" for b in result.baseline_results)
        baseline = f'<h2>Baseline results</h2><div class="card scroll"><table>{rows}</table></div>'

    scope = md.get("scope", [])
    scope_html = ("<h2>Scope and limitations</h2><div class=\"card\"><ul>" + "".join(f"<li>{esc(s)}</li>" for s in scope) + "</ul></div>") if scope else ""
    help_html = "<h2>How to read the finding statuses</h2><div class=\"card help\">" + "".join(
        f"<p><span class=\"chip\">{s}</span> {esc(STATUS_HELP[s])}</p>" for s in STATUS_ORDER) + "</div>"

    opts = md.get("options", {})
    meta_items = [
        ("Scan type", result.scan_type), ("Started", fmt_time(result.started_at)),
        ("Duration", f"{result.duration_seconds}s" if result.duration_seconds is not None else "-"),
        ("HTTP requests", result.requests_made if result.scan_type == "web" else "-"),
        ("Findings", f"{len(security)} security · {len(quality)} quality"), ("Scanner", f"{result.tool} {result.tool_version}"),
        ("Rate limit", f"{opts['rate_limit_per_second']:g} req/s" if opts else "-"),
    ]
    meta_html = "".join(f"<div><dt>{esc(k)}</dt><dd>{esc(v)}</dd></div>" for k, v in meta_items)

    body = f"""<div class="wrap">
<div class="card hero"><div class="brand">{read_asset('logo.svg')}<div><div class="wordmark">AYY<span>SCANNER</span></div><h1>Security scan report</h1></div></div>
<div class="target">{esc(result.target)}</div><dl class="meta-grid">{meta_html}</dl></div>
{notices}
<h2>Security score</h2>{_score_card(result)}
<h2>Summary</h2><div class="card">{_summary(result)}</div>
<h2>Security findings</h2><div class="filters" role="group" aria-label="Filter findings">{filter_buttons}</div>{findings_html}
{quality_html}{_facts(result)}{_checks(result)}{baseline}{scope_html}{help_html}
<div class="foot">Generated by {esc(result.tool)} {esc(result.tool_version)} · {esc(fmt_time(result.finished_at or result.started_at))}<br>Only scan systems you own or are authorized to test.</div>
</div>"""

    css = read_asset("tokens.css") + REPORT_CSS
    css_hash = base64.b64encode(hashlib.sha256(css.encode()).digest()).decode()
    js_hash = base64.b64encode(hashlib.sha256(REPORT_JS.encode()).digest()).decode()
    csp = f"default-src 'none'; img-src data:; style-src 'sha256-{css_hash}'; script-src 'sha256-{js_hash}'; base-uri 'none'; form-action 'none'"
    return (
        '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        f'<meta http-equiv="Content-Security-Policy" content="{csp}">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n<meta name="referrer" content="no-referrer">\n'
        f"<title>AYYSCANNER report - {esc(result.target)}</title>\n<style>{css}</style>\n</head>\n<body>\n{body}\n<script>{REPORT_JS}</script>\n</body>\n</html>\n"
    )
