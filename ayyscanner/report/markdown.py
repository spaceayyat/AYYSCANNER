"""Markdown report. Scanned-site text is only ever placed inside code fences
or escaped, so it cannot inject Markdown/HTML structure into the document."""

from __future__ import annotations

import re
from typing import Any

from ayyscanner.models import Finding, ScanResult
from ayyscanner.report.common import (OUTCOME_LABELS, SEVERITY_ORDER, STATUS_HELP, STATUS_ORDER, fmt_time, key_observations,
                                     score_headline, score_notes)

# Characters that can open emphasis, links, HTML, tables or entities. Because "[" is escaped, "(" / "!" cannot
# form links or images on their own, so they (and "-") are left alone to keep the raw text readable.
_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|&~])")
_LINE_START = re.compile(r"^([-+#>=]|\d+[.)])")


def md(text: Any) -> str:
    """Escape text for inline Markdown and collapse it to one line."""
    escaped = _MD_SPECIAL.sub(r"\\\1", " ".join(str(text if text is not None else "").split()))
    return _LINE_START.sub(r"\\\1", escaped, count=1)  # a leading "-", "#", "1." would start a list/heading


def fence(text: str, lang: str = "") -> str:
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}{lang}\n{text}\n{ticks}"


def code(text: Any) -> str:
    text = " ".join(str(text).split())
    ticks = "`" * (max((len(m) for m in re.findall(r"`+", text)), default=0) + 1)
    return f"{ticks} {text} {ticks}"


def _finding(f: Finding, n: int, result: ScanResult) -> str:
    lines = [f"### {n}. {md(f.title)}", "",
             f"**Severity:** {f.severity.value} · **Status:** {f.status.value} · **Confidence:** {f.confidence.value}", ""]
    lines.append(f"- **Finding ID:** {code(f.id)}")
    if f.target:
        lines.append(f"- **Affected URL / endpoint:** {code(f.target)}")
    if f.parameter:
        lines.append(f"- **Parameter:** {code(f.parameter)}")
    if f.cwe or f.owasp:
        lines.append(f"- **Classification:** {md(' · '.join(b for b in (f.cwe, f.owasp) if b))}")
    lines.append(f"- **Observed:** {fmt_time(result.started_at)}")
    lines += ["", "**Description**", "", md(f.description), ""]
    lines += ["**Technical details**", ""]
    if f.detection_method:
        lines += [f"*Detection method:* {md(f.detection_method)}", ""]
    if f.evidence:
        lines += [fence(f.evidence), ""]
    lines += ["**Impact**", "", md(f.impact), "", "**Remediation**", "", md(f.remediation), ""]
    if f.references:
        lines += ["**References**", ""] + [f"- <{r}>" if r.startswith(("http://", "https://")) and " " not in r and ">" not in r else f"- {code(r)}" for r in f.references] + [""]
    return "\n".join(lines)


def render_markdown(result: ScanResult) -> str:
    security, quality = result.sorted_findings("security"), result.sorted_findings("quality")
    counts, statuses = result.severity_breakdown("security"), result.status_breakdown("security")
    out = ["# AYYSCANNER security scan report", "",
           f"**Target:** {code(result.target)}", "",
           "| | |", "|---|---|",
           f"| Scan type | {md(result.scan_type)} |", f"| Started | {fmt_time(result.started_at)} |",
           f"| Duration | {result.duration_seconds if result.duration_seconds is not None else '-'} s |",
           f"| HTTP requests | {result.requests_made if result.scan_type == 'web' else '-'} |",
           f"| Outcome | {md(OUTCOME_LABELS.get(result.outcome, result.outcome))} |",
           f"| Scanner | {md(result.tool)} {md(result.tool_version)} |", ""]
    if result.errors:
        out += ["> **Warnings / errors during the scan**", ">"] + [f"> - {md(e)}" for e in result.errors] + [""]
    score = result.score()
    out += ["## Security score", "", f"**{md(score_headline(score))}**" + (" (out of 100, higher is better)" if score["rated"] else ""), "",
            md(score["meaning"]), ""]
    if score["rated"]:
        cov = score["coverage"]
        out += [f"Based on {cov['ran']} of {cov['total']} checks that ran. {md(score['method'])}", ""]
        if score["factors"]:
            out += ["| Points lost | Finding | Severity | Status | Count |", "|---|---|---|---|---|"]
            out += [f"| -{f['penalty']:g} | {md(f['title'])} | {f['severity']} | {f['status']} | {f['count']} |" for f in score["factors"]] + [""]
    out += [f"> {md(n)}" for n in score_notes(score)] + ([""] if score_notes(score) else [])
    out += ["## Summary", "", "| " + " | ".join(SEVERITY_ORDER) + " |", "|" + "---|" * len(SEVERITY_ORDER),
            "| " + " | ".join(str(counts[s]) for s in SEVERITY_ORDER) + " |", "",
            " · ".join(f"**{statuses[s]}** {s.lower()}" for s in STATUS_ORDER), ""]
    if quality:
        out += [f"Plus {len(quality)} site-quality / SEO note(s), listed separately and not counted above.", ""]
    obs = key_observations(result)
    if obs:
        out += ["**Key observations**", ""] + [f"- {md(o)}" for o in obs] + [""]
    out += ["## Security findings", ""]
    out += [_finding(f, i, result) for i, f in enumerate(security, 1)] or ["No security findings were reported.", ""]
    if quality:
        out += ["## Site quality & SEO notes", ""] + [_finding(f, i, result) for i, f in enumerate(quality, 1)]
    checks = result.metadata.get("checks")
    if checks:
        out += ["## Checks performed", "", "| Check | Status | Note |", "|---|---|---|"]
        out += [f"| {md(c['name'])} | {md(c['status'])} | {md(c['note'])} |" for c in checks] + [""]
    if result.baseline_results:
        out += ["## Baseline results", "", "| Rule | Description | Status | Detail |", "|---|---|---|---|"]
        out += [f"| {md(b.rule_id)} | {md(b.description)} | {b.status.value} | {md(b.detail)} |" for b in result.baseline_results] + [""]
    if result.metadata.get("scope"):
        out += ["## Scope and limitations", ""] + [f"- {md(s)}" for s in result.metadata["scope"]] + [""]
    out += ["## How to read the finding statuses", ""] + [f"- **{s}**: {md(STATUS_HELP[s])}" for s in STATUS_ORDER] + [""]
    out += ["---", f"Generated by {md(result.tool)} {md(result.tool_version)}. Only scan systems you own or are authorized to test.", ""]
    return "\n".join(out)
