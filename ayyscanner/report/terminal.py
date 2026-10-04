"""Plain-text terminal report."""

from __future__ import annotations

from ayyscanner.models import ScanResult, Severity
from ayyscanner.report.common import (OUTCOME_LABELS, SEVERITY_ORDER, STATUS_ORDER, factor_text, fmt_time, key_observations,
                                     score_headline, score_notes)

_COLOR = {Severity.CRITICAL: "\033[95m", Severity.HIGH: "\033[91m", Severity.MEDIUM: "\033[93m",
          Severity.LOW: "\033[94m", Severity.INFO: "\033[90m"}
_RESET = "\033[0m"


def render_terminal(result: ScanResult, use_color: bool = True) -> str:
    def c(sev: Severity, text: str) -> str:
        return f"{_COLOR[sev]}{text}{_RESET}" if use_color else text

    lines = [f"AYYSCANNER report - {result.scan_type} scan", f"Target:   {result.target}",
             f"Started:  {fmt_time(result.started_at)}"]
    if result.duration_seconds is not None:
        lines.append(f"Duration: {result.duration_seconds}s" + (f", {result.requests_made} HTTP requests" if result.scan_type == "web" else ""))
    lines += [f"Outcome:  {OUTCOME_LABELS.get(result.outcome, result.outcome)}", ""]

    score = result.score()
    lines.append(f"Security score: {score_headline(score)}" + (f"  (checks that ran: {score['coverage']['ran']}/{score['coverage']['total']})" if score["rated"] and score["coverage"]["total"] else ""))
    if score["rated"]:
        lines.append(f"  {score['meaning']}")
        if score["factors"]:
            lines.append("  What lowered the score:")
            lines += [f"    {factor_text(f)}" for f in score["factors"]]
    lines += [f"  Note: {n}" for n in score_notes(score)]
    lines.append("")

    counts, statuses = result.severity_breakdown("security"), result.status_breakdown("security")
    lines.append("Security findings by severity:")
    lines += [f"  {c(Severity(s), s):<{20 if use_color else 14}} {counts[s]}" for s in SEVERITY_ORDER]
    lines.append("  " + ", ".join(f"{statuses[s]} {s.lower()}" for s in STATUS_ORDER))
    pc = result.passed_checks()
    if pc["total"] and result.outcome != "failed":
        lines.append(f"  Passed: {pc['count']} of {pc['total']} {pc['unit']} ({pc['note']})")
    quality = len(result.sorted_findings("quality"))
    if quality:
        lines.append(f"  (+ {quality} site-quality / SEO note(s), not counted above)")
    for obs in key_observations(result):
        lines.append(f"  - {obs}")
    lines.append("")

    if result.baseline_results:
        lines.append("Baseline results:")
        for b in result.baseline_results:
            lines.append(f"  [{b.status.value:^5}] {b.rule_id}: {b.description}")
            if b.status.value != "PASS":
                lines.append(f"          -> {b.detail}")
        lines.append("")

    for label, domain in (("Security findings", "security"), ("Site quality & SEO notes", "quality")):
        findings = result.sorted_findings(domain)
        if not findings:
            continue
        lines.append(f"{label} ({len(findings)}):")
        for f in findings:
            lines += ["", c(f.severity, f"[{f.severity.value}] {f.title}  ({f.status.value}, {f.confidence.value} confidence)"),
                      f"  id: {f.id}" + (f"   {f.cwe}" if f.cwe else "") + (f"   {f.owasp}" if f.owasp else "")]
            if f.target:
                lines.append(f"  url: {f.target}" + (f"   parameter: {f.parameter}" if f.parameter else ""))
            for name, value in (("what", f.description), ("evidence", f.evidence), ("impact", f.impact), ("fix", f.remediation)):
                if value:
                    lines.append(f"  {name}: {value}")
            if f.references:
                lines.append("  refs: " + ", ".join(f.references))
        lines.append("")

    if result.errors:
        lines += ["Warnings / errors during the scan:"] + [f"  - {e}" for e in result.errors]
    return "\n".join(lines)
