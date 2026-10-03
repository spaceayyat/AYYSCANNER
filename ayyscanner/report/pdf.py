"""PDF report built with reportlab (pure Python, no browser needed).

The standard PDF fonts only cover Latin-1/CP1252 text, so characters outside
that range in scanned content are replaced with '?' rather than rendered as
broken boxes.
"""

from __future__ import annotations

import io
from typing import Any

from reportlab.graphics.shapes import Drawing, Line, Polygon
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from ayyscanner.models import Finding, ScanResult
from ayyscanner.report.common import (
    OUTCOME_LABELS,
    SEVERITY_ORDER,
    STATUS_HELP,
    STATUS_ORDER,
    factor_text,
    fmt_time,
    key_observations,
    score_headline,
    score_notes,
)

BRAND = colors.HexColor("#C2202F")
SCORE_COLORS = {"excellent": "#13773A", "good": "#4D7A12", "fair": "#94560A", "poor": "#C2261B", "critical": "#9D1450", "unrated": "#4B5565"}
SEV_COLORS = {"Critical": "#9D1450", "High": "#C2261B", "Medium": "#94560A", "Low": "#1A5BBD", "Informational": "#4B5565"}
INK, MUTED, RULE, TINT = colors.HexColor("#14181F"), colors.HexColor("#4F5A69"), colors.HexColor("#DBDFE6"), colors.HexColor("#F1F3F6")
PAGE_W = A4[0] - 36 * mm


def _t(value: Any) -> str:
    """Make text safe for a Paragraph: cp1252-encodable and XML-escaped."""
    text = "" if value is None else str(value)
    text = text.encode("cp1252", "replace").decode("cp1252")
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()["BodyText"]
    body = ParagraphStyle("body", parent=base, fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=INK, alignment=TA_LEFT, wordWrap="CJK")
    return {
        "body": body,
        "muted": ParagraphStyle("muted", parent=body, textColor=MUTED, fontSize=8.5, leading=12),
        "h1": ParagraphStyle("h1", parent=body, fontName="Helvetica-Bold", fontSize=21, leading=25),
        "h2": ParagraphStyle("h2", parent=body, fontName="Helvetica-Bold", fontSize=14, leading=18, spaceBefore=16, spaceAfter=6),
        "h3": ParagraphStyle("h3", parent=body, fontName="Helvetica-Bold", fontSize=11.5, leading=15, spaceBefore=8),
        "label": ParagraphStyle("label", parent=body, fontName="Helvetica-Bold", fontSize=7.5, leading=10, textColor=MUTED, spaceBefore=10),
        "mono": ParagraphStyle("mono", parent=body, fontName="Courier", fontSize=8, leading=10.5, backColor=TINT, borderPadding=4, leftIndent=2, spaceAfter=8),
        "wordmark": ParagraphStyle("wordmark", parent=body, fontName="Helvetica-Bold", fontSize=10, leading=12, textColor=INK),
    }


def _logo(size: float = 32) -> Drawing:
    d = Drawing(size, size)
    s = size / 64.0
    for pts in ([6, 24, 6, 6, 24, 6], [40, 6, 58, 6, 58, 24], [58, 40, 58, 58, 40, 58], [24, 58, 6, 58, 6, 40]):
        for i in range(0, 4, 2):
            d.add(Line(pts[i] * s, (64 - pts[i + 1]) * s, pts[i + 2] * s, (64 - pts[i + 3]) * s, strokeColor=BRAND, strokeWidth=6 * s))
    d.add(Polygon([32 * s, 45 * s, 45 * s, 32 * s, 32 * s, 19 * s, 19 * s, 32 * s], fillColor=BRAND, strokeColor=None))
    return d


def _kv(rows: list[tuple[str, Any]], st: dict[str, ParagraphStyle], widths=(0.28, 0.72)) -> Table:
    data = [[Paragraph(f"<b>{_t(k)}</b>", st["muted"]), Paragraph(_t(v), st["body"])] for k, v in rows if v not in (None, "")]
    t = Table(data, colWidths=[PAGE_W * w for w in widths], hAlign="LEFT")
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
                           ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    return t


def _finding_block(f: Finding, n: int, result: ScanResult, st: dict[str, ParagraphStyle]) -> list[Any]:
    sev = colors.HexColor(SEV_COLORS[f.severity.value])
    chips = Table([[f.severity.value.upper(), f.status.value.upper(), f"CONFIDENCE: {f.confidence.value.upper()}"]],
                  colWidths=[26 * mm, 30 * mm, 42 * mm], hAlign="LEFT")
    chips.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, 0), sev), ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
                               ("BACKGROUND", (1, 0), (2, 0), TINT), ("TEXTCOLOR", (1, 0), (2, 0), MUTED),
                               ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                               ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                               ("LINEAFTER", (0, 0), (1, 0), 2, colors.white)]))
    meta: list[tuple[str, Any]] = [("Affected URL", f.target), ("Parameter", f.parameter),
                                   ("Classification", " · ".join(b for b in (f.cwe, f.owasp) if b)), ("Finding ID", f.id),
                                   ("Observed", fmt_time(result.started_at))]
    head = KeepTogether([Paragraph(f"{n}. {_t(f.title)}", st["h3"]), Spacer(1, 3), chips, Spacer(1, 6), _kv(meta, st)])
    flow: list[Any] = [head, Paragraph("DESCRIPTION", st["label"]), Paragraph(_t(f.description), st["body"]),
                       Paragraph("TECHNICAL DETAILS", st["label"])]
    if f.detection_method:
        flow.append(Paragraph(f"<b>Detection method:</b> {_t(f.detection_method)}", st["body"]))
    if f.evidence:
        flow.append(Spacer(1, 3))
        flow.append(Paragraph(_t(f.evidence).replace("\n", "<br/>"), st["mono"]))
    flow += [Paragraph("IMPACT", st["label"]), Paragraph(_t(f.impact), st["body"]),
             Paragraph("REMEDIATION", st["label"]), Paragraph(_t(f.remediation), st["body"])]
    if f.references:
        flow.append(Paragraph("REFERENCES", st["label"]))
        flow += [Paragraph(f"• {_t(r)}", st["muted"]) for r in f.references]
    flow.append(Spacer(1, 14))
    return flow


def _footer(target: str):
    def draw(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 10 * mm, f"AYYSCANNER report  ·  {_t(target)[:90]}")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
        canvas.setStrokeColor(RULE)
        canvas.line(18 * mm, 13 * mm, A4[0] - 18 * mm, 13 * mm)
        canvas.restoreState()
    return draw


def render_pdf(result: ScanResult) -> bytes:
    st = _styles()
    security, quality = result.sorted_findings("security"), result.sorted_findings("quality")
    counts, statuses = result.severity_breakdown("security"), result.status_breakdown("security")
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=18 * mm,
                            title=f"AYYSCANNER report - {result.target}"[:200], author="AYYSCANNER")

    title_block = Table([[_logo(38), [Paragraph("AYYSCANNER", st["wordmark"]), Paragraph("Security scan report", st["h1"])]]],
                        colWidths=[16 * mm, PAGE_W - 16 * mm], hAlign="LEFT")
    title_block.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (0, 0), 0)]))
    story: list[Any] = [title_block, Spacer(1, 8), Paragraph(_t(result.target), ParagraphStyle("t", parent=st["body"], fontName="Courier", fontSize=10)), Spacer(1, 8)]
    story.append(_kv([
        ("Scan type", result.scan_type), ("Started", fmt_time(result.started_at)),
        ("Duration", f"{result.duration_seconds}s" if result.duration_seconds is not None else None),
        ("HTTP requests", result.requests_made if result.scan_type == "web" else None),
        ("Outcome", OUTCOME_LABELS.get(result.outcome, result.outcome)),
        ("Scanner", f"{result.tool} {result.tool_version}"),
    ], st))
    if result.errors:
        story += [Paragraph("WARNINGS / ERRORS DURING THE SCAN", st["label"])] + [Paragraph(f"• {_t(e)}", st["body"]) for e in result.errors]

    score = result.score()
    sc_color = colors.HexColor(SCORE_COLORS.get(score["band"], "#4B5565"))
    big = ParagraphStyle("scorebig", parent=st["body"], fontName="Helvetica-Bold", fontSize=34, leading=38, textColor=sc_color)
    sc_table = Table([[Paragraph(f"{score['score']}<font size=13 color='#4F5A69'> / 100</font>" if score["rated"] else "Not rated", big),
                       [Paragraph(f"<b>{_t(score['label'])}</b>", ParagraphStyle("v", parent=st["body"], fontSize=13, leading=17, textColor=sc_color)),
                        Paragraph(_t(score["meaning"]), st["body"]),
                        Paragraph(_t(f"Higher is better. Based on {score['coverage']['ran']} of {score['coverage']['total']} checks that ran.") if score["rated"] else "", st["muted"])]]],
                      colWidths=[44 * mm, PAGE_W - 44 * mm], hAlign="LEFT")
    sc_table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("BOX", (0, 0), (-1, -1), 0.5, RULE), ("LINEABOVE", (0, 0), (-1, 0), 3, sc_color),
                                  ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8), ("LEFTPADDING", (0, 0), (-1, -1), 10)]))
    story += [Paragraph("Security score", st["h2"]), sc_table]
    if score["rated"] and score["factors"]:
        story.append(Paragraph("WHAT LOWERED THE SCORE", st["label"]))
        story += [Paragraph(f"• {_t(factor_text(f))}", st["body"]) for f in score["factors"]]
    story += [Paragraph(f"<i>{_t(n)}</i>", st["muted"]) for n in score_notes(score)]
    story.append(Paragraph(_t(score["method"]), st["muted"]))

    story.append(Paragraph("Summary", st["h2"]))
    sev_table = Table([[s.upper() for s in SEVERITY_ORDER], [str(counts[s]) for s in SEVERITY_ORDER]], colWidths=[PAGE_W / 5] * 5, hAlign="LEFT")
    style = [("ALIGN", (0, 0), (-1, -1), "CENTER"), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, 0), 7.5),
             ("FONTSIZE", (0, 1), (-1, 1), 20), ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"), ("BOX", (0, 0), (-1, -1), 0.5, RULE),
             ("INNERGRID", (0, 0), (-1, -1), 0.5, RULE), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]
    for i, s in enumerate(SEVERITY_ORDER):
        c = colors.HexColor(SEV_COLORS[s])
        style += [("TEXTCOLOR", (i, 0), (i, 1), c), ("LINEABOVE", (i, 0), (i, 0), 2.5, c)]
    sev_table.setStyle(TableStyle(style))
    story += [sev_table, Spacer(1, 6),
              Paragraph(" · ".join(f"<b>{statuses[s]}</b> {s.lower()}" for s in STATUS_ORDER), st["body"])]
    if quality:
        story.append(Paragraph(f"Plus {len(quality)} site-quality / SEO note(s), listed separately and not counted above.", st["muted"]))
    if not security and result.outcome != "failed":
        story.append(Paragraph("<b>No security findings were reported by the checks that ran.</b> This does not prove the site is secure.", st["body"]))
    for obs in key_observations(result):
        story.append(Paragraph(f"• {_t(obs)}", st["body"]))

    if security:
        story += [PageBreak(), Paragraph("Security findings", st["h2"])]
        for i, f in enumerate(security, 1):
            story += _finding_block(f, i, result, st)
    if quality:
        story += [PageBreak(), Paragraph("Site quality &amp; SEO notes", st["h2"]),
                  Paragraph("Not security issues; these do not count toward the totals above.", st["muted"])]
        for i, f in enumerate(quality, 1):
            story += _finding_block(f, i, result, st)

    checks = result.metadata.get("checks")
    if checks:
        story.append(Paragraph("Checks performed", st["h2"]))
        story.append(_kv([(c["name"], c["status"] + (f" - {c['note']}" if c["note"] else "")) for c in checks], st, widths=(0.4, 0.6)))
    if result.baseline_results:
        story.append(Paragraph("Baseline results", st["h2"]))
        story.append(_kv([(b.rule_id, f"{b.status.value}: {b.description} ({b.detail})") for b in result.baseline_results], st))
    if result.metadata.get("scope"):
        story.append(Paragraph("Scope and limitations", st["h2"]))
        story += [Paragraph(f"• {_t(s)}", st["body"]) for s in result.metadata["scope"]]
    story.append(Paragraph("How to read the finding statuses", st["h2"]))
    story += [Paragraph(f"<b>{s}</b>: {_t(STATUS_HELP[s])}", st["body"]) for s in STATUS_ORDER]

    footer = _footer(result.target)
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
