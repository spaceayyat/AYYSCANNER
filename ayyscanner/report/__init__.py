"""Report rendering: one ScanResult in, any supported format out."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ayyscanner.models import ScanResult
from ayyscanner.report.common import filename_for
from ayyscanner.report.csv_export import render_csv
from ayyscanner.report.html import render_html
from ayyscanner.report.markdown import render_markdown
from ayyscanner.report.pdf import render_pdf
from ayyscanner.report.terminal import render_terminal


@dataclass(frozen=True)
class ReportFormat:
    key: str
    label: str
    mimetype: str
    extension: str
    render: Callable[[ScanResult], bytes]


def _text(fn: Callable[[ScanResult], str]) -> Callable[[ScanResult], bytes]:
    return lambda result: fn(result).encode("utf-8")


FORMATS: dict[str, ReportFormat] = {
    f.key: f
    for f in (
        ReportFormat("html", "HTML report", "text/html; charset=utf-8", "html", _text(render_html)),
        ReportFormat("txt", "Plain text (.txt)", "text/plain; charset=utf-8", "txt", _text(lambda r: render_terminal(r, use_color=False))),
        ReportFormat("pdf", "PDF report", "application/pdf", "pdf", render_pdf),
        ReportFormat("md", "Markdown", "text/markdown; charset=utf-8", "md", _text(render_markdown)),
        ReportFormat("json", "JSON (machine-readable)", "application/json", "json", _text(lambda r: r.to_json())),
        ReportFormat("csv", "CSV (findings table)", "text/csv; charset=utf-8", "csv", _text(render_csv)),
    )
}


def render(result: ScanResult, fmt: str) -> bytes:
    if fmt not in FORMATS:
        raise ValueError(f"Unknown report format '{fmt}'. Choose one of: {', '.join(FORMATS)}.")
    return FORMATS[fmt].render(result)


__all__ = ["FORMATS", "ReportFormat", "render", "render_terminal", "filename_for"]
