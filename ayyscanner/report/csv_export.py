"""CSV export of all findings. Every cell is neutralized against spreadsheet
formula injection (page titles and headers come from the scanned site)."""

from __future__ import annotations

import csv
import io

from ayyscanner.models import ScanResult
from ayyscanner.report.common import csv_safe

COLUMNS = ["severity", "status", "confidence", "domain", "category", "id", "title", "affected_url", "parameter",
           "description", "evidence", "impact", "remediation", "cwe", "owasp", "references", "detection_method"]


def render_csv(result: ScanResult) -> str:
    buf = io.StringIO(newline="")
    writer = csv.writer(buf)
    writer.writerow(COLUMNS)
    for f in result.sorted_findings():
        row = [f.severity.value, f.status.value, f.confidence.value, f.domain, f.category, f.id, f.title, f.target,
               f.parameter, f.description, f.evidence, f.impact, f.remediation, f.cwe, f.owasp,
               " ".join(f.references), f.detection_method]
        writer.writerow([csv_safe(c) for c in row])
    return buf.getvalue()
