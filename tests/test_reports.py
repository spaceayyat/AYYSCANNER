import base64
import csv
import hashlib
import io
import json
import re
import shutil
import subprocess
import tempfile
import unittest

from ayyscanner import __version__
from pathlib import Path

from ayyscanner.models import Confidence, Finding, FindingStatus, ScanResult, Severity
from ayyscanner.report import FORMATS, render, render_terminal
from ayyscanner.report.common import csv_safe, filename_for, safe_http_url
from ayyscanner.report.markdown import fence, md

EVIL = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'


def make_result():
    r = ScanResult(scan_type="web", target="https://example.test/", requests_made=12)
    r.add(Finding("WEB-X-1", "Sec finding " + EVIL, "headers", Severity.HIGH, Confidence.HIGH, "desc " + EVIL, "evidence " + EVIL + "\n```\nbreak out",
                  "impact", "fix", ["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/", "javascript:alert(3)"],
                  target="https://example.test/?q=" + EVIL, parameter="p", detection_method="dm", cwe="CWE-693", owasp="A05:2021 Security Misconfiguration"))
    r.add(Finding("WEB-X-2", "Potential thing", "content", Severity.LOW, Confidence.MEDIUM, "d", "e", "i", "r", status=FindingStatus.POTENTIAL))
    r.add(Finding("SEO-X", "=HYPERLINK(\"http://evil\",\"x\")", "seo", Severity.MEDIUM, Confidence.HIGH, "d", "+cmd|' /C calc'!A0", "i", "r"))
    r.metadata = {"page": {"requested_url": "https://example.test/", "final_url": "https://example.test/", "status_code": 200, "response_time_ms": 5.0, "content_type": "text/html",
                           "page_size_bytes": 10, "truncated": False, "title": EVIL, "html_lang": "en", "word_count": 3, "redirect_chain": []},
                  "technical": {"is_https": True, "security_headers": {"CSP": False, "HSTS": True}, "cookies": [{"name": EVIL, "secure": False, "httponly": True, "samesite": None}]},
                  "links": {"unique_count": 1, "internal_count": 1, "external_count": 0, "other_count": 0, "checked_count": 1, "broken_count": 0, "redirect_count": 0,
                            "items": [{"url": "javascript:alert(4)", "link_type": "other", "status_code": None, "checked": False, "is_broken": False, "is_redirect": False, "note": None}]},
                  "checks": [{"name": "Headers", "status": "ran", "note": ""}], "scope": ["One page only."], "options": {"rate_limit_per_second": 5.0}}
    r.mark_finished()
    return r


class HtmlReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = render(make_result(), "html").decode()

    def test_hostile_content_is_escaped_everywhere(self):
        self.assertNotIn("<script>alert", self.html)
        self.assertNotIn("<img src=x", self.html)
        self.assertEqual(len(re.findall(r"<script\b", self.html)), 1, "only the report's own script may exist")

    def test_dangerous_urls_never_become_links(self):
        self.assertNotIn('href="javascript:', self.html)
        self.assertIn("https://owasp.org/Top10/A05_2021-Security_Misconfiguration/", self.html)
        self.assertEqual(safe_http_url("javascript:alert(1)"), None)
        self.assertEqual(safe_http_url("data:text/html,x"), None)
        self.assertEqual(safe_http_url("https://ok.test/a"), "https://ok.test/a")

    def test_csp_hashes_match_the_inline_style_and_script(self):
        csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', self.html).group(1)
        def sha(text): return "sha256-" + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()
        style = re.search(r"<style>(.*?)</style>", self.html, re.S).group(1)
        script = re.search(r"<script>(.*?)</script>", self.html, re.S).group(1)
        self.assertIn(f"style-src '{sha(style)}'", csp); self.assertIn(f"script-src '{sha(script)}'", csp)
        self.assertIn("default-src 'none'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotRegex(self.html, r'<[a-z]+[^>]*\sstyle="', "inline style attributes would be blocked by the CSP")

    def test_contains_every_required_section_and_field(self):
        for needle in ("Security scan report", "Summary", "Security findings", "Affected URL / endpoint", "Parameter", "Description", "Technical details",
                       "Detection method", "Evidence", "Impact", "Remediation", "References", "Confidence: High", "CWE-693", "Observed", "HTTP requests",
                       f"AYYSCANNER {__version__}", "Checks performed", "Scope and limitations", "How to read the finding statuses", "Site quality"):
            self.assertIn(needle, self.html)

    def test_quality_findings_are_not_in_the_security_totals(self):
        tiles = {label: count for count, label in re.findall(r"<b>(\d+)</b><span>(\w+)</span>", self.html)}
        self.assertEqual((tiles["High"], tiles["Medium"]), ("1", "0"))  # the Medium SEO note is excluded

    def test_failed_scan_report_does_not_claim_success(self):
        r = ScanResult(scan_type="web", target="https://x.test/", outcome="failed", errors=["Could not resolve the hostname 'x.test'."]); r.mark_finished()
        html = render(r, "html").decode()
        self.assertIn("Failed", html); self.assertIn("Could not resolve", html)
        self.assertNotIn("No security findings were reported by the checks that ran", html)

    def test_clean_scan_states_the_limits_of_the_claim(self):
        r = ScanResult(scan_type="web", target="https://x.test/"); r.mark_finished()
        self.assertIn("does not prove the site is secure", render(r, "html").decode())


class OtherFormatTests(unittest.TestCase):
    def setUp(self):
        self.result = make_result()

    def test_json_round_trip_preserves_everything(self):
        data = json.loads(render(self.result, "json"))
        self.assertEqual(ScanResult.from_dict(data).to_dict(), self.result.to_dict())
        self.assertEqual(data["summary"]["security"]["total"], 2); self.assertEqual(data["summary"]["quality"]["total"], 1)

    def test_csv_is_safe_to_open_in_a_spreadsheet(self):
        rows = list(csv.DictReader(io.StringIO(render(self.result, "csv").decode())))
        self.assertEqual(len(rows), 3)
        for row in rows:
            for cell in row.values():
                self.assertNotIn(cell[:1], ("=", "+", "@", "\t", "\r"), cell[:40])
        seo = next(r for r in rows if r["id"] == "SEO-X")
        self.assertTrue(seo["title"].startswith("'=")); self.assertTrue(seo["evidence"].startswith("'+"))
        self.assertEqual(csv_safe("normal"), "normal"); self.assertEqual(csv_safe(None), ""); self.assertEqual(csv_safe("-5"), "'-5")

    def test_markdown_cannot_be_broken_by_scanned_content(self):
        text = render(self.result, "md").decode()
        prose = re.sub(r"(`{3,}).*?\1", "", text, flags=re.S)          # fenced blocks are literal
        prose = re.sub(r"(`+) .*? \1", "", prose)                       # so are inline code spans
        prose = re.sub(r"<https?://[^>\s]+>", "", prose)                # autolinks we emit on purpose
        self.assertNotRegex(prose, r"(?<!\\)<", "an unescaped '<' outside code could inject HTML")
        self.assertIn("````", text, "evidence containing ``` needs a longer fence")
        body = fence("a ``` b")
        self.assertTrue(body.startswith("````") and body.endswith("````"), "fence must be longer than any backtick run inside")
        self.assertEqual(md("**bold** [x](y) <b>"), r"\*\*bold\*\* \[x\](y) \<b\>")
        self.assertEqual((md("CWE-693 (note)"), md("- item"), md("# h"), md("1. x"), md("a & b")), ("CWE-693 (note)", r"\- item", r"\# h", r"\1. x", r"a \& b"))
        for needle in ("# AYYSCANNER security scan report", "**Severity:** High", "**Status:** Confirmed", "Detection method", "CWE-693"):
            self.assertIn(needle, text)

    def test_pdf_is_a_real_document_with_the_full_detail(self):
        data = render(self.result, "pdf")
        self.assertTrue(data.startswith(b"%PDF") and data.rstrip().endswith(b"%%EOF"))
        if shutil.which("pdftotext"):
            with tempfile.TemporaryDirectory() as d:
                (Path(d) / "r.pdf").write_bytes(data)
                text = subprocess.run(["pdftotext", str(Path(d) / "r.pdf"), "-"], capture_output=True, text=True).stdout
            for needle in ("Security scan report", "Sec finding", "TECHNICAL DETAILS", "IMPACT", "REMEDIATION", "REFERENCES", "CWE-693", "Page 1"):
                self.assertIn(needle, text)

    def test_pdf_survives_non_latin_text_and_markup_characters(self):
        r = ScanResult(scan_type="web", target="https://example.test/")
        r.add(Finding("X", "Title with 日本語 & <tags> \u202e", "headers", Severity.LOW, Confidence.HIGH, "d & <b>", "ev " + "A" * 500, "i", "r"))
        r.mark_finished()
        self.assertTrue(render(r, "pdf").startswith(b"%PDF"))

    def test_terminal_report(self):
        text = render_terminal(self.result, use_color=False)
        self.assertIn("Security findings by severity", text); self.assertIn("(+ 1 site-quality", text); self.assertNotIn("\033[", text)
        self.assertIn("\033[", render_terminal(self.result, use_color=True))

    def test_every_registered_format_renders_and_rejects_unknown(self):
        for key in FORMATS:
            self.assertTrue(render(self.result, key))
        with self.assertRaises(ValueError):
            render(self.result, "exe")

    def test_filenames_are_safe(self):
        r = ScanResult(scan_type="web", target="https://evil.test/../../etc/passwd?x=1")
        name = filename_for(r, "pdf")
        self.assertRegex(name, r"^ayyscanner-[A-Za-z0-9.-]+-\d{8}-\d{4}\.pdf$")
        self.assertNotIn("/", name)


if __name__ == "__main__":
    unittest.main()
