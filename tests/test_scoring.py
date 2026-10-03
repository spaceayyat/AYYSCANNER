"""The 0-100 security score: derived only from findings, deterministic, explained."""

import json
import unittest

from ayyscanner.models import Confidence, Finding, FindingStatus, ScanResult, Severity
from ayyscanner.report import render, render_terminal
from ayyscanner.scoring import BANDS, band_for, compute_score


def F(fid, sev, conf=Confidence.HIGH, category="headers", status=None, target=""):
    return Finding(fid, f"Title {fid}", category, sev, conf, "d", "e", "i", "r", target=target, status=status)


class ScoreMath(unittest.TestCase):
    def test_no_findings_is_100(self):
        s = compute_score([])
        self.assertEqual((s["score"], s["band"], s["rated"]), (100, "excellent", True))
        self.assertEqual(s["factors"], [])

    def test_points_by_severity_and_status(self):
        self.assertEqual(compute_score([F("a", Severity.MEDIUM)])["score"], 92)
        self.assertEqual(compute_score([F("a", Severity.LOW)])["score"], 97)
        self.assertEqual(compute_score([F("a", Severity.MEDIUM, Confidence.LOW)])["score"], 96)  # Potential counts half
        self.assertEqual(compute_score([F("a", Severity.INFO)])["score"], 100)
        self.assertEqual(compute_score([F("a", Severity.MEDIUM), F("b", Severity.LOW)])["score"], 89)

    def test_quality_findings_never_count(self):
        s = compute_score([F("a", Severity.HIGH, category="seo"), F("b", Severity.MEDIUM, category="links")])
        self.assertEqual(s["score"], 100)

    def test_repeats_add_25_percent_each_up_to_double(self):
        def penalty(n):
            return compute_score([F("c", Severity.LOW, target=str(i)) for i in range(n)])["factors"][0]["penalty"]

        self.assertEqual(penalty(1), 3.0)
        self.assertEqual(penalty(2), 3.75)   # 3 x 1.25
        self.assertEqual(penalty(3), 4.5)    # 3 x 1.5
        self.assertEqual(penalty(5), 6.0)    # capped at 2 x the single-instance penalty
        self.assertEqual(penalty(40), 6.0)

    def test_confirmed_critical_and_high_cap_the_score(self):
        crit = compute_score([F("env", Severity.CRITICAL)])
        self.assertEqual(crit["score"], 39)
        self.assertEqual(len(crit["caps_applied"]), 1)
        high = compute_score([F("h", Severity.HIGH)])
        self.assertEqual(high["score"], 74)
        self.assertEqual(compute_score([F("h", Severity.HIGH, Confidence.LOW)])["score"], 91)  # a Potential High is not capped

    def test_score_is_clamped_to_0_100(self):
        s = compute_score([F(f"x{i}", Severity.CRITICAL) for i in range(10)])
        self.assertEqual(s["score"], 0)
        self.assertEqual(s["band"], "critical")

    def test_failed_scan_is_not_rated_and_partial_is_flagged(self):
        s = compute_score([F("a", Severity.LOW)], outcome="failed")
        self.assertIsNone(s["score"])
        self.assertFalse(s["rated"])
        p = compute_score([F("a", Severity.LOW)], outcome="partial")
        self.assertEqual((p["score"], p["partial"]), (97, True))

    def test_bands_cover_every_score(self):
        for n in range(101):
            key, label, _ = band_for(n)
            self.assertTrue(key and label)
        self.assertEqual([b[1] for b in BANDS], ["excellent", "good", "fair", "poor", "critical"])
        self.assertEqual((band_for(90)[0], band_for(89)[0], band_for(75)[0], band_for(74)[0], band_for(50)[0], band_for(49)[0],
                          band_for(25)[0], band_for(24)[0]), ("excellent", "good", "good", "fair", "fair", "poor", "poor", "critical"))

    def test_deterministic_and_order_independent(self):
        items = [F("a", Severity.HIGH), F("b", Severity.MEDIUM, Confidence.LOW), F("c", Severity.LOW, target="1"), F("c", Severity.LOW, target="2")]
        first = compute_score(items)
        self.assertEqual(first, compute_score(list(reversed(items))))
        self.assertEqual(first, compute_score(items))

    def test_informational_findings_are_not_factors(self):
        s = compute_score([F("a", Severity.MEDIUM), F("i", Severity.INFO)])
        self.assertEqual([f["id"] for f in s["factors"]], ["a"])
        self.assertEqual(s["finding_count"], 2)

    def test_band_ranges_are_contiguous(self):
        bands = compute_score([])["bands"]
        self.assertEqual([(b["min"], b["max"]) for b in bands], [(90, 100), (75, 89), (50, 74), (25, 49), (0, 24)])

    def test_factors_explain_the_deduction(self):
        s = compute_score([F("a", Severity.MEDIUM), F("b", Severity.LOW)])
        self.assertEqual([f["id"] for f in s["factors"]], ["a", "b"])  # biggest first
        self.assertEqual(round(sum(f["penalty"] for f in s["factors"])), 100 - s["score"])
        self.assertEqual(s["factors"][0]["title"], "Title a")


class ScoreInResults(unittest.TestCase):
    def result(self):
        r = ScanResult(scan_type="web", target="https://example.test/")
        r.metadata["checks"] = [{"name": "A", "status": "ran", "note": ""}, {"name": "B", "status": "ran", "note": ""}, {"name": "C", "status": "failed", "note": "x"}]
        r.add(F("a", Severity.MEDIUM))
        r.add(F("b", Severity.LOW))
        r.mark_finished()
        return r

    def test_json_contains_the_score(self):
        data = json.loads(self.result().to_json())
        self.assertEqual(data["score"]["score"], 89)
        self.assertEqual(data["score"]["coverage"], {"ran": 2, "skipped": 0, "failed": 1, "total": 3})

    def test_round_trip_gives_the_same_score(self):
        r = self.result()
        again = ScanResult.from_dict(json.loads(r.to_json()))
        self.assertEqual(again.score(), r.score())

    def test_every_format_shows_the_score(self):
        r = self.result()
        self.assertIn("89/100", render_terminal(r, use_color=False))
        self.assertIn("89/100", render(r, "md").decode())
        html = render(r, "html").decode()
        self.assertIn("89/100", html)
        self.assertIn('class="gauge"', html)
        self.assertIn("What lowered the score", html)
        pdf = render(r, "pdf")
        self.assertTrue(pdf.startswith(b"%PDF"))

    def test_html_score_card_escapes_finding_titles(self):
        r = ScanResult(scan_type="web", target="https://example.test/")
        r.add(Finding("x", "<script>alert(1)</script>", "headers", Severity.MEDIUM, Confidence.HIGH, "d", "e", "i", "r"))
        html = render(r, "html").decode()
        self.assertNotIn("<script>alert(1)</script>", html)

    def test_failed_scan_renders_not_rated(self):
        r = ScanResult(scan_type="web", target="https://example.test/", outcome="failed")
        self.assertIn("Not rated", render_terminal(r, use_color=False))
        self.assertIn("Not rated", render(r, "html").decode())
        self.assertTrue(render(r, "pdf").startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
