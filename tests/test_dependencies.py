import json
import tempfile
import unittest
from pathlib import Path

import requests

from ayyscanner.models import FindingStatus, Severity
from ayyscanner.scanners.dependencies import (collect_dependencies, cvss3_base_score, discover_manifests, parse_package_lock_json,
                                              parse_requirements_txt, run_dependency_scan, severity_from_osv)

CRITICAL_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


class Resp:
    def __init__(self, data): self.data = data
    def raise_for_status(self): pass
    def json(self): return self.data


class FakeOsv:
    def __init__(self, detail=None):
        self.detail = detail if detail is not None else {"id": "GHSA-1", "summary": "Flask DoS", "severity": [{"type": "CVSS_V3", "score": CRITICAL_VECTOR}]}
        self.calls = []
    def post(self, url, json=None, timeout=None):
        self.calls.append(("POST", url)); return Resp({"results": [{"vulns": [{"id": "GHSA-1", "modified": "x"}]}]})
    def get(self, url, timeout=None):
        self.calls.append(("GET", url)); return Resp(self.detail)


class Down:
    def post(self, *a, **k): raise requests.ConnectionError("no network")


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def test_requirements_pinned_and_unpinned(self):
        p = self.dir / "requirements.txt"
        p.write_text("# c\nflask==2.0.1\nrequests>=2.0\n-r other.txt\nnumpy\n")
        deps = {d.name: d.version for d in parse_requirements_txt(p)}
        self.assertEqual(deps, {"flask": "2.0.1", "requests": None, "numpy": None})

    def test_package_lock(self):
        p = self.dir / "package-lock.json"
        p.write_text(json.dumps({"packages": {"": {"name": "root"}, "node_modules/left-pad": {"version": "1.3.0"}}}))
        self.assertEqual([(d.name, d.version) for d in parse_package_lock_json(p)], [("left-pad", "1.3.0")])

    def test_discovery_across_manifests(self):
        (self.dir / "requirements.txt").write_text("a==1\n"); (self.dir / "package-lock.json").write_text('{"packages": {"node_modules/b": {"version": "2"}}}')
        self.assertEqual(len(discover_manifests(self.dir)), 2)
        self.assertEqual(sorted(d.ecosystem for d in collect_dependencies(self.dir)), ["PyPI", "npm"])


class SeverityTests(unittest.TestCase):
    def test_cvss3_matches_published_scores(self):
        known = {CRITICAL_VECTOR: 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
                 "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
                 "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H": 8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0}
        for vector, score in known.items():
            self.assertEqual(cvss3_base_score(vector), score, vector)

    def test_unparseable_vectors_are_not_guessed(self):
        self.assertIsNone(cvss3_base_score("garbage")); self.assertIsNone(cvss3_base_score("CVSS:4.0/AV:N"))

    def test_regression_critical_vector_is_not_rated_low(self):
        # The original implementation grabbed the last number in the string ("3.1") and rated this Low.
        self.assertEqual(severity_from_osv({"severity": [{"type": "CVSS_V3", "score": CRITICAL_VECTOR}]})[0], Severity.CRITICAL)

    def test_labels_scores_and_fallback(self):
        self.assertEqual(severity_from_osv({"database_specific": {"severity": "MODERATE"}})[0], Severity.MEDIUM)
        self.assertEqual(severity_from_osv({"severity": [{"score": "7.5"}]})[0], Severity.HIGH)
        sev, basis = severity_from_osv({})
        self.assertEqual(sev, Severity.MEDIUM); self.assertIn("assumed", basis)


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp()); (self.dir / "requirements.txt").write_text("flask==0.12\nrequests>=2\n")

    def test_match_is_confirmed_with_real_severity_and_human_reference(self):
        r = run_dependency_scan(str(self.dir), session=FakeOsv(), rate_limit=20)
        vuln = next(f for f in r.findings if f.id.startswith("DEP-VULN"))
        self.assertEqual((vuln.severity, vuln.status), (Severity.CRITICAL, FindingStatus.CONFIRMED))
        self.assertEqual(vuln.references, ["https://osv.dev/vulnerability/GHSA-1"])
        self.assertEqual(r.outcome, "complete")

    def test_unpinned_is_informational_only(self):
        r = run_dependency_scan(str(self.dir), session=FakeOsv(), rate_limit=20)
        unresolved = next(f for f in r.findings if f.id.startswith("DEP-UNRESOLVED"))
        self.assertEqual(unresolved.status, FindingStatus.INFORMATIONAL)

    def test_missing_details_do_not_invent_a_severity_basis(self):
        r = run_dependency_scan(str(self.dir), session=FakeOsv(detail={}), rate_limit=20)
        self.assertIn("unavailable", next(f for f in r.findings if f.id.startswith("DEP-VULN")).evidence)

    def test_network_failure_is_reported_and_marks_results_partial(self):
        r = run_dependency_scan(str(self.dir), session=Down(), rate_limit=20)
        self.assertEqual(r.outcome, "partial"); self.assertIn("NOT checked", r.errors[0])

    def test_offline_says_vulnerabilities_were_not_checked(self):
        r = run_dependency_scan(str(self.dir), offline=True)
        self.assertEqual(r.outcome, "partial"); self.assertIn("NOT checked", r.errors[0])

    def test_missing_directory_and_no_manifests_fail_clearly(self):
        self.assertEqual(run_dependency_scan("/nonexistent/dir").outcome, "failed")
        self.assertEqual(run_dependency_scan(tempfile.mkdtemp()).outcome, "failed")


if __name__ == "__main__":
    unittest.main()
