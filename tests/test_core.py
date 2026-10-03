import json
import tempfile
import unittest
from pathlib import Path

from ayyscanner.baseline import evaluate_baseline
from ayyscanner.models import (BaselineResult, BaselineStatus, Confidence, Finding, FindingStatus, ScanResult, Severity)
from ayyscanner.settings import Settings, SettingsError, load_dotenv
from ayyscanner.web_scan.options import OptionsError, ScanOptions
from ayyscanner.web_scan.urls import InvalidUrlError, parse_target, swap_scheme


def finding(fid="T-1", severity=Severity.MEDIUM, category="web", confidence=Confidence.HIGH, **kw):
    return Finding(id=fid, title="t", category=category, severity=severity, confidence=confidence,
                   description="d", evidence="e", impact="i", remediation="r", **kw)


class ModelTests(unittest.TestCase):
    def test_severity_rank_ordering(self):
        ranks = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        self.assertEqual([s.rank for s in ranks], sorted(s.rank for s in ranks))

    def test_status_is_derived_when_not_given(self):
        self.assertEqual(finding(severity=Severity.INFO).status, FindingStatus.INFORMATIONAL)
        self.assertEqual(finding(confidence=Confidence.LOW).status, FindingStatus.POTENTIAL)
        self.assertEqual(finding().status, FindingStatus.CONFIRMED)
        self.assertEqual(finding(status=FindingStatus.POTENTIAL).status, FindingStatus.POTENTIAL)

    def test_duplicates_are_dropped_but_different_targets_are_kept(self):
        r = ScanResult()
        self.assertTrue(r.add(finding("A", target="https://x/1")))
        self.assertFalse(r.add(finding("A", target="https://x/1")))
        self.assertTrue(r.add(finding("A", target="https://x/2")))
        self.assertTrue(r.add(finding("A", target="https://x/1", parameter="p")))
        self.assertEqual(len(r.findings), 3)

    def test_sorted_by_severity_then_status(self):
        r = ScanResult()
        r.add(finding("L", Severity.LOW)); r.add(finding("C", Severity.CRITICAL))
        r.add(finding("M2", Severity.MEDIUM, status=FindingStatus.POTENTIAL)); r.add(finding("M1", Severity.MEDIUM))
        self.assertEqual([f.id for f in r.sorted_findings()], ["C", "M1", "M2", "L"])

    def test_quality_findings_never_count_as_security(self):
        r = ScanResult()
        r.add(finding("S", Severity.HIGH, category="headers")); r.add(finding("Q", Severity.HIGH, category="seo"))
        self.assertEqual(r.severity_breakdown("security")["High"], 1)
        self.assertEqual(r.severity_breakdown("quality")["High"], 1)
        self.assertEqual(r.severity_breakdown()["High"], 2)
        quality_only = ScanResult(); quality_only.add(finding("Q", Severity.HIGH, category="links"))
        self.assertFalse(quality_only.has_serious_findings())

    def test_informational_status_is_not_serious(self):
        r = ScanResult(); r.add(finding("X", Severity.HIGH, status=FindingStatus.INFORMATIONAL))
        self.assertFalse(r.has_serious_findings())

    def test_round_trip_keeps_every_field(self):
        r = ScanResult(scan_type="web", target="https://example.com", requests_made=7, outcome="partial", errors=["warn"], metadata={"a": {"b": 1}})
        r.add(finding("M", Severity.MEDIUM, references=["https://x"], target="https://t", parameter="p", detection_method="dm", cwe="CWE-1", owasp="A05"))
        r.baseline_results.append(BaselineResult("R1", "d", BaselineStatus.PASS, "ok")); r.mark_finished()
        back = ScanResult.from_dict(json.loads(r.to_json()))
        self.assertEqual(back.to_dict(), r.to_dict())
        f = back.findings[0]
        self.assertEqual((f.parameter, f.detection_method, f.cwe, f.owasp, f.status), ("p", "dm", "CWE-1", "A05", FindingStatus.CONFIRMED))

    def test_old_json_without_new_fields_still_loads(self):
        old = {"scan_type": "web", "target": "t", "findings": [{"id": "X", "title": "t", "category": "web", "severity": "High",
               "confidence": "High", "description": "d", "evidence": "e", "impact": "i", "remediation": "r"}]}
        self.assertEqual(ScanResult.from_dict(old).findings[0].status, FindingStatus.CONFIRMED)

    def test_unknown_enum_value_is_rejected_not_guessed(self):
        with self.assertRaises(ValueError):
            Finding.from_dict({"id": "X", "title": "t", "category": "c", "severity": "Catastrophic", "confidence": "High", "description": "d"})


class BaselineTests(unittest.TestCase):
    def run_rule(self, rule, *findings, scan_type="web"):
        r = ScanResult(scan_type=scan_type, target="t")
        for f in findings:
            r.add(f)
        evaluate_baseline({"rules": [{"id": "R", "description": "d", **rule}]}, r)
        return r.baseline_results[0].status

    def test_require_absence_of_id(self):
        rule = {"type": "require_absence_of_id", "finding_id": "WEB-TLS-NOHTTPS"}
        self.assertEqual(self.run_rule(rule), BaselineStatus.PASS)
        self.assertEqual(self.run_rule(rule, finding("WEB-TLS-NOHTTPS", Severity.HIGH)), BaselineStatus.FAIL)

    def test_forbid_finding_prefix_and_custom_fail_status(self):
        rule = {"type": "forbid_finding_prefix", "prefix": "WEB-HDR-MISSING", "fail_status": "WARN"}
        self.assertEqual(self.run_rule(rule, finding("WEB-HDR-MISSING-X", Severity.LOW)), BaselineStatus.WARN)
        self.assertEqual(self.run_rule({**rule, "fail_status": "FAIL"}, finding("SYS-SSH-ROOTLOGIN", category="system"), finding("WEB-HDR-MISSING-Y")), BaselineStatus.FAIL)

    def test_no_high_in_category(self):
        rule = {"type": "require_no_high_or_above_in_category", "category": "system"}
        self.assertEqual(self.run_rule(rule, finding("S", Severity.CRITICAL, category="system")), BaselineStatus.FAIL)
        self.assertEqual(self.run_rule(rule, finding("S", Severity.LOW, category="system")), BaselineStatus.PASS)

    def test_unknown_rule_type_is_not_applicable(self):
        self.assertEqual(self.run_rule({"type": "bogus"}), BaselineStatus.NOT_APPLICABLE)


class UrlTests(unittest.TestCase):
    def test_valid_inputs_are_normalized(self):
        cases = {"example.com": "https://example.com/", " https://Example.com/a?b=1#frag ": "https://example.com/a?b=1",
                 "localhost:8000": "https://localhost:8000/", "http://[::1]:9000/": "http://[::1]:9000/", "127.0.0.1:8080/x": "https://127.0.0.1:8080/x"}
        for raw, want in cases.items():
            self.assertEqual(parse_target(raw).url, want, raw)

    def test_scheme_defaulted_flag(self):
        self.assertTrue(parse_target("example.com").scheme_defaulted)
        self.assertFalse(parse_target("http://example.com").scheme_defaulted)

    def test_idn_host_is_punycoded(self):
        self.assertEqual(parse_target("münchen.de").url, "https://xn--mnchen-3ya.de/")

    def test_bad_inputs_are_rejected_with_a_message(self):
        for raw in ["", "   ", "foo", "javascript:alert(1)", "file:///etc/passwd", "ftp://x.com", "https://user:pw@x.com",
                    "http://", "a b.com", "http://x.com:99999", "https://" + "a" * 3000 + ".com"]:
            with self.assertRaises(InvalidUrlError, msg=raw[:30]) as cm:
                parse_target(raw)
            self.assertTrue(str(cm.exception))

    def test_swap_scheme_only_on_standard_ports(self):
        self.assertEqual(swap_scheme("https://x.com/a?q=1", "http"), "http://x.com/a?q=1")
        self.assertIsNone(swap_scheme("https://x.com:8443/", "http"))
        self.assertEqual(swap_scheme("https://x.com:8443/", "http", any_port=True), "http://x.com:8443/")


class OptionsTests(unittest.TestCase):
    def test_defaults_and_unknown_keys(self):
        self.assertEqual(ScanOptions.from_dict(None), ScanOptions())
        self.assertEqual(ScanOptions.from_dict({"from_a_future_version": 1}), ScanOptions())

    def test_valid_values_are_applied(self):
        o = ScanOptions.from_dict({"timeout": 3, "rate_limit_per_second": 1.5, "check_cors": False, "max_links_to_check": 0})
        self.assertEqual((o.timeout, o.rate_limit_per_second, o.check_cors, o.max_links_to_check), (3, 1.5, False, 0))

    def test_invalid_values_are_reported_per_field_never_silently_defaulted(self):
        with self.assertRaises(OptionsError) as cm:
            ScanOptions.from_dict({"timeout": 999, "rate_limit_per_second": "fast", "check_tls": "yes", "user_agent": "bad\nagent", "max_links_to_check": True})
        self.assertEqual(set(cm.exception.fields), {"timeout", "rate_limit_per_second", "check_tls", "user_agent", "max_links_to_check"})


class SettingsTests(unittest.TestCase):
    def test_defaults_listen_on_loopback_only(self):
        s = Settings.from_env({})
        self.assertEqual((s.host, s.port), ("127.0.0.1", 8765))
        self.assertEqual(s.allowed_hosts, {"127.0.0.1", "localhost", "::1"})

    def test_remote_binding_requires_explicit_opt_in_and_hosts(self):
        for env in ({"AYYSCANNER_HOST": "0.0.0.0"}, {"AYYSCANNER_HOST": "0.0.0.0", "AYYSCANNER_ALLOW_REMOTE": "1"}):
            with self.assertRaises(SettingsError):
                Settings.from_env(env)
        ok = Settings.from_env({"AYYSCANNER_HOST": "0.0.0.0", "AYYSCANNER_ALLOW_REMOTE": "1", "AYYSCANNER_ALLOWED_HOSTS": "scan.internal"})
        self.assertEqual(ok.allowed_hosts, {"scan.internal"})

    def test_bad_values_give_clear_errors(self):
        for env in ({"AYYSCANNER_PORT": "abc"}, {"AYYSCANNER_PORT": "70000"}, {"AYYSCANNER_MAX_CONCURRENT_SCANS": "0"}, {"AYYSCANNER_LOG_LEVEL": "LOUD"}):
            with self.assertRaises(SettingsError, msg=str(env)):
                Settings.from_env(env)

    def test_dotenv_never_overrides_real_environment(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / ".env"
            path.write_text('# comment\nAYYSCANNER_PORT=9001\nAYYSCANNER_HOST="127.0.0.1"\nAYYSCANNER_LOG_LEVEL=DEBUG\nnot a pair\n')
            env = {"AYYSCANNER_LOG_LEVEL": "ERROR"}
            load_dotenv(path, env)
            self.assertEqual((env["AYYSCANNER_PORT"], env["AYYSCANNER_HOST"], env["AYYSCANNER_LOG_LEVEL"]), ("9001", "127.0.0.1", "ERROR"))
            load_dotenv(Path(d) / "missing.env", env)  # a missing file is fine


if __name__ == "__main__":
    unittest.main()
