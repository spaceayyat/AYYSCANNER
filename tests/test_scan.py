import socket
import threading
import time
import unittest
from unittest import mock

from ayyscanner.models import OUTCOME_COMPLETE, OUTCOME_FAILED, OUTCOME_PARTIAL
from ayyscanner.web_scan import probes, run_web_scan
from ayyscanner.web_scan.options import ScanOptions
from tests.support import GOOD_HEADERS, HAVE_OPENSSL, Route, Site, page

FAST = ScanOptions(rate_limit_per_second=20)


def ids(result):
    return {f.id for f in result.findings}


def rich_routes():
    return {
        "/": Route(200, page('<a href="/ok">ok</a> <a href="/missing">gone</a> <a href="/redir">r</a> <a href="/forbidden">f</a> <a href="javascript:alert(1)">js</a>'
                             '<img src="a.png"><form action="http://evil.test/x" method="get"><input type="password"></form>'),
                   headers=[("Set-Cookie", "sessionid=SECRETCOOKIEVALUE; Path=/"), ("Server", "nginx/1.18.0")]),
        "/ok": Route(200, page()), "/redir": Route(302, headers=[("Location", "/ok")]), "/forbidden": Route(403, "no"),
        "/.git/HEAD": Route(200, "ref: refs/heads/main\n", content_type="text/plain"),
    }


class FullScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.site = Site(rich_routes()); cls.site.__enter__()
        cls.result = run_web_scan(cls.site.url + "/", FAST)

    @classmethod
    def tearDownClass(cls):
        cls.site.__exit__(None, None, None)

    def test_expected_findings(self):
        expected = {"WEB-TLS-NOHTTPS", "WEB-EXPOSED-GIT", "WEB-BANNER-SERVER", "WEB-COOKIE-HTTPONLY", "WEB-COOKIE-SAMESITE", "WEB-FORM-PASSWORD-HTTP",
                    "WEB-FORM-PASSWORD-GET", "WEB-HDR-MISSING-CONTENT-SECURITY-POLICY", "LINK-BROKEN", "LINK-REDIRECT", "SEO-IMG-ALT-MISSING"}
        self.assertEqual(expected - ids(self.result), set())
        self.assertEqual(self.result.outcome, OUTCOME_COMPLETE)

    def test_request_count_is_exactly_what_the_server_saw(self):
        self.assertEqual(self.result.requests_made, len(self.site.requests) - self._later_requests())

    def _later_requests(self):
        return 0  # the scan in setUpClass is the only client at this point

    def test_no_duplicate_findings_and_deterministic_order(self):
        keys = [f.dedupe_key for f in self.result.findings]
        self.assertEqual(len(keys), len(set(keys)))
        ranks = [f.severity.rank for f in self.result.sorted_findings("security")]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_security_and_quality_are_separated(self):
        self.assertTrue(all(f.category in ("seo", "links", "page") for f in self.result.findings if f.domain == "quality"))
        self.assertNotIn("SEO-IMG-ALT-MISSING", {f.id for f in self.result.sorted_findings("security")})

    def test_restricted_link_is_not_called_broken(self):
        links = {i["url"].rsplit("/", 1)[-1]: i for i in self.result.metadata["links"]["items"]}
        self.assertTrue(links["missing"]["is_broken"]); self.assertFalse(links["forbidden"]["is_broken"])
        self.assertIn("HTTP 403", links["forbidden"]["note"]); self.assertTrue(links["redir"]["is_redirect"])
        self.assertFalse(links["ok"]["is_broken"] or links["ok"]["is_redirect"])

    def test_secrets_never_reach_the_result(self):
        blob = self.result.to_json()
        self.assertNotIn("SECRETCOOKIEVALUE", blob)

    def test_every_check_is_accounted_for(self):
        checks = {c["name"]: c["status"] for c in self.result.metadata["checks"]}
        self.assertEqual(checks["Cookie attributes"], "ran")
        self.assertEqual(checks["Link status"], "ran")
        self.assertEqual(checks["TLS certificate and protocol"], "skipped")  # target is plain HTTP
        self.assertTrue(self.result.metadata["scope"])

    def test_metadata_sections_present(self):
        for key in ("page", "seo", "technical", "links", "checks", "options", "scope"):
            self.assertIn(key, self.result.metadata)
        self.assertEqual(self.result.metadata["page"]["status_code"], 200)


class TlsScanTests(unittest.TestCase):
    @unittest.skipUnless(HAVE_OPENSSL, "openssl CLI needed to create a test certificate")
    def test_self_signed_certificate_is_reported_and_the_scan_continues(self):
        with Site({"/": Route(200, page(), headers=GOOD_HEADERS + [("Set-Cookie", "sid=abc; Path=/")])}, tls=True) as site:
            r = run_web_scan(site.url, FAST)
        self.assertEqual(r.outcome, OUTCOME_COMPLETE)
        cert = next(f for f in r.findings if f.id == "WEB-TLS-CERT-INVALID")
        self.assertIn("self-signed", cert.evidence)
        self.assertTrue(any("without certificate verification" in e for e in r.errors), "the user must be told verification was skipped")
        self.assertEqual(r.metadata["technical"]["tls"]["version"], "TLSv1.3")
        self.assertTrue(r.metadata["technical"]["is_https"])
        self.assertIn("WEB-COOKIE-SECURE", ids(r))  # HTTPS-only checks ran
        self.assertNotIn("WEB-TLS-NOHTTPS", ids(r))
        self.assertFalse({i for i in ids(r) if i.startswith("WEB-HDR-MISSING")}, "all good headers were sent")

    @unittest.skipUnless(HAVE_OPENSSL, "openssl CLI needed to create a test certificate")
    def test_explicit_https_is_never_silently_downgraded(self):
        with Site({"/": Route(200, page())}) as plain_http_site:
            r = run_web_scan(plain_http_site.url.replace("http://", "https://"), FAST)
        self.assertEqual(r.outcome, OUTCOME_FAILED)
        self.assertEqual(plain_http_site.requests, [])


class FailureTests(unittest.TestCase):
    def test_invalid_url_fails_with_a_message_and_no_traffic(self):
        r = run_web_scan("ftp://x.com", FAST)
        self.assertEqual((r.outcome, r.requests_made), (OUTCOME_FAILED, 0))
        self.assertIn("Unsupported URL scheme", r.errors[0])
        self.assertEqual(r.findings, [], "a failed scan must not invent findings")

    def test_unreachable_target_is_a_failed_scan_not_a_critical_finding(self):
        r = run_web_scan("http://127.0.0.1:1/", FAST)
        self.assertEqual(r.outcome, OUTCOME_FAILED)
        self.assertEqual(r.findings, [])
        self.assertIn("refused", r.errors[0])

    def test_timeout(self):
        with Site({"/": Route(200, page(), delay=3)}) as site:
            r = run_web_scan(site.url, ScanOptions(rate_limit_per_second=20, timeout=1))
        self.assertEqual(r.outcome, OUTCOME_FAILED); self.assertIn("timed out after 1 seconds", r.errors[0])

    def test_http_error_page_is_labelled(self):
        with Site({"/": Route(500, "<html><title>Oops</title></html>")}) as site:
            r = run_web_scan(site.url, FAST)
        self.assertIn("PAGE-HTTP-ERROR", ids(r)); self.assertTrue(any("HTTP 500" in e for e in r.errors))

    def test_non_html_response_still_gets_header_checks_but_skips_html_checks(self):
        with Site({"/": Route(200, '{"ok": true}', content_type="application/json")}) as site:
            r = run_web_scan(site.url, FAST)
        self.assertIn("PAGE-NOT-HTML", ids(r)); self.assertIn("WEB-HDR-MISSING-CONTENT-SECURITY-POLICY", ids(r))
        self.assertFalse({i for i in ids(r) if i.startswith(("SEO-TITLE", "SEO-H1", "LINK-"))})
        self.assertIn("skipped", {c["status"] for c in r.metadata["checks"] if c["name"].startswith("HTML content")})

    def test_body_size_cap_is_reported(self):
        with Site({"/": Route(200, page("x " * 5000))}) as site:
            r = run_web_scan(site.url, ScanOptions(rate_limit_per_second=20, max_body_bytes=10_000))
        self.assertIn("PAGE-TRUNCATED", ids(r))


class BehaviourTests(unittest.TestCase):
    def test_scheme_less_input_falls_back_to_http_and_says_so(self):
        with Site({"/": Route(200, page())}) as site:
            r = run_web_scan(site.url.replace("http://", ""), FAST)
        self.assertEqual(r.outcome, OUTCOME_COMPLETE)
        self.assertTrue(r.target.startswith("http://")); self.assertTrue(any("http:// was scanned instead" in e for e in r.errors))

    def test_passive_only_sends_one_request(self):
        opts = ScanOptions(rate_limit_per_second=20, check_internal_links=False, check_external_links=False, check_cors=False,
                           check_well_known_files=False, check_sensitive_files=False, check_http_to_https_redirect=False)
        with Site(rich_routes()) as site:
            r = run_web_scan(site.url + "/", opts)
            self.assertEqual((r.requests_made, len(site.requests)), (1, 1))
        self.assertEqual({c["status"] for c in r.metadata["checks"] if "CORS" in c["name"] or "Sensitive" in c["name"]}, {"skipped"})

    def test_link_limit_is_applied_and_reported(self):
        links = "".join(f'<a href="/p{i}">p{i}</a>' for i in range(12))
        with Site({"/": Route(200, page(links))}) as site:
            r = run_web_scan(site.url + "/", ScanOptions(rate_limit_per_second=20, max_links_to_check=5))
        self.assertEqual(r.metadata["links"]["checked_count"], 5)
        self.assertTrue(any("limit is 5" in e for e in r.errors))

    def test_link_checker_cannot_be_steered_at_the_private_network(self):
        # A "public" target whose page links to an internal address: the internal link must not be requested.
        with Site({"/": Route(200, page('<a href="http://internal.test/admin">a</a><a href="/ok">ok</a>')), "/ok": Route(200, page())}) as site:
            def resolver(host, port, proto=0):
                ip = {"internal.test": "10.0.0.5"}.get(host, "93.184.216.34")  # everything else looks public, incl. the test server
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]
            r = run_web_scan(site.url + "/", FAST, resolver=resolver)
        item = next(i for i in r.metadata["links"]["items"] if "internal.test" in i["url"])
        self.assertFalse(item["checked"]); self.assertIn("Skipped", item["note"])
        self.assertFalse(item["is_broken"], "an unchecked link must not be reported as broken")
        self.assertTrue(any("private/internal" in e for e in r.errors))

    def test_redirect_to_a_different_host_is_flagged(self):
        with Site({"/": Route(200, page())}) as target:
            with Site({"/": lambda h: Route(302, headers=[("Location", target.url.replace("127.0.0.1", "localhost") + "/")])}) as front:
                r = run_web_scan(front.url + "/", FAST)
        self.assertTrue(any("redirected to a different host" in e for e in r.errors))

    def test_cancel_mid_scan_returns_partial_results_quickly(self):
        links = "".join(f'<a href="/s{i}">s{i}</a>' for i in range(20))
        routes = {"/": Route(200, page(links))}
        routes.update({f"/s{i}": Route(200, page(), delay=1.0) for i in range(20)})
        cancel = threading.Event()
        with Site(routes) as site:
            t0 = time.time()
            r = run_web_scan(site.url + "/", FAST, cancel_event=cancel, progress_cb=lambda p, stage, m: cancel.set() if stage == "links" and p > 72 else None)
            elapsed = time.time() - t0
        self.assertEqual(r.outcome, OUTCOME_PARTIAL)
        self.assertTrue(any("stopped before it finished" in e for e in r.errors))
        self.assertLess(elapsed, 8, "cancel must not wait for all 20 slow links")
        self.assertTrue(r.findings, "findings gathered before cancelling are kept")

    def test_a_crashing_stage_is_reported_and_other_stages_still_run(self):
        with Site({"/": Route(200, page())}) as site:
            with mock.patch.object(probes, "check_sensitive_files", side_effect=RuntimeError("boom")):
                with self.assertLogs("ayyscanner", level="ERROR"):
                    r = run_web_scan(site.url + "/", FAST)
        self.assertEqual(r.outcome, OUTCOME_PARTIAL)
        self.assertTrue(any("Sensitive file exposure" in e and "skipped" in e for e in r.errors))
        self.assertNotIn("boom", " ".join(r.errors), "internal exception text must not reach the user")
        self.assertIn("WEB-HDR-MISSING-CONTENT-SECURITY-POLICY", ids(r))
        self.assertEqual(next(c["status"] for c in r.metadata["checks"] if c["name"].startswith("Sensitive")), "failed")

    def test_progress_is_monotonic_and_ends_at_100(self):
        seen = []
        with Site(rich_routes()) as site:
            run_web_scan(site.url + "/", FAST, progress_cb=lambda p, s, m: seen.append(p))
        self.assertEqual(seen, sorted(seen)); self.assertEqual(seen[-1], 100)


if __name__ == "__main__":
    unittest.main()
