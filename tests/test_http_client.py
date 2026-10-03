import socket
import threading
import time
import unittest

from ayyscanner.web_scan.http import HttpClient, ScanCancelled, resolve_is_public
from ayyscanner.web_scan.options import ScanOptions
from tests.support import Route, Site


def fake_resolver(mapping):
    def resolver(host, port, proto=0):
        if host not in mapping:
            raise socket.gaierror(-2, "Name or service not known")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (mapping[host], 0))]
    return resolver


def client(**kw):
    allow_private = kw.pop("allow_private", True)
    return HttpClient(ScanOptions(rate_limit_per_second=20, **kw), allow_private=allow_private)


class FetchTests(unittest.TestCase):
    def test_basic_get_and_request_count_matches_the_server(self):
        with Site({"/": Route(200, "hello", content_type="text/plain")}) as site:
            c = client()
            for _ in range(3):
                res = c.fetch(site.url + "/")
            self.assertEqual(res.response.text, "hello")
            self.assertEqual(c.requests_made, 3)
            self.assertEqual(len(site.requests), 3, "the counter must equal what the server actually saw")

    def test_redirects_are_followed_and_recorded(self):
        with Site({"/a": Route(302, headers=[("Location", "/b")]), "/b": Route(301, headers=[("Location", "/c")]), "/c": Route(200, "end")}) as site:
            res = client().fetch(site.url + "/a")
            self.assertEqual(res.response.url, site.url + "/c")
            self.assertEqual([s for _, s in res.response.redirects], [302, 301])

    def test_redirect_loop_gives_a_readable_error(self):
        with Site({"/loop": Route(302, headers=[("Location", "/loop")])}) as site:
            res = client().fetch(site.url + "/loop")
            self.assertEqual(res.error.kind, "redirects")
            self.assertIn("redirect", res.error.message)

    def test_follow_redirects_false_returns_the_redirect_itself(self):
        with Site({"/a": Route(302, headers=[("Location", "/b")])}) as site:
            self.assertEqual(client().fetch(site.url + "/a", follow_redirects=False).response.status, 302)

    def test_body_is_capped_and_marked_truncated(self):
        with Site({"/big": Route(200, "x" * 200_000, content_type="text/plain")}) as site:
            res = client().fetch(site.url + "/big", max_bytes=50_000)
            self.assertEqual((len(res.response.body), res.response.truncated), (50_000, True))
            small = client().fetch(site.url + "/big", max_bytes=500_000)
            self.assertEqual((len(small.response.body), small.response.truncated), (200_000, False))

    def test_max_bytes_zero_reads_headers_only(self):
        with Site({"/": Route(200, "body")}) as site:
            self.assertEqual(client().fetch(site.url + "/", max_bytes=0).response.body, b"")

    def test_timeout_message_names_the_limit(self):
        with Site({"/slow": Route(200, "x", delay=3)}) as site:
            t0 = time.time()
            res = client(timeout=1).fetch(site.url + "/slow")
            self.assertEqual(res.error.kind, "timeout")
            self.assertIn("1 seconds", res.error.message)
            self.assertLess(time.time() - t0, 2.5)

    def test_connection_refused_and_dns_failure_messages(self):
        refused = client().fetch("http://127.0.0.1:1/")
        self.assertEqual(refused.error.kind, "refused")
        self.assertIn("127.0.0.1:1", refused.error.message)
        dns = client().fetch("http://no-such-host.invalid/")
        self.assertEqual(dns.error.kind, "dns")
        self.assertIn("no-such-host.invalid", dns.error.message)
        for err in (refused.error, dns.error):
            self.assertNotIn("0x", err.message)
            self.assertNotIn("Traceback", err.message)

    def test_multiple_set_cookie_headers_are_all_seen(self):
        with Site({"/": Route(200, "x", headers=[("Set-Cookie", "a=1"), ("Set-Cookie", "b=2; Secure")])}) as site:
            self.assertEqual(client().fetch(site.url + "/").response.set_cookies, ["a=1", "b=2; Secure"])

    def test_scanner_neither_stores_nor_sends_cookies(self):
        with Site({"/": Route(200, "x", headers=[("Set-Cookie", "session=abc")])}) as site:
            c = client()
            c.fetch(site.url + "/"); c.fetch(site.url + "/")
            self.assertTrue(all("cookie" not in headers for _, _, headers in site.requests))

    def test_custom_request_headers_and_user_agent_are_sent(self):
        with Site({"/": Route(200, "x")}) as site:
            client(user_agent="Custom-UA/1").fetch(site.url + "/", headers={"Origin": "https://o.example"})
            headers = site.requests[0][2]
            self.assertEqual((headers["user-agent"], headers["origin"]), ("Custom-UA/1", "https://o.example"))

    def test_cancel_stops_before_sending(self):
        with Site({"/": Route(200, "x")}) as site:
            cancel = threading.Event(); cancel.set()
            c = HttpClient(ScanOptions(rate_limit_per_second=20), allow_private=True, cancel_event=cancel)
            with self.assertRaises(ScanCancelled):
                c.fetch(site.url + "/")
            self.assertEqual(len(site.requests), 0)

    def test_rate_limit_is_enforced(self):
        with Site({"/": Route(200, "x")}) as site:
            c = HttpClient(ScanOptions(rate_limit_per_second=5), allow_private=True)  # 0.2 s apart
            t0 = time.time()
            for _ in range(6):
                c.fetch(site.url + "/")
            self.assertGreaterEqual(time.time() - t0, 0.9)


class SsrfGuardTests(unittest.TestCase):
    RESOLVER = staticmethod(fake_resolver({"public.test": "93.184.216.34", "internal.test": "10.0.0.5", "loop.test": "127.0.0.1",
                                          "meta.test": "169.254.169.254", "mapped.test": "::ffff:127.0.0.1", "mixed.test": "93.184.216.34"}))

    def guarded(self):
        return HttpClient(ScanOptions(rate_limit_per_second=20), allow_private=False, resolver=self.RESOLVER)

    def test_resolve_is_public_classification(self):
        for host, want in [("public.test", True), ("internal.test", False), ("loop.test", False), ("meta.test", False), ("nx.test", None)]:
            self.assertIs(resolve_is_public(host, self.RESOLVER), want, host)

    def test_private_targets_are_refused_for_public_scans(self):
        for host in ("internal.test", "loop.test", "meta.test"):
            res = self.guarded().fetch(f"http://{host}/")
            self.assertEqual(res.error.kind, "blocked", host)
            self.assertIn("private or internal", res.error.message)

    def test_blocked_requests_never_reach_the_network_or_the_counter(self):
        c = self.guarded()
        c.fetch("http://internal.test/")
        self.assertEqual(c.requests_made, 0)

    def test_non_http_schemes_are_refused(self):
        for url in ("file:///etc/passwd", "ftp://x/", "gopher://x/"):
            self.assertEqual(self.guarded().fetch(url).error.kind, "blocked", url)

    def test_redirect_into_the_private_network_is_blocked_at_the_hop(self):
        # A public-looking page that redirects to a loopback address must not be followed.
        with Site({"/r": Route(302, headers=[("Location", "http://meta.test/latest/meta-data")])}) as site:
            c = HttpClient(ScanOptions(rate_limit_per_second=20), allow_private=False,
                           resolver=fake_resolver({"127.0.0.1": "93.184.216.34", "meta.test": "169.254.169.254"}))
            res = c.fetch(site.url + "/r")  # first hop 'looks public' through the fake resolver
            self.assertEqual(res.error.kind, "blocked")
            self.assertEqual(c.requests_made, 1, "only the first hop may be requested")

    def test_private_targets_are_allowed_when_the_scan_target_itself_is_private(self):
        with Site({"/": Route(200, "ok")}) as site:
            self.assertTrue(client(allow_private=True).fetch(site.url + "/").ok)


if __name__ == "__main__":
    unittest.main()
