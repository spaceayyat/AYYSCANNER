import unittest

from bs4 import BeautifulSoup

from ayyscanner.models import FindingStatus, Severity
from ayyscanner.web_scan import probes, security, seo
from ayyscanner.web_scan.links import extract_links
from ayyscanner.web_scan.page import build_page_info, count_words
from tests.support import Route, Site, make_ctx, make_response


def ids(ctx):
    return {f.id for f in ctx.result.findings}


def by_id(ctx, fid):
    return next(f for f in ctx.result.findings if f.id == fid)


def soup(html):
    return BeautifulSoup(html, "html.parser")


class HeaderTests(unittest.TestCase):
    def test_everything_missing_on_https(self):
        ctx = make_ctx()
        security.check_headers(ctx, make_response(), True)
        self.assertEqual(ids(ctx), {f"WEB-HDR-MISSING-{h}" for h in (
            "CONTENT-SECURITY-POLICY", "STRICT-TRANSPORT-SECURITY", "X-CONTENT-TYPE-OPTIONS", "X-FRAME-OPTIONS", "REFERRER-POLICY", "PERMISSIONS-POLICY")})
        self.assertEqual(by_id(ctx, "WEB-HDR-MISSING-CONTENT-SECURITY-POLICY").severity, Severity.MEDIUM)
        self.assertEqual(by_id(ctx, "WEB-HDR-MISSING-REFERRER-POLICY").status, FindingStatus.INFORMATIONAL)
        self.assertEqual(by_id(ctx, "WEB-HDR-MISSING-X-FRAME-OPTIONS").parameter, "X-Frame-Options")

    def test_hsts_is_not_expected_over_plain_http(self):
        ctx = make_ctx("http://example.test/")
        security.check_headers(ctx, make_response("http://example.test/"), False)
        self.assertNotIn("WEB-HDR-MISSING-STRICT-TRANSPORT-SECURITY", ids(ctx))

    def test_csp_frame_ancestors_satisfies_clickjacking_protection(self):
        ctx = make_ctx()
        security.check_headers(ctx, make_response(headers={"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"}), True)
        self.assertNotIn("WEB-HDR-MISSING-X-FRAME-OPTIONS", ids(ctx))
        self.assertNotIn("WEB-HDR-MISSING-CONTENT-SECURITY-POLICY", ids(ctx))

    def test_report_only_csp_does_not_count_as_enforced(self):
        ctx = make_ctx()
        security.check_headers(ctx, make_response(headers={"Content-Security-Policy-Report-Only": "default-src 'self'"}), True)
        self.assertIn("Report-Only", by_id(ctx, "WEB-HDR-MISSING-CONTENT-SECURITY-POLICY").evidence)

    def test_hsts_strength(self):
        for value, weak in [("max-age=300", True), ("max-age=31536000; includeSubDomains", False), ("includeSubDomains", True), ('max-age="600"', True)]:
            ctx = make_ctx()
            security.check_headers(ctx, make_response(headers={"Strict-Transport-Security": value}), True)
            self.assertEqual("WEB-HDR-HSTS-WEAK" in ids(ctx), weak, value)

    def test_csp_weakness_detection(self):
        cases = {"script-src 'self' 'unsafe-inline'": True, "script-src 'self' 'nonce-abc' 'unsafe-inline'": False, "default-src 'self'": False,
                 "default-src *": True, "script-src 'self' 'unsafe-eval'": True, "img-src 'self'": True, "script-src 'self' https://cdn.example": False}
        for csp, weak in cases.items():
            ctx = make_ctx()
            security.check_headers(ctx, make_response(headers={"Content-Security-Policy": csp}), True)
            self.assertEqual("WEB-CSP-WEAK" in ids(ctx), weak, csp)

    def test_server_banners(self):
        for headers, expected, severity in [({"Server": "nginx"}, "WEB-BANNER-SERVER", Severity.INFO), ({"Server": "Apache/2.4.41 (Ubuntu)"}, "WEB-BANNER-SERVER", Severity.LOW),
                                            ({"X-Powered-By": "PHP/7.4.3"}, "WEB-BANNER-X-POWERED-BY", Severity.LOW)]:
            ctx = make_ctx()
            security.check_banners(ctx, make_response(headers=headers))
            self.assertEqual(by_id(ctx, expected).severity, severity, headers)


class CookieTests(unittest.TestCase):
    def run_cookies(self, cookies, https=True):
        ctx = make_ctx("https://example.test/" if https else "http://example.test/")
        security.check_cookies(ctx, make_response(cookies=cookies), https)
        return ctx

    def test_flags_are_checked_and_grouped_per_attribute(self):
        ctx = self.run_cookies(["a=1; Path=/", "b=2; Path=/"])
        self.assertEqual(ids(ctx), {"WEB-COOKIE-SECURE", "WEB-COOKIE-HTTPONLY", "WEB-COOKIE-SAMESITE"})
        self.assertEqual(by_id(ctx, "WEB-COOKIE-SECURE").parameter, "a, b")

    def test_well_configured_cookie_is_clean(self):
        self.assertEqual(ids(self.run_cookies(["id=1; Secure; HttpOnly; SameSite=Lax"])), set())

    def test_session_cookies_are_escalated(self):
        ctx = self.run_cookies(["PHPSESSID=abc; Path=/"])
        self.assertEqual(by_id(ctx, "WEB-COOKIE-HTTPONLY").severity, Severity.MEDIUM)
        self.assertEqual(by_id(ctx, "WEB-COOKIE-SECURE").severity, Severity.MEDIUM)
        self.assertEqual(by_id(self.run_cookies(["theme=dark"]), "WEB-COOKIE-SECURE").severity, Severity.LOW)

    def test_secure_is_meaningless_over_http_and_csrf_cookies_may_be_js_readable(self):
        self.assertNotIn("WEB-COOKIE-SECURE", ids(self.run_cookies(["a=1"], https=False)))
        self.assertNotIn("WEB-COOKIE-HTTPONLY", ids(self.run_cookies(["XSRF-TOKEN=1; Secure; SameSite=Lax"])))

    def test_samesite_none_requires_secure(self):
        self.assertIn("WEB-COOKIE-SAMESITE-NONE", ids(self.run_cookies(["a=1; SameSite=None; HttpOnly"])))

    def test_cookie_values_are_never_stored(self):
        ctx = self.run_cookies(["sessionid=SUPERSECRETVALUE; Path=/"])
        blob = str(ctx.result.to_dict()) + str(ctx.facts)
        self.assertNotIn("SUPERSECRETVALUE", blob)
        self.assertIn("sessionid=<redacted>", blob)


class ContentTests(unittest.TestCase):
    def test_mixed_content_active_vs_passive(self):
        ctx = make_ctx()
        security.check_mixed_content(ctx, soup('<script src="http://a/x.js"></script><link rel="stylesheet" href="http://a/s.css"><img src="http://a/i.png"><iframe src="//a/f"></iframe>'), True)
        self.assertEqual(ids(ctx), {"WEB-MIXED-ACTIVE", "WEB-MIXED-PASSIVE"})
        self.assertEqual(ctx.facts["mixed_content"]["active"], 2)  # script + stylesheet; the protocol-relative iframe resolves to https

    def test_non_subresource_links_are_not_mixed_content(self):
        ctx = make_ctx()
        security.check_mixed_content(ctx, soup('<link rel="canonical" href="http://a/"><link rel="alternate" href="http://a/x"><a href="http://a/">x</a>'), True)
        self.assertEqual(ids(ctx), set())

    def test_no_mixed_content_finding_on_an_http_page(self):
        ctx = make_ctx("http://example.test/")
        security.check_mixed_content(ctx, soup('<script src="http://a/x.js"></script>'), False)
        self.assertEqual(ids(ctx), set())

    def test_forms(self):
        cases = [('<form action="http://x/login" method="post"><input type="password"></form>', True, {"WEB-FORM-INSECURE-ACTION"}),
                 ('<form action="/login"><input type="password"></form>', True, {"WEB-FORM-PASSWORD-GET"}),
                 ('<form action="/login" method="post"><input type="password"></form>', True, set()),
                 ('<form action="/login" method="post"><input type="password"></form>', False, {"WEB-FORM-PASSWORD-HTTP"}),
                 ('<form action="/search"><input type="text" name="q"></form>', True, set())]
        for html, https, expected in cases:
            ctx = make_ctx("https://example.test/" if https else "http://example.test/")
            security.check_forms(ctx, soup(html), https)
            self.assertEqual(ids(ctx), expected, html)

    def test_subresource_integrity(self):
        html = ('<script src="https://cdn.other.net/a.js"></script><script src="https://cdn.other.net/b.js" integrity="sha384-x" crossorigin="anonymous"></script>'
                '<script src="/local.js"></script><script src="https://www.example.test/www.js"></script>'
                '<link rel="stylesheet" href="https://fonts.other.net/c.css"><link rel="icon" href="https://cdn.other.net/i.png">')
        ctx = make_ctx()
        security.check_third_party_scripts(ctx, soup(html))
        self.assertEqual(ctx.facts["third_party_without_sri"], 2)
        self.assertIn("a.js", by_id(ctx, "WEB-SRI-MISSING").evidence)
        self.assertNotIn("b.js", by_id(ctx, "WEB-SRI-MISSING").evidence)

    def test_error_message_disclosure_is_potential_not_confirmed(self):
        ctx = make_ctx()
        security.check_info_disclosure(ctx, "<pre>Traceback (most recent call last):\n  File x</pre> ... Fatal error: boom in /var/www/a.php on line 12")
        self.assertEqual(len(ctx.result.findings), 2)
        self.assertTrue(all(f.status == FindingStatus.POTENTIAL for f in ctx.result.findings))
        clean = make_ctx(); security.check_info_disclosure(clean, "<p>Nothing to see</p>"); self.assertEqual(ids(clean), set())


class RegressionTests(unittest.TestCase):
    def test_counting_words_must_not_delete_scripts(self):
        # The original code decomposed <script> in the body while counting words, so the
        # mixed-content and JSON-LD checks that ran afterwards never saw them.
        html = ('<html><head><title>t</title></head><body><p>hello big world</p><script src="http://cdn/x.js"></script>'
                '<script type="application/ld+json">{"@type":"Organization"}</script></body></html>')
        s = soup(html)
        self.assertEqual(count_words(s), 3)
        self.assertEqual(len(s.find_all("script")), 2)
        ctx = make_ctx()
        security.check_mixed_content(ctx, s, True)
        self.assertIn("WEB-MIXED-ACTIVE", ids(ctx))
        info = build_page_info("https://example.test/", make_response(body=html), s, True)
        facts = seo.run_seo_checks(ctx, info, s)
        self.assertTrue(facts["structured_data_present"])
        self.assertEqual(facts["structured_data_types"], ["Organization"])

    def test_decorative_empty_alt_is_not_flagged(self):
        ctx = make_ctx()
        info = build_page_info("https://example.test/", make_response(body="x"), soup("<html></html>"), True)
        seo.run_seo_checks(ctx, info, soup('<img src="a.png" alt=""><img src="b.png" alt="A logo">'))
        self.assertNotIn("SEO-IMG-ALT-MISSING", ids(ctx))
        ctx2 = make_ctx(); seo.run_seo_checks(ctx2, info, soup('<img src="a.png">'))
        self.assertIn("SEO-IMG-ALT-MISSING", ids(ctx2))

    def test_relative_canonical_is_resolved_before_comparing(self):
        html = '<html><head><title>A title that is long enough</title><link rel="canonical" href="/page"></head><body></body></html>'
        s = soup(html)
        info = build_page_info("https://example.test/page", make_response("https://example.test/page", body=html), s, True)
        ctx = make_ctx("https://example.test/page"); seo.run_seo_checks(ctx, info, s)
        self.assertNotIn("SEO-CANONICAL-MISMATCH", ids(ctx))


class SeoTests(unittest.TestCase):
    def run_seo(self, html):
        s = soup(html)
        info = build_page_info("https://example.test/", make_response(body=html), s, True)
        ctx = make_ctx(); seo.run_seo_checks(ctx, info, s)
        return ctx

    def test_missing_pieces(self):
        got = ids(self.run_seo("<html><body><p>hi</p></body></html>"))
        self.assertTrue({"SEO-TITLE-MISSING", "SEO-METADESC-MISSING", "SEO-H1-MISSING", "SEO-VIEWPORT-MISSING", "SEO-CANONICAL-MISSING"} <= got)

    def test_title_length_bounds_and_noindex(self):
        self.assertIn("SEO-TITLE-TOO-SHORT", ids(self.run_seo("<title>Hi</title>")))
        self.assertIn("SEO-TITLE-TOO-LONG", ids(self.run_seo(f"<title>{'x' * 80}</title>")))
        self.assertIn("SEO-TITLE-EMPTY", ids(self.run_seo("<title></title>")))
        self.assertEqual(by_id(self.run_seo('<meta name="robots" content="noindex, follow">'), "SEO-ROBOTS-NOINDEX").status, FindingStatus.POTENTIAL)

    def test_seo_never_produces_security_findings(self):
        ctx = self.run_seo("<html></html>")
        self.assertTrue(ctx.result.findings and all(f.domain == "quality" for f in ctx.result.findings))
        self.assertTrue(all(f.severity.rank <= Severity.MEDIUM.rank for f in ctx.result.findings))


class LinkExtractionTests(unittest.TestCase):
    def test_classification_dedup_fragments_and_base(self):
        html = ('<base href="https://example.test/docs/"><a href="a">A</a><a href="a#top">A2</a><a href="https://other.test/x">X</a>'
                '<a href="mailto:me@x.com">m</a><a href="javascript:alert(1)">j</a><a href="#top">t</a><a href="  ">empty</a>')
        links = extract_links("https://example.test/", soup(html))
        kinds = {i.url: i.link_type for i in links.items}
        self.assertEqual(kinds["https://example.test/docs/a"], "internal")
        self.assertEqual(kinds["https://other.test/x"], "external")
        self.assertEqual(kinds["javascript:alert(1)"], "other")
        self.assertEqual(next(i for i in links.items if i.url.endswith("/docs/a")).occurrences, 2)
        self.assertEqual((links.total_found, links.unique_count, links.duplicate_count), (6, 5, 1))


class ProbeTests(unittest.TestCase):
    def run_probe(self, routes, fn):
        with Site(routes) as site:
            ctx = make_ctx(site.url + "/")
            fn(ctx)
            return ctx, site

    def test_git_exposure_requires_real_git_content(self):
        ctx, _ = self.run_probe({"/.git/HEAD": Route(200, "ref: refs/heads/main\n", content_type="text/plain")}, probes.check_sensitive_files)
        self.assertIn("WEB-EXPOSED-GIT", ids(ctx))
        for body in ("<html><title>Welcome</title>catch-all page</html>", "not a git file"):
            ctx, _ = self.run_probe({"/.git/HEAD": Route(200, body), "/.env": Route(200, body), "/phpinfo.php": Route(200, body)}, probes.check_sensitive_files)
            self.assertEqual(ids(ctx), set(), "a 200 status alone must not be reported as an exposure")

    def test_env_file_is_redacted_and_escalated_only_for_secret_like_keys(self):
        ctx, _ = self.run_probe({"/.env": Route(200, "APP_NAME=demo\nDB_PASSWORD=hunter2\nAPI_KEY=abc123\n", content_type="text/plain")}, probes.check_sensitive_files)
        f = by_id(ctx, "WEB-EXPOSED-ENV")
        self.assertEqual(f.severity, Severity.CRITICAL)
        self.assertNotIn("hunter2", str(ctx.result.to_dict())); self.assertNotIn("abc123", str(ctx.result.to_dict()))
        self.assertIn("DB_PASSWORD", f.evidence)
        ctx, _ = self.run_probe({"/.env": Route(200, "APP_NAME=demo\nDEBUG=true\n", content_type="text/plain")}, probes.check_sensitive_files)
        self.assertEqual(by_id(ctx, "WEB-EXPOSED-ENV").severity, Severity.HIGH)

    def test_phpinfo(self):
        ctx, _ = self.run_probe({"/phpinfo.php": Route(200, "<html><title>phpinfo()</title>PHP Version 8.1.2</html>")}, probes.check_sensitive_files)
        self.assertIn("WEB-EXPOSED-PHPINFO", ids(ctx))

    def test_sensitive_probe_can_be_disabled_and_is_recorded_as_skipped(self):
        with Site({"/.git/HEAD": Route(200, "ref: refs/heads/main")}) as site:
            ctx = make_ctx(site.url + "/", check_sensitive_files=False); probes.check_sensitive_files(ctx)
            self.assertEqual((ids(ctx), site.requests, ctx.checks[0]["status"]), (set(), [], "skipped"))

    def test_well_known_files(self):
        routes = {"/robots.txt": Route(200, "User-agent: *\nSitemap: https://x/sitemap.xml\n", content_type="text/plain"),
                  "/.well-known/security.txt": Route(200, "Contact: mailto:sec@example.test\n", content_type="text/plain")}
        ctx, _ = self.run_probe(routes, probes.check_well_known)
        self.assertEqual(ids(ctx), set(), "robots.txt declares a sitemap, and security.txt has a Contact")
        ctx, _ = self.run_probe({}, probes.check_well_known)
        self.assertEqual(ids(ctx), {"SEO-ROBOTS-TXT-MISSING", "SEO-SITEMAP-MISSING", "WEB-SECURITY-TXT-MISSING"})

    def test_html_catch_all_is_not_mistaken_for_robots_txt(self):
        ctx, _ = self.run_probe({"/robots.txt": Route(200, "<html><body>Home</body></html>")}, probes.check_well_known)
        self.assertIn("SEO-ROBOTS-TXT-MISSING", ids(ctx))

    def test_network_errors_do_not_produce_false_missing_findings(self):
        ctx = make_ctx("http://127.0.0.1:1/")
        probes.check_well_known(ctx)
        self.assertEqual(ids(ctx), set())
        self.assertTrue(ctx.result.errors)


class CorsTests(unittest.TestCase):
    def cors_ctx(self, route_fn, main_headers=None):
        with Site({"/": route_fn}) as site:
            ctx = make_ctx(site.url + "/")
            security.check_cors(ctx, make_response(site.url + "/", headers=main_headers or {}))
            return ctx

    def test_reflection_with_credentials_is_high(self):
        ctx = self.cors_ctx(lambda h: Route(200, "x", headers=[("Access-Control-Allow-Origin", h.headers.get("Origin", "")), ("Access-Control-Allow-Credentials", "true")]))
        self.assertEqual(by_id(ctx, "WEB-CORS-REFLECT-CREDS").severity, Severity.HIGH)

    def test_reflection_without_credentials_is_only_potential(self):
        ctx = self.cors_ctx(lambda h: Route(200, "x", headers=[("Access-Control-Allow-Origin", h.headers.get("Origin", ""))]))
        self.assertEqual(by_id(ctx, "WEB-CORS-REFLECT").status, FindingStatus.POTENTIAL)

    def test_static_allow_list_is_fine_and_wildcard_is_noted(self):
        ctx = self.cors_ctx(lambda h: Route(200, "x", headers=[("Access-Control-Allow-Origin", "https://trusted.test")]))
        self.assertEqual(ids(ctx), set())
        ctx = self.cors_ctx(lambda h: Route(200, "x"), main_headers={"Access-Control-Allow-Origin": "*"})
        self.assertEqual(ids(ctx), {"WEB-CORS-WILDCARD"})


if __name__ == "__main__":
    unittest.main()
