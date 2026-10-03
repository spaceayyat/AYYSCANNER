import time
import unittest

from ayyscanner.server import COOKIE_NAME, create_app
from ayyscanner.server.jobs import JobManager
from ayyscanner.settings import Settings
from tests.support import Route, Site, page

HOST = {"Host": "127.0.0.1:8765"}


def get(client, path, headers=None):
    """GET that fully reads (and so closes) the response, so no file handles leak in tests."""
    response = client.get(path, headers=headers or HOST)
    response.get_data()
    response.close()
    return response


JSON = {"Content-Type": "application/json"}
FAST = {"rate_limit_per_second": 20}


class ServerCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(Settings())
        self.client = self.app.test_client()
        get(self.client, "/", headers=HOST)  # receives the session cookie

    def post(self, url, body, **kw):
        return self.client.post(url, json=body, headers={**HOST, **kw.pop("headers", {})}, **kw)

    def wait(self, job_id, timeout=30):
        end = time.time() + timeout
        while time.time() < end:
            data = get(self.client, f"/api/scans/{job_id}", headers=HOST).get_json()
            if data["state"] in ("done", "failed", "cancelled"):
                return data
            time.sleep(0.1)
        self.fail("scan did not finish")


class GuardTests(ServerCase):
    def test_unknown_host_header_is_rejected(self):
        for path in ("/", "/api/health", "/static/app.js"):
            r = get(self.client, path, headers={"Host": "evil.example"})
            self.assertEqual(r.status_code, 403, path)
            self.assertEqual(r.get_json()["error"]["code"], "bad_host")

    def test_api_needs_the_session_cookie(self):
        fresh = self.app.test_client()
        self.assertEqual(get(fresh, "/api/health", headers=HOST).status_code, 403)
        self.assertEqual(fresh.post("/api/scans", json={}, headers=HOST).status_code, 403)
        self.assertEqual(get(self.client, "/api/health", headers=HOST).status_code, 200)

    def test_a_forged_cookie_is_rejected(self):
        fresh = self.app.test_client()
        fresh.set_cookie(COOKIE_NAME, "guess", domain="127.0.0.1")
        self.assertEqual(get(fresh, "/api/health", headers=HOST).status_code, 403)

    def test_cookie_attributes(self):
        cookie = get(self.app.test_client(), "/", headers=HOST).headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie); self.assertIn("SameSite=Strict", cookie)

    def test_cross_origin_and_non_json_posts_are_rejected(self):
        self.assertEqual(self.post("/api/scans", {}, headers={"Origin": "https://evil.example"}).get_json()["error"]["code"], "bad_origin")
        r = self.client.post("/api/scans", data="url=http://x", headers={**HOST, "Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual((r.status_code, r.get_json()["error"]["code"]), (415, "json_required"))
        same_origin = self.post("/api/scans", {}, headers={"Origin": "http://127.0.0.1:8765"})
        self.assertEqual(same_origin.get_json()["error"]["code"], "authorization_required")

    def test_security_headers_on_every_response(self):
        for r in (get(self.client, "/", headers=HOST), get(self.client, "/api/health", headers=HOST), get(self.client, "/nope", headers=HOST)):
            self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
            self.assertIn("frame-ancestors 'none'", r.headers["Content-Security-Policy"])
            self.assertEqual(r.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(get(self.client, "/api/health", headers=HOST).headers["Cache-Control"], "no-store")

    def test_no_path_traversal_through_static_or_assets(self):
        for path in ("/assets/../models.py", "/assets/models.py", "/assets/%2e%2e%2fmodels.py", "/static/../__init__.py", "/static/%2e%2e/settings.py"):
            self.assertEqual(get(self.client, path, headers=HOST).status_code, 404, path)
        self.assertEqual(get(self.client, "/assets/tokens.css", headers=HOST).status_code, 200)

    def test_oversized_bodies_are_refused(self):
        r = self.client.post("/api/scans", data="x" * 200_000, headers={**HOST, **JSON})
        self.assertEqual(r.status_code, 413)


class ValidationTests(ServerCase):
    def test_authorization_is_mandatory_and_must_be_literally_true(self):
        for auth in (None, False, "true", 1, "yes"):
            r = self.post("/api/scans", {"url": "https://example.com", "authorized": auth})
            self.assertEqual((r.status_code, r.get_json()["error"]["code"]), (400, "authorization_required"), repr(auth))

    def test_bad_urls_get_human_messages(self):
        for url, fragment in (("", "Please enter"), ("file:///etc/passwd", "Unsupported URL scheme"), ("foo", "Did you mean"), (123, "Please enter"), (None, "Please enter")):
            r = self.post("/api/scans", {"url": url, "authorized": True})
            self.assertEqual((r.status_code, r.get_json()["error"]["code"]), (400, "invalid_url"), repr(url))
            self.assertIn(fragment, r.get_json()["error"]["message"])

    def test_bad_options_are_reported_per_field(self):
        r = self.post("/api/scans", {"url": "https://example.com", "authorized": True, "options": {"timeout": 0, "check_cors": "maybe"}})
        err = r.get_json()["error"]
        self.assertEqual((r.status_code, err["code"]), (400, "invalid_options")); self.assertEqual(set(err["fields"]), {"timeout", "check_cors"})

    def test_malformed_bodies(self):
        self.assertEqual(self.post("/api/scans", [1, 2]).get_json()["error"]["code"], "invalid_body")
        r = self.client.post("/api/scans", data="{not json", headers={**HOST, **JSON})
        self.assertEqual(r.status_code, 400)

    def test_config_endpoint_mirrors_server_limits(self):
        cfg = get(self.client, "/api/config", headers=HOST).get_json()
        self.assertEqual(cfg["limits"]["timeout"]["max"], 60)
        self.assertEqual({f["key"] for f in cfg["formats"]}, {"html", "pdf", "md", "json", "csv"})

    def test_unknown_scan_ids_404_as_json(self):
        for path in ("/api/scans/nope", "/api/scans/nope/report"):
            r = get(self.client, path, headers=HOST)
            self.assertEqual(r.status_code, 404); self.assertIn("error", r.get_json())
        self.assertEqual(self.post("/api/scans/nope/cancel", {}).status_code, 404)


class LifecycleTests(ServerCase):
    def test_full_scan_then_every_report_format(self):
        with Site({"/": Route(200, page('<a href="/missing">x</a>'), headers=[("Set-Cookie", "sid=SECRETVALUE")])}) as site:
            r = self.post("/api/scans", {"url": site.url, "authorized": True, "options": FAST})
            self.assertEqual(r.status_code, 202)
            job = self.wait(r.get_json()["id"])
        self.assertEqual(job["state"], "done"); self.assertEqual(job["progress"]["percent"], 100)
        self.assertEqual(job["result"]["outcome"], "complete"); self.assertTrue(job["observations"])
        self.assertNotIn("SECRETVALUE", str(job))
        for fmt, ctype in (("html", "text/html"), ("pdf", "application/pdf"), ("md", "text/markdown"), ("json", "application/json"), ("csv", "text/csv")):
            rep = get(self.client, f"/api/scans/{job['id']}/report?format={fmt}", headers=HOST)
            self.assertEqual(rep.status_code, 200, fmt); self.assertIn(ctype, rep.headers["Content-Type"])
            self.assertRegex(rep.headers["Content-Disposition"], r'^attachment; filename="ayyscanner-127\.0\.0\.1-\d{8}-\d{4}\.' + fmt + '"$')
        inline = get(self.client, f"/api/scans/{job['id']}/report?format=html&inline=1", headers=HOST)
        self.assertTrue(inline.headers["Content-Disposition"].startswith("inline")); self.assertIn("sandbox", inline.headers["Content-Security-Policy"])
        self.assertEqual(get(self.client, f"/api/scans/{job['id']}/report?format=exe", headers=HOST).status_code, 400)

    def test_unreachable_target_is_a_failed_job_with_a_message(self):
        job = self.wait(self.post("/api/scans", {"url": "http://127.0.0.1:1", "authorized": True, "options": FAST}).get_json()["id"])
        self.assertEqual(job["state"], "failed"); self.assertIn("refused", job["error"])

    def test_cancel(self):
        routes = {"/": Route(200, page("".join(f'<a href="/s{i}">s</a>' for i in range(20))))}
        routes.update({f"/s{i}": Route(200, page(), delay=1.0) for i in range(20)})
        with Site(routes) as site:
            jid = self.post("/api/scans", {"url": site.url, "authorized": True, "options": FAST}).get_json()["id"]
            for _ in range(100):
                if get(self.client, f"/api/scans/{jid}", headers=HOST).get_json()["progress"]["stage"] == "links":
                    break
                time.sleep(0.1)
            self.assertEqual(self.post(f"/api/scans/{jid}/cancel", {}).status_code, 200)
            job = self.wait(jid)
        self.assertEqual(job["state"], "cancelled"); self.assertEqual(job["result"]["outcome"], "partial")
        self.assertEqual(get(self.client, f"/api/scans/{jid}/report?format=json", headers=HOST).status_code, 200, "partial results stay exportable")

    def test_concurrency_limit(self):
        app = create_app(Settings(), manager=JobManager(max_concurrent=1)); client = app.test_client(); get(client, "/")
        with Site({"/": Route(200, page(), delay=1.5)}) as site:
            body = {"url": site.url, "authorized": True, "options": FAST}
            first = client.post("/api/scans", json=body, headers=HOST)
            second = client.post("/api/scans", json=body, headers=HOST)
            self.assertEqual((first.status_code, second.status_code, second.get_json()["error"]["code"]), (202, 429, "busy"))
            time.sleep(3)

    def test_report_before_results_exist_is_a_clear_error(self):
        with Site({"/": Route(200, page(), delay=1.5)}) as site:
            jid = self.post("/api/scans", {"url": site.url, "authorized": True, "options": FAST}).get_json()["id"]
            r = get(self.client, f"/api/scans/{jid}/report?format=html", headers=HOST)
            self.assertEqual((r.status_code, r.get_json()["error"]["code"]), (409, "not_ready"))
            self.wait(jid)

    def test_finished_jobs_are_bounded_in_memory(self):
        from ayyscanner.server import jobs as jobs_mod
        manager = JobManager(max_concurrent=10)
        with Site({"/": Route(200, page())}) as site:
            for _ in range(jobs_mod.MAX_KEPT_JOBS + 6):
                job = manager.submit(site.url, __import__("ayyscanner.web_scan.options", fromlist=["ScanOptions"]).ScanOptions(rate_limit_per_second=20, check_internal_links=False,
                        check_external_links=False, check_cors=False, check_well_known_files=False, check_sensitive_files=False, check_http_to_https_redirect=False))
                while not job.is_finished:
                    time.sleep(0.02)
        self.assertLessEqual(len(manager._jobs), jobs_mod.MAX_KEPT_JOBS)


if __name__ == "__main__":
    unittest.main()


class InstanceAndSaveTests(unittest.TestCase):
    """Home / Run reuses a running instance; finished scans are saved automatically."""

    def test_healthz_identifies_the_app_and_tracks_open_tabs(self):
        app = create_app(Settings())
        client = app.test_client()
        get(client, "/")
        info = get(client, "/healthz").get_json()
        self.assertEqual((info["app"], info["ui_open"]), ("ayyscanner", False))
        client.post("/api/ui/ping", json={"tab": "t1"}, headers=HOST)
        self.assertTrue(get(client, "/healthz").get_json()["ui_open"])
        client.post("/api/ui/ping", json={"tab": "t2"}, headers=HOST)
        client.post("/api/ui/closed", json={"tab": "t1"}, headers=HOST)
        self.assertTrue(get(client, "/healthz").get_json()["ui_open"])  # t2 still open
        client.post("/api/ui/closed", json={"tab": "t2"}, headers=HOST)
        self.assertFalse(get(client, "/healthz").get_json()["ui_open"])

    def test_healthz_still_checks_the_host_header(self):
        self.assertEqual(get(create_app(Settings()).test_client(), "/healthz", headers={"Host": "evil.example"}).status_code, 403)

    def test_second_launch_reuses_the_running_server(self):
        import io
        import threading
        from contextlib import redirect_stdout
        from unittest import mock
        from werkzeug.serving import make_server
        from ayyscanner.instance import reuse_running

        server = make_server("127.0.0.1", 0, create_app(Settings()), threaded=True)
        settings = Settings(port=server.server_port)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with mock.patch("webbrowser.open") as opened, redirect_stdout(io.StringIO()) as out:
                self.assertTrue(reuse_running(settings))      # nobody has the UI open: open it once
                opened.assert_called_once_with(settings.url)
            urllib_get = __import__("urllib.request").request.urlopen
            req = __import__("urllib.request").request.Request(settings.url)
            with urllib_get(req, timeout=5) as resp:
                cookie = resp.headers["Set-Cookie"].split(";")[0]
            ping = __import__("urllib.request").request.Request(
                settings.url + "api/ui/ping", data=b'{"tab":"x"}', headers={"Content-Type": "application/json", "Cookie": cookie})
            urllib_get(ping, timeout=5).read()
            with mock.patch("webbrowser.open") as opened, redirect_stdout(io.StringIO()) as out:
                self.assertTrue(reuse_running(settings))      # UI already open: no second window
                opened.assert_not_called()
                self.assertIn("already running and open", out.getvalue())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)

    def test_no_instance_means_start_normally(self):
        import socket
        from ayyscanner.instance import reuse_running
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        self.assertFalse(reuse_running(Settings(port=port)))

    def test_finished_scans_are_saved_and_restored_after_a_restart(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp, Site({"/": Route(200, page("<p>hi</p>"))}) as site:
            settings = Settings(data_dir=Path(tmp))
            app = create_app(settings)
            client = app.test_client()
            get(client, "/")
            r = client.post("/api/scans", json={"url": site.url, "authorized": True, "options": {**FAST, "check_internal_links": False,
                            "check_external_links": False, "check_tls": False}}, headers=HOST)
            job_id = r.get_json()["id"]
            ServerCase.wait(type("W", (), {"client": client, "fail": self.fail})(), job_id)
            time.sleep(0.3)  # the file is written right after the state flips to done
            self.assertEqual(len(list(Path(tmp).glob("*.json"))), 1)
            self.assertEqual(list(Path(tmp).glob(".tmp-*")), [])  # atomic write leaves no temp files

            restarted = create_app(settings).test_client()        # a new server process
            get(restarted, "/")
            listing = get(restarted, "/api/scans").get_json()
            self.assertTrue(listing["saved"])
            self.assertEqual([s["id"] for s in listing["scans"]], [job_id])
            full = get(restarted, f"/api/scans/{job_id}").get_json()
            self.assertEqual(full["state"], "done")
            self.assertIn("findings", full["result"])
            self.assertEqual(get(restarted, f"/api/scans/{job_id}/report?format=json").status_code, 200)

    def test_corrupt_or_foreign_files_in_the_data_folder_are_ignored(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "broken.json").write_text("{not json")
            (Path(tmp) / "..evil.json").write_text("{}")
            client = create_app(Settings(data_dir=Path(tmp))).test_client()
            get(client, "/")
            self.assertEqual(get(client, "/api/scans").get_json()["scans"], [])

    def test_store_rejects_path_traversal_ids(self):
        import tempfile
        from pathlib import Path
        from ayyscanner.server.store import ScanStore
        with tempfile.TemporaryDirectory() as tmp:
            store = ScanStore(Path(tmp) / "scans")
            self.assertFalse(store.save({"id": "../../evil", "result": {}}))
            self.assertFalse(any(Path(tmp).rglob("evil*")))
