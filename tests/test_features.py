"""Scan types in the UI, settings, history, passed checks, friendly errors, TXT export."""

import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from ayyscanner.errors import explain, explain_notice
from ayyscanner.models import ScanResult
from ayyscanner.report import render
from ayyscanner.scanners.dependencies import run_dependency_scan
from ayyscanner.scanners.system import run_system_scan
from ayyscanner.server import create_app
from ayyscanner.server.jobs import JobManager
from ayyscanner.settings import Settings
from ayyscanner.userprefs import DEFAULTS, PrefsError, PrefsStore, validate
from ayyscanner.web_scan import run_web_scan
from ayyscanner.web_scan.options import ScanOptions
from tests.support import GOOD_HEADERS, Route, Site, page
from tests.test_dependencies import FakeOsv

HOST = {"Host": "127.0.0.1:8765"}
FAST = {"rate_limit_per_second": 20, "check_internal_links": False, "check_external_links": False, "check_tls": False}


def wait(client, job_id, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        r = client.get(f"/api/scans/{job_id}", headers=HOST)
        data = r.get_json(); r.close()
        if data["state"] in ("done", "failed", "cancelled"):
            return data
        time.sleep(0.1)
    raise AssertionError("scan did not finish")


class Client:
    def __init__(self, settings=None):
        self.app = create_app(settings or Settings())
        self.c = self.app.test_client()
        self.c.get("/", headers=HOST).close()

    def post(self, url, body):
        return self.c.post(url, json=body, headers=HOST)

    def get(self, url):
        r = self.c.get(url, headers=HOST); r.get_data(); r.close(); return r

    def put(self, url, body):
        return self.c.put(url, json=body, headers=HOST)

    def delete(self, url):
        return self.c.delete(url, headers=HOST)


class PrefsTests(unittest.TestCase):
    def test_defaults_and_validation(self):
        self.assertEqual(validate({}), DEFAULTS)
        self.assertEqual(validate({"theme": "dark", "ui_scale": 120})["theme"], "dark")
        for bad in ({"theme": "pink"}, {"ui_scale": 500}, {"scan_timeout": True}, {"show_informational": "yes"}, {"sort_findings": 3}):
            with self.assertRaises(PrefsError, msg=bad):
                validate(bad)
        with self.assertRaises(PrefsError):
            validate([1])
        self.assertEqual(validate({"unknown_future_key": 1}), DEFAULTS)  # ignored, not an error

    def test_settings_survive_a_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "settings.json"
            PrefsStore(path).update({"theme": "dark", "request_timeout": 25, "auto_save_history": False})
            again = PrefsStore(path).get()
            self.assertEqual((again["theme"], again["request_timeout"], again["auto_save_history"]), ("dark", 25, False))
            self.assertEqual(list(path.parent.glob(".tmp-*")), [])
            self.assertEqual(PrefsStore(path).reset(), DEFAULTS)

    def test_one_corrupt_value_does_not_reset_everything(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.json"
            path.write_text('{"theme": "dark", "ui_scale": 99999}')
            got = PrefsStore(path).get()
            self.assertEqual((got["theme"], got["ui_scale"]), ("dark", DEFAULTS["ui_scale"]))
            path.write_text("{broken")
            self.assertEqual(PrefsStore(path).get(), DEFAULTS)

    def test_settings_api_persists_across_server_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = Settings(data_dir=Path(tmp))
            a = Client(s)
            self.assertEqual(a.put("/api/settings", {"theme": "light", "compact": 1}).status_code, 200)
            bad = a.put("/api/settings", {"ui_scale": 5})
            self.assertEqual((bad.status_code, bad.get_json()["error"]["code"]), (400, "invalid_settings"))
            b = Client(s)  # "restart"
            self.assertEqual(b.get("/api/settings").get_json()["settings"]["theme"], "light")
            self.assertEqual(b.get("/api/config").get_json()["settings"]["theme"], "light")
            self.assertEqual(b.post("/api/settings/reset", {}).get_json()["settings"]["theme"], "system")

    def test_put_still_needs_session_json_and_same_origin(self):
        a = Client()
        fresh = a.app.test_client()
        self.assertEqual(fresh.put("/api/settings", json={}, headers=HOST).status_code, 403)
        self.assertEqual(a.c.put("/api/settings", data="x", headers=HOST).status_code, 415)
        self.assertEqual(a.c.put("/api/settings", json={}, headers={**HOST, "Origin": "http://evil.example"}).status_code, 403)
        self.assertEqual(a.c.delete("/api/scans", headers={**HOST, "Origin": "http://evil.example"}).status_code, 403)


class PassedChecksAndScoreTests(unittest.TestCase):
    def test_web_scan_reports_which_checks_passed(self):
        with Site({"/": Route(200, page(), headers=GOOD_HEADERS)}) as site:
            r = run_web_scan(site.url, ScanOptions(**{k: v for k, v in FAST.items()}))
        d = r.to_dict()["summary"]["passed_checks"]
        self.assertEqual(d["unit"], "checks")
        self.assertGreater(d["count"], 0)
        self.assertLessEqual(d["count"], d["total"])
        self.assertIn("Security headers", d["items"])  # all five good headers sent: that check group found nothing

    def test_a_failing_check_group_is_not_counted_as_passed(self):
        with Site({"/": Route(200, page())}) as site:  # no security headers at all
            r = run_web_scan(site.url, ScanOptions(**FAST))
        self.assertNotIn("Security headers", r.passed_checks()["items"])
        self.assertTrue(any(c["name"] == "Security headers" and c["issues"] > 0 for c in r.metadata["checks"]))

    def test_quality_checks_are_never_counted_as_security_passes(self):
        with Site({"/": Route(200, page(), headers=GOOD_HEADERS)}) as site:
            r = run_web_scan(site.url, ScanOptions(**FAST))
        self.assertNotIn("SEO and page quality", r.passed_checks()["items"])

    def test_system_scan_records_every_check_honestly(self):
        r = run_system_scan()
        names = [c["name"] for c in r.metadata["checks"]]
        self.assertEqual(len(names), 5)
        self.assertTrue(all(c["status"] in ("ran", "skipped", "failed") for c in r.metadata["checks"]))
        self.assertIsNotNone(r.score()["score"])
        again = ScanResult.from_dict(r.to_dict())
        self.assertEqual(again.passed_checks(), r.passed_checks())

    def test_system_scan_progress_steps_are_real_checks(self):
        seen = []
        run_system_scan(progress_cb=lambda pct, stage, msg: seen.append(msg))
        self.assertEqual(len(seen), 5)
        self.assertTrue(all(m.endswith("…") for m in seen))

    def test_a_permission_problem_skips_one_check_and_marks_the_scan_partial(self):
        import psutil
        with mock.patch.object(psutil, "net_connections", side_effect=PermissionError()):
            r = run_system_scan()
        ports = next(c for c in r.metadata["checks"] if c["name"] == "Listening network ports")
        self.assertEqual(ports["status"], "skipped")
        self.assertEqual(r.outcome, "partial")
        self.assertTrue(any("Insufficient permissions" in e for e in r.errors))
        self.assertEqual(explain_notice(r.errors[0])["title"], "Permission is required to perform this system check.")

    def test_dependency_scan_counts_clean_packages(self):
        d = Path(tempfile.mkdtemp())
        (d / "requirements.txt").write_text("flask==2.0.1\nrequests==2.0.0\nnumpy\n")
        progress = []
        r = run_dependency_scan(str(d), session=FakeOsv(), rate_limit=20, progress_cb=lambda p, s, m: progress.append(m))
        pc = r.to_dict()["summary"]["passed_checks"]
        self.assertEqual((pc["unit"], pc["total"]), ("packages", 2))   # numpy has no pin, so it cannot be checked
        self.assertEqual(pc["count"], 1)  # FakeOsv reports one vulnerable package out of two
        self.assertTrue(progress and all(m.endswith("…") for m in progress))

    def test_offline_dependency_scan_does_not_claim_clean_packages(self):
        d = Path(tempfile.mkdtemp()); (d / "requirements.txt").write_text("flask==2.0.1\n")
        pc = run_dependency_scan(str(d), offline=True).passed_checks()
        self.assertEqual(pc["count"], 0)
        self.assertIn("did not run", pc["note"])

    def test_dependency_scan_without_a_lookup_is_not_rated(self):
        from tests.test_dependencies import Down
        d = Path(tempfile.mkdtemp()); (d / "requirements.txt").write_text("flask==2.0.1\n")
        for r in (run_dependency_scan(str(d), offline=True), run_dependency_scan(str(d), session=Down(), rate_limit=20)):
            sc = r.score()
            self.assertEqual((sc["score"], sc["rated"], sc["label"]), (None, False, "Not rated"))
            self.assertIn("OSV.dev", sc["meaning"])
        ok = run_dependency_scan(str(d), session=FakeOsv(), rate_limit=20).score()
        self.assertTrue(ok["rated"])

    def test_osv_unreachable_message_is_friendly(self):
        from tests.test_dependencies import Down
        d = Path(tempfile.mkdtemp()); (d / "requirements.txt").write_text("flask==2.0.1\n")
        r = run_dependency_scan(str(d), session=Down(), rate_limit=20)
        self.assertEqual(explain_notice(r.errors[0])["title"], "OSV.dev could not be reached. Dependency vulnerability results may be unavailable.")


class ErrorExplanationTests(unittest.TestCase):
    def test_known_failures_get_plain_headlines_and_keep_details(self):
        cases = [("web", "The connection to localhost:1 was refused. The site may be down", "Unable to connect to the target."),
                 ("web", "That doesn't look like a valid website address (check the host and port).", "Invalid URL."),
                 ("web", "Could not resolve the hostname 'x'. Check", "Unable to find that website."),
                 ("project", "Project directory not found: /x", "Project folder not found."),
                 ("project", "No recognized dependency manifest files found (looked for", "No dependency files found."),
                 ("system", "Insufficient permissions to list all listening sockets.", "Permission is required to perform this system check.")]
        for kind, raw, title in cases:
            info = explain(kind, raw)
            self.assertEqual(info["title"], title, raw)
            self.assertEqual(info["details"], raw)
        self.assertIn("Something went wrong", explain("internal", "", "KeyError: 'x'")["title"])
        self.assertEqual(explain("web", "something odd")["message"], "something odd")  # unknown: still not a Python error


class ScanKindApiTests(unittest.TestCase):
    def test_system_scan_via_api_with_history_and_export(self):
        c = Client()
        self.assertEqual(c.post("/api/scans", {"kind": "system"}).get_json()["error"]["code"], "authorization_required")
        job = wait(c.c, c.post("/api/scans", {"kind": "system", "authorized": True}).get_json()["id"])
        self.assertEqual((job["kind"], job["state"]), ("system", "done"))
        self.assertIn(job["result"]["outcome"], ("complete", "partial"))
        self.assertIsInstance(job["result"]["score"]["score"], int)
        txt = c.get(f"/api/scans/{job['id']}/report?format=txt")
        self.assertEqual(txt.status_code, 200)
        self.assertIn("Security score:", txt.get_data(as_text=True))
        self.assertNotIn("\x1b[", txt.get_data(as_text=True))
        row = c.get("/api/scans").get_json()["scans"][0]
        self.assertEqual((row["kind"], row["id"]), ("system", job["id"]))
        self.assertIsInstance(row["score"], int)
        self.assertEqual(set(row["severity"]), {"Critical", "High", "Medium", "Low", "Informational"})

    def test_project_scan_via_api(self):
        d = Path(tempfile.mkdtemp()); (d / "requirements.txt").write_text("flask==2.0.1\n")
        c = Client()
        with mock.patch("requests.Session", lambda: FakeOsv()):
            job = wait(c.c, c.post("/api/scans", {"kind": "project", "directory": str(d), "authorized": True}).get_json()["id"])
        self.assertEqual((job["kind"], job["state"], job["target"]), ("project", "done", str(d.resolve())))
        self.assertTrue(any(f["id"].startswith("DEP-VULN-flask") for f in job["result"]["findings"]))
        self.assertEqual(job["result"]["summary"]["passed_checks"]["unit"], "packages")

    def test_project_folder_is_validated(self):
        c = Client()
        for directory, text in (("", "Enter the folder"), ("/definitely/not/here", "was not found"), (__file__, "is a file"), (5, "Enter the folder")):
            r = c.post("/api/scans", {"kind": "project", "directory": directory, "authorized": True})
            self.assertEqual((r.status_code, r.get_json()["error"]["code"]), (400, "invalid_directory"), directory)
            self.assertIn(text, r.get_json()["error"]["message"])

    def test_project_without_manifests_fails_with_a_friendly_error(self):
        c = Client()
        job = wait(c.c, c.post("/api/scans", {"kind": "project", "directory": tempfile.mkdtemp(), "authorized": True}).get_json()["id"])
        self.assertEqual(job["state"], "failed")
        self.assertEqual(job["error_info"]["title"], "No dependency files found.")
        self.assertIn("No recognized dependency", job["error_info"]["details"])

    def test_unknown_kind_and_default_kind(self):
        c = Client()
        self.assertEqual(c.post("/api/scans", {"kind": "nuke", "authorized": True}).get_json()["error"]["code"], "invalid_kind")
        with Site({"/": Route(200, page())}) as site:  # no "kind": old clients still mean a website scan
            r = c.post("/api/scans", {"url": site.url, "authorized": True, "options": FAST})
            self.assertEqual(r.get_json()["kind"], "web")
            wait(c.c, r.get_json()["id"])

    def test_invalid_url_error_has_the_friendly_headline(self):
        c = Client()
        r = c.post("/api/scans", {"kind": "web", "url": "not a url", "authorized": True})
        self.assertEqual(r.get_json()["error"]["code"], "invalid_url")


class HistoryTests(unittest.TestCase):
    def _scan(self, c, site):
        r = c.post("/api/scans", {"url": site.url, "authorized": True, "options": FAST})
        return wait(c.c, r.get_json()["id"])

    def test_delete_one_and_clear_all_remove_files_too(self):
        with tempfile.TemporaryDirectory() as tmp, Site({"/": Route(200, page())}) as site:
            c = Client(Settings(data_dir=Path(tmp)))
            a, b = self._scan(c, site), self._scan(c, site)
            time.sleep(0.3)
            scans = Path(tmp) / "scans"
            self.assertEqual(len(list(scans.glob("*.json"))), 2)
            self.assertEqual(c.delete(f"/api/scans/{a['id']}").status_code, 200)
            self.assertEqual(c.get(f"/api/scans/{a['id']}").status_code, 404)
            self.assertEqual([s["id"] for s in c.get("/api/scans").get_json()["scans"]], [b["id"]])
            self.assertEqual(len(list(scans.glob("*.json"))), 1)
            self.assertEqual(c.delete("/api/scans").get_json()["removed"], 1)
            self.assertEqual(c.get("/api/scans").get_json()["scans"], [])
            self.assertEqual(list(scans.glob("*.json")), [])
            self.assertEqual(Client(Settings(data_dir=Path(tmp))).get("/api/scans").get_json()["scans"], [])  # still gone after restart
            self.assertEqual(c.delete("/api/scans/nope").status_code, 404)

    def test_a_running_scan_cannot_be_deleted_or_cleared(self):
        with Site({"/": Route(200, page(), delay=1.5)}) as site:
            c = Client()
            jid = c.post("/api/scans", {"url": site.url, "authorized": True, "options": FAST}).get_json()["id"]
            r = c.delete(f"/api/scans/{jid}")
            self.assertEqual((r.status_code, r.get_json()["error"]["code"]), (409, "still_running"))
            self.assertEqual(c.delete("/api/scans").get_json()["removed"], 0)
            wait(c.c, jid)

    def test_turning_history_off_stops_saving_but_still_shows_the_result(self):
        with tempfile.TemporaryDirectory() as tmp, Site({"/": Route(200, page())}) as site:
            c = Client(Settings(data_dir=Path(tmp)))
            c.put("/api/settings", {"auto_save_history": False})
            job = self._scan(c, site)
            time.sleep(0.3)
            self.assertEqual(list((Path(tmp) / "scans").glob("*.json")) if (Path(tmp) / "scans").exists() else [], [])
            self.assertEqual(c.get(f"/api/scans/{job['id']}").get_json()["state"], "done")  # still viewable this session
            c.put("/api/settings", {"auto_save_history": True})
            self._scan(c, site); time.sleep(0.3)
            self.assertEqual(len(list((Path(tmp) / "scans").glob("*.json"))), 1)

    def test_old_v1_history_files_still_open(self):
        with tempfile.TemporaryDirectory() as tmp, Site({"/": Route(200, page())}) as site:
            c = Client(Settings(data_dir=Path(tmp)))
            job = self._scan(c, site); time.sleep(0.3)
            import json
            f = Path(tmp) / "scans" / f"{job['id']}.json"
            rec = json.loads(f.read_text()); rec.pop("kind"); rec.pop("error_info"); rec["result"].pop("score")
            f.write_text(json.dumps(rec))
            row = Client(Settings(data_dir=Path(tmp))).get("/api/scans").get_json()["scans"][0]
            self.assertEqual(row["kind"], "web")
            self.assertIsInstance(row["score"], int)


class TimeLimitTests(unittest.TestCase):
    def test_scan_time_limit_stops_the_scan_and_keeps_partial_results(self):
        class Prefs:
            def get(self): return {**DEFAULTS, "scan_timeout": 0.5}
        routes = {"/": Route(200, page("".join(f'<a href="/s{i}">x</a>' for i in range(30))))}
        routes.update({f"/s{i}": Route(200, page(), delay=1.0) for i in range(30)})
        with Site(routes) as site:
            m = JobManager(2, None, Prefs())
            job = m.submit(site.url, ScanOptions(rate_limit_per_second=20, link_check_concurrency=1))
            for _ in range(200):
                if job.is_finished:
                    break
                time.sleep(0.1)
        self.assertEqual(job.state, "done")
        self.assertEqual(job.result.outcome, "partial")
        self.assertTrue(any("time limit" in e for e in job.result.errors))


class ExportTests(unittest.TestCase):
    def test_every_export_format_contains_score_target_and_recommendations(self):
        with Site({"/": Route(200, page())}) as site:
            r = run_web_scan(site.url, ScanOptions(**FAST))
        text = render(r, "txt").decode()
        html = render(r, "html").decode()
        for blob in (text, html):
            self.assertIn(site.url.rstrip("/").split("//")[1], blob)
            self.assertIn("score", blob.lower())
        self.assertIn("AYYSCANNER", html)
        self.assertIn("passed", html.lower())
        self.assertIn("fix:", text)
        self.assertGreater(len(render(r, "pdf")), 1000)
        self.assertEqual(__import__("json").loads(render(r, "json"))["score"]["score"], r.score()["score"])


if __name__ == "__main__":
    unittest.main()
