"""First-run desktop shortcut: created once, never duplicated, repaired when the project moves, never fatal."""

import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ayyscanner import shortcut

ROOT = Path(__file__).resolve().parent.parent


class Sandbox(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.desktop = self.tmp / "Desktop"
        self.desktop.mkdir()
        self.state = self.tmp / "state"
        env = {"AYYSCANNER_DESKTOP_DIR": str(self.desktop), "AYYSCANNER_STATE_DIR": str(self.state)}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("AYYSCANNER_NO_SHORTCUT", None)

    def project(self, name="proj"):
        """A minimal copy of the project layout (launchers + icons) in the sandbox."""
        root = self.tmp / name
        (root / "ayyscanner" / "assets").mkdir(parents=True)
        for f in ("run.py", "run_linux.sh", "run_windows.bat"):
            shutil.copy(ROOT / f, root / f)
        for icon in ("ayyscanner.png", "ayyscanner.ico", "ayyscanner.icns"):
            shutil.copy(ROOT / "ayyscanner" / "assets" / icon, root / "ayyscanner" / "assets" / icon)
        return root


class LinuxShortcut(Sandbox):
    def test_creates_once_with_logo_and_launcher(self):
        root = self.project()
        out = shortcut.ensure_shortcut(root, system="linux")
        self.assertEqual(out.status, shortcut.CREATED)
        entry = (self.desktop / "AYYSCANNER.desktop").read_text()
        self.assertIn(f'Exec="{root}/run_linux.sh"', entry)
        self.assertIn(f"Icon={root}/ayyscanner/assets/ayyscanner.png", entry)
        self.assertIn(f"Path={root}", entry)
        self.assertTrue(os.access(self.desktop / "AYYSCANNER.desktop", os.X_OK))
        self.assertEqual(json.loads((self.state / "shortcut.json").read_text())["root"], str(root.resolve()))

    def test_repeated_launches_do_not_duplicate_or_rewrite(self):
        root = self.project()
        shortcut.ensure_shortcut(root, system="linux")
        mtime = (self.desktop / "AYYSCANNER.desktop").stat().st_mtime_ns
        for _ in range(5):
            self.assertEqual(shortcut.ensure_shortcut(root, system="linux").status, shortcut.EXISTS)
        self.assertEqual(os.listdir(self.desktop), ["AYYSCANNER.desktop"])
        self.assertEqual((self.desktop / "AYYSCANNER.desktop").stat().st_mtime_ns, mtime)

    def test_deleted_on_purpose_is_not_recreated_but_can_be_forced(self):
        root = self.project()
        shortcut.ensure_shortcut(root, system="linux")
        (self.desktop / "AYYSCANNER.desktop").unlink()
        self.assertEqual(shortcut.ensure_shortcut(root, system="linux").status, shortcut.SKIPPED)
        self.assertEqual(os.listdir(self.desktop), [])
        self.assertEqual(shortcut.ensure_shortcut(root, force=True, system="linux").status, shortcut.CREATED)
        self.assertEqual(os.listdir(self.desktop), ["AYYSCANNER.desktop"])

    def test_moved_project_updates_the_same_file(self):
        first, second = self.project("one"), self.project("two")
        shortcut.ensure_shortcut(first, system="linux")
        out = shortcut.ensure_shortcut(second, system="linux")
        self.assertEqual(out.status, shortcut.UPDATED)
        self.assertEqual(os.listdir(self.desktop), ["AYYSCANNER.desktop"])
        self.assertIn(str(second), (self.desktop / "AYYSCANNER.desktop").read_text())

    def test_edited_or_stale_entry_is_repaired(self):
        root = self.project()
        shortcut.ensure_shortcut(root, system="linux")
        (self.desktop / "AYYSCANNER.desktop").write_text("[Desktop Entry]\nExec=/gone/run_linux.sh\n")
        self.assertEqual(shortcut.ensure_shortcut(root, system="linux").status, shortcut.UPDATED)
        self.assertIn(str(root), (self.desktop / "AYYSCANNER.desktop").read_text())

    def test_opt_out_and_missing_desktop_and_non_project(self):
        root = self.project()
        with mock.patch.dict(os.environ, {"AYYSCANNER_NO_SHORTCUT": "1"}):
            self.assertEqual(shortcut.ensure_shortcut(root, system="linux").status, shortcut.SKIPPED)
        with mock.patch.dict(os.environ, {"AYYSCANNER_DESKTOP_DIR": str(self.tmp / "nope")}):
            self.assertEqual(shortcut.ensure_shortcut(root, system="linux").status, shortcut.SKIPPED)
        self.assertEqual(shortcut.ensure_shortcut(self.tmp / "empty", system="linux").status, shortcut.SKIPPED)
        self.assertEqual(os.listdir(self.desktop), [])

    def test_never_raises(self):
        root = self.project()
        with mock.patch.dict(shortcut._WRITERS, {"linux": mock.Mock(side_effect=PermissionError("read-only"))}):
            out = shortcut.ensure_shortcut(root, system="linux")
        self.assertEqual(out.status, shortcut.FAILED)
        self.assertIn("read-only", shortcut.describe(out))

    def test_remove(self):
        root = self.project()
        shortcut.ensure_shortcut(root, system="linux")
        self.assertEqual(shortcut.remove_shortcut("linux").status, shortcut.REMOVED)
        self.assertEqual(os.listdir(self.desktop), [])
        self.assertFalse((self.state / "shortcut.json").exists())
        self.assertEqual(shortcut.remove_shortcut("linux").status, shortcut.SKIPPED)

    def test_path_with_spaces_and_quotes(self):
        root = self.project('my "odd" proj')
        shortcut.ensure_shortcut(root, system="linux")
        entry = (self.desktop / "AYYSCANNER.desktop").read_text()
        self.assertIn('Exec="' + str(root).replace('"', '\\"') + '/run_linux.sh"', entry)

    def test_run_py_end_to_end_cli_does_not_create(self):
        """`run.py report ...` is not 'opening the app', so it must not touch the Desktop."""
        env = {**os.environ, "AYYSCANNER_NO_SHORTCUT": ""}
        subprocess.run([sys.executable, str(ROOT / "run.py"), "--help"], env=env, capture_output=True, timeout=60)
        self.assertEqual(os.listdir(self.desktop), [])

    def test_run_py_flags(self):
        env = {**os.environ}
        out = subprocess.run([sys.executable, str(ROOT / "run.py"), "--create-shortcut"], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("desktop shortcut", out.stdout)
        self.assertEqual(os.listdir(self.desktop), ["AYYSCANNER.desktop"])
        out = subprocess.run([sys.executable, str(ROOT / "run.py"), "--remove-shortcut"], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(os.listdir(self.desktop), [])


class WindowsShortcut(Sandbox):
    """PowerShell cannot run here, so the call is captured: what matters is what Windows is asked to build."""

    def test_asks_powershell_for_one_lnk_with_icon_target_and_workdir(self):
        root = self.project()
        calls = []

        def fake(cmd, **kw):
            calls.append((cmd, kw["env"]))
            (self.desktop / "AYYSCANNER.lnk").write_bytes(b"lnk")  # what the COM call would produce
            return subprocess.CompletedProcess(cmd, 0, "", "")

        out = shortcut.ensure_shortcut(root, system="windows", runner=fake)
        self.assertEqual(out.status, shortcut.CREATED)
        cmd, env = calls[0]
        self.assertEqual(cmd[0], "powershell")
        self.assertIn("CreateShortcut", cmd[-1])
        self.assertEqual(env["AYY_TARGET"], str(root / "run_windows.bat"))
        self.assertEqual(env["AYY_WORKDIR"], str(root))
        self.assertEqual(env["AYY_ICON"], str(root / "ayyscanner" / "assets" / "ayyscanner.ico"))
        self.assertEqual(env["AYY_LNK"], str(self.desktop / "AYYSCANNER.lnk"))
        self.assertEqual(shortcut.ensure_shortcut(root, system="windows", runner=fake).status, shortcut.EXISTS)
        self.assertEqual(len(calls), 1, "second launch must not call PowerShell again")
        self.assertEqual(os.listdir(self.desktop), ["AYYSCANNER.lnk"])

    def test_powershell_failure_is_reported_not_raised(self):
        root = self.project()
        fake = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, "", "boom")  # noqa: E731
        out = shortcut.ensure_shortcut(root, system="windows", runner=fake)
        self.assertEqual(out.status, shortcut.FAILED)
        self.assertIn("boom", out.message)
        self.assertFalse((self.state / "shortcut.json").exists(), "no record when nothing was created")

    def test_desktop_folder_comes_from_windows_not_a_guess(self):
        with mock.patch.dict(os.environ, {"AYYSCANNER_DESKTOP_DIR": ""}):
            redirected = self.tmp / "OneDrive" / "Desktop"
            redirected.mkdir(parents=True)
            fake = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, f"{redirected}\r\n", "")  # noqa: E731
            self.assertEqual(shortcut.desktop_dir("windows", fake), redirected)

    def test_launcher_and_icon_exist_in_the_project(self):
        self.assertTrue((ROOT / "run_windows.bat").is_file())
        self.assertEqual((ROOT / "ayyscanner" / "assets" / "ayyscanner.ico").read_bytes()[:4], b"\x00\x00\x01\x00")  # ICO header


class MacShortcut(Sandbox):
    def test_builds_an_app_bundle(self):
        root = self.project()
        out = shortcut.ensure_shortcut(root, system="macos")
        self.assertEqual(out.status, shortcut.CREATED)
        app = self.desktop / "AYYSCANNER.app"
        info = plistlib.loads((app / "Contents" / "Info.plist").read_bytes())
        self.assertEqual(info["CFBundleExecutable"], "launch")
        self.assertEqual(info["CFBundleIconFile"], "ayyscanner")
        self.assertTrue((app / "Contents" / "Resources" / "ayyscanner.icns").is_file())
        script = app / "Contents" / "MacOS" / "launch"
        self.assertTrue(os.access(script, os.X_OK))
        self.assertIn(str(root), script.read_text())
        if shutil.which("bash"):
            self.assertEqual(subprocess.run(["bash", "-n", str(script)]).returncode, 0)
        self.assertEqual(shortcut.ensure_shortcut(root, system="macos").status, shortcut.EXISTS)
        self.assertEqual(os.listdir(self.desktop), ["AYYSCANNER.app"])


class Icons(unittest.TestCase):
    def test_icons_present_and_valid(self):
        import struct

        assets = ROOT / "ayyscanner" / "assets"
        png = (assets / "ayyscanner.png").read_bytes()
        self.assertEqual(png[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(struct.unpack(">II", png[16:24]), (256, 256))
        ico = (assets / "ayyscanner.ico").read_bytes()
        reserved, kind, count = struct.unpack("<HHH", ico[:6])
        self.assertEqual((reserved, kind), (0, 1))
        sizes = {ico[6 + 16 * i] or 256 for i in range(count)}  # width byte, 0 means 256
        self.assertTrue({16, 32, 48, 256} <= sizes, sizes)
        self.assertTrue((assets / "ayyscanner.icns").read_bytes().startswith(b"icns"))


if __name__ == "__main__":
    unittest.main()
