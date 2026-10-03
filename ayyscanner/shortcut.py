"""Create a desktop shortcut for AYYSCANNER the first time the project is run.

Standard library only: run.py calls this before the dependencies are installed.

What it does
------------
* Windows: `AYYSCANNER.lnk` on the real Desktop (OneDrive-redirected Desktops included), pointing at
  run_windows.bat, with the logo as its icon (assets/ayyscanner.ico).
* Linux:   `AYYSCANNER.desktop` on the Desktop and in the applications menu
  (~/.local/share/applications), pointing at run_linux.sh, with assets/ayyscanner.png.
* macOS:   `AYYSCANNER.app` on the Desktop (a tiny bundle that opens Terminal and runs run_linux.sh),
  with assets/ayyscanner.icns.

When it runs
------------
Only when the project is started for its UI (`python run.py`, the .bat / .sh launchers, double-click),
and only when needed:

* There is one fixed file name per platform, so a shortcut can never be duplicated.
* A small record in ~/.ayyscanner/shortcut.json remembers which project folder the shortcut points
  to. If the shortcut is already there and correct nothing is touched. If the project folder moved,
  the existing shortcut is rewritten in place. If you deleted the shortcut on purpose, it is not
  brought back; `python run.py --create-shortcut` recreates it, `--remove-shortcut` removes it.
* No Desktop folder (servers, containers, CI) means nothing is created.
* Set AYYSCANNER_NO_SHORTCUT=1 to turn this off entirely.

The shortcut itself never stops the app from starting: every failure is caught and reported in one line.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

APP_NAME = "AYYSCANNER"
DESCRIPTION = "AYYSCANNER web security scanner"
RECORD_VERSION = 1

# Result codes of ensure_shortcut()
CREATED, UPDATED, EXISTS, SKIPPED, REMOVED, FAILED = "created", "updated", "exists", "skipped", "removed", "failed"


@dataclass(frozen=True)
class Outcome:
    status: str
    path: Optional[Path] = None
    message: str = ""


Runner = Callable[..., "subprocess.CompletedProcess[str]"]


# --------------------------------------------------------------------------- locations

def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def state_dir() -> Path:
    raw = os.environ.get("AYYSCANNER_STATE_DIR", "").strip()
    return Path(raw).expanduser() if raw else Path.home() / ".ayyscanner"


def record_path() -> Path:
    return state_dir() / "shortcut.json"


def platform_name() -> str:
    if os.name == "nt":
        return "windows"
    return "macos" if sys.platform == "darwin" else "linux"


def _run(cmd: list[str], runner: Runner = subprocess.run, env: Optional[dict[str, str]] = None, timeout: float = 30):
    return runner(cmd, capture_output=True, text=True, timeout=timeout, env=env, check=False)


def desktop_dir(system: Optional[str] = None, runner: Runner = subprocess.run) -> Optional[Path]:
    """The user's Desktop folder, or None when there is none (never creates it)."""
    override = os.environ.get("AYYSCANNER_DESKTOP_DIR", "").strip()
    if override:
        p = Path(override).expanduser()
        return p if p.is_dir() else None
    system = system or platform_name()
    home = Path.home()
    candidates: list[Path] = []
    if system == "windows":
        try:  # the real location, including a OneDrive-redirected Desktop
            out = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                        "[Environment]::GetFolderPath('Desktop')"], runner, timeout=20)
            if out.returncode == 0 and out.stdout.strip():
                candidates.append(Path(out.stdout.strip().splitlines()[-1].strip()))
        except (OSError, subprocess.SubprocessError):
            pass
        candidates += [home / "Desktop", home / "OneDrive" / "Desktop"]
    elif system == "linux":
        try:
            out = _run(["xdg-user-dir", "DESKTOP"], runner, timeout=10)
            if out.returncode == 0 and out.stdout.strip():
                candidates.append(Path(out.stdout.strip()))
        except (OSError, subprocess.SubprocessError):
            pass
        dirs_file = home / ".config" / "user-dirs.dirs"
        try:
            for line in dirs_file.read_text(encoding="utf-8").splitlines():
                if line.startswith("XDG_DESKTOP_DIR="):
                    candidates.append(Path(line.split("=", 1)[1].strip().strip('"').replace("$HOME", str(home))))
        except OSError:
            pass
        candidates.append(home / "Desktop")
    else:
        candidates.append(home / "Desktop")
    for c in candidates:
        if c.is_dir():
            return c
    return None


def shortcut_filename(system: str) -> str:
    return {"windows": f"{APP_NAME}.lnk", "linux": f"{APP_NAME}.desktop", "macos": f"{APP_NAME}.app"}[system]


def icon_file(root: Path, system: str) -> Path:
    return root / "ayyscanner" / "assets" / {"windows": "ayyscanner.ico", "linux": "ayyscanner.png", "macos": "ayyscanner.icns"}[system]


def launcher_file(root: Path, system: str) -> Path:
    return root / ("run_windows.bat" if system == "windows" else "run_linux.sh")


# --------------------------------------------------------------------------- the record

def read_record() -> dict:
    try:
        data = json.loads(record_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def write_record(root: Path, path: Path, system: str) -> None:
    record_path().parent.mkdir(parents=True, exist_ok=True)
    record = {"version": RECORD_VERSION, "platform": system, "root": str(root), "shortcut": str(path),
              "updated": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    tmp = record_path().with_suffix(".tmp")
    tmp.write_text(json.dumps(record, indent=2), encoding="utf-8")
    os.replace(tmp, record_path())


# --------------------------------------------------------------------------- Linux

def desktop_entry(root: Path, system: str = "linux") -> str:
    """Contents of the .desktop file. Exec/Path values are quoted per the Desktop Entry spec."""
    def quote(value: str) -> str:
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`") + '"'

    exec_line = quote(str(launcher_file(root, "linux"))).replace("%", "%%")
    return "\n".join([
        "[Desktop Entry]", "Version=1.0", "Type=Application", f"Name={APP_NAME}", f"Comment={DESCRIPTION}",
        f"Exec={exec_line}", f"Path={root}", f"Icon={icon_file(root, 'linux')}",
        "Terminal=true",  # shows the server log and lets you stop it with Ctrl+C, like run_linux.sh
        "Categories=Network;Security;", "StartupNotify=false", ""])


def _write_linux(root: Path, desktop: Path, runner: Runner) -> Path:
    content = desktop_entry(root)
    apps = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "applications"
    targets = [desktop / shortcut_filename("linux")]
    if not os.environ.get("AYYSCANNER_DESKTOP_DIR"):  # the menu entry is part of a real install, not of a test sandbox
        apps.mkdir(parents=True, exist_ok=True)
        targets.append(apps / "ayyscanner.desktop")
    for target in targets:
        target.write_text(content, encoding="utf-8")
        target.chmod(0o755)
    entry = targets[0]
    try:  # GNOME needs this to launch a Desktop file without the "Allow Launching" prompt
        _run(["gio", "set", str(entry), "metadata::trusted", "true"], runner, timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass
    return entry


# --------------------------------------------------------------------------- Windows

POWERSHELL_SCRIPT = (
    "$ErrorActionPreference='Stop';"
    "$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:AYY_LNK);"
    "$s.TargetPath=$env:AYY_TARGET;$s.WorkingDirectory=$env:AYY_WORKDIR;"
    "$s.IconLocation=$env:AYY_ICON+',0';$s.Description=$env:AYY_DESC;$s.WindowStyle=1;$s.Save()"
)


def _write_windows(root: Path, desktop: Path, runner: Runner) -> Path:
    lnk = desktop / shortcut_filename("windows")
    env = {**os.environ, "AYY_LNK": str(lnk), "AYY_TARGET": str(launcher_file(root, "windows")), "AYY_WORKDIR": str(root),
           "AYY_ICON": str(icon_file(root, "windows")), "AYY_DESC": DESCRIPTION}  # values travel in the environment: no quoting problems
    out = _run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", POWERSHELL_SCRIPT], runner, env=env)
    if out.returncode != 0 or not lnk.exists():
        raise OSError((out.stderr or out.stdout or "PowerShell could not create the shortcut").strip()[:300])
    return lnk


# --------------------------------------------------------------------------- macOS

def _write_macos(root: Path, desktop: Path, runner: Runner) -> Path:
    import plistlib
    import shutil

    app = desktop / shortcut_filename("macos")
    if app.exists():
        shutil.rmtree(app)
    (app / "Contents" / "MacOS").mkdir(parents=True)
    (app / "Contents" / "Resources").mkdir(parents=True)
    shutil.copyfile(icon_file(root, "macos"), app / "Contents" / "Resources" / "ayyscanner.icns")
    plist = {"CFBundleName": APP_NAME, "CFBundleDisplayName": APP_NAME, "CFBundleIdentifier": "app.ayyscanner.launcher",
             "CFBundleExecutable": "launch", "CFBundleIconFile": "ayyscanner", "CFBundlePackageType": "APPL",
             "CFBundleVersion": "1", "LSMinimumSystemVersion": "10.13"}
    (app / "Contents" / "Info.plist").write_bytes(plistlib.dumps(plist))
    script = app / "Contents" / "MacOS" / "launch"
    run_cmd = f"cd {shlex.quote(str(root))} && exec {shlex.quote(str(launcher_file(root, 'linux')))}"
    script.write_text("#!/bin/bash\n"  # opens Terminal so the server log is visible and Ctrl+C stops it
                      f"RUN={shlex.quote(run_cmd)}\n"
                      "osascript -e \"tell application \\\"Terminal\\\" to do script \\\"$RUN\\\"\" "
                      "-e 'tell application \"Terminal\" to activate'\n", encoding="utf-8")
    script.chmod(0o755)
    return app


_WRITERS = {"linux": _write_linux, "windows": _write_windows, "macos": _write_macos}


# --------------------------------------------------------------------------- public API

def _entry_is_current(path: Path, root: Path, system: str) -> bool:
    """Best-effort check that an existing shortcut still matches what we would write for this folder."""
    try:
        if system == "linux":
            return path.read_text(encoding="utf-8") == desktop_entry(root)
        if system == "macos":
            return str(root) in (path / "Contents" / "MacOS" / "launch").read_text(encoding="utf-8")
    except OSError:
        return False
    return True  # Windows: the record (checked by the caller) is the source of truth


def ensure_shortcut(root: Optional[Path] = None, force: bool = False, system: Optional[str] = None,
                    runner: Runner = subprocess.run) -> Outcome:
    """Create the desktop shortcut if (and only if) it is needed. Never raises."""
    try:
        if os.environ.get("AYYSCANNER_NO_SHORTCUT", "").strip().lower() in {"1", "true", "yes", "on"} and not force:
            return Outcome(SKIPPED, message="disabled by AYYSCANNER_NO_SHORTCUT")
        root = (root or project_root()).resolve()
        system = system or platform_name()
        if not (root / "run.py").is_file() or not launcher_file(root, system).is_file():
            return Outcome(SKIPPED, message="not running from a project folder")
        icon = icon_file(root, system)
        desktop = desktop_dir(system, runner)
        if desktop is None:
            return Outcome(SKIPPED, message="no Desktop folder found")
        target = desktop / shortcut_filename(system)
        record = read_record()
        recorded_here = record.get("root") == str(root) and record.get("platform") == system
        exists = target.exists()

        if exists and recorded_here and _entry_is_current(target, root, system) and not force:
            return Outcome(EXISTS, target)
        if not exists and recorded_here and not force:
            return Outcome(SKIPPED, target, "the shortcut was removed on purpose; run `python run.py --create-shortcut` to restore it")
        if not icon.is_file():
            return Outcome(FAILED, message=f"icon file missing: {icon}")
        written = _WRITERS[system](root, desktop, runner)  # fixed file name: overwrite, never a second copy
        write_record(root, written, system)
        return Outcome(UPDATED if exists else CREATED, written)
    except Exception as exc:  # noqa: BLE001 - a shortcut problem must never stop the app
        return Outcome(FAILED, message=f"{type(exc).__name__}: {exc}")


def remove_shortcut(system: Optional[str] = None, runner: Runner = subprocess.run) -> Outcome:
    """Delete the shortcut (and the Linux menu entry) and forget the record."""
    import shutil

    try:
        system = system or platform_name()
        desktop = desktop_dir(system, runner)
        removed = None
        paths = [desktop / shortcut_filename(system)] if desktop else []
        if system == "linux" and not os.environ.get("AYYSCANNER_DESKTOP_DIR"):
            paths.append(Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "applications" / "ayyscanner.desktop")
        for p in paths:
            if p.is_dir():
                shutil.rmtree(p)
                removed = removed or p
            elif p.exists():
                p.unlink()
                removed = removed or p
        record_path().unlink(missing_ok=True)
        return Outcome(REMOVED if removed else SKIPPED, removed, "" if removed else "there was no shortcut to remove")
    except Exception as exc:  # noqa: BLE001
        return Outcome(FAILED, message=f"{type(exc).__name__}: {exc}")


def describe(outcome: Outcome) -> Optional[str]:
    """One user-facing line, or None when there is nothing worth saying."""
    if outcome.status == CREATED:
        return f"Created a desktop shortcut: {outcome.path}"
    if outcome.status == UPDATED:
        return f"Updated the desktop shortcut to point at this folder: {outcome.path}"
    if outcome.status == REMOVED:
        return f"Removed the desktop shortcut: {outcome.path}"
    if outcome.status == FAILED:
        return f"Note: could not create the desktop shortcut ({outcome.message}). AYYSCANNER works without it."
    return None
