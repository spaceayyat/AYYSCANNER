#!/usr/bin/env python3
"""One-command launcher:  python run.py

On the first run it creates a private virtual environment (.venv) and installs the
dependencies from requirements.txt; after that it simply starts AYYSCANNER. If the
dependencies are already importable (your own environment, CI, a container) it runs
directly and touches nothing. Any arguments are passed to the ayyscanner command:

    python run.py                      start the web UI (or reuse it if it is already running)
    python run.py web https://example.com --yes
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
REQUIRED_MODULES = ("flask", "requests", "bs4", "reportlab")
MIN_PYTHON = (3, 10)


def die(message: str) -> "None":
    print(f"\nError: {message}", file=sys.stderr)
    sys.exit(1)


def dependencies_available() -> bool:
    return all(importlib.util.find_spec(name) is not None for name in REQUIRED_MODULES)


def venv_python() -> Path:
    return VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def run(cmd: list[str], failure_hint: str) -> None:
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError:
        die(failure_hint)
    except FileNotFoundError:
        die(f"Could not run {cmd[0]}.")


def bootstrap() -> int:
    """Create .venv if needed, install requirements, then re-run this script inside it."""
    python = venv_python()
    if not python.exists():
        print("First run: creating a private Python environment in .venv ...")
        run([sys.executable, "-m", "venv", str(VENV)],
            "Could not create a virtual environment.\n"
            "On Debian/Ubuntu install the venv module first:  sudo apt install python3-venv")
    print("Installing dependencies (first run only) ...")
    run([str(python), "-m", "pip", "install", "--disable-pip-version-check", "-q", "-r", str(ROOT / "requirements.txt")],
        "Could not install the dependencies. Check your internet connection and try again.\n"
        "To see the details run:  .venv/bin/python -m pip install -r requirements.txt  (Windows: .venv\\Scripts\\python -m pip ...)")
    return subprocess.call([str(python), str(Path(__file__).resolve()), *sys.argv[1:]], env={**os.environ, "AYYSCANNER_BOOTSTRAPPED": "1"})


def reuse_running_instance() -> bool:
    """Plain `python run.py` while AYYSCANNER is already running: reuse it, start nothing new.

    Uses only the standard library, so it works before the dependencies are installed."""
    if sys.argv[1:] not in ([], ["serve"]):
        return False
    sys.path.insert(0, str(ROOT))
    try:
        from ayyscanner.instance import reuse_running
        from ayyscanner.settings import Settings, SettingsError, load_dotenv

        for env_file in (Path.cwd() / ".env", ROOT / ".env"):
            load_dotenv(env_file)
        try:
            settings = Settings.from_env()
        except SettingsError:
            return False  # the normal start-up path reports the configuration error
        return reuse_running(settings)
    except Exception:  # noqa: BLE001 - the shortcut must never stop a normal start
        return False


def main() -> int:
    if sys.version_info < MIN_PYTHON:
        die(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer is required (you have {sys.version.split()[0]}).")
    if reuse_running_instance():
        return 0
    if not dependencies_available():
        if os.environ.get("AYYSCANNER_BOOTSTRAPPED"):
            die("The dependencies are still missing after installation. Delete the .venv folder and run again.")
        return bootstrap()
    sys.path.insert(0, str(ROOT))
    from ayyscanner.cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    sys.exit(main())
