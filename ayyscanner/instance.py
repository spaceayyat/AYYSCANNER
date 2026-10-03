"""Detect an AYYSCANNER that is already running, so Home / Run reuses it.

Standard library only: run.py calls this before the dependencies are installed.
"""

from __future__ import annotations

import json
import urllib.request
import webbrowser
from typing import Optional

from ayyscanner.settings import Settings

# Never send this probe through an HTTP proxy: the server is on this machine.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def probe(settings: Settings, timeout: float = 1.5) -> Optional[dict]:
    """Return the /healthz payload if an AYYSCANNER answers on the configured port, else None."""
    try:
        with _OPENER.open(settings.url + "healthz", timeout=timeout) as response:
            data = json.loads(response.read(4096).decode("utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("app") == "ayyscanner" else None


def reuse_running(settings: Settings) -> bool:
    """If AYYSCANNER already runs on this address, reuse it instead of starting a second server.

    Opens the UI only when no browser tab currently shows it. Returns True when an
    instance was found (the caller should then exit successfully)."""
    info = probe(settings)
    if info is None:
        return False
    if info.get("ui_open"):
        print(f"AYYSCANNER is already running and open in your browser ({settings.url}).")
    elif settings.open_browser:
        print(f"AYYSCANNER is already running. Opening {settings.url}")
        webbrowser.open(settings.url)
    else:
        print(f"AYYSCANNER is already running at {settings.url}")
    return True
