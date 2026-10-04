"""Server configuration from environment variables (and an optional .env file).

Precedence: real environment variables > .env file > built-in defaults.
See .env.example for the list of variables.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class SettingsError(ValueError):
    """Invalid configuration. The message says what to change."""


def load_dotenv(path: Path, environ: Optional[dict[str, str]] = None) -> None:
    """Minimal .env reader: KEY=VALUE lines, '#' comments, optional quotes.
    Never overrides a variable that is already set."""
    environ = os.environ if environ is None else environ
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        environ.setdefault(key.strip(), value)


def _data_dir(env: Mapping[str, str]) -> Optional[Path]:
    """AYYSCANNER_DATA_DIR, or ~/.ayyscanner. Scan history goes in its `scans` subfolder, settings in settings.json.
    Set AYYSCANNER_DATA_DIR=off to write nothing to disk."""
    raw = env.get("AYYSCANNER_DATA_DIR", "").strip()
    if raw.lower() in {"off", "none", "0", "false"}:
        return None
    return Path(raw).expanduser() if raw else Path.home() / ".ayyscanner"


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    host: str = "127.0.0.1"
    port: int = 8765
    open_browser: bool = True
    max_concurrent_scans: int = 2
    allow_remote: bool = False
    extra_allowed_hosts: tuple[str, ...] = ()
    log_level: str = "INFO"
    debug: bool = False
    data_dir: Optional[Path] = None  # folder for saved scans (data_dir/scans) and settings.json; None = nothing is written to disk

    @property
    def allowed_hosts(self) -> frozenset[str]:
        """Host header values the server will answer to (DNS-rebinding defence)."""
        hosts = set(LOOPBACK_HOSTS) if not self.allow_remote else set()
        return frozenset(hosts | {h.lower() for h in self.extra_allowed_hosts})

    @property
    def url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host}:{self.port}/"

    @classmethod
    def from_env(cls, environ: Optional[Mapping[str, str]] = None) -> "Settings":
        env = os.environ if environ is None else environ
        try:
            port = int(env.get("AYYSCANNER_PORT", cls.port))
            concurrent = int(env.get("AYYSCANNER_MAX_CONCURRENT_SCANS", cls.max_concurrent_scans))
        except ValueError:
            raise SettingsError("AYYSCANNER_PORT and AYYSCANNER_MAX_CONCURRENT_SCANS must be whole numbers.") from None
        if not 1 <= port <= 65535:
            raise SettingsError("AYYSCANNER_PORT must be between 1 and 65535.")
        if not 1 <= concurrent <= 10:
            raise SettingsError("AYYSCANNER_MAX_CONCURRENT_SCANS must be between 1 and 10.")
        level = env.get("AYYSCANNER_LOG_LEVEL", cls.log_level).upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
            raise SettingsError("AYYSCANNER_LOG_LEVEL must be DEBUG, INFO, WARNING or ERROR.")
        settings = cls(
            host=env.get("AYYSCANNER_HOST", cls.host).strip(),
            port=port,
            open_browser=_truthy(env.get("AYYSCANNER_OPEN_BROWSER", "1")),
            max_concurrent_scans=concurrent,
            allow_remote=_truthy(env.get("AYYSCANNER_ALLOW_REMOTE", "0")),
            extra_allowed_hosts=tuple(h.strip() for h in env.get("AYYSCANNER_ALLOWED_HOSTS", "").split(",") if h.strip()),
            log_level=level,
            debug=_truthy(env.get("AYYSCANNER_DEBUG", "0")),
            data_dir=_data_dir(env),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        if self.host.lower() not in LOOPBACK_HOSTS:
            if not self.allow_remote or not self.extra_allowed_hosts:
                raise SettingsError(
                    f"AYYSCANNER_HOST={self.host} would make the scanner reachable from other machines. "
                    "It can launch scans from this computer, so it listens on localhost only by default. "
                    "If you really need this, set AYYSCANNER_ALLOW_REMOTE=1 and list the host names you will "
                    "use in AYYSCANNER_ALLOWED_HOSTS, and put it behind authentication (for example a reverse proxy)."
                )
