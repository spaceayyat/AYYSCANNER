"""TLS inspection: protocol version and certificate validity/expiry.

Uses only the standard library. It opens one extra TCP connection and does one
TLS handshake, separate from the HTTP requests (which are counted elsewhere).
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass
class TlsInfo:
    version: Optional[str] = None
    cipher: Optional[str] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    not_after: Optional[str] = None  # ISO 8601, UTC
    days_remaining: Optional[int] = None
    verify_error: Optional[str] = None  # why certificate verification failed, if it did
    error: Optional[str] = None  # the handshake could not be completed at all


def _common_name(rdns) -> Optional[str]:
    for rdn in rdns or ():
        for key, value in rdn:
            if key in ("commonName", "organizationName"):
                return value
    return None


def _handshake(host: str, port: int, timeout: float, verify: bool) -> tuple[Optional[str], Optional[str], dict]:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cipher = tls.cipher()
            return tls.version(), (cipher[0] if cipher else None), (tls.getpeercert() or {})


def inspect_tls(host: str, port: int, timeout: float) -> TlsInfo:
    info = TlsInfo()
    try:
        version, cipher, cert = _handshake(host, port, timeout, verify=True)
    except ssl.SSLCertVerificationError as exc:
        info.verify_error = (exc.verify_message or exc.reason or "certificate verification failed").rstrip(".")
        try:  # still learn the protocol version from an unverified handshake
            info.version, info.cipher, _ = _handshake(host, port, timeout, verify=False)
        except (OSError, ssl.SSLError):
            pass
        return info
    except (OSError, ssl.SSLError) as exc:
        info.error = f"{type(exc).__name__}: {exc}"[:200]
        return info

    info.version, info.cipher = version, cipher
    info.issuer = _common_name(cert.get("issuer"))
    info.subject = _common_name(cert.get("subject"))
    not_after = cert.get("notAfter")
    if not_after:
        expires = ssl.cert_time_to_seconds(not_after)
        info.not_after = datetime.fromtimestamp(expires, timezone.utc).isoformat()
        info.days_remaining = int((expires - time.time()) // 86400)
    return info
