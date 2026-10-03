"""URL validation, normalization and classification helpers."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

MAX_URL_LENGTH = 2048


class InvalidUrlError(ValueError):
    """The user-supplied URL cannot be turned into something scannable. The
    message is written for humans and is safe to show."""


@dataclass(frozen=True)
class Target:
    url: str
    scheme_defaulted: bool  # user typed no scheme, so https was assumed


def parse_target(raw: str | None) -> Target:
    """Turn user input such as ``example.com`` or `` https://example.com/a `` into
    a validated absolute http(s) URL, or raise InvalidUrlError."""
    candidate = (raw or "").strip()
    if not candidate:
        raise InvalidUrlError("Please enter a website URL, for example https://example.com")
    if len(candidate) > MAX_URL_LENGTH:
        raise InvalidUrlError(f"That URL is too long (maximum {MAX_URL_LENGTH} characters).")
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in candidate):
        raise InvalidUrlError("The URL contains spaces or control characters. Remove them and try again.")

    defaulted = "://" not in candidate
    if defaulted:
        candidate = "https://" + candidate

    try:
        parts = urlsplit(candidate)
        port = parts.port  # raises ValueError for an invalid port
    except ValueError:
        raise InvalidUrlError("That doesn't look like a valid website address (check the host and port).") from None

    if parts.scheme not in ("http", "https"):
        raise InvalidUrlError(
            f"Unsupported URL scheme '{parts.scheme}'. Only http:// and https:// targets can be scanned."
        )
    host = parts.hostname
    if not host:
        raise InvalidUrlError("That doesn't look like a valid website address (no host name found).")
    if parts.username is not None or parts.password is not None:
        raise InvalidUrlError(
            "URLs containing a username or password are not supported. Remove 'user:password@' from the address."
        )
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise InvalidUrlError("The host name contains characters that are not valid in a domain name.") from None
    # A bare word such as "foo" (no scheme, no dot, no port) is almost always a typo.
    is_bare_word = "." not in ascii_host and ":" not in ascii_host and ascii_host != "localhost"
    if defaulted and port is None and is_bare_word:
        raise InvalidUrlError(f"'{host}' doesn't look like a website address. Did you mean '{host}.com'?")

    netloc = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
    if port is not None:
        netloc += f":{port}"
    return Target(urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, "")), defaulted)


def swap_scheme(url: str, scheme: str, *, any_port: bool = False) -> str | None:
    """Return `url` with another scheme. Unless `any_port` is set, returns None
    for custom ports, where an http<->https swap is not meaningful."""
    parts = urlsplit(url)
    if parts.port is not None and not any_port and parts.port not in (80, 443):
        return None
    host = parts.hostname or ""
    netloc = f"[{host}]" if ":" in host else host
    if parts.port is not None and any_port:
        netloc += f":{parts.port}"
    return urlunsplit((scheme, netloc, parts.path, parts.query, ""))


def host_key(url: str) -> str:
    """Lower-cased host without a leading 'www.', used for same-site checks."""
    host = (urlsplit(url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def is_same_site(url_a: str, url_b: str) -> bool:
    return host_key(url_a) == host_key(url_b)
