"""Security checks that read the response the scanner already has.

Everything here is passive analysis of one response (plus, where noted, one
extra harmless GET). Nothing sends attack payloads.
"""

from __future__ import annotations

import re
from dataclasses import asdict
from typing import Any, Optional
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from ayyscanner.models import FindingStatus, Severity
from ayyscanner.web_scan.context import ScanContext
from ayyscanner.web_scan.http import Response
from ayyscanner.web_scan.rules import HEADER_RULES
from ayyscanner.web_scan.tls import inspect_tls
from ayyscanner.web_scan.urls import host_key

CORS_PROBE_ORIGIN = "https://ayyscanner-cors-check.invalid"
HSTS_MIN_SECONDS = 15_552_000  # ~180 days
MAX_LISTED = 5  # examples listed in a finding's evidence

_BANNER_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")
_VERSION_RE = re.compile(r"\d+\.\d+|/\d")
_SESSION_COOKIE_RE = re.compile(r"sess|sid|auth|token|jwt|login|remember", re.I)
_JS_READABLE_COOKIE_RE = re.compile(r"csrf|xsrf", re.I)

_DISCLOSURE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"Traceback \(most recent call last\)"), "Python stack trace"),
    (re.compile(r"(?:Warning|Fatal error|Parse error|Notice):[^\n]{0,200}\bon line \d+", re.I), "PHP error message"),
    (re.compile(r"\bat System\.[A-Za-z.]+\(|System\.[A-Za-z]+Exception\b"), ".NET stack trace"),
    (re.compile(r"\bat (?:org|java|javax|com)\.[\w.$]+\([\w.]+\.java:\d+\)"), "Java stack trace"),
    (re.compile(r"You have an error in your SQL syntax|\bORA-\d{5}\b|PG::[A-Za-z]+Error|SQLSTATE\[\w+\]", re.I), "SQL error message"),
    (re.compile(r"<title>\s*phpinfo\(\)", re.I), "phpinfo() output"),
]


def _short(text: str, limit: int = 200) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _listed(items: list[str], limit: int = MAX_LISTED) -> str:
    shown = "; ".join(_short(i, 160) for i in items[:limit])
    return shown + (f"; … and {len(items) - limit} more" if len(items) > limit else "")


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------


def check_https(ctx: ScanContext, is_https: bool) -> None:
    ctx.facts["is_https"] = is_https
    if not is_https:
        ctx.add("WEB-TLS-NOHTTPS", parameter="scheme", evidence=f"The final URL uses plain HTTP: {ctx.url}")


# ---------------------------------------------------------------------------
# Response headers
# ---------------------------------------------------------------------------


def _csp_directives(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            directives.setdefault(tokens[0].lower(), tokens[1:])
    return directives


def check_headers(ctx: ScanContext, resp: Response, is_https: bool) -> None:
    lower = {k.lower(): v for k, v in resp.headers.items()}
    csp = lower.get("content-security-policy")
    present: dict[str, bool] = {}

    for key, spec in HEADER_RULES.items():
        if key == "strict-transport-security" and not is_https:
            continue  # HSTS is only meaningful (and only honoured) over HTTPS
        if key == "x-frame-options":
            has = key in lower or bool(csp and "frame-ancestors" in csp.lower())
        else:
            has = key in lower
        present[spec["display"]] = has
        if has:
            continue

        evidence = f"Header not present. Response headers seen: {', '.join(sorted(lower)) or '(none)'}"
        description = f"The response did not include a {spec['display']} header."
        if key == "x-frame-options":
            description = "The response had neither an X-Frame-Options header nor a Content-Security-Policy frame-ancestors directive."
        if key == "content-security-policy" and "content-security-policy-report-only" in lower:
            evidence += " | Only Content-Security-Policy-Report-Only is set, which reports violations but does not enforce anything."
        extra = {"cwe": spec["cwe"]} if "cwe" in spec else {}
        ctx.add(
            "WEB-HDR-MISSING", id_suffix=key.upper(), parameter=key.title(),
            evidence=_short(evidence, 400), title=f"Missing {spec['display']}" if key != "x-frame-options" else "Missing clickjacking protection",
            description=description, severity=spec["severity"], status=spec["status"],
            impact=spec["impact"], remediation=spec["remediation"], references=[spec["ref"]], **extra,
        )

    ctx.facts["security_headers"] = present

    hsts = lower.get("strict-transport-security")
    if hsts and is_https:
        m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
        if m is None or int(m.group(1)) < HSTS_MIN_SECONDS:
            age = m.group(1) if m else "not set"
            ctx.add("WEB-HDR-HSTS-WEAK", parameter="Strict-Transport-Security",
                    evidence=f"Strict-Transport-Security: {_short(hsts)} (max-age {age}; recommended at least {HSTS_MIN_SECONDS})")

    if csp:
        _check_csp_strength(ctx, csp)


def _check_csp_strength(ctx: ScanContext, csp: str) -> None:
    directives = _csp_directives(csp)
    source = "script-src" if "script-src" in directives else "default-src" if "default-src" in directives else None
    if source is None:
        ctx.add("WEB-CSP-WEAK", parameter="Content-Security-Policy",
                evidence="The policy has neither script-src nor default-src, so script sources are not restricted.")
        return
    tokens = [t.lower() for t in directives[source]]
    protected = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) or t == "'strict-dynamic'" for t in tokens)
    weak = [t for t in tokens if t in ("'unsafe-eval'", "*", "http:", "https:", "data:")]
    if "'unsafe-inline'" in tokens and not protected:
        weak.append("'unsafe-inline'")
    if weak:
        ctx.add("WEB-CSP-WEAK", parameter="Content-Security-Policy", evidence=f"{source} contains: {' '.join(weak)}")


def check_banners(ctx: ScanContext, resp: Response) -> None:
    banners: dict[str, str] = {}
    for name in _BANNER_HEADERS:
        value = resp.headers.get(name)
        if not value:
            continue
        banners[name] = _short(value, 120)
        suffix = name.upper()
        if name == "Server" and not _VERSION_RE.search(value):
            ctx.add("WEB-BANNER", id_suffix=suffix, parameter=name, evidence=f"{name}: {_short(value)}",
                    title="Server software disclosed (no version)", severity=Severity.INFO,
                    status=FindingStatus.INFORMATIONAL,
                    description="The Server header names the web server software but not its version.",
                    impact="Minor: it narrows down what the server runs, but gives no exact version to look up.")
        else:
            ctx.add("WEB-BANNER", id_suffix=suffix, parameter=name, evidence=f"{name}: {_short(value)}",
                    title=f"Software details disclosed via {name}",
                    description=f"The {name} response header reveals what software runs on the server.")
    ctx.facts["server_banners"] = banners


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------


def check_cors(ctx: ScanContext, resp: Response) -> None:
    acao = resp.headers.get("Access-Control-Allow-Origin")
    if acao == "*":
        ctx.add("WEB-CORS-WILDCARD", parameter="Access-Control-Allow-Origin", evidence="Access-Control-Allow-Origin: *")
    ctx.facts["cors"] = {"allow_origin": acao, "probed": False}
    if not ctx.options.check_cors:
        ctx.note_check("CORS origin reflection", "skipped", "disabled in options")
        return

    probe = ctx.client.fetch(ctx.url, "GET", max_bytes=0, follow_redirects=False, headers={"Origin": CORS_PROBE_ORIGIN})
    if not probe.ok:
        ctx.note_check("CORS origin reflection", "failed", probe.error.message if probe.error else "")
        return
    ctx.note_check("CORS origin reflection", "ran")
    allowed = probe.response.headers.get("Access-Control-Allow-Origin")
    creds = (probe.response.headers.get("Access-Control-Allow-Credentials") or "").lower() == "true"
    ctx.facts["cors"] = {"allow_origin": acao, "probed": True, "reflects_origin": allowed == CORS_PROBE_ORIGIN, "allow_credentials": creds}
    if allowed == CORS_PROBE_ORIGIN:
        evidence = f"Sent Origin: {CORS_PROBE_ORIGIN} -> received Access-Control-Allow-Origin: {allowed}"
        if creds:
            ctx.add("WEB-CORS-REFLECT-CREDS", parameter="Access-Control-Allow-Origin",
                    evidence=evidence + " and Access-Control-Allow-Credentials: true")
        else:
            ctx.add("WEB-CORS-REFLECT", parameter="Access-Control-Allow-Origin", evidence=evidence)


# ---------------------------------------------------------------------------
# Cookies
# ---------------------------------------------------------------------------


def parse_set_cookie(raw: str) -> dict[str, Any]:
    """Parse one Set-Cookie header. The cookie *value* is never kept."""
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs: dict[str, str] = {}
    for part in parts[1:]:
        key, _, val = part.partition("=")
        if key:
            attrs[key.strip().lower()] = val.strip()
    redacted = f"{name}=<redacted>" + "".join(f"; {p}" for p in parts[1:] if p)
    return {"name": name, "secure": "secure" in attrs, "httponly": "httponly" in attrs,
            "samesite": attrs.get("samesite"), "redacted": redacted}


def check_cookies(ctx: ScanContext, resp: Response, is_https: bool) -> None:
    cookies = [parse_set_cookie(c) for c in resp.set_cookies if c.strip()]
    ctx.facts["cookies"] = [{k: v for k, v in c.items() if k != "redacted"} for c in cookies]
    if not cookies:
        return

    def is_session(c: dict[str, Any]) -> bool:
        return bool(_SESSION_COOKIE_RE.search(c["name"]))

    any_session = any(is_session(c) for c in cookies)

    def report(rule: str, affected: list[dict[str, Any]], escalate: bool = False) -> None:
        if not affected:
            return
        overrides: dict[str, Any] = {}
        if escalate and any(is_session(c) for c in affected):
            overrides["severity"] = Severity.MEDIUM  # session/auth cookies matter more
        elif rule == "WEB-COOKIE-SAMESITE" and not any_session:
            overrides.update(severity=Severity.INFO, status=FindingStatus.INFORMATIONAL)
        names = ", ".join(c["name"] for c in affected)
        ctx.add(rule, parameter=_short(names, 200), evidence=_listed([c["redacted"] for c in affected]), **overrides)

    if is_https:
        report("WEB-COOKIE-SECURE", [c for c in cookies if not c["secure"]], escalate=True)
    report("WEB-COOKIE-HTTPONLY", [c for c in cookies if not c["httponly"] and not _JS_READABLE_COOKIE_RE.search(c["name"])], escalate=True)
    report("WEB-COOKIE-SAMESITE", [c for c in cookies if c["samesite"] is None])
    report("WEB-COOKIE-SAMESITE-NONE", [c for c in cookies if (c["samesite"] or "").lower() == "none" and not c["secure"]])


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------


def report_cert_problem(ctx: ScanContext, host: str, port: int, reason: str) -> None:
    ctx.add("WEB-TLS-CERT-INVALID", parameter=host,
            description=f"The certificate presented by {host} failed verification: {reason}.",
            evidence=f"TLS handshake to {host}:{port} failed certificate verification: {reason}")


def check_tls(ctx: ScanContext) -> None:
    parts = urlsplit(ctx.url)
    if parts.scheme != "https" or not parts.hostname:
        ctx.note_check("TLS certificate and protocol", "skipped", "target is not served over HTTPS")
        return
    if not ctx.options.check_tls:
        ctx.note_check("TLS certificate and protocol", "skipped", "disabled in options")
        return
    host, port = parts.hostname, parts.port or 443
    info = inspect_tls(host, port, ctx.options.timeout)
    ctx.facts["tls"] = asdict(info)

    if info.verify_error:
        report_cert_problem(ctx, host, port, info.verify_error)
    if info.error:
        ctx.note_check("TLS certificate and protocol", "failed", info.error)
        ctx.warn(f"TLS details could not be read: {info.error}")
        return
    ctx.note_check("TLS certificate and protocol", "ran")

    if info.version in ("SSLv3", "TLSv1", "TLSv1.1"):
        ctx.add("WEB-TLS-OLDPROTOCOL", parameter=host, evidence=f"Negotiated protocol: {info.version} with {host}:{port}")
    if info.days_remaining is not None and info.days_remaining < 30:
        severity = Severity.MEDIUM if info.days_remaining < 14 else Severity.LOW
        ctx.add("WEB-TLS-CERT-EXPIRING", parameter=host, severity=severity,
                evidence=f"Certificate for {host} expires {info.not_after} ({info.days_remaining} day(s) from now); issuer: {info.issuer or 'unknown'}")


# ---------------------------------------------------------------------------
# HTML content
# ---------------------------------------------------------------------------


def _urls(soup: BeautifulSoup, base: str, selectors: list[tuple[str, str, Optional[str]]]) -> list[str]:
    """Collect absolute URLs from (tag, attribute, required-rel) selectors."""
    found: list[str] = []
    for tag, attr, rel in selectors:
        for el in soup.find_all(tag):
            value = el.get(attr)
            if not value or not isinstance(value, str):
                continue
            if rel and rel not in [r.lower() for r in (el.get("rel") or [])]:
                continue
            found.append(urljoin(base, value.strip()))
    return found


def check_mixed_content(ctx: ScanContext, soup: BeautifulSoup, is_https: bool) -> None:
    if not is_https:
        ctx.facts["mixed_content"] = {"active": 0, "passive": 0}
        return
    active = _urls(soup, ctx.url, [("script", "src", None), ("iframe", "src", None), ("link", "href", "stylesheet"),
                                   ("object", "data", None), ("embed", "src", None)])
    passive = _urls(soup, ctx.url, [("img", "src", None), ("audio", "src", None), ("video", "src", None),
                                    ("source", "src", None), ("video", "poster", None)])
    active = [u for u in active if u.lower().startswith("http://")]
    passive = [u for u in passive if u.lower().startswith("http://")]
    ctx.facts["mixed_content"] = {"active": len(active), "passive": len(passive), "examples": (active + passive)[:10]}
    if active:
        ctx.add("WEB-MIXED-ACTIVE", evidence=f"{len(active)} resource(s): {_listed(active)}")
    if passive:
        ctx.add("WEB-MIXED-PASSIVE", evidence=f"{len(passive)} resource(s): {_listed(passive)}")


def check_forms(ctx: ScanContext, soup: BeautifulSoup, is_https: bool) -> None:
    forms = soup.find_all("form")
    password_inputs = soup.find_all("input", attrs={"type": re.compile(r"^password$", re.I)})
    ctx.facts["forms"] = {"count": len(forms), "password_fields": len(password_inputs)}

    if password_inputs and not is_https:
        ctx.add("WEB-FORM-PASSWORD-HTTP", parameter="input[type=password]",
                evidence=f"{len(password_inputs)} password field(s) found on {ctx.url}")

    insecure_actions: list[str] = []
    get_password_forms = 0
    for form in forms:
        action = urljoin(ctx.url, (form.get("action") or "").strip())
        if is_https and action.lower().startswith("http://"):
            insecure_actions.append(action)
        has_password = form.find("input", attrs={"type": re.compile(r"^password$", re.I)}) is not None
        if has_password and (form.get("method") or "get").strip().lower() == "get":
            get_password_forms += 1
    if insecure_actions:
        ctx.add("WEB-FORM-INSECURE-ACTION", parameter="form[action]",
                evidence=f"{len(insecure_actions)} form(s) post to: {_listed(insecure_actions)}")
    if get_password_forms:
        ctx.add("WEB-FORM-PASSWORD-GET", parameter="form[method]",
                evidence=f"{get_password_forms} form(s) with a password field use method GET (or no method, which defaults to GET)")


def check_third_party_scripts(ctx: ScanContext, soup: BeautifulSoup) -> None:
    page_host = host_key(ctx.url)
    missing: list[str] = []
    for tag, attr, rel in (("script", "src", None), ("link", "href", "stylesheet")):
        for el in soup.find_all(tag):
            value = el.get(attr)
            if not value or not isinstance(value, str) or el.get("integrity"):
                continue
            if rel and rel not in [r.lower() for r in (el.get("rel") or [])]:
                continue
            absolute = urljoin(ctx.url, value.strip())
            if absolute.lower().startswith(("http://", "https://")) and host_key(absolute) != page_host:
                missing.append(absolute)
    ctx.facts["third_party_without_sri"] = len(missing)
    if missing:
        ctx.add("WEB-SRI-MISSING", parameter="script[integrity], link[integrity]",
                evidence=f"{len(missing)} third-party resource(s) without integrity: {_listed(missing)}")


def check_info_disclosure(ctx: ScanContext, body_text: str) -> None:
    for pattern, label in _DISCLOSURE_PATTERNS:
        match = pattern.search(body_text[:300_000])
        if match:
            ctx.add("WEB-INFODISC", id_suffix=label.replace(" ", "-").replace("(", "").replace(")", "").upper(),
                    title=f"Possible information disclosure: {label}",
                    description=f"The page body contains text that looks like a {label}.",
                    evidence=f"Matched text: {_short(match.group(0), 160)}")
