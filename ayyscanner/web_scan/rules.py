"""Catalog of every finding the web scanner can report.

All static text (description, impact, remediation, CWE/OWASP mapping, how the
issue is detected) lives here so it can be reviewed in one place. Check code
only supplies what it *actually observed* - the evidence, the URL, the
parameter - via `make_finding()`.

Reference links point at OWASP, MITRE CWE, MDN and W3C/Google documentation.
They are static strings and are not verified at scan time.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from ayyscanner.models import Confidence, Finding, FindingStatus, Severity

S = Severity
ST = FindingStatus

_OWASP = {
    "A01": ("A01:2021 Broken Access Control", "A01_2021-Broken_Access_Control"),
    "A02": ("A02:2021 Cryptographic Failures", "A02_2021-Cryptographic_Failures"),
    "A05": ("A05:2021 Security Misconfiguration", "A05_2021-Security_Misconfiguration"),
    "A08": ("A08:2021 Software and Data Integrity Failures", "A08_2021-Software_and_Data_Integrity_Failures"),
}

_CS = "https://cheatsheetseries.owasp.org/cheatsheets/"
_MDN = "https://developer.mozilla.org/en-US/docs/Web/"
_GSC = "https://developers.google.com/search/docs/"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: str
    severity: Severity
    description: str
    impact: str
    remediation: str
    detection: str
    cwe: str = ""
    owasp: str = ""  # key into _OWASP
    references: tuple[str, ...] = ()
    status: Optional[FindingStatus] = None  # None -> derived from severity/confidence
    confidence: Confidence = Confidence.HIGH


def _cwe_url(cwe: str) -> str:
    return f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[-1]}.html"


_RULE_LIST: list[Rule] = [
    # ------------------------------------------------------------ transport
    Rule(
        "WEB-TLS-NOHTTPS", "Site is not served over HTTPS", "transport", S.HIGH,
        "The page was delivered over unencrypted HTTP.",
        "Everything sent between the visitor and the site - cookies, form submissions, "
        "login credentials, page content - can be read or modified by anyone on the network "
        "path (public Wi-Fi, a compromised router, an ISP).",
        "Obtain a TLS certificate (free from Let's Encrypt or your host), serve the whole site "
        "over HTTPS, redirect all HTTP traffic to HTTPS, then enable HSTS.",
        "The final URL of the request, after redirects, used the http:// scheme.",
        cwe="CWE-319", owasp="A02", references=(_CS + "Transport_Layer_Security_Cheat_Sheet.html",),
    ),
    Rule(
        "WEB-TLS-NOREDIRECT", "HTTP does not redirect to HTTPS", "transport", S.MEDIUM,
        "Requesting the plain-HTTP version of this site did not end on an HTTPS URL.",
        "Visitors who type the bare domain or follow an old http:// link stay on an unencrypted "
        "connection and can be intercepted or downgraded by an active attacker.",
        "Answer every http:// request with a permanent (301/308) redirect to the https:// "
        "equivalent, and send an HSTS header so browsers stop trying HTTP at all.",
        "One extra GET to the http:// form of the URL; redirects were followed and the final scheme inspected.",
        cwe="CWE-319", owasp="A02", references=(_CS + "HTTP_Strict_Transport_Security_Cheat_Sheet.html",),
    ),
    Rule(
        "WEB-TLS-CERT-INVALID", "TLS certificate could not be verified", "transport", S.HIGH,
        "A TLS handshake with certificate and hostname verification enabled failed.",
        "Browsers show a full-page security warning. Users who click through, and any client "
        "that skips verification, are exposed to man-in-the-middle attacks; the site also looks untrustworthy.",
        "Install a valid certificate from a trusted CA that covers this exact hostname, serve the "
        "full intermediate chain, and automate renewal (ACME / Let's Encrypt).",
        "A TLS handshake against the system trust store; the failure reason is reported by the TLS library.",
        cwe="CWE-295", owasp="A02", references=(_CS + "Transport_Layer_Security_Cheat_Sheet.html",),
    ),
    Rule(
        "WEB-TLS-CERT-EXPIRING", "TLS certificate expires soon", "transport", S.MEDIUM,
        "The certificate presented by the server is close to its expiry date.",
        "Once the certificate expires every browser will block the site with a security warning "
        "until it is renewed.",
        "Renew the certificate now and automate renewal (ACME clients such as certbot or your host's managed certificates).",
        "The certificate's notAfter date was read from a verified TLS handshake.",
        owasp="A02", references=(_CS + "Transport_Layer_Security_Cheat_Sheet.html",),
    ),
    Rule(
        "WEB-TLS-OLDPROTOCOL", "Deprecated TLS version negotiated", "transport", S.HIGH,
        "The server negotiated a TLS protocol version older than 1.2.",
        "TLS 1.0 and 1.1 have known cryptographic weaknesses and were deprecated by RFC 8996.",
        "Disable TLS 1.0/1.1 on the server or load balancer and require TLS 1.2 or newer (prefer 1.3).",
        "The protocol version negotiated in a TLS handshake was read from the connection.",
        cwe="CWE-326", owasp="A02", references=(_CS + "Transport_Layer_Security_Cheat_Sheet.html",),
    ),
    Rule(
        "WEB-MIXED-ACTIVE", "Active mixed content: scripts, styles or frames loaded over HTTP", "transport", S.MEDIUM,
        "This HTTPS page references scripts, stylesheets or frames over plain HTTP.",
        "An attacker on the network can replace these resources and run arbitrary code or alter the "
        "page. Modern browsers block most of them, which also breaks page functionality.",
        "Change every resource URL to https:// (or a relative URL) and add a "
        "`upgrade-insecure-requests` CSP directive as a safety net.",
        "The page HTML was parsed for script, stylesheet and iframe URLs beginning with http://.",
        cwe="CWE-319", owasp="A02", references=(_MDN + "Security/Mixed_content",),
    ),
    Rule(
        "WEB-MIXED-PASSIVE", "Passive mixed content: images or media loaded over HTTP", "transport", S.LOW,
        "This HTTPS page references images or media over plain HTTP.",
        "The resources can be observed or swapped by a network attacker, and browsers show a "
        "'not fully secure' indicator.",
        "Serve these resources over HTTPS and update the URLs.",
        "The page HTML was parsed for image, audio and video URLs beginning with http://.",
        cwe="CWE-319", owasp="A02", references=(_MDN + "Security/Mixed_content",),
    ),
    # -------------------------------------------------------------- headers
    Rule(
        "WEB-HDR-MISSING", "Missing security header", "headers", S.LOW,
        "The response did not include the header.", "", "", "The response headers of the main request were inspected.",
        cwe="CWE-693", owasp="A05", references=("https://owasp.org/www-project-secure-headers/",),
    ),
    Rule(
        "WEB-HDR-HSTS-WEAK", "HSTS max-age is too short", "headers", S.LOW,
        "The Strict-Transport-Security header is present but its max-age is below six months.",
        "A short HSTS lifetime lets browsers forget the HTTPS-only rule quickly, leaving repeat "
        "visitors exposed to downgrade attacks again.",
        "Use `max-age=31536000` (one year) or more, ideally with `includeSubDomains`.",
        "The max-age directive of the Strict-Transport-Security response header was parsed.",
        cwe="CWE-693", owasp="A05", references=(_CS + "HTTP_Strict_Transport_Security_Cheat_Sheet.html",),
    ),
    Rule(
        "WEB-CSP-WEAK", "Content-Security-Policy allows unsafe script sources", "headers", S.MEDIUM,
        "The Content-Security-Policy is present but permits unsafe script sources.",
        "Directives such as 'unsafe-inline', 'unsafe-eval' or wildcard sources allow injected "
        "scripts to run, which removes most of the protection CSP is meant to provide against XSS.",
        "Remove 'unsafe-inline'/'unsafe-eval' from script-src (use nonces or hashes instead) and "
        "replace wildcard sources with specific hosts.",
        "The script-src (or default-src) directive of the Content-Security-Policy header was parsed.",
        cwe="CWE-693", owasp="A05", references=(_CS + "Content_Security_Policy_Cheat_Sheet.html",),
    ),
    Rule(
        "WEB-CORS-REFLECT-CREDS", "CORS reflects arbitrary origins and allows credentials", "headers", S.HIGH,
        "The server echoed an attacker-chosen Origin in Access-Control-Allow-Origin and also "
        "sent Access-Control-Allow-Credentials: true.",
        "Any website a logged-in user visits can read authenticated responses from this site "
        "(account data, tokens, CSRF secrets) using the user's own browser session.",
        "Validate Origin against a fixed allow-list of trusted origins. Never reflect the request "
        "Origin, and do not combine credentials with a permissive policy.",
        "One extra GET with a synthetic `Origin: https://ayyscanner-cors-check.invalid` header; "
        "the CORS response headers were compared with the sent origin.",
        cwe="CWE-942", owasp="A05", references=(_MDN + "HTTP/CORS",),
    ),
    Rule(
        "WEB-CORS-REFLECT", "CORS reflects arbitrary origins", "headers", S.MEDIUM,
        "The server echoed an attacker-chosen Origin in Access-Control-Allow-Origin.",
        "Any website can read this response from a visitor's browser. That is harmless for public "
        "data, but dangerous if responses depend on cookies or network position (e.g. an intranet).",
        "Replace origin reflection with an explicit allow-list of trusted origins.",
        "One extra GET with a synthetic `Origin: https://ayyscanner-cors-check.invalid` header; "
        "the CORS response headers were compared with the sent origin.",
        cwe="CWE-942", owasp="A05", references=(_MDN + "HTTP/CORS",),
        status=ST.POTENTIAL, confidence=Confidence.MEDIUM,
    ),
    Rule(
        "WEB-CORS-WILDCARD", "CORS allows any origin (wildcard)", "headers", S.LOW,
        "The response sent Access-Control-Allow-Origin: *.",
        "Any website can read this response. Acceptable for genuinely public, unauthenticated "
        "resources; a problem if the endpoint returns non-public data.",
        "If the resource is not meant to be public, restrict Access-Control-Allow-Origin to trusted origins.",
        "The Access-Control-Allow-Origin response header of the main request was inspected.",
        cwe="CWE-942", owasp="A05", references=(_MDN + "HTTP/CORS",),
        status=ST.POTENTIAL, confidence=Confidence.MEDIUM,
    ),
    Rule(
        "WEB-BANNER", "Server software version disclosed", "headers", S.LOW,
        "A response header reveals the software (and version) running on the server.",
        "Knowing the exact product and version lets an attacker look up published exploits for it "
        "instead of guessing.",
        "Suppress or generalize the header at the web server / reverse proxy "
        "(e.g. `server_tokens off;` in nginx, `ServerTokens Prod` in Apache).",
        "The response headers of the main request were inspected for product/version strings.",
        cwe="CWE-200", owasp="A05",
        references=("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",),
    ),
    # -------------------------------------------------------------- cookies
    Rule(
        "WEB-COOKIE-SECURE", "Cookies set without the Secure attribute", "cookies", S.LOW,
        "One or more cookies were set on an HTTPS response without the Secure attribute.",
        "The browser will also send these cookies over plain HTTP, where they can be captured - "
        "for a session cookie this means account takeover.",
        "Add the `Secure` attribute to every cookie set over HTTPS.",
        "The Set-Cookie headers of the main response were parsed (cookie values are never stored).",
        cwe="CWE-614", owasp="A05", references=("https://owasp.org/www-community/controls/SecureCookieAttribute",),
    ),
    Rule(
        "WEB-COOKIE-HTTPONLY", "Cookies set without the HttpOnly attribute", "cookies", S.LOW,
        "One or more cookies were set without the HttpOnly attribute.",
        "JavaScript on the page can read these cookies, so any XSS bug can steal them "
        "(for a session cookie, this hands over the session).",
        "Add `HttpOnly` to cookies that client-side script does not need to read.",
        "The Set-Cookie headers of the main response were parsed (cookie values are never stored).",
        cwe="CWE-1004", owasp="A05", references=("https://owasp.org/www-community/HttpOnly",),
    ),
    Rule(
        "WEB-COOKIE-SAMESITE", "Cookies set without a SameSite attribute", "cookies", S.LOW,
        "One or more cookies were set without an explicit SameSite attribute.",
        "Without SameSite, older browsers attach the cookie to cross-site requests, which enables "
        "cross-site request forgery (CSRF). Current browsers default to Lax, so real-world impact is reduced.",
        "Add `SameSite=Lax` (or `Strict`) to cookies; use `None` only where cross-site use is required, together with `Secure`.",
        "The Set-Cookie headers of the main response were parsed (cookie values are never stored).",
        cwe="CWE-1275", owasp="A05", references=(_MDN + "HTTP/Headers/Set-Cookie#samesitesamesite-value",),
    ),
    Rule(
        "WEB-COOKIE-SAMESITE-NONE", "Cookies use SameSite=None without Secure", "cookies", S.MEDIUM,
        "One or more cookies specify SameSite=None but not Secure.",
        "Modern browsers reject such cookies outright, and where accepted they are sent on cross-site requests over any transport.",
        "Add `Secure` to every cookie that uses `SameSite=None`.",
        "The Set-Cookie headers of the main response were parsed (cookie values are never stored).",
        cwe="CWE-1275", owasp="A05", references=(_MDN + "HTTP/Headers/Set-Cookie#samesitesamesite-value",),
    ),
    # -------------------------------------------------------------- content
    Rule(
        "WEB-INFODISC", "Possible information disclosure in page content", "content", S.MEDIUM,
        "The page body contains text that looks like a debugging or error message.",
        "Error output can reveal file paths, framework and library versions, database structure or "
        "source code that help an attacker plan a targeted attack.",
        "Disable debug / verbose error output in production and serve generic error pages; log details server-side only.",
        "The first part of the HTML body was matched against a small set of well-known error-message signatures.",
        cwe="CWE-209", owasp="A05", references=(_CS + "Error_Handling_Cheat_Sheet.html",),
        status=ST.POTENTIAL, confidence=Confidence.MEDIUM,
    ),
    Rule(
        "WEB-SRI-MISSING", "Third-party resources loaded without Subresource Integrity", "content", S.LOW,
        "Scripts or stylesheets are loaded from other origins without an integrity attribute.",
        "If the third-party host is compromised, attacker-controlled code runs in your visitors' browsers "
        "with full access to your page (a supply-chain attack).",
        "Add `integrity=\"sha384-...\"` and `crossorigin=\"anonymous\"` to third-party <script> and <link> tags, or self-host the files.",
        "The page HTML was parsed for script/stylesheet tags whose host differs from the page's host and that lack `integrity`.",
        cwe="CWE-353", owasp="A08", references=(_MDN + "Security/Subresource_Integrity",),
        status=ST.POTENTIAL, confidence=Confidence.MEDIUM,
    ),
    Rule(
        "WEB-FORM-INSECURE-ACTION", "Form submits data over plain HTTP", "content", S.HIGH,
        "A form on an HTTPS page sends its data to an http:// URL.",
        "Whatever the visitor types - including passwords and personal data - travels unencrypted and can be intercepted.",
        "Change the form action to an https:// URL (or a relative URL).",
        "The page HTML was parsed for <form action> values beginning with http:// on an HTTPS page.",
        cwe="CWE-319", owasp="A02", references=(_CS + "Transport_Layer_Security_Cheat_Sheet.html",),
    ),
    Rule(
        "WEB-FORM-PASSWORD-HTTP", "Password field on a page served over HTTP", "content", S.HIGH,
        "A password input exists on a page delivered without HTTPS.",
        "Passwords are sent in clear text and the page itself can be modified in transit to steal them.",
        "Serve every page containing a login or password form only over HTTPS.",
        "The page HTML was parsed for <input type=password> on a page whose final URL is http://.",
        cwe="CWE-523", owasp="A02", references=(_CS + "Transport_Layer_Security_Cheat_Sheet.html",),
    ),
    Rule(
        "WEB-FORM-PASSWORD-GET", "Password field in a form that uses the GET method", "content", S.MEDIUM,
        "A form containing a password field submits with method GET.",
        "Passwords end up in the URL, and therefore in browser history, server and proxy logs and Referer headers.",
        "Use method=\"post\" for any form that collects credentials.",
        "The page HTML was parsed for forms with a password input and a GET (or missing) method.",
        cwe="CWE-598", owasp="A02", references=(_CS + "Authentication_Cheat_Sheet.html",),
    ),
    # ------------------------------------------------------------- exposure
    Rule(
        "WEB-EXPOSED-GIT", "Git repository metadata is publicly readable", "exposure", S.HIGH,
        "/.git/HEAD is served and has the format of a real Git HEAD file.",
        "An attacker can often download the full repository, including source code, history and "
        "any secrets ever committed.",
        "Block access to dot-directories at the web server (or remove the .git folder from the web root) and rotate any secrets that were ever committed.",
        "One GET to /.git/HEAD; the body was validated against the Git HEAD file format (not just an HTTP 200).",
        cwe="CWE-538", owasp="A05",
        references=("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",),
    ),
    Rule(
        "WEB-EXPOSED-ENV", "Environment file (.env) is publicly readable", "exposure", S.HIGH,
        "/.env is served and contains KEY=VALUE configuration lines. Values are deliberately not shown in this report.",
        "Environment files typically hold database passwords, API keys and application secrets. "
        "Anyone who can fetch the file can use them.",
        "Remove the file from the web root or block it at the web server, then rotate every secret it contained.",
        "One GET to /.env; the body was validated as KEY=VALUE lines (not an HTML error page). Values are redacted.",
        cwe="CWE-538", owasp="A05", references=(_CS + "Secrets_Management_Cheat_Sheet.html",),
    ),
    Rule(
        "WEB-EXPOSED-PHPINFO", "phpinfo() page is publicly accessible", "exposure", S.MEDIUM,
        "A phpinfo() output page is served.",
        "It exposes PHP and module versions, server paths, environment variables and configuration that help an attacker.",
        "Delete the file from the production server.",
        "One GET to /phpinfo.php; the body was matched for the phpinfo() page signature.",
        cwe="CWE-200", owasp="A05",
    ),
    Rule(
        "WEB-SECURITY-TXT-MISSING", "No security.txt file published", "exposure", S.INFO,
        "/.well-known/security.txt was not found.",
        "Without a published contact, security researchers who find a problem have no clear way to report it to you.",
        "Publish a security.txt (RFC 9116) with a contact address at /.well-known/security.txt.",
        "One GET to /.well-known/security.txt.",
        references=("https://securitytxt.org/",),
    ),
    # --------------------------------------------------------------- quality
    Rule(
        "PAGE-HTTP-ERROR", "Target returned an HTTP error status", "page", S.INFO,
        "The main request returned a 4xx/5xx status code.",
        "Header, cookie and content findings describe the *error response*, which may differ from the real site.",
        "Verify the URL, or scan a page that returns 200.", "The status code of the final response was read.",
    ),
    Rule(
        "PAGE-NOT-HTML", "Response is not an HTML page", "page", S.INFO,
        "The response Content-Type is not HTML.",
        "HTML-based checks (SEO, mixed content, forms, third-party scripts, links) were skipped. "
        "Header, cookie and TLS checks still apply.",
        "If this URL should serve a web page, check the server routing.", "The Content-Type response header was inspected.",
    ),
    Rule(
        "PAGE-TRUNCATED", "Page was larger than the analysis limit", "page", S.INFO,
        "Only the first part of the response body was analysed.",
        "Findings that depend on the page content (links, forms, scripts) may be incomplete.",
        "Scan a smaller page, or raise the body-size limit.", "The response body was read up to a fixed byte limit.",
    ),
    Rule(
        "LINK-BROKEN", "Broken links", "links", S.LOW,
        "Links on the page returned an error status or could not be reached.",
        "Visitors hit dead ends, and search engines may treat the page as poorly maintained.",
        "Fix or remove the broken links.", "A HEAD (or GET) request was sent to each checked link and the status inspected.",
    ),
    Rule(
        "LINK-REDIRECT", "Links that redirect", "links", S.INFO,
        "Links on the page redirect to a different URL.",
        "Redirects add latency and may indicate outdated URLs.",
        "Update these links to point directly at the final URL.", "A HEAD (or GET) request was sent to each checked link and redirects were followed.",
    ),
    Rule("SEO-TITLE-MISSING", "Missing page title", "seo", S.MEDIUM,
         "The page has no <title> element.",
         "The title is what search results and browser tabs show; without it, click-through and ranking suffer.",
         "Add a unique, descriptive <title> of roughly 10-60 characters.", "The HTML head was parsed for a <title> element.",
         references=(_GSC + "appearance/title-link",)),
    Rule("SEO-TITLE-EMPTY", "Empty page title", "seo", S.MEDIUM,
         "The <title> element is present but empty.", "An empty title behaves like a missing one.",
         "Give the page a unique, descriptive title.", "The HTML head was parsed for a <title> element.",
         references=(_GSC + "appearance/title-link",)),
    Rule("SEO-TITLE-TOO-SHORT", "Page title is very short", "seo", S.LOW,
         "The title is shorter than about 10 characters.", "Very short titles are rarely descriptive enough to stand out.",
         "Aim for roughly 10-60 characters that describe the page.", "The <title> text length was measured.",
         status=ST.POTENTIAL, confidence=Confidence.MEDIUM, references=(_GSC + "appearance/title-link",)),
    Rule("SEO-TITLE-TOO-LONG", "Page title may be truncated in search results", "seo", S.LOW,
         "The title is longer than about 60 characters.", "Search engines usually truncate long titles.",
         "Shorten the title to roughly 10-60 characters.", "The <title> text length was measured.",
         status=ST.POTENTIAL, confidence=Confidence.MEDIUM, references=(_GSC + "appearance/title-link",)),
    Rule("SEO-METADESC-MISSING", "Missing meta description", "seo", S.LOW,
         "The page has no <meta name=\"description\"> tag.",
         "Search engines will generate a snippet from page text instead, which is often less compelling.",
         "Add a unique meta description of roughly 50-160 characters.", "The HTML head was parsed for a meta description.",
         references=(_GSC + "appearance/snippet",)),
    Rule("SEO-METADESC-EMPTY", "Empty meta description", "seo", S.LOW,
         "The meta description tag is present but empty.", "It gives search engines nothing useful to show.",
         "Write a unique meta description of roughly 50-160 characters.", "The HTML head was parsed for a meta description.",
         references=(_GSC + "appearance/snippet",)),
    Rule("SEO-METADESC-TOO-SHORT", "Meta description is short", "seo", S.INFO,
         "The meta description is shorter than about 50 characters.", "It may not give searchers enough context.",
         "Aim for roughly 50-160 characters.", "The meta description length was measured.",
         references=(_GSC + "appearance/snippet",)),
    Rule("SEO-METADESC-TOO-LONG", "Meta description may be truncated", "seo", S.INFO,
         "The meta description is longer than about 160 characters.", "Search engines usually truncate it.",
         "Aim for roughly 50-160 characters.", "The meta description length was measured.",
         references=(_GSC + "appearance/snippet",)),
    Rule("SEO-H1-MISSING", "Missing H1 heading", "seo", S.LOW,
         "The page has no <h1> element.", "The H1 tells users and search engines what the page is about.",
         "Add one descriptive <h1>.", "The HTML body was parsed for <h1> elements."),
    Rule("SEO-H1-MULTIPLE", "Multiple H1 headings", "seo", S.INFO,
         "The page has more than one <h1> element.",
         "Usually fine with HTML5 sectioning, but classic SEO guidance prefers one.",
         "Consider one <h1> for the main heading and <h2>/<h3> for sections.", "The HTML body was parsed for <h1> elements."),
    Rule("SEO-IMG-ALT-MISSING", "Images without an alt attribute", "seo", S.LOW,
         "Some <img> tags have no alt attribute at all.",
         "Screen-reader users get no description, and search engines lose context. (alt=\"\" is fine for purely decorative images.)",
         "Add a concise alt attribute; use alt=\"\" for decorative images.", "The HTML body was parsed for <img> tags without alt.",
         references=("https://www.w3.org/WAI/tutorials/images/decision-tree/",)),
    Rule("SEO-CANONICAL-MISSING", "No canonical tag", "seo", S.INFO,
         "The page has no <link rel=\"canonical\">.",
         "Search engines must guess the preferred URL when a page is reachable at several addresses.",
         "Add a self-referencing canonical tag.", "The HTML head was parsed for a canonical link.",
         references=(_GSC + "crawling-indexing/consolidate-duplicate-urls",)),
    Rule("SEO-CANONICAL-MISMATCH", "Canonical tag points to a different URL", "seo", S.INFO,
         "The canonical URL differs from the page's own URL.",
         "Often intentional, but a mistake here can remove the page from search results.",
         "Confirm this is the intended canonical target.", "The canonical link was resolved and compared with the final URL.",
         references=(_GSC + "crawling-indexing/consolidate-duplicate-urls",)),
    Rule("SEO-ROBOTS-NOINDEX", "Page is set to noindex", "seo", S.LOW,
         "The robots meta tag includes 'noindex'.", "The page is excluded from search results.",
         "Remove 'noindex' if the page should be discoverable.", "The robots meta tag was parsed.",
         status=ST.POTENTIAL, confidence=Confidence.MEDIUM,
         references=(_GSC + "crawling-indexing/robots-meta-tag",)),
    Rule("SEO-VIEWPORT-MISSING", "Missing mobile viewport meta tag", "seo", S.LOW,
         "No <meta name=\"viewport\"> tag was found.",
         "Mobile browsers render a desktop-width layout scaled down, hurting usability and mobile ranking.",
         "Add <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">.", "The HTML head was parsed for a viewport meta tag.",
         references=(_MDN + "HTML/Viewport_meta_tag",)),
    Rule("SEO-ROBOTS-TXT-MISSING", "No robots.txt found", "seo", S.INFO,
         "/robots.txt did not return a plain-text 200 response.", "Crawlers get no explicit guidance.",
         "Add a robots.txt if you want explicit control over crawling.", "One GET to /robots.txt."),
    Rule("SEO-SITEMAP-MISSING", "No sitemap.xml at the default location", "seo", S.INFO,
         "/sitemap.xml did not return an XML 200 response.", "A sitemap helps search engines discover pages; it may exist at another URL.",
         "Add a sitemap.xml and/or reference it from robots.txt.", "One GET to /sitemap.xml.",
         status=ST.POTENTIAL, confidence=Confidence.LOW, references=(_GSC + "crawling-indexing/sitemaps/overview",)),
]

RULES: dict[str, Rule] = {r.id: r for r in _RULE_LIST}

# Header-missing family: header key -> (display name, severity, status, impact, remediation, reference)
HEADER_RULES: dict[str, dict[str, Any]] = {
    "content-security-policy": dict(
        display="Content-Security-Policy", severity=S.MEDIUM, status=ST.CONFIRMED,
        impact="CSP is the main browser-side defence against cross-site scripting (XSS) and data injection. "
               "Without it, any XSS bug on the site is much easier to exploit.",
        remediation="Send a Content-Security-Policy. A reasonable starting point is "
                    "`default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`. "
                    "Deploy with Content-Security-Policy-Report-Only first to avoid breaking the site.",
        ref=_CS + "Content_Security_Policy_Cheat_Sheet.html"),
    "strict-transport-security": dict(
        display="Strict-Transport-Security", severity=S.MEDIUM, status=ST.CONFIRMED,
        impact="HSTS tells browsers to always use HTTPS for this host. Without it, visitors are exposed to "
               "protocol-downgrade attacks and cookie theft on the first plain-HTTP request.",
        remediation="Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on all HTTPS responses.",
        ref=_CS + "HTTP_Strict_Transport_Security_Cheat_Sheet.html"),
    "x-content-type-options": dict(
        display="X-Content-Type-Options", severity=S.LOW, status=ST.CONFIRMED,
        impact="Without `nosniff`, browsers may guess a response's type and execute e.g. an uploaded text file as a script.",
        remediation="Send `X-Content-Type-Options: nosniff`.",
        ref=_MDN + "HTTP/Headers/X-Content-Type-Options"),
    "x-frame-options": dict(
        display="Clickjacking protection (X-Frame-Options / CSP frame-ancestors)", severity=S.LOW, status=ST.CONFIRMED,
        impact="Other sites can embed this page in a hidden frame and trick users into clicking its buttons (clickjacking).",
        remediation="Send `Content-Security-Policy: frame-ancestors 'none'` (or 'self'), and `X-Frame-Options: DENY` for old browsers.",
        ref=_CS + "Clickjacking_Defense_Cheat_Sheet.html", cwe="CWE-1021"),
    "referrer-policy": dict(
        display="Referrer-Policy", severity=S.INFO, status=ST.INFORMATIONAL,
        impact="Without an explicit policy the browser default applies (usually strict-origin-when-cross-origin), "
               "so URL details may still leak to other sites on some clients.",
        remediation="Send `Referrer-Policy: strict-origin-when-cross-origin` (or stricter).",
        ref=_MDN + "HTTP/Headers/Referrer-Policy"),
    "permissions-policy": dict(
        display="Permissions-Policy", severity=S.INFO, status=ST.INFORMATIONAL,
        impact="Browser features (camera, microphone, geolocation...) are not explicitly restricted for this page and embedded content.",
        remediation="Send a Permissions-Policy that disables unused features, e.g. `camera=(), microphone=(), geolocation=()`.",
        ref=_MDN + "HTTP/Headers/Permissions-Policy"),
}


def make_finding(
    rule_id: str,
    *,
    evidence: str,
    target: str,
    parameter: str = "",
    id_suffix: str = "",
    **overrides: Any,
) -> Finding:
    """Build a Finding from a catalog rule.

    `overrides` may replace any Finding field (title, description, severity,
    status, impact, remediation, detection_method, references, cwe, owasp,
    confidence) when a check needs to be more specific than the catalog text.
    """
    rule = RULES[rule_id]
    cwe = overrides.pop("cwe", rule.cwe)
    owasp = overrides.pop("owasp", rule.owasp)
    references = list(overrides.pop("references", rule.references))
    ref_links = ([_cwe_url(cwe)] if cwe else []) + (
        [f"https://owasp.org/Top10/{_OWASP[owasp][1]}/"] if owasp in _OWASP else []
    )
    fields: dict[str, Any] = dict(
        id=f"{rule.id}-{id_suffix}" if id_suffix else rule.id,
        title=rule.title,
        category=rule.category,
        severity=rule.severity,
        confidence=rule.confidence,
        description=rule.description,
        evidence=evidence,
        impact=rule.impact,
        remediation=rule.remediation,
        references=ref_links + [r for r in references if r not in ref_links],
        target=target,
        parameter=parameter,
        detection_method=rule.detection,
        cwe=cwe,
        owasp=_OWASP[owasp][0] if owasp in _OWASP else "",
        status=rule.status,
    )
    fields.update(overrides)
    return Finding(**fields)
