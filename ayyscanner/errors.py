"""Turns scanner failures into plain-language messages.

Every failure shown in the UI has three parts: a short headline, an explanation of what to do,
and the original technical text for the expandable "Technical details" section. Matching is by
the messages our own scanners produce, so an unrecognised failure still gets a safe, generic
explanation instead of a raw Python error.
"""

from __future__ import annotations

from typing import Any, Optional

# (substring in the scanner's message, headline, advice). First match wins.
_WEB = (
    ("valid website", "Invalid URL.", "Check the address for typos. A domain such as example.com or a full URL such as http://localhost:3000 works."),
    ("website url", "Invalid URL.", "Enter a domain such as example.com or a full URL such as http://localhost:3000."),
    ("too long", "Invalid URL.", "Use a shorter address."),
    ("spaces or control", "Invalid URL.", "Remove spaces and special characters from the address."),
    ("host name", "Invalid URL.", "Check the host name for typos."),
    ("doesn't look like a website", "Invalid URL.", "Check the address for typos."),
    ("not valid", "Invalid URL.", "Check the address for typos."),
    ("resolve the hostname", "Unable to find that website.", "The name could not be looked up. Check the spelling and your internet connection."),
    ("refused", "Unable to connect to the target.", "Nothing is accepting connections there. Check that the site or server is running and the port is right."),
    ("timed out", "The target took too long to answer.", "It may be down, slow or blocked by a firewall. Try again, or raise the request timeout in Settings."),
    ("reset", "Unable to connect to the target.", "The server closed the connection. Try again in a moment."),
    ("certificate", "The security certificate could not be verified.", "The site's HTTPS certificate is not trusted. This is itself a security finding."),
    ("tls", "A secure connection could not be set up.", "The site's HTTPS setup has a problem."),
    ("redirected more than", "The site keeps redirecting.", "It may be stuck in a redirect loop."),
)
_PROJECT = (
    ("directory not found", "Project folder not found.", "Check the folder path. It must exist on this computer."),
    ("no recognized dependency", "No dependency files found.", "AYYSCANNER looks for requirements.txt, package-lock.json and pyproject.toml in that folder."),
)
_SYSTEM = (
    ("insufficient permissions", "Permission is required to perform this system check.", "Run AYYSCANNER with administrator rights (or as root) to include this check. The other checks still ran."),
    ("permission", "Permission is required to perform this system check.", "Run AYYSCANNER with administrator rights to include this check."),
)


def explain(kind: str, message: str, details: Optional[str] = None) -> dict[str, Any]:
    """kind: 'web' | 'system' | 'project' | 'internal'."""
    low = (message or "").lower()
    table = {"web": _WEB, "project": _PROJECT, "system": _SYSTEM}.get(kind, ())
    for needle, title, advice in table:
        if needle in low:
            return {"title": title, "message": advice, "details": details or message}
    if kind == "internal":
        return {"title": "Something went wrong inside AYYSCANNER.", "message": "The scan stopped unexpectedly. Try again; if it keeps happening, the technical details below help when reporting it.", "details": details or message}
    return {"title": "The scan could not be completed.", "message": message or "The scan failed.", "details": details or message}


def explain_notice(message: str) -> dict[str, str]:
    """For non-fatal notes on a finished scan (result.errors): a friendlier headline when we recognise it."""
    low = message.lower()
    if "osv.dev could not be reached" in low or "osv.dev" in low and "not" in low:
        return {"title": "OSV.dev could not be reached. Dependency vulnerability results may be unavailable.", "details": message}
    if "permission" in low:
        return {"title": "Permission is required to perform this system check.", "details": message}
    return {"title": message, "details": ""}
