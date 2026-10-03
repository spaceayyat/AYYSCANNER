"""System security posture scanner.

All checks here are local, read-only introspection: reading `platform`
info, listing listening sockets via `psutil`, checking file permission
bits, and looking at a small, fixed set of well-known config files/paths.
Nothing here modifies system state, escalates privileges, or attempts to
exploit anything it finds.
"""

from __future__ import annotations

import platform
import stat
from pathlib import Path
from typing import Optional

from ayyscanner.models import Confidence, Finding, ScanResult, Severity
import logging

logger = logging.getLogger("ayyscanner.system")

# Ports that are commonly dangerous to expose without justification when
# bound to a non-loopback address. This is informational context, not an
# exhaustive or authoritative list.
NOTABLE_PORTS = {
    21: ("FTP", Severity.MEDIUM, "FTP transmits credentials and data in cleartext."),
    23: ("Telnet", Severity.HIGH, "Telnet transmits credentials and data in cleartext."),
    445: ("SMB", Severity.MEDIUM, "SMB exposed externally is a common lateral-movement vector."),
    3389: ("RDP", Severity.HIGH, "RDP exposed externally is a frequent brute-force/ransomware entry point."),
    5900: ("VNC", Severity.HIGH, "VNC is often deployed with weak or no authentication."),
    27017: ("MongoDB", Severity.HIGH, "Default MongoDB configurations have historically allowed unauthenticated access."),
    6379: ("Redis", Severity.HIGH, "Default Redis configurations have historically allowed unauthenticated access."),
    22: ("SSH", Severity.INFO, "SSH exposure is often expected; verify password auth is disabled."),
}

WORLD_WRITABLE_CHECK_PATHS = [
    "/etc",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/ssh/sshd_config",
]


def _finding(
    fid: str,
    title: str,
    severity: Severity,
    confidence: Confidence,
    description: str,
    evidence: str,
    impact: str,
    remediation: str,
    references: Optional[list[str]] = None,
) -> Finding:
    return Finding(
        id=fid,
        title=title,
        category="system",
        severity=severity,
        confidence=confidence,
        description=description,
        evidence=evidence,
        impact=impact,
        remediation=remediation,
        references=references or [],
        target=platform.node(),
    )


def check_os_version(result: ScanResult) -> None:
    system = platform.system()
    release = platform.release()
    version = platform.version()
    result.metadata["os"] = {"system": system, "release": release, "version": version}
    result.add(
        _finding(
            fid="SYS-OS-001",
            title="Operating system identified",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            description="Baseline OS identification for this scan.",
            evidence=f"{system} {release} ({version})",
            impact="None -- informational context for other findings.",
            remediation="No action required.",
        )
    )


def check_listening_ports(result: ScanResult) -> None:
    try:
        import psutil
    except ImportError:
        result.errors.append("psutil not installed; skipping listening port check.")
        return

    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        result.errors.append(
            "Insufficient permissions to list all listening sockets. "
            "Re-run with elevated privileges for a complete port check."
        )
        return
    except Exception as exc:  # pragma: no cover - defensive
        result.errors.append(f"Failed to enumerate listening ports: {exc}")
        return

    seen_ports: set[int] = set()
    for conn in connections:
        if conn.status != psutil.CONN_LISTEN or not conn.laddr:
            continue
        port = conn.laddr.port
        addr = conn.laddr.ip
        if port in seen_ports:
            continue
        seen_ports.add(port)

        is_external = addr not in ("127.0.0.1", "::1", "localhost")
        name, base_severity, note = NOTABLE_PORTS.get(
            port, ("unknown service", Severity.INFO, "")
        )

        if port in NOTABLE_PORTS and is_external:
            severity = base_severity
        elif port in NOTABLE_PORTS:
            severity = Severity.INFO
        else:
            severity = Severity.INFO

        result.add(
            _finding(
                fid=f"SYS-PORT-{port}",
                title=f"Listening port {port} ({name}) on {addr}",
                severity=severity,
                confidence=Confidence.HIGH,
                description=(
                    f"Port {port} ({name}) is listening on "
                    f"{'a non-loopback' if is_external else 'the loopback'} interface."
                ),
                evidence=f"laddr={addr}:{port} pid={conn.pid}",
                impact=note or "Unrecognized service; review whether it should be exposed.",
                remediation=(
                    "If this service does not need to be reachable from other hosts, "
                    "bind it to 127.0.0.1 or restrict access via firewall rules."
                    if is_external
                    else "No action required if this is intentionally local-only."
                ),
            )
        )


def check_file_permissions(result: ScanResult) -> None:
    for path_str in WORLD_WRITABLE_CHECK_PATHS:
        path = Path(path_str)
        if not path.exists():
            continue
        try:
            mode = path.stat().st_mode
        except OSError as exc:
            result.errors.append(f"Could not stat {path_str}: {exc}")
            continue

        world_writable = bool(mode & stat.S_IWOTH)
        if world_writable:
            result.add(
                _finding(
                    fid=f"SYS-PERM-{path_str.replace('/', '_')}",
                    title=f"World-writable sensitive path: {path_str}",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=(
                        f"{path_str} is writable by any local user, which can allow "
                        "privilege escalation or tampering."
                    ),
                    evidence=f"mode={oct(stat.S_IMODE(mode))}",
                    impact="Any local user could modify this sensitive file.",
                    remediation=f"Remove world-write permission: chmod o-w {path_str}",
                )
            )


def check_ssh_hardening(result: ScanResult) -> None:
    sshd_config = Path("/etc/ssh/sshd_config")
    if not sshd_config.exists():
        return
    try:
        content = sshd_config.read_text(errors="ignore")
    except OSError as exc:
        result.errors.append(f"Could not read sshd_config: {exc}")
        return

    def _directive_enabled(name: str, content: str) -> Optional[bool]:
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0].lower() == name.lower():
                return parts[1].lower() == "yes"
        return None

    password_auth = _directive_enabled("PasswordAuthentication", content)
    root_login = _directive_enabled("PermitRootLogin", content)

    if password_auth is True:
        result.add(
            _finding(
                fid="SYS-SSH-PASSAUTH",
                title="SSH password authentication is enabled",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description="sshd_config explicitly enables PasswordAuthentication.",
                evidence="PasswordAuthentication yes",
                impact="Increases exposure to credential brute-forcing.",
                remediation="Disable password auth and use key-based authentication only.",
            )
        )

    if root_login is True:
        result.add(
            _finding(
                fid="SYS-SSH-ROOTLOGIN",
                title="SSH root login is permitted",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="sshd_config explicitly enables PermitRootLogin.",
                evidence="PermitRootLogin yes",
                impact="Allows direct root login over SSH, removing an audit boundary.",
                remediation="Set 'PermitRootLogin no' and use sudo from a named account instead.",
            )
        )


def check_firewall_status(result: ScanResult) -> None:
    system = platform.system()
    status: Optional[str] = None
    if system == "Linux":
        if Path("/usr/sbin/ufw").exists() or Path("/usr/bin/ufw").exists():
            status = "ufw binary present (status not queried without elevated run)"
        elif Path("/etc/nftables.conf").exists() or Path("/etc/sysconfig/iptables").exists():
            status = "nftables/iptables configuration file present"
        else:
            status = "no common firewall config detected"
    elif system == "Darwin":
        status = "check System Settings > Network > Firewall manually"
    elif system == "Windows":
        status = "check Windows Defender Firewall settings manually"

    if status:
        result.add(
            _finding(
                fid="SYS-FW-001",
                title="Firewall presence check",
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                description="Best-effort local check for firewall tooling.",
                evidence=status,
                impact="A missing or disabled firewall increases exposure of any listening service.",
                remediation="Ensure a host firewall is enabled and default-deny for inbound traffic.",
            )
        )


def run_system_scan() -> ScanResult:
    logger.info("Starting system scan")
    result = ScanResult(scan_type="system", target=platform.node())
    check_os_version(result)
    check_listening_ports(result)
    check_file_permissions(result)
    check_ssh_hardening(result)
    check_firewall_status(result)
    result.mark_finished()
    logger.info("System scan complete: %d findings", len(result.findings))
    return result
