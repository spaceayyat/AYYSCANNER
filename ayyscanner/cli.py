"""Command line interface.

    python -m ayyscanner                 start the web UI (same as `serve`)
    python -m ayyscanner web URL         scan a website from the terminal
    python -m ayyscanner system          check this machine's configuration
    python -m ayyscanner project DIR     check a project's dependencies (OSV.dev)
    python -m ayyscanner report FILE     re-render a saved JSON scan
    python -m ayyscanner baseline SCAN BASELINE

Exit codes: 0 ok, 1 error or failed scan, 2 High/Critical findings or a failed baseline rule.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import sys
import threading
from pathlib import Path
from typing import Optional

from ayyscanner import __version__
from ayyscanner.baseline import evaluate_baseline, load_baseline
from ayyscanner.models import OUTCOME_FAILED, ScanResult
from ayyscanner.report import FORMATS, filename_for, render, render_terminal
from ayyscanner.settings import Settings, SettingsError, load_dotenv
from ayyscanner.web_scan import InvalidUrlError, ScanOptions, run_web_scan
from ayyscanner.web_scan.options import OptionsError
from ayyscanner.web_scan.urls import parse_target

log = logging.getLogger("ayyscanner")
FORMAT_CHOICES = ["terminal", *FORMATS]
FILE_BY_DEFAULT = {"html", "pdf"}  # too awkward to print to a terminal

AUTHORIZATION_NOTICE = (
    "AYYSCANNER sends real requests to the target below.\n"
    "Only continue if you OWN this target or have EXPLICIT PERMISSION to test it.\n"
    "Target: {target}\n"
)


def confirm_authorization(target: str, assume_yes: bool) -> bool:
    """A speed bump and an audit trail, not a technical control: no local tool
    can verify that you are authorized."""
    print(AUTHORIZATION_NOTICE.format(target=target), file=sys.stderr)  # stderr keeps stdout clean for piping
    if assume_yes:
        log.info("Authorization confirmed via --yes for %s", target)
        return True
    print("Type 'yes' to confirm you are authorized to scan this target: ", end="", file=sys.stderr, flush=True)
    try:
        answer = input()
    except EOFError:
        answer = ""
    confirmed = answer.strip().lower() == "yes"
    log.info("Authorization %s for %s", "confirmed" if confirmed else "DENIED", target)
    if not confirmed:
        print("Authorization not confirmed. Aborting.", file=sys.stderr)
    return confirmed


def emit(result: ScanResult, fmt: str, output: Optional[str]) -> None:
    """Write the report to a file, or stdout for text formats."""
    if fmt == "terminal":
        text = render_terminal(result, use_color=output is None and sys.stdout.isatty())
        if output:
            Path(output).write_text(text, encoding="utf-8")
        else:
            print(text)
        return
    data = render(result, fmt)
    if output is None and fmt in FILE_BY_DEFAULT:
        output = filename_for(result, FORMATS[fmt].extension)
    if output is None:
        sys.stdout.write(data.decode("utf-8"))
        return
    Path(output).write_bytes(data)
    print(f"{FORMATS[fmt].label} written to {output}", file=sys.stderr)


def exit_code(result: ScanResult) -> int:
    if result.outcome == OUTCOME_FAILED:
        return 1
    return 2 if result.has_serious_findings() or result.baseline_breakdown().get("FAIL", 0) else 0


def finish(result: ScanResult, args: argparse.Namespace) -> int:
    if result.outcome == OUTCOME_FAILED:
        # A report of zero findings would look like a clean bill of health, so print the error instead.
        for message in result.errors:
            print(f"Error: {message}", file=sys.stderr)
        return 1
    if getattr(args, "baseline", None):
        evaluate_baseline(load_baseline(args.baseline), result)
    emit(result, args.format, args.output)
    return exit_code(result)


# ---------------------------------------------------------------- commands


def cmd_serve(args: argparse.Namespace) -> int:
    from ayyscanner.server import run_server

    settings = Settings.from_env()
    overrides = {k: v for k, v in (("host", args.host), ("port", args.port)) if v is not None}
    if args.no_browser:
        overrides["open_browser"] = False
    settings = dataclasses.replace(settings, **overrides)
    settings.validate()
    return run_server(settings)


def cmd_web(args: argparse.Namespace) -> int:
    try:
        target = parse_target(args.url)
        options = ScanOptions.from_dict({
            "timeout": args.timeout, "rate_limit_per_second": args.rate_limit, "max_links_to_check": args.max_links,
            **({"check_internal_links": False, "check_external_links": False} if args.skip_links or args.passive_only else {}),
            **({"check_cors": False, "check_well_known_files": False, "check_sensitive_files": False,
                "check_http_to_https_redirect": False} if args.passive_only else {}),
        })
    except (InvalidUrlError, OptionsError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.dry_run:
        print(f"[DRY RUN] Would scan {target.url} (timeout {options.timeout:g}s, {options.rate_limit_per_second:g} req/s). No requests were made.")
        return 0
    if not confirm_authorization(target.url, args.yes):
        return 1

    cancel, holder = threading.Event(), {}

    def worker() -> None:
        holder["result"] = run_web_scan(
            args.url, options, cancel_event=cancel,
            progress_cb=(lambda pct, stage, msg: print(f"[{pct:3d}%] {msg}", file=sys.stderr)) if args.verbose else None)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    try:
        while thread.is_alive():
            thread.join(0.2)
    except KeyboardInterrupt:
        print("\nStopping the scan ...", file=sys.stderr)
        cancel.set()
        thread.join()
    return finish(holder["result"], args)


def cmd_system(args: argparse.Namespace) -> int:
    if args.dry_run:
        print("[DRY RUN] Would check: OS/version, listening ports, sensitive file permissions, SSH hardening, firewall presence. No checks performed.")
        return 0
    from ayyscanner.scanners.system import run_system_scan

    return finish(run_system_scan(), args)


def cmd_project(args: argparse.Namespace) -> int:
    if args.dry_run:
        print(f"[DRY RUN] Would read requirements.txt / package-lock.json / pyproject.toml in {args.directory} and query OSV.dev. Nothing was read or sent.")
        return 0
    from ayyscanner.scanners.dependencies import run_dependency_scan

    return finish(run_dependency_scan(args.directory, timeout=args.timeout, rate_limit=args.rate_limit, offline=args.offline), args)


def _load_scan(path: str) -> ScanResult:
    return ScanResult.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def cmd_report(args: argparse.Namespace) -> int:
    try:
        result = _load_scan(args.scan_json)
    except (OSError, ValueError, KeyError) as exc:
        print(f"Error: could not read a saved scan from {args.scan_json}: {exc}", file=sys.stderr)
        return 1
    emit(result, args.format, args.output)
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    try:
        result = _load_scan(args.scan_json)
        evaluate_baseline(load_baseline(args.baseline_json), result)
    except (OSError, ValueError, KeyError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    emit(result, args.format, args.output)
    return exit_code(result)


# ------------------------------------------------------------------ parser


def _common(p: argparse.ArgumentParser, default_format: str = "terminal", baseline: bool = True) -> None:
    p.add_argument("-f", "--format", choices=FORMAT_CHOICES, default=default_format, help=f"output format (default: {default_format})")
    p.add_argument("-o", "--output", help="write the report to this file (html and pdf default to a generated file name)")
    p.add_argument("-v", "--verbose", action="store_true", help="show progress and debug logging")
    if baseline:
        p.add_argument("--baseline", help="evaluate this baseline JSON file against the results")
    p.add_argument("--dry-run", action="store_true", help="show what would be checked, then exit")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ayyscanner",
        description="AYYSCANNER - web security scanner. Only scan systems you own or are authorized to test.",
        epilog="Run without a command to start the web UI.")
    parser.add_argument("--version", action="version", version=f"AYYSCANNER {__version__}")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("serve", help="start the web UI (default)")
    p.add_argument("--host", help="interface to listen on (default 127.0.0.1)")
    p.add_argument("--port", type=int, help="port (default 8765)")
    p.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("web", help="scan a website from the terminal")
    p.add_argument("url", help="the authorized target, e.g. https://example.com")
    _common(p)
    p.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds (default 10)")
    p.add_argument("--rate-limit", type=float, default=5.0, help="max requests per second (default 5)")
    p.add_argument("--max-links", type=int, default=100, help="max links to status-check (default 100)")
    p.add_argument("--skip-links", action="store_true", help="do not status-check links")
    p.add_argument("--passive-only", action="store_true", help="analyse only the main response: no link checks, CORS probe, redirect probe or well-known/sensitive file requests")
    p.add_argument("-y", "--yes", action="store_true", help="skip the authorization prompt (scripts/CI)")
    p.set_defaults(func=cmd_web)

    p = sub.add_parser("system", help="check this machine's security configuration")
    _common(p)
    p.set_defaults(func=cmd_system)

    p = sub.add_parser("project", help="check a project's dependencies for known vulnerabilities")
    p.add_argument("directory", help="project directory containing requirements.txt, package-lock.json or pyproject.toml")
    _common(p)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--rate-limit", type=float, default=5.0)
    p.add_argument("--offline", action="store_true", help="only parse manifests; skip OSV.dev lookups")
    p.set_defaults(func=cmd_project)

    p = sub.add_parser("report", help="re-render a saved JSON scan in another format")
    p.add_argument("scan_json")
    p.add_argument("-f", "--format", choices=FORMAT_CHOICES, default="html")
    p.add_argument("-o", "--output")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("baseline", help="evaluate a baseline against a saved JSON scan")
    p.add_argument("scan_json")
    p.add_argument("baseline_json")
    p.add_argument("-f", "--format", choices=FORMAT_CHOICES, default="terminal")
    p.add_argument("-o", "--output")
    p.set_defaults(func=cmd_baseline)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    for env_file in (Path.cwd() / ".env", Path(__file__).resolve().parent.parent / ".env"):
        load_dotenv(env_file)
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if getattr(args, "verbose", False) else logging.WARNING, format="%(levelname)s %(message)s")
    try:
        return args.func(args) if getattr(args, "func", None) else cmd_serve(argparse.Namespace(host=None, port=None, no_browser=False))
    except SettingsError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
