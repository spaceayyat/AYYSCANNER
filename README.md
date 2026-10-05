# AYYSCANNER

**A friendly, defensive security scanner for websites, your own computer, and your software projects, with a clear 0-100 score and a plain-English fix for every problem.**

Point it at a website (including `localhost` and devices on your network), at this computer, or at a project folder.
It tells you what is wrong, how serious it is, how sure it is, and exactly how to fix it. It runs entirely on your
machine, in your browser, with nothing to sign up for and no data sent anywhere.

**By Abdellah Ayyat** · Instagram: [@spaceayyat](https://instagram.com/spaceayyat)

> **Only scan systems you own or have explicit permission to test.** Website scans send real requests to the target.

## Run it in 3 steps

You need **Python 3.10 or newer** and a web browser. Nothing else: no Node.js, no database, no Docker.

**1. Install Python** (skip if you have it; check with `python --version` or `python3 --version`)

| System | How |
|---|---|
| Windows | Download from [python.org/downloads](https://www.python.org/downloads/) and **tick "Add python.exe to PATH"** in the installer. |
| macOS | Download from [python.org/downloads](https://www.python.org/downloads/), or run `brew install python`. |
| Linux | Usually installed. On Debian/Ubuntu also run `sudo apt install python3-venv`. |

**2. Get AYYSCANNER**: either click the green **Code** button on GitHub, then **Download ZIP**, and unzip it (if the repository is private, be signed in to GitHub with access); or:

```bash
git clone https://github.com/spaceayyat/AYYSCANNER.git
cd AYYSCANNER
```

**3. Start it**

| System | Start |
|---|---|
| Windows | Double-click **`run_windows.bat`** |
| macOS / Linux | In a terminal inside the folder: **`./run_linux.sh`** (if it says "permission denied": `chmod +x run_linux.sh`) |
| Any system | `python run.py` (or `python3 run.py`) |

The first start takes a minute: it installs the few libraries it needs into a private `.venv` folder (internet needed once).
Then **your browser opens by itself** at <http://127.0.0.1:8765/>. If it doesn't, open that address manually.

**Every time after that:** double-click the **AYYSCANNER icon that appeared on your Desktop** on the first run. If it is
already running, clicking it again just brings it up, with no second copy and no extra tabs. To stop AYYSCANNER, close its
terminal window (or press `Ctrl+C` in it).

**Your first scan (about 20 seconds):** type a website into the **Quick scan** box (for example `example.com`, or
`http://localhost:3000` for a site on your own machine), press **Quick scan**, confirm you are allowed to test it, and read your score.

Something not working? See [Common problems](#common-problems).

## What it can do

- **Website scans** over HTTP and HTTPS, including `localhost` and LAN addresses: HTTPS and TLS certificate, security headers
  (CSP, HSTS, clickjacking, `nosniff`, Referrer and Permissions Policy), cookie flags, CORS mistakes, mixed content, forms that
  post over HTTP, third-party scripts without Subresource Integrity, leaked server versions and error messages, and files that
  must never be public (`/.git`, `/.env`, `phpinfo()`). SEO and broken-link checks are reported separately and never touch the security score.
- **System scans** of the computer it runs on: operating system, open network ports (flagging risky ones such as Telnet, RDP,
  VNC, exposed databases), permissions on sensitive files, SSH server settings and firewall presence. Read-only.
- **Project scans** of `requirements.txt`, `package-lock.json` and `pyproject.toml`: every pinned dependency is checked against the
  public **OSV.dev** vulnerability database, with severity taken from the advisory's own CVSS data.
- **One 0-100 security score** per scan, with the exact list of what lowered it, and a history of past scans you can reopen.
- **Reports you can share:** self-contained HTML, PDF, plain text, Markdown, JSON and CSV, plus one-click copy of a summary, a
  score or a single finding.
- **A command line** for scripts and CI, with exit codes and pass/fail baselines (see [Command line](#command-line)).

## Why it is different

Most security scanners are either heavyweight tools built for specialists, or one-click tools that hand you a long list with no
indication of what is real. AYYSCANNER is built to be **safe to run, honest about what it knows, and understandable by someone who
is not a security expert**.

| | What AYYSCANNER does | Why that matters |
|---|---|---|
| **Honest results** | Every finding is **Confirmed** (directly observed), **Potential** (hints, verify manually) or **Informational**, with a separate confidence level. Every report lists which checks **ran, were skipped or failed**. | You can tell real problems from guesses, and a clean result never overstates what was checked. |
| **A score you can audit** | The 0-100 score is a fixed formula over the findings: same findings, same score. It shows exactly which findings cost how many points. A confirmed Critical or High problem caps the score. | No black box. And many small wins cannot hide one big hole. |
| **No flattering answers** | If the vulnerability lookup could not run (offline, OSV.dev down), a project scan is **Not rated**, not a reassuring 100. Failed scans are never "clean". | A wrong "all clear" is worse than no answer. |
| **Safe by design** | Passive and read-only: one page, plain requests, no attack payloads, no logins, no form submission, nothing exploited or changed. | You can run it against your own production site without worrying it will break something. |
| **Three scanners, one app** | Website, this computer and project dependencies in one interface, one score model, one history. | One tool and one report format instead of three. |
| **Private by default** | Runs on `127.0.0.1`. No account, no telemetry, no cloud. Scan history and settings are plain files on your disk. Cookie and `.env` **values are never recorded**. Only a website scan (to the target) and a project scan (package names and versions to OSV.dev) ever go online. | Your results about your own systems stay yours. |
| **A hardened scanner** | The local web UI defends itself: localhost only, allow-listed `Host` headers (DNS-rebinding defence), session cookie plus same-origin checks, strict CSP, an SSRF guard so a hostile page cannot make it probe your internal network, and size and time limits. | A tool that can launch scans from your machine must not become an attack path. |
| **Easy to run** | Double-click to start, a Desktop icon, and no Node, Docker or database. A running copy is reused instead of duplicated. | Minutes from download to first result. |
| **Built for teams too** | `--passive-only`, JSON output, **exit codes** (`2` = High/Critical found) and **baseline rules** in a JSON file for pass/fail policies in CI. | The same tool works for a quick look and for an automated pipeline. |
| **Tested** | 224 automated tests that run real scans against local test servers, with no internet needed. | Changes do not silently break results. |

### An honest comparison: when to use something else

AYYSCANNER is deliberately **not** a replacement for full penetration-testing suites or enterprise vulnerability platforms.
Those tools (for example proxy-based testers or commercial scanners) do things AYYSCANNER intentionally does not:

| You need... | Use |
|---|---|
| Crawling a whole site, or testing pages behind a login | A full web application scanner or proxy-based tester |
| Active testing for injection, XSS and similar flaws, or JavaScript-rendered pages | A dynamic (DAST) scanner or a manual penetration test |
| Network-wide vulnerability and compliance scanning across many hosts | An enterprise vulnerability management platform |
| A formal audit or certification | A qualified human assessor |

What AYYSCANNER is best at: a **fast, safe, explainable first look** (and a regular health check) at the things that are most
often wrong and cheapest to fix, with results a non-specialist can act on. A high score means *the checks it ran found little*,
not that a site is secure, and every report says so.

## The app

| Screen | What it does |
|---|---|
| **Home** | **Quick scan** (type a website, one click, nothing to configure) and three cards: **Website scan** (HTTP, HTTPS, localhost, LAN), **System scan** (this computer; the card lists exactly what is checked) and **Project scan** (dependencies via OSV.dev). **Recent scans** shows target, type, date, score and finding count; click one to reopen it, delete one, or clear the history. |
| **Results** | Security score (0-100) at the top, summary cards (Critical, High, Medium, Low, Informational, Passed checks), then findings with severity, explanation, why it matters, evidence, fix and affected URL/file. Search, filter by severity or category, sort by severity or name, hide informational, compact or detailed view. **Copy summary / Copy score / Copy finding** buttons. **Export** as HTML, PDF, TXT, Markdown, JSON or CSV. |
| **Progress** | Only steps that really happen are listed (connect, headers, page content, ... or the five system checks, or reading files / OSV.dev lookup). You can leave the page; the scan keeps running. |
| **Settings** | Theme (remembered), interface size, scan time limit, request timeout, auto-save history, show informational, sort order, compact/detailed results, privacy explanation, clear history, create desktop shortcut, about. Saved automatically and kept across restarts. |
| **Help** | Plain-language guide: what can and cannot be scanned, limits (one page, no JavaScript, no login), system and dependency scanning, why OSV.dev needs internet, what to do about errors. |

Errors are written in plain language ("Unable to connect to the target.", "Invalid URL.", "OSV.dev could not be reached.
Dependency vulnerability results may be unavailable.", "Permission is required to perform this system check.") with the
original technical text in an expandable **Technical details** section.

**Project scans** read `requirements.txt`, `package-lock.json` and `pyproject.toml` in the folder you type. A project scan
whose OSV.dev lookup did not run is shown as **Not rated** rather than a misleading 100. **Passed checks** means check
groups that ran and found nothing (website/system scans) or pinned packages with no known vulnerability (project scans).

**Home / Run is one action.** Run the launcher again (or double-click it again) whenever you like: if AYYSCANNER is
already running it is reused. No second server starts, and no second browser tab opens if the UI is already open
(it only opens one when none is showing it). In the app, the **Home** button (top left) returns to the start screen
in one click, without reloading and without interrupting a running scan.

**Nothing to save by hand.** Finished scans are written to disk the moment they end (`~/.ayyscanner/scans`, the last
50, kept 30 days), so they survive closing the tab, reloading or restarting the server, and appear under **Recent
scans** on the Home screen. Settings are saved the moment you change them (`~/.ayyscanner/settings.json`). The target
URL, project folder and scan options are remembered as you type. Every scan asks for a confirmation before it starts,
which is deliberately never remembered.

## Optional setup

**Desktop shortcut.** The first time you start the app, AYYSCANNER puts a shortcut with its logo on your Desktop, so
from then on you can launch it without opening the project folder (Windows: `AYYSCANNER.lnk`; Linux: `AYYSCANNER.desktop`
plus an entry in the applications menu; macOS: `AYYSCANNER.app`). It is created once and never duplicated: if it is
already there nothing happens, and if you move the project folder the existing shortcut is updated in place. If you
delete it, it stays deleted. `python run.py --create-shortcut` brings it back and `python run.py --remove-shortcut`
removes it. No Desktop folder (a server, a container) means nothing is created. Set `AYYSCANNER_NO_SHORTCUT=1` to turn
it off. The shortcut opens a terminal window that shows the server log; close it or press Ctrl+C there to stop AYYSCANNER. If the dependencies are already importable (your own environment, CI, a container),
`run.py` uses them as they are and creates nothing.


**Manual install**, if you prefer to manage the environment yourself:

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m ayyscanner               # or: pip install . && ayyscanner
```


## Requirements

- **Python 3.10 or newer.** Developed and tested on Python 3.12 (Linux); 3.10 and 3.11 have not been run.
- A modern browser: Chrome/Edge 123+, Firefox 126+ or Safari 17.5+ (the theme system uses CSS `light-dark()`; the interface-size setting uses CSS `zoom`).
- Dependencies (installed automatically): Flask, Requests, Beautiful Soup, ReportLab, and optionally psutil
  (only for `system` scans). No Node.js, no database, no build step.

## What it checks

Everything is read from the responses it receives. Nothing is exploited, submitted or fuzzed.

| Area | Examples |
|---|---|
| Transport | HTTPS in use, HTTP to HTTPS redirect, TLS certificate validity/expiry, TLS version, mixed content, forms posting over HTTP |
| Headers | CSP (and weak CSP), HSTS (and weak HSTS), clickjacking protection, `nosniff`, Referrer/Permissions-Policy, CORS misconfiguration, server/version banners |
| Cookies | `Secure`, `HttpOnly`, `SameSite` (values are never recorded) |
| Content | error/stack-trace leakage, third-party scripts without Subresource Integrity |
| Exposure | publicly readable `/.git/HEAD`, `/.env` (values redacted), `phpinfo()`, missing `security.txt` |
| Quality (reported separately) | SEO basics, broken and redirecting links |

**Limits:** one page is analysed (no crawling), JavaScript is not executed, and there is no authentication.
A report with no findings means *these checks found nothing*, not that the site is secure. Every report says so and
lists exactly which checks ran, were skipped or failed.

## Reading the results

Each finding carries two separate judgements:

- **Severity**: Critical / High / Medium / Low / Informational: how bad it is *if it is real*.
- **Status**: how sure the scanner is.
  - **Confirmed**: directly observed (for example a header is absent from the response).
  - **Potential**: indicators found, but it depends on context the scanner can't see. Verify manually.
  - **Informational**: context with no direct security impact.

There is also a **confidence** level, plus the evidence, affected URL, parameter, impact, remediation, CWE/OWASP
mapping, detection method and timestamp. Site-quality notes (SEO, links) never count toward the security totals.

### Security score (0-100)

Every scan gets one overall score, shown at the top of the results, in the recent-scans list and in every export
(it is also in the JSON as `score`). Higher is better. It is calculated only from the scan's own security findings, so
the same findings always give the same score:

- It starts at 100 and loses points per finding: **Critical 30, High 18, Medium 8, Low 3**. A **Confirmed** finding
  counts in full, a **Potential** one counts half, Informational notes count nothing.
- The same issue found in several places (for example three cookies without `HttpOnly`) adds 25% per extra instance,
  up to double, so one noisy rule cannot sink the score alone.
- A confirmed Critical finding caps the score at 39, a confirmed High at 74, so many small wins cannot hide one big
  problem.
- SEO and link-quality notes never count. A scan that failed is "Not rated". A scan that stopped early is scored on
  the checks that ran and marked partial.

| Score | Meaning |
|---|---|
| 90-100 Excellent | No significant weaknesses were found by the checks that ran |
| 75-89 Good | Only minor weaknesses |
| 50-74 Needs improvement | Several weaknesses; plan fixes soon |
| 25-49 Poor | Serious weaknesses; fix promptly |
| 0-24 Critical | Severe weaknesses; fix these first |

The results screen lists exactly which findings cost how many points. The score measures only what this scanner looks
for: 100 does not mean a site is secure. The rules live in `ayyscanner/scoring.py`.

### Exporting

From the results screen choose **Export**: HTML (self-contained, light/dark, printable, with the score and branding), PDF,
plain text (.txt), Markdown, JSON (machine-readable) or CSV (findings table). Results are saved automatically (see above), so you can come back
and export later.

## Configuration

All optional. Copy `.env.example` to `.env`, or set real environment variables (they win over `.env`).

| Variable | Default | Meaning |
|---|---|---|
| `AYYSCANNER_HOST` | `127.0.0.1` | Interface to listen on. Keep it local (see *Security*). |
| `AYYSCANNER_PORT` | `8765` | Port |
| `AYYSCANNER_OPEN_BROWSER` | `1` | Open the UI on start |
| `AYYSCANNER_NO_SHORTCUT` | unset | Set to `1` to never create the desktop shortcut |
| `AYYSCANNER_MAX_CONCURRENT_SCANS` | `2` | Simultaneous scans (1-10) |
| `AYYSCANNER_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `AYYSCANNER_DEBUG` | `0` | Include exception details in API errors (developers only) |
| `AYYSCANNER_DATA_DIR` | `~/.ayyscanner` | Folder for saved scans (`scans/`) and `settings.json`. Set to `off` to write nothing to disk. |
| `AYYSCANNER_ALLOW_REMOTE`, `AYYSCANNER_ALLOWED_HOSTS` | unset | Only for deliberately exposing the UI; both required |

Scan options (rate limit, which checks run, link limits, user agent) are under **Scan options** on the Website scan card and
are remembered. The request timeout and scan time limit are in **Settings**. Behind a corporate proxy, set `HTTP_PROXY` / `HTTPS_PROXY`.

## Command line

```bash
python -m ayyscanner web https://example.com            # terminal report (asks you to confirm authorization)
python -m ayyscanner web https://example.com -y -f pdf  # no prompt; writes ayyscanner-<host>-<date>.pdf
python -m ayyscanner web https://example.com -y -f json -o scan.json --passive-only
python -m ayyscanner report scan.json -f html -o report.html   # re-render a saved scan
python -m ayyscanner system                             # check this machine's configuration
python -m ayyscanner project ./my-app                   # dependency vulnerabilities via OSV.dev
python -m ayyscanner baseline scan.json examples/baseline.json # evaluate pass/fail rules
```

`--passive-only` sends a single request (no link checks, CORS probe, redirect probe or well-known/sensitive file
requests). Ctrl+C stops a scan and still reports what was found. Exit codes: `0` ok, `1` error or failed scan,
`2` High/Critical findings or a failed baseline rule. Progress and errors go to stderr, so `-f json > file` stays clean.

## Security of the scanner itself

The web UI can start scans from your machine, so it is treated as a sensitive service:

- Listens on **localhost only** by default and refuses to start otherwise unless explicitly configured.
- Answers only to allow-listed `Host` headers (DNS-rebinding defence) and requires a `SameSite=Strict`, HttpOnly
  session cookie on every API call; state-changing calls must be same-origin JSON.
- Strict CSP and security headers on the UI; the UI builds its DOM with `textContent` only, so content scraped from a
  hostile site cannot execute. Exported HTML reports carry their own hash-pinned CSP; CSV output is protected against
  spreadsheet formula injection.
- **SSRF guard:** if the target is a public site, links found on its page that point to private/loopback/link-local
  addresses are never requested, and every redirect hop is validated. Scanning your own `localhost`/LAN site works
  normally.
- Response bodies are size-capped, requests have timeouts, the scanner stores no cookies and sends no `.netrc`
  credentials, and cookie values and `.env` values never appear in results.
- Clients never supply file paths; report file names are generated server-side.

Known limit: the SSRF check resolves a host name before connecting, so a hostile DNS server could in theory answer
differently the second time. It narrows the attack surface; it is not a sandbox.

## Production / packaging

There is no build step. `pip install .` builds and installs a wheel that provides the `ayyscanner` command. The
built-in server is meant for one user on one machine; running it behind another WSGI server or exposing it to a
network is not something this project has tested or supports.

## Common problems

| Problem | Fix |
|---|---|
| `Port 8765 is already in use` | If it is AYYSCANNER itself, the launcher simply reuses it. Otherwise stop the other program or set `AYYSCANNER_PORT=8800` (or run `python run.py serve --port 8800`). |
| Browser didn't open | Open the address printed in the terminal. |
| "Missing or invalid session" in the UI | The server was restarted. Reload the page. |
| Windows: `python` not found | Install Python from python.org and tick **Add python.exe to PATH**; `run_windows.bat` also tries the `py` launcher. |
| Linux: "Could not create a virtual environment" | `sudo apt install python3-venv`, then run again. |
| "Could not install the dependencies" | Needs internet once. Retry, or check proxy settings. |
| Colours look wrong or missing | Update your browser (see Requirements). |
| "TLS certificate could not be verified" | That is a finding, not a scanner fault. The scan continues without verification and says so. |
| Many links show "Restricted" | Some sites answer automated requests with 403/429/999. Those are not counted as broken. |
| Non-Latin text shows as `?` in the PDF | The built-in PDF fonts are Latin-only. Use the HTML, Markdown or JSON export. |

## Development

```bash
python -m unittest discover -s tests -t .     # the whole suite; no extra packages needed
```

The tests run real scans against throw-away local HTTP and HTTPS servers, so they need no internet (the HTTPS tests
use the `openssl` command to make a temporary certificate and are skipped without it; the OSV.dev client is tested
with a fake session).

```
ayyscanner/
  web_scan/      the scan engine: rules.py (every finding's text), security.py, probes.py, seo.py, links.py,
                 http.py (shared client: limits, redirects, SSRF guard), orchestrator in __init__.py
  report/        one ScanResult -> html, pdf, txt, md, json, csv, terminal
  server/        Flask app, background jobs (website/system/project), history store, static UI (index.html, app.css, js/*.js)
  assets/        tokens.css (the single theme/design-token file), logo.svg, launcher icons (.ico/.png/.icns)
  scanners/      system and dependency scanners (CLI)
  models.py      Finding / ScanResult     cli.py      command line     settings.py   environment config
  scoring.py     the 0-100 security score  shortcut.py first-run desktop shortcut (standard library only)
  userprefs.py   Settings page storage     errors.py   plain-language error messages     instance.py   reuse a running instance
```

The launcher icons are generated from the logo geometry by `python tools/make_icons.py` (needs Pillow; the generated
files are committed, so users never need it).

To add a check: add its text to `web_scan/rules.py`, write the check function, call it from
`web_scan/__init__.py` with `_run_stage(...)`, and add a test. Colours live only in `assets/tokens.css`.

## Contact

Questions, ideas or bug reports: open a GitHub issue, or message **[@spaceayyat](https://instagram.com/spaceayyat)** on Instagram.

## License

AYYSCANNER Proprietary License, see `LICENSE.txt`. Credits are in `CREDITS.txt`.
