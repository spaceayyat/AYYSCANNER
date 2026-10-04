// The results screen: score, summary cards, filterable findings, detail tabs, copy and export.
import { $$, copyButton, fmtDate, fmtDuration, h, KIND_LABEL, safeUrl, slug, svgEl } from "./util.js";

const SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"];
const STATUSES = ["Confirmed", "Potential", "Informational"];
const SEV_RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, SEVERITIES.length - i]));

const sevChip = (s) => h("span", { class: `chip sev sev-${slug(s)}`, text: s });
const statusChip = (s) => h("span", { class: `chip st ${s === "Confirmed" ? "confirmed" : s === "Potential" ? "potential" : "info"}`, text: s });

function link(url, label) {
  const safe = safeUrl(url);
  return safe ? h("a", { href: safe, rel: "noopener noreferrer", target: "_blank", text: label || url }) : h("span", { text: url });
}
function refLabel(url) {
  try {
    const u = new URL(url);
    if (u.hostname === "cwe.mitre.org") return "MITRE CWE-" + u.pathname.split("/").pop().replace(".html", "");
    if (u.hostname === "owasp.org" && u.pathname.startsWith("/Top10/")) return "OWASP Top 10: " + u.pathname.split("/").filter(Boolean).pop().replace(/[_-]/g, " ");
    return u.hostname + u.pathname.replace(/\/$/, "");
  } catch { return url; }
}

// ------------------------------------------------------------------ text for copying
export function findingText(f) {
  return [`[${f.severity}] ${f.title} (${f.status}, ${f.confidence} confidence)`,
    f.target ? `Where: ${f.target}${f.parameter ? `  (${f.parameter})` : ""}` : null,
    f.description ? `What: ${f.description}` : null,
    f.impact ? `Why it matters: ${f.impact}` : null,
    f.evidence ? `Evidence: ${f.evidence}` : null,
    f.remediation ? `Fix: ${f.remediation}` : null].filter(Boolean).join("\n");
}
export function scoreText(job) {
  const sc = job.result.score;
  return sc && sc.rated ? `Security score for ${job.result.target}: ${sc.score}/100 (${sc.label})` : `Security score for ${job.result.target}: not rated`;
}
export function summaryText(job) {
  const r = job.result, sec = r.summary.security, pc = r.summary.passed_checks;
  const top = r.findings.filter((f) => f.domain === "security" && f.severity !== "Informational").slice(0, 5);
  return [`AYYSCANNER ${KIND_LABEL[job.kind] || ""} scan of ${r.target}`.replace("  ", " "),
    `Scanned: ${fmtDate(r.started_at)}${r.outcome !== "complete" ? ` (${r.outcome} results)` : ""}`,
    scoreText(job),
    `Findings: ${SEVERITIES.map((s) => `${sec.severity_breakdown[s]} ${s.toLowerCase()}`).join(", ")}`,
    pc && pc.total ? `Passed: ${pc.count} of ${pc.total} ${pc.unit}` : null,
    top.length ? "Top issues:" : "No security issues were reported by the checks that ran.",
    ...top.map((f) => `- [${f.severity}] ${f.title}${f.target ? ` (${f.target})` : ""}`),
  ].filter((x) => x !== null).join("\n");
}

// ------------------------------------------------------------------ one finding
function findingEl(f, result, { open, compact }) {
  const facts = [[f.category === "dependencies" || f.category === "system" ? "Affected target" : "Affected URL / endpoint", f.target], ["Parameter", f.parameter],
    ["Classification", [f.cwe, f.owasp].filter(Boolean).join(" · ")], ["Finding ID", f.id]].filter(([, v]) => v);
  return h("details", { class: `finding sev-${slug(f.severity)}${compact ? " compact" : ""}`, open: open ? true : null },
    h("summary", {},
      h("div", { class: "head" }, sevChip(f.severity), statusChip(f.status), h("span", { class: "chip", text: `Confidence: ${f.confidence}` }), h("span", { class: "chip cat", text: f.category })),
      h("div", { class: "title", text: f.title }),
      f.target ? h("div", { class: "where", text: f.target + (f.parameter ? `  ·  ${f.parameter}` : "") }) : null),
    h("div", { class: "body" },
      h("div", { class: "body-actions" }, copyButton("Copy finding", () => findingText(f), "btn link")),
      h("dl", {}, ...facts.map(([k, v]) => h("div", {}, h("dt", { text: k }), h("dd", {}, h("code", { text: v }))))),
      h("h4", { text: "What was found" }), h("p", { text: f.description }),
      f.evidence || f.detection_method ? [h("h4", { text: "Evidence" }),
        f.evidence ? h("pre", { class: "evidence", text: f.evidence }) : null,
        f.detection_method ? h("p", {}, h("strong", { text: "Detection method: " }), f.detection_method) : null] : null,
      h("h4", { text: "Why it matters" }), h("p", { text: f.impact }),
      h("h4", { text: "How to fix it" }), h("p", { text: f.remediation }),
      f.references.length ? [h("h4", { text: "References" }), h("ul", {}, ...f.references.map((r) => h("li", {}, link(r, refLabel(r)))))] : null,
      h("p", { class: "muted", text: `Observed ${fmtDate(result.started_at)} · ${result.tool} ${result.tool_version}` })));
}

function emptyState(kind, hiddenInfo) {
  if (kind === "clean") return h("div", { class: "panel state ok" }, h("h3", { text: "No security findings reported" }),
    h("p", { text: "None of the checks that ran found a problem. That does not prove the target is secure: AYYSCANNER only looks for specific things. See Scan details for exactly what ran." }));
  return h("div", { class: "panel state" }, h("h3", { text: "No findings match these filters" }),
    h("p", { text: hiddenInfo ? "Informational findings are hidden. Tick “Show informational” or clear a filter to see more." : "Clear a filter to see more results." }));
}

// ------------------------------------------------------------------ tables used by the detail tabs
function table(headers, rows) {
  return h("div", { class: "table-wrap" }, h("table", {},
    headers ? h("thead", {}, h("tr", {}, ...headers.map((t) => h("th", { text: t })))) : null, h("tbody", {}, ...rows)));
}
const kvRows = (pairs) => pairs.filter(([, v]) => v !== null && v !== undefined && v !== "").map(([k, v]) => h("tr", {}, h("th", { text: k }), h("td", {}, v instanceof Node ? v : String(v))));

function pageTab(result) {
  const md = result.metadata, page = md.page, tech = md.technical || {};
  const cards = [];
  if (page) {
    cards.push(h("div", { class: "card" }, h("h3", { text: "Page" }), table(null, kvRows([
      ["Requested URL", page.requested_url], ["Final URL", page.final_url], ["HTTP status", page.status_code],
      ["Response time", `${Math.round(page.response_time_ms)} ms`], ["Content type", page.content_type],
      ["Size analysed", `${page.page_size_bytes.toLocaleString()} bytes${page.truncated ? " (truncated)" : ""}`],
      ["Title", page.title], ["Language", page.html_lang], ["Words", page.word_count],
      ["Redirects", page.redirect_chain.map((r) => `${r.url} (${r.status})`).join(" → ") || "None"]]))));
  }
  if (tech.security_headers) {
    cards.push(h("div", { class: "card" }, h("h3", { text: "Security headers" }), table(null,
      Object.entries(tech.security_headers).map(([k, v]) => h("tr", {}, h("th", { text: k }), h("td", { class: v ? "yes" : "no", text: v ? "Present" : "Missing" }))))));
  }
  if (tech.tls) {
    const t = tech.tls;
    cards.push(h("div", { class: "card" }, h("h3", { text: "TLS" }), table(null, kvRows([
      ["Protocol", t.version], ["Cipher", t.cipher], ["Issuer", t.issuer], ["Expires", t.not_after ? fmtDate(t.not_after) : null],
      ["Days remaining", t.days_remaining], ["Verification error", t.verify_error], ["Handshake error", t.error]]))));
  }
  if (tech.cookies && tech.cookies.length) {
    cards.push(h("div", { class: "card" }, h("h3", { text: "Cookies (values are never recorded)" }), table(["Name", "Secure", "HttpOnly", "SameSite"],
      tech.cookies.map((c) => h("tr", {}, h("td", { text: c.name }),
        h("td", { class: c.secure ? "yes" : "no", text: c.secure ? "Yes" : "No" }), h("td", { class: c.httponly ? "yes" : "no", text: c.httponly ? "Yes" : "No" }),
        h("td", { class: c.samesite ? "" : "no", text: c.samesite || "Not set" }))))));
  }
  if (!cards.length) cards.push(h("div", { class: "panel state" }, h("h3", { text: "No page data" }), h("p", { text: "The page could not be analysed." })));
  return h("div", { class: "grid-2" }, ...cards);
}

function linksTab(result) {
  const links = result.metadata.links;
  if (!links) return h("div", { class: "panel state" }, h("h3", { text: "No links analysed" }), h("p", { text: "Links are only analysed for HTML pages." }));
  const status = (i) => i.is_broken ? "Broken" : i.is_redirect ? "Redirect" : i.checked ? (i.note ? "Restricted" : "OK") : "Not checked";
  const body = h("div", {});
  const select = h("select", { "aria-label": "Filter links" }, ...["All", "Broken", "Redirect", "Restricted", "Not checked"].map((o) => h("option", { value: o, text: o })));
  const draw = () => {
    const rows = links.items.filter((i) => select.value === "All" || status(i) === select.value).slice(0, 500);
    body.replaceChildren(rows.length ? table(["URL", "Type", "HTTP", "Result", "Note"], rows.map((i) => h("tr", {},
      h("td", {}, h("code", { text: i.url })), h("td", { text: i.link_type }), h("td", { text: i.status_code || (i.checked ? "error" : "-") }),
      h("td", { class: i.is_broken ? "no" : i.checked && !i.note ? "yes" : "na", text: status(i) }), h("td", { text: i.note || i.error || "" }))))
      : h("div", { class: "panel state" }, h("p", { text: "No links match this filter." })));
  };
  select.addEventListener("change", draw);
  draw();
  return h("div", { class: "tabpanel" },
    h("div", { class: "toolbar" }, h("span", { class: "muted", text: `${links.unique_count} unique · ${links.internal_count} internal · ${links.external_count} external · ${links.checked_count} checked · ${links.broken_count} broken · ${links.redirect_count} redirecting` }), h("span", { class: "spacer" }), select),
    body);
}

function detailsTab(job) {
  const result = job.result, md = result.metadata, opts = md.options || {}, cards = [];
  if (md.checks) cards.push(h("div", { class: "card" }, h("h3", { text: "Checks performed" }), table(["Check", "Status", "Note"],
    md.checks.map((c) => h("tr", {}, h("td", { text: c.name }), h("td", { class: c.status === "ran" ? "yes" : c.status === "failed" ? "no" : "na", text: c.status }), h("td", { text: c.note || "" }))))));
  cards.push(h("div", { class: "card" }, h("h3", { text: "Scan" }), table(null, kvRows([
    ["Type", `${KIND_LABEL[job.kind] || job.kind} scan`], ["Target", result.target], ["Started", fmtDate(result.started_at)], ["Duration", fmtDuration(result.duration_seconds)],
    ["HTTP requests", job.kind === "web" ? result.requests_made : null], ["Scanner", `${result.tool} ${result.tool_version}`],
    ["Rate limit", opts.rate_limit_per_second ? `${opts.rate_limit_per_second} req/s` : null], ["Request timeout", opts.timeout ? `${opts.timeout} s` : null], ["User agent", opts.user_agent]]))));
  if (md.manifests_found) cards.push(h("div", { class: "card" }, h("h3", { text: "Dependencies" }), table(null, kvRows([
    ["Files read", md.manifests_found.join("\n")], ["Packages found", md.dependency_summary ? md.dependency_summary.total : md.dependencies_found],
    ["Pinned (can be checked)", md.dependency_summary ? md.dependency_summary.checked : null], ["With known vulnerabilities", md.dependency_summary && md.dependency_summary.osv_checked ? md.dependency_summary.vulnerable : null]]))));
  if (md.os) cards.push(h("div", { class: "card" }, h("h3", { text: "This computer" }), table(null, kvRows([["System", md.os.system], ["Release", md.os.release], ["Version", md.os.version]]))));
  if (md.scope) cards.push(h("div", { class: "card" }, h("h3", { text: "Scope and limitations" }), h("ul", {}, ...md.scope.map((s) => h("li", { text: s })))));
  cards.push(h("div", { class: "card" }, h("h3", { text: "What the statuses mean" }), h("ul", {},
    h("li", {}, h("strong", { text: "Confirmed: " }), "directly observed."), h("li", {}, h("strong", { text: "Potential: " }), "indicators found; verify manually."), h("li", {}, h("strong", { text: "Informational: " }), "context with no direct security impact."))));
  return h("div", { class: "grid-2" }, ...cards);
}

// ------------------------------------------------------------------ security score (gauge + what lowered it)
function gauge(score) {
  const R = 52, C = 2 * Math.PI * R, rated = typeof score.score === "number";
  const svg = svgEl("svg", { class: "gauge", viewBox: "0 0 120 120", role: "img",
    "aria-label": rated ? `Security score ${score.score} out of 100: ${score.label}` : "Security score: not rated" });
  svg.append(svgEl("circle", { class: "track", cx: 60, cy: 60, r: R }));
  if (rated && score.score > 0) {
    svg.append(svgEl("circle", { class: "arc", cx: 60, cy: 60, r: R, transform: "rotate(-90 60 60)", "stroke-dasharray": `${(C * score.score / 100).toFixed(2)} ${C.toFixed(2)}` }));
  }
  svg.append(svgEl("text", { class: "num", x: 60, y: 69 }, rated ? String(score.score) : "–"), svgEl("text", { class: "of", x: 60, y: 88 }, rated ? "OUT OF 100" : "NOT RATED"));
  return svg;
}
function factorEl(f, max) {
  const meter = svgEl("svg", { viewBox: "0 0 100 5", preserveAspectRatio: "none", "aria-hidden": "true" });
  meter.append(svgEl("rect", { x: 0, y: 0, width: Math.max(2, (100 * f.penalty) / max).toFixed(1), height: 5 }));
  return h("li", { class: `factor sev-${slug(f.severity)}` },
    h("div", { class: "name" }, sevChip(f.severity), statusChip(f.status), h("span", { text: f.title }), f.count > 1 ? h("span", { class: "muted", text: `× ${f.count}` }) : null),
    h("span", { class: "pts", text: `−${f.penalty.toFixed(f.penalty % 1 ? 1 : 0)}` }), h("div", { class: "meter" }, meter));
}
function scorePanel(job) {
  const sc = job.result.score;
  if (!sc) return null;
  const rated = sc.rated, cov = sc.coverage, notes = [];
  const scale = h("div", { class: "score-scale", "aria-label": "Score bands" },
    ...sc.bands.slice().reverse().map((b) => h("span", { class: `score-${b.key}${b.key === sc.band ? " on" : ""}` }, h("i"), `${b.min}–${b.max} ${b.label}`)));
  const maxPenalty = Math.max(1, ...sc.factors.map((f) => f.penalty));
  if (sc.partial && rated) notes.push("This scan stopped early or skipped a check, so the score only reflects the checks that ran. It may be higher than the real picture.");
  if (cov.failed) notes.push(`${cov.failed} check${cov.failed === 1 ? "" : "s"} failed to run and could not count toward the score.`);
  sc.caps_applied.forEach((c) => notes.push(c.reason));
  if (rated && sc.score === 100) notes.push("100 means the checks that ran found nothing to deduct. It does not prove the target is secure.");
  return h("div", { class: `panel score-panel score-${sc.band}`, role: "region", "aria-label": "Overall security score" },
    h("div", { class: "score-main" }, gauge(sc),
      h("div", { class: "score-text" },
        h("div", { class: "score-label", text: "SECURITY SCORE" }),
        h("h2", {}, rated ? `${sc.score} / 100` : "Not rated", h("span", { class: "verdict", text: rated ? sc.label : "" })),
        h("p", { text: sc.meaning }),
        h("p", { class: "what", text: rated
          ? `Out of 100, higher is better. It starts at 100 and loses points for each issue the scanner confirmed or suspected, weighted by severity.${cov.total ? ` Based on ${cov.ran} of ${cov.total} checks that ran.` : ""}`
          : "A score needs at least one completed check." }),
        scale)),
    rated ? h("div", { class: "score-factors" },
      h("h3", { text: sc.factors.length ? `What lowered the score${sc.factors_total > sc.factors.length ? ` (top ${sc.factors.length} of ${sc.factors_total})` : ""}` : "What lowered the score" }),
      sc.factors.length ? h("ul", { class: "factor-list" }, ...sc.factors.map((f) => factorEl(f, maxPenalty))) : h("p", { class: "muted", text: "Nothing. No security findings were deducted." })) : null,
    ...notes.map((n) => h("p", { class: "score-note", text: n })),
    h("details", { class: "score-details" }, h("summary", { text: "How is this score calculated?" }), h("p", { text: sc.method }),
      h("p", { text: "The same findings always produce the same score. SEO and link-quality notes are never counted." })));
}

// ------------------------------------------------------------------ export menu
function exportMenu(job, config) {
  const base = `/api/scans/${encodeURIComponent(job.id)}/report`;
  const items = [["HTML report (open in new tab)", `${base}?format=html&inline=1`, true], ["HTML report (download)", `${base}?format=html`],
    ...config.formats.filter((f) => f.key !== "html").map((f) => [f.label, `${base}?format=${f.key}`])];
  return h("details", { class: "menu" }, h("summary", { class: "btn secondary", text: "Export ▾" }),
    h("div", { class: "menu-list" }, ...items.map(([label, href, tab]) => h("a", { href, ...(tab ? { target: "_blank", rel: "noopener" } : { download: "" }), text: label }))));
}

// ------------------------------------------------------------------ the whole screen
export function renderResults(root, job, ctx) {
  const { settings, config, onNewScan, onNotify } = ctx;
  const result = job.result, kind = job.kind || "web";
  const sec = result.summary.security, qual = result.summary.quality, pc = result.summary.passed_checks;
  const view = {
    tab: "findings", severity: null, status: null, category: "", q: "",
    sort: settings.sort_findings, compact: settings.result_view === "compact", showInfo: settings.show_informational,
  };
  const outcomeLabel = { complete: "Completed", partial: "Partial", failed: "Failed" }[result.outcome] || result.outcome;

  const head = h("div", { class: "panel result-head" },
    h("div", { class: "result-top" },
      h("div", {}, h("div", { class: "result-title" }, h("h2", { text: `${KIND_LABEL[kind] || ""} scan results` }),
        h("span", { class: `chip ${result.outcome === "complete" ? "st confirmed" : "st potential"}`, text: outcomeLabel })),
        h("div", { class: "result-target", text: result.target })),
      h("div", { class: "actions" }, exportMenu(job, config),
        copyButton("Copy summary", () => summaryText(job)), copyButton("Copy score", () => scoreText(job)),
        h("button", { type: "button", class: "btn primary", onclick: onNewScan, text: "New scan" }))),
    h("div", { class: "meta-row" },
      h("span", {}, "Scanned ", h("b", { text: fmtDate(result.started_at) })), h("span", {}, "Duration ", h("b", { text: fmtDuration(result.duration_seconds) })),
      kind === "web" ? h("span", {}, "HTTP requests ", h("b", { text: result.requests_made })) : null,
      h("span", {}, "Scanner ", h("b", { text: `${result.tool} ${result.tool_version}` }))));

  const notices = (job.notices && job.notices.length) || result.outcome !== "complete"
    ? h("div", { class: "notice" }, h("strong", { text: result.outcome === "partial" ? "Results are incomplete" : "Notes from this scan" }),
      h("ul", {}, ...(job.notices || []).map((n) => h("li", {}, n.title,
        n.details && n.details !== n.title ? h("details", { class: "tech" }, h("summary", { text: "Technical details" }), h("pre", { text: n.details })) : null)))) : null;

  // summary cards: severity tiles filter the findings; "Passed checks" shows what went right
  const tiles = h("div", { class: "tiles", role: "group", "aria-label": "Filter findings by severity" });
  const statusRow = h("div", { class: "summary-row", role: "group", "aria-label": "Filter findings by status" });
  const findingsHost = h("div", {}), tabsHost = h("div", {});
  SEVERITIES.forEach((s) => tiles.append(h("button", { type: "button", class: `tile sev-${slug(s)}`, "data-sev": s, "aria-pressed": "false", onclick: () => {
    view.severity = view.severity === s ? null : s; view.tab = "findings"; if (s === "Informational") view.showInfo = true; refresh(); } },
    h("b", { text: sec.severity_breakdown[s] }), h("span", { text: s }))));
  tiles.append(h("div", { class: "tile passed", title: pc.note }, h("b", { text: pc.total ? pc.count : "–" }), h("span", { text: pc.total ? `Passed checks · of ${pc.total} ${pc.unit}` : "Passed checks" })));
  STATUSES.forEach((s) => statusRow.append(h("button", { type: "button", class: "chip", "data-status": s, "aria-pressed": "false", onclick: () => {
    view.status = view.status === s ? null : s; view.tab = "findings"; refresh(); }, text: `${sec.status_breakdown[s]} ${s.toLowerCase()}` })));
  const total = sec.total;
  const bar = svgEl("svg", { viewBox: "0 0 100 10", preserveAspectRatio: "none", class: "sevbar", role: "img", "aria-label": "Severity distribution" });
  let x = 0;
  for (const s of SEVERITIES) {
    const n = sec.severity_breakdown[s];
    if (!n || !total) continue;
    const w = (100 * n) / total;
    bar.append(svgEl("rect", { class: `bar-${slug(s)}`, x: x.toFixed(2), y: "0", width: w.toFixed(2), height: "10" })); x += w;
  }
  const passedList = pc.items && pc.items.length
    ? h("details", { class: "passed-list" }, h("summary", { text: `What passed (${pc.items.length})` }), h("ul", {}, ...pc.items.map((i) => h("li", { text: i }))), h("p", { class: "muted", text: pc.note }))
    : (pc.total === 0 && pc.note ? h("p", { class: "muted", text: pc.note }) : null);
  const summary = h("div", { class: "panel" },
    h("div", { class: "summary-head" }, h("h2", { text: "Security summary" }), h("span", { class: "muted", text: total ? `${total} finding${total === 1 ? "" : "s"}` : "No findings" })),
    tiles, bar, statusRow, passedList,
    job.observations && job.observations.length ? h("ul", { class: "observations" }, ...job.observations.map((o) => h("li", { text: o }))) : null,
    qual.total ? h("p", { class: "muted", text: `Plus ${qual.total} site-quality / SEO note(s) in their own tab. They are not counted above.` }) : null);

  // tabs available for this kind of scan
  const tabs = [["findings", "Security findings", sec.total]];
  if (kind === "web") tabs.push(["quality", "Quality & SEO", qual.total]);
  if (result.metadata.page) tabs.push(["page", "Page & headers"]);
  if (result.metadata.links) tabs.push(["links", "Links", result.metadata.links.broken_count]);
  tabs.push(["details", "Scan details"]);
  const tablist = h("div", { class: "tabs", role: "tablist" });
  tabs.forEach(([key, label, count]) => tablist.append(h("button", { type: "button", role: "tab", "data-tab": key, "aria-selected": "false", onclick: () => { view.tab = key; refresh(); } },
    label, count !== null && count !== undefined ? h("span", { class: "count", text: count }) : null)));
  findingsHost.append(tablist, tabsHost);

  // ---- findings list with search / filter / sort
  function visibleFindings(domain) {
    const q = view.q.trim().toLowerCase();
    const list = result.findings.filter((f) => f.domain === domain).filter((f) =>
      (view.showInfo || f.severity !== "Informational" || view.severity === "Informational") &&
      (!view.severity || f.severity === view.severity) && (!view.status || f.status === view.status) &&
      (!view.category || f.category === view.category) &&
      (!q || [f.title, f.id, f.target, f.parameter, f.evidence, f.description, f.category].join(" ").toLowerCase().includes(q)));
    list.sort(view.sort === "name"
      ? (a, b) => a.title.localeCompare(b.title)
      : (a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || a.title.localeCompare(b.title));
    return list;
  }
  function findingsPanel(domain) {
    const all = result.findings.filter((f) => f.domain === domain);
    const wrap = h("div", { class: "tabpanel" }), list = h("div", { class: "tabpanel" });
    if (!all.length) {
      wrap.append(domain === "security" ? emptyState("clean") : h("div", { class: "panel state" }, h("h3", { text: "No site-quality notes" }), h("p", { text: "No SEO or link issues were found." })));
      return wrap;
    }
    const cats = [...new Set(all.map((f) => f.category))].sort();
    const search = h("input", { type: "text", placeholder: "Search findings …", "aria-label": "Search findings", value: view.q });
    const sevSel = h("select", { "aria-label": "Filter by severity" }, h("option", { value: "", text: "All severities" }), ...SEVERITIES.map((s) => h("option", { value: s, text: s })));
    const catSel = h("select", { "aria-label": "Filter by category" }, h("option", { value: "", text: "All categories" }),
      ...cats.map((c) => h("option", { value: c, text: `${c} (${all.filter((f) => f.category === c).length})` })));
    const sortSel = h("select", { "aria-label": "Sort findings" }, h("option", { value: "severity", text: "Sort: severity" }), h("option", { value: "name", text: "Sort: name (A–Z)" }));
    const viewSel = h("select", { "aria-label": "Result display" }, h("option", { value: "detailed", text: "Detailed" }), h("option", { value: "compact", text: "Compact" }));
    const infoBox = h("input", { type: "checkbox", id: `show-info-${domain}` });
    const infoLabel = h("label", { class: "check inline", for: `show-info-${domain}` }, infoBox, h("span", { text: "Show informational" }));
    sevSel.value = view.severity || ""; catSel.value = view.category; sortSel.value = view.sort; viewSel.value = view.compact ? "compact" : "detailed"; infoBox.checked = view.showInfo;
    const info = h("p", { class: "muted result-count", role: "status" });
    const draw = () => {
      const shown = visibleFindings(domain);
      const hidden = !view.showInfo ? all.filter((f) => f.severity === "Informational").length : 0;
      info.textContent = `Showing ${shown.length} of ${all.length}${hidden ? ` (${hidden} informational hidden)` : ""}`;
      list.replaceChildren(...(shown.length ? shown.map((f, i) => findingEl(f, result, { open: !view.compact && shown.length <= 3 && i === 0, compact: view.compact })) : [emptyState("filtered", hidden > 0)]));
    };
    search.addEventListener("input", () => { view.q = search.value; draw(); });
    sevSel.addEventListener("change", () => { view.severity = sevSel.value || null; syncTiles(); draw(); });
    catSel.addEventListener("change", () => { view.category = catSel.value; draw(); });
    sortSel.addEventListener("change", () => { view.sort = sortSel.value; draw(); });
    viewSel.addEventListener("change", () => { view.compact = viewSel.value === "compact"; draw(); });
    infoBox.addEventListener("change", () => { view.showInfo = infoBox.checked; draw(); });
    const toggle = (open) => () => $$("details.finding", list).forEach((d) => { d.open = open; });
    wrap.append(h("div", { class: "toolbar" }, search, sevSel, catSel, sortSel, viewSel, infoLabel),
      h("div", { class: "toolbar" }, info, h("span", { class: "spacer" }),
        h("button", { type: "button", class: "btn link", onclick: toggle(true), text: "Expand all" }), h("button", { type: "button", class: "btn link", onclick: toggle(false), text: "Collapse all" }),
        copyButton("Copy all findings", () => visibleFindings(domain).map(findingText).join("\n\n"), "btn link")),
      list);
    draw();
    return wrap;
  }

  function syncTiles() {
    $$(".tile[data-sev]", tiles).forEach((t) => t.setAttribute("aria-pressed", String(view.severity === t.dataset.sev)));
    $$("button", statusRow).forEach((b) => b.setAttribute("aria-pressed", String(view.status === b.dataset.status)));
  }
  function refresh() {
    syncTiles();
    $$("button", tablist).forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === view.tab)));
    const t = view.tab;
    tabsHost.replaceChildren(t === "findings" ? findingsPanel("security") : t === "quality" ? findingsPanel("quality")
      : t === "page" ? pageTab(result) : t === "links" ? linksTab(result) : detailsTab(job));
  }

  root.replaceChildren(...[head, notices, scorePanel(job), summary, findingsHost].filter(Boolean)); // replaceChildren(null) would insert the text "null"
  refresh();
  if (onNotify) onNotify(job);
}
