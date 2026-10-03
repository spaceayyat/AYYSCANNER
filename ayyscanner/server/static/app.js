"use strict";
/* AYYSCANNER web UI.
 * Security note: every piece of scanned-site content (titles, headers, URLs,
 * evidence) is inserted with textContent / createTextNode only, never innerHTML,
 * and links are created only for http(s) URLs. */
(() => {
  const SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"];
  const STATUSES = ["Confirmed", "Potential", "Informational"];
  const STEPS = ["Connect", "Headers, cookies & TLS", "Page content", "Well-known files", "SEO checks", "Links"];
  const STAGE_TO_STEP = { connecting: 0, parsing: 0, headers: 1, cors: 1, content: 2, probes: 3, seo: 4, links: 5, finalizing: 6, done: 6 };
  const STORE = { theme: "ayyscanner.theme", options: "ayyscanner.options", target: "ayyscanner.target" };

  const OPTION_FIELDS = [
    { group: "Requests" },
    { key: "timeout", type: "number", step: 1 },
    { key: "rate_limit_per_second", type: "number", step: 0.5 },
    { key: "user_agent", type: "text", label: "User agent", help: "Identifies the scanner to the target's logs." },
    { group: "Checks" },
    { key: "check_tls", type: "checkbox", label: "TLS certificate and protocol" },
    { key: "check_http_to_https_redirect", type: "checkbox", label: "HTTP to HTTPS redirect" },
    { key: "check_cors", type: "checkbox", label: "CORS origin reflection (1 extra request)" },
    { key: "check_well_known_files", type: "checkbox", label: "robots.txt, sitemap.xml, security.txt" },
    { key: "check_sensitive_files", type: "checkbox", label: "Exposed files (.git, .env, phpinfo)" },
    { group: "Links" },
    { key: "check_internal_links", type: "checkbox", label: "Check internal links" },
    { key: "check_external_links", type: "checkbox", label: "Check external links" },
    { key: "max_links_to_check", type: "number", step: 1 },
    { key: "link_check_concurrency", type: "number", step: 1 },
  ];

  const $ = (sel, root = document) => root.querySelector(sel);
  const state = { recentCount: 0, config: null, jobId: null, job: null, poll: null, tab: "findings", filter: { severity: null, status: null, q: "" } };

  // ---------------------------------------------------------------- helpers
  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : String(v));
    }
    for (const kid of kids.flat()) {
      if (kid === null || kid === undefined || kid === false) continue;
      el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }
  const slug = (s) => s.toLowerCase().replace(/\s+/g, "-");
  const safeUrl = (u) => (typeof u === "string" && /^https?:\/\/[^\s]+$/i.test(u) ? u : null);
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* storage unavailable */ } },
  };
  function fmtDuration(s) {
    if (s == null) return "-";
    if (s < 60) return `${s.toFixed(1)} s`;
    return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;
  }
  function fmtDate(iso) {
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? "-" : d.toLocaleString();
  }
  function show(el, visible) { el.hidden = !visible; }

  class ApiError extends Error {
    constructor(message, code, fields) { super(message); this.code = code; this.fields = fields || {}; }
  }
  async function api(path, options) {
    let res;
    try {
      res = await fetch(path, { credentials: "same-origin", ...options });
    } catch {
      throw new ApiError("Could not reach the AYYSCANNER server. Check that it is still running, then reload this page.", "network");
    }
    let body = null;
    try { body = await res.json(); } catch { /* non-JSON error body */ }
    if (!res.ok) {
      const e = (body && body.error) || {};
      throw new ApiError(e.message || `The server returned an error (HTTP ${res.status}).`, e.code || "http", e.fields);
    }
    return body;
  }

  // ------------------------------------------------------------------ theme
  function applyTheme(choice, persist) {
    if (choice === "light" || choice === "dark") document.documentElement.dataset.theme = choice;
    else delete document.documentElement.dataset.theme;
    if (persist) store.set(STORE.theme, choice);
    document.querySelectorAll("[data-theme-choice]").forEach((b) =>
      b.setAttribute("aria-pressed", String(b.dataset.themeChoice === choice)));
  }
  function initTheme() {
    const saved = store.get(STORE.theme);
    applyTheme(saved === "light" || saved === "dark" ? saved : "system", false);
    document.querySelectorAll("[data-theme-choice]").forEach((b) =>
      b.addEventListener("click", () => applyTheme(b.dataset.themeChoice, true)));
  }

  // ---------------------------------------------------------------- options
  function buildOptionsForm() {
    const grid = $("#options-grid");
    grid.replaceChildren(h("p", { class: "field-error", id: "options-error", role: "alert", hidden: true }));
    const saved = (() => { try { return JSON.parse(store.get(STORE.options) || "{}"); } catch { return {}; } })();
    const values = { ...state.config.defaults, ...saved };
    for (const f of OPTION_FIELDS) {
      if (f.group) { grid.append(h("div", { class: "options-group", text: f.group })); continue; }
      const id = `opt-${f.key}`;
      const limit = state.config.limits[f.key];
      if (f.type === "checkbox") {
        grid.append(h("label", { class: "check" }, h("input", { type: "checkbox", id, "data-option": f.key, checked: values[f.key] ? true : null }), h("span", { text: f.label })));
      } else {
        const input = h("input", { type: f.type, id, "data-option": f.key, autocomplete: "off",
          ...(f.type === "number" ? { min: limit.min, max: limit.max, step: f.step } : { maxlength: 200 }) });
        input.value = values[f.key];
        grid.append(h("div", {}, h("label", { for: id, text: f.label || limit.label }), input,
          limit ? h("small", { text: `${limit.min} to ${limit.max}` }) : f.help ? h("small", { text: f.help }) : null));
      }
    }
  }
  function readOptions() {
    const out = {};
    for (const el of document.querySelectorAll("[data-option]")) {
      const key = el.dataset.option;
      if (el.type === "checkbox") out[key] = el.checked;
      else if (el.type === "number") out[key] = el.value.trim() === "" ? NaN : Number(el.value);
      else out[key] = el.value;
    }
    return out;
  }
  function validateOptions(opts) {
    const problems = {};
    for (const [k, lim] of Object.entries(state.config.limits)) {
      const v = opts[k];
      if (typeof v !== "number" || Number.isNaN(v) || v < lim.min || v > lim.max) problems[k] = `${lim.label} must be between ${lim.min} and ${lim.max}.`;
    }
    if (!opts.user_agent || !opts.user_agent.trim()) problems.user_agent = "User agent must not be empty.";
    return problems;
  }
  function showOptionErrors(problems) {
    const box = $("#options-error");
    const msgs = Object.values(problems);
    box.textContent = msgs.join(" ");
    show(box, msgs.length > 0);
    document.querySelectorAll("[data-option]").forEach((el) => el.setAttribute("aria-invalid", String(el.dataset.option in problems)));
    if (msgs.length) $("#options").open = true;
  }

  // -------------------------------------------------------------- scan flow
  function setError(id, message) {
    const el = $(id);
    el.textContent = message || "";
    show(el, Boolean(message));
  }
  function setBusy(busy) {
    $("#scan-btn").disabled = busy;
    $("#scan-btn").textContent = busy ? "Scanning …" : "Start scan";
    $("#target").disabled = busy;
  }
  function showPanels({ scan = true, progress = false, error = false, results = false, empty = false, recent = scan }) {
    show($("#scan-panel"), scan); show($("#progress-panel"), progress); show($("#error-panel"), error);
    show($("#results"), results); show($("#empty-state"), empty);
    show($("#recent-panel"), recent && state.recentCount > 0);
  }

  async function onSubmit(event) {
    event.preventDefault();
    setError("#target-error", ""); setError("#authorized-error", "");
    const url = $("#target").value.trim();
    const authorized = $("#authorized").checked;
    const opts = readOptions();
    const problems = validateOptions(opts);
    showOptionErrors(problems);
    let bad = false;
    if (!url) { setError("#target-error", "Enter a website URL, for example https://example.com"); $("#target").setAttribute("aria-invalid", "true"); $("#target").focus(); bad = true; }
    if (!authorized) { setError("#authorized-error", "Confirm that you own this target or have permission to test it."); bad = true; }
    if (bad || Object.keys(problems).length) return;
    $("#target").setAttribute("aria-invalid", "false");

    store.set(STORE.target, url);
    store.set(STORE.options, JSON.stringify(opts));
    setBusy(true);
    try {
      const job = await api("/api/scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url, authorized, options: opts }) });
      watchJob(job.id, url);
      loadRecent();
    } catch (err) {
      setBusy(false);
      if (err.code === "invalid_url") { setError("#target-error", err.message); $("#target").setAttribute("aria-invalid", "true"); }
      else if (err.code === "authorization_required") setError("#authorized-error", err.message);
      else if (err.code === "invalid_options") showOptionErrors(err.fields);
      else showFailure("The scan could not be started", err.message);
    }
  }

  function watchJob(id, target) {
    clearTimeout(state.poll);
    state.jobId = id; state.job = null;
    setBusy(true);
    $("#progress-target").textContent = target;
    $("#progress-bar").value = 0;
    $("#progress-message").textContent = "Starting …";
    $("#progress-elapsed").textContent = "";
    renderSteps(0);
    showPanels({ scan: true, progress: true });
    $("#progress-panel").scrollIntoView({ behavior: "smooth", block: "nearest" });
    schedulePoll(0);
  }

  function renderSteps(current) {
    $("#steps").replaceChildren(...STEPS.map((label, i) =>
      h("li", { "data-state": i < current ? "done" : i === current ? "current" : "pending", "aria-current": i === current ? "step" : null, text: label })));
  }

  function schedulePoll(failures) {
    clearTimeout(state.poll);
    const elapsed = state.job ? state.job.progress.elapsed_seconds : 0;
    state.poll = setTimeout(() => poll(failures), elapsed > 30 ? 1500 : 800);
  }
  async function poll(failures) {
    const id = state.jobId;
    if (!id) return;
    let job;
    try {
      job = await api(`/api/scans/${encodeURIComponent(id)}`);
    } catch (err) {
      if (err.code === "not_found") return showFailure("This scan is no longer available", "The server may have been restarted. Start a new scan.");
      if (failures >= 3) return showFailure("Lost connection to the scanner", err.message);
      return schedulePoll(failures + 1);
    }
    if (id !== state.jobId) return;
    state.job = job;
    const p = job.progress;
    if (job.state === "queued" || job.state === "running") {
      $("#progress-bar").value = p.percent;
      $("#progress-message").textContent = p.message || "Working …";
      $("#progress-elapsed").textContent = `· ${fmtDuration(p.elapsed_seconds)}`;
      renderSteps(STAGE_TO_STEP[p.stage] ?? 0);
      return schedulePoll(0);
    }
    setBusy(false);
    if (job.state === "failed") return showFailure("The scan could not be completed", job.error || "The scan failed.");
    renderResults(job);
  }

  function showFailure(title, message) {
    clearTimeout(state.poll);
    state.jobId = null;
    setBusy(false);
    $("#error-title").textContent = title;
    $("#error-message").textContent = message;
    showPanels({ scan: true, error: true, empty: true });
    $("#error-panel").scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  async function cancelScan() {
    if (!state.jobId) return;
    $("#cancel-btn").disabled = true;
    $("#progress-message").textContent = "Stopping …";
    try { await api(`/api/scans/${encodeURIComponent(state.jobId)}/cancel`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }); }
    catch (err) { $("#progress-message").textContent = err.message; }
    finally { setTimeout(() => { $("#cancel-btn").disabled = false; }, 1500); }
  }

  function resetToScan() {
    clearTimeout(state.poll);
    state.jobId = null; state.job = null;
    setBusy(false);
    showPanels({ scan: true, empty: true });
    $("#results").replaceChildren();
    loadRecent();
    $("#target").focus();
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  // Home: one click back to the start screen. Never reloads the page, never opens another tab,
  // and never interrupts a scan that is running (it keeps showing its progress).
  function goHome() {
    const scanning = !$("#progress-panel").hidden;
    if (scanning) { window.scrollTo({ top: 0, behavior: "smooth" }); return; }
    resetToScan();
  }

  // ------------------------------------------------- recent (saved) scans
  const scoreBand = (n) => (n >= 90 ? "excellent" : n >= 75 ? "good" : n >= 50 ? "fair" : n >= 25 ? "poor" : "critical");
  const STATE_LABEL = { queued: "Queued", running: "Running", done: "Completed", failed: "Failed", cancelled: "Stopped" };
  async function loadRecent() {
    let data;
    try { data = await api("/api/scans"); } catch { return null; }
    state.recentCount = data.scans.length;
    $("#recent-note").textContent = data.saved ? "Saved automatically on this computer" : "Kept until the server stops";
    $("#recent-list").replaceChildren(...data.scans.slice(0, 10).map((s) => {
      const active = s.state === "queued" || s.state === "running";
      const detail = active ? `Running · ${s.percent}%` : `${STATE_LABEL[s.state] || s.state}${s.findings != null ? ` · ${s.findings} finding${s.findings === 1 ? "" : "s"}` : ""} · ${fmtDate(new Date((s.finished || s.created) * 1000).toISOString())}`;
      return h("li", {},
        h("div", { class: "what" }, h("span", { class: "mono", text: s.target }), h("span", { class: "when", text: detail })),
        typeof s.score === "number" ? h("span", { class: `score-badge score-${scoreBand(s.score)}`, title: "Security score", text: `${s.score}/100` }) : null,
        h("button", { type: "button", class: "btn secondary", onclick: () => openScan(s.id, s.target), text: active ? "View progress" : "Open" }));
    }));
    if (!$("#scan-panel").hidden) show($("#recent-panel"), state.recentCount > 0);
    return data;
  }
  async function openScan(id, target) {
    clearTimeout(state.poll);  // a pending poll of another scan must not redraw this one
    let job;
    try { job = await api(`/api/scans/${encodeURIComponent(id)}`); } catch (err) { return showFailure("That scan is no longer available", err.message); }
    if (job.state === "queued" || job.state === "running") return watchJob(id, target);
    state.jobId = id;
    if (job.state === "failed" && !job.result) return showFailure("The scan could not be completed", job.error || "The scan failed.");
    renderResults(job);
  }

  // ---------------------------------------- automatic saving of the form
  function saveDraft() {
    store.set(STORE.target, $("#target").value.trim());
    const opts = readOptions();
    if (!Object.keys(validateOptions(opts)).length) store.set(STORE.options, JSON.stringify(opts));
  }
  let draftTimer = null;
  function scheduleDraftSave() { clearTimeout(draftTimer); draftTimer = setTimeout(saveDraft, 300); }

  // Tell the server this page is open (so launching again reuses it instead of opening another tab).
  const TAB_ID = (crypto.randomUUID ? crypto.randomUUID() : String(Math.random()).slice(2) + Date.now()).slice(0, 36);
  const ping = () => api("/api/ui/ping", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ tab: TAB_ID }) }).catch(() => {});

  // --------------------------------------------------------------- results
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

  function findingEl(f, result, open) {
    const facts = [["Affected URL / endpoint", f.target], ["Parameter", f.parameter], ["Classification", [f.cwe, f.owasp].filter(Boolean).join(" · ")], ["Finding ID", f.id]]
      .filter(([, v]) => v);
    return h("details", { class: `finding sev-${slug(f.severity)}`, open: open ? true : null },
      h("summary", {},
        h("div", { class: "head" }, sevChip(f.severity), statusChip(f.status), h("span", { class: "chip", text: `Confidence: ${f.confidence}` })),
        h("div", { class: "title", text: f.title }),
        f.target ? h("div", { class: "where", text: f.target + (f.parameter ? `  ·  ${f.parameter}` : "") }) : null),
      h("div", { class: "body" },
        h("dl", {}, ...facts.map(([k, v]) => h("div", {}, h("dt", { text: k }), h("dd", {}, h("code", { text: v }))))),
        h("h4", { text: "Description" }), h("p", { text: f.description }),
        h("h4", { text: "Technical details" }),
        f.detection_method ? h("p", {}, h("strong", { text: "Detection method: " }), f.detection_method) : null,
        f.evidence ? h("pre", { class: "evidence", text: f.evidence }) : null,
        h("h4", { text: "Impact" }), h("p", { text: f.impact }),
        h("h4", { text: "Remediation" }), h("p", { text: f.remediation }),
        f.references.length ? [h("h4", { text: "References" }), h("ul", {}, ...f.references.map((r) => h("li", {}, link(r, refLabel(r)))))] : null,
        h("p", { class: "muted", text: `Observed ${fmtDate(result.started_at)} · ${result.tool} ${result.tool_version}` })));
  }

  function emptyState(kind) {
    if (kind === "clean") return h("div", { class: "panel state ok" }, h("h3", { text: "No security findings reported" }),
      h("p", { text: "None of the checks that ran found a problem. That does not prove the site is secure: only a single page was inspected, passively. See Scan details for exactly what ran." }));
    return h("div", { class: "panel state" }, h("h3", { text: "No findings match these filters" }), h("p", { text: "Clear a filter to see more results." }));
  }

  function renderFindings(container, result, domain) {
    const all = result.findings.filter((f) => f.domain === domain);
    const q = state.filter.q.trim().toLowerCase();
    const shown = all.filter((f) =>
      (!state.filter.severity || f.severity === state.filter.severity) &&
      (!state.filter.status || f.status === state.filter.status) &&
      (!q || [f.title, f.id, f.target, f.parameter, f.evidence, f.description].join(" ").toLowerCase().includes(q)));
    container.replaceChildren();
    if (!all.length) {
      container.append(domain === "security" ? emptyState("clean") : h("div", { class: "panel state" }, h("h3", { text: "No site-quality notes" }), h("p", { text: "No SEO or link issues were found." })));
      return;
    }
    if (!shown.length) { container.append(emptyState("filtered")); return; }
    shown.forEach((f, i) => container.append(findingEl(f, result, shown.length <= 3 && i === 0)));
  }

  function findingsPanel(result, domain) {
    const list = h("div", { class: "tabpanel" });
    const search = h("input", { type: "text", placeholder: "Search findings …", "aria-label": "Search findings", value: state.filter.q });
    search.addEventListener("input", () => { state.filter.q = search.value; renderFindings(list, result, domain); });
    const toggle = (open) => () => list.querySelectorAll("details.finding").forEach((d) => { d.open = open; });
    const bar = h("div", { class: "toolbar" }, search, h("span", { class: "spacer" }),
      h("button", { type: "button", class: "btn link", onclick: toggle(true), text: "Expand all" }),
      h("button", { type: "button", class: "btn link", onclick: toggle(false), text: "Collapse all" }));
    const wrap = h("div", { class: "tabpanel" }, bar, list);
    renderFindings(list, result, domain);
    return wrap;
  }

  function table(headers, rows) {
    return h("div", { class: "table-wrap" }, h("table", {},
      headers ? h("thead", {}, h("tr", {}, ...headers.map((t) => h("th", { text: t })))) : null,
      h("tbody", {}, ...rows)));
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

  function detailsTab(result) {
    const md = result.metadata, opts = md.options || {};
    const cards = [];
    if (md.checks) cards.push(h("div", { class: "card" }, h("h3", { text: "Checks performed" }), table(["Check", "Status", "Note"],
      md.checks.map((c) => h("tr", {}, h("td", { text: c.name }), h("td", { class: c.status === "ran" ? "yes" : c.status === "failed" ? "no" : "na", text: c.status }), h("td", { text: c.note }))))));
    cards.push(h("div", { class: "card" }, h("h3", { text: "Scan" }), table(null, kvRows([
      ["Target", result.target], ["Started", fmtDate(result.started_at)], ["Duration", fmtDuration(result.duration_seconds)], ["HTTP requests", result.requests_made],
      ["Scanner", `${result.tool} ${result.tool_version}`], ["Rate limit", opts.rate_limit_per_second ? `${opts.rate_limit_per_second} req/s` : null], ["Timeout", opts.timeout ? `${opts.timeout} s` : null], ["User agent", opts.user_agent]]))));
    if (md.scope) cards.push(h("div", { class: "card" }, h("h3", { text: "Scope and limitations" }), h("ul", {}, ...md.scope.map((s) => h("li", { text: s })))));
    cards.push(h("div", { class: "card" }, h("h3", { text: "What the statuses mean" }), h("ul", {},
      h("li", {}, h("strong", { text: "Confirmed: " }), "directly observed in the response."), h("li", {}, h("strong", { text: "Potential: " }), "indicators found; verify manually."), h("li", {}, h("strong", { text: "Informational: " }), "context with no direct security impact."))));
    return h("div", { class: "grid-2" }, ...cards);
  }

  function exportMenu(job) {
    const base = `/api/scans/${encodeURIComponent(job.id)}/report`;
    const items = [["HTML report (open in new tab)", `${base}?format=html&inline=1`, true], ["HTML report (download)", `${base}?format=html`],
      ...state.config.formats.filter((f) => f.key !== "html").map((f) => [f.label, `${base}?format=${f.key}`])];
    return h("details", { class: "menu" }, h("summary", { class: "btn secondary" }, "Export report ▾"),
      h("div", { class: "menu-list" }, ...items.map(([label, href, tab]) => h("a", { href, ...(tab ? { target: "_blank", rel: "noopener" } : { download: "" }), text: label }))));
  }

  // ------------------------------------------------------------ security score
  const SVGNS = "http://www.w3.org/2000/svg";
  function svgEl(tag, attrs, text) {
    const el = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
    if (text !== undefined) el.textContent = text;
    return el;
  }
  function gauge(score) {
    const R = 52, C = 2 * Math.PI * R, rated = typeof score.score === "number";
    const svg = svgEl("svg", { class: "gauge", viewBox: "0 0 120 120", role: "img",
      "aria-label": rated ? `Security score ${score.score} out of 100: ${score.label}` : "Security score: not rated" });
    svg.append(svgEl("circle", { class: "track", cx: 60, cy: 60, r: R }));
    if (rated && score.score > 0) {
      svg.append(svgEl("circle", { class: "arc", cx: 60, cy: 60, r: R, transform: "rotate(-90 60 60)",
        "stroke-dasharray": `${(C * score.score / 100).toFixed(2)} ${C.toFixed(2)}` }));
    }
    svg.append(svgEl("text", { class: "num", x: 60, y: 69 }, rated ? String(score.score) : "–"),
      svgEl("text", { class: "of", x: 60, y: 88 }, rated ? "OUT OF 100" : "NOT RATED"));
    return svg;
  }
  function factorEl(f, max) {
    const meter = svgEl("svg", { viewBox: "0 0 100 5", preserveAspectRatio: "none", "aria-hidden": "true" });
    meter.append(svgEl("rect", { x: 0, y: 0, width: Math.max(2, (100 * f.penalty) / max).toFixed(1), height: 5 }));
    return h("li", { class: `factor sev-${slug(f.severity)}` },
      h("div", { class: "name" }, sevChip(f.severity), statusChip(f.status), h("span", { text: f.title }),
        f.count > 1 ? h("span", { class: "muted", text: `× ${f.count}` }) : null),
      h("span", { class: "pts", text: `−${f.penalty.toFixed(f.penalty % 1 ? 1 : 0)}` }),
      h("div", { class: "meter" }, meter));
  }
  function scorePanel(result) {
    const sc = result.score;
    if (!sc) return null;
    const rated = sc.rated;
    const scale = h("div", { class: "score-scale", "aria-label": "Score bands" },
      ...sc.bands.slice().reverse().map((b) => h("span", { class: `score-${b.key}${b.key === sc.band ? " on" : ""}` },
        h("i"), `${b.min}–${b.max} ${b.label}`)));
    const maxPenalty = Math.max(1, ...sc.factors.map((f) => f.penalty));
    const cov = sc.coverage;
    const notes = [];
    if (sc.partial && rated) notes.push("This scan stopped early, so the score only reflects the checks that ran. It may be higher than the real picture.");
    if (cov.failed) notes.push(`${cov.failed} check${cov.failed === 1 ? "" : "s"} failed to run and could not count toward the score.`);
    sc.caps_applied.forEach((c) => notes.push(c.reason));
    if (rated && sc.score === 100) notes.push("100 means the checks that ran found nothing to deduct. It does not prove the site is secure.");
    return h("div", { class: `panel score-panel score-${sc.band}`, role: "region", "aria-label": "Overall security score" },
      h("div", { class: "score-main" }, gauge(sc),
        h("div", { class: "score-text" },
          h("h2", {}, "Security score", h("span", { class: "verdict", text: rated ? `${sc.score}/100 · ${sc.label}` : sc.label })),
          h("p", { text: sc.meaning }),
          h("p", { class: "what", text: rated
            ? `A summary of the security findings from this scan, out of 100 (higher is better). It starts at 100 and loses points for each issue the scanner confirmed or suspected, weighted by severity. Based on ${cov.ran} of ${cov.total} checks that ran.`
            : "A score needs at least one completed check." }),
          scale)),
      rated ? h("div", { class: "score-factors" },
        h("h3", { text: sc.factors.length ? `What lowered the score${sc.factors_total > sc.factors.length ? ` (top ${sc.factors.length} of ${sc.factors_total})` : ""}` : "What lowered the score" }),
        sc.factors.length ? h("ul", { class: "factor-list" }, ...sc.factors.map((f) => factorEl(f, maxPenalty)))
          : h("p", { class: "muted", text: "Nothing. No security findings were deducted." })) : null,
      ...notes.map((n) => h("p", { class: "score-note", text: n })),
      h("details", { class: "score-details" }, h("summary", { text: "How is this score calculated?" }), h("p", { text: sc.method }),
        h("p", { text: "The same findings always produce the same score. SEO and link-quality notes are never counted." })));
  }

  function renderResults(job) {
    clearTimeout(state.poll);
    const result = job.result;
    state.job = job;
    state.filter = { severity: null, status: null, q: "" };
    state.tab = "findings";
    const sec = result.summary.security, qual = result.summary.quality;
    const outcomeLabel = { complete: "Completed", partial: "Partial", failed: "Failed" }[result.outcome] || result.outcome;
    const root = $("#results");

    const head = h("div", { class: "panel result-head" },
      h("div", { class: "result-top" },
        h("div", {}, h("div", { class: "result-title" }, h("h2", { text: "Scan results" }), h("span", { class: `chip ${result.outcome === "complete" ? "st confirmed" : "st potential"}`, text: outcomeLabel })),
          h("div", { class: "result-target", text: result.target })),
        h("div", { class: "actions" }, exportMenu(job), h("button", { type: "button", class: "btn primary", onclick: resetToScan, text: "New scan" }))),
      h("div", { class: "meta-row" },
        h("span", {}, "Scanned ", h("b", { text: fmtDate(result.started_at) })), h("span", {}, "Duration ", h("b", { text: fmtDuration(result.duration_seconds) })),
        h("span", {}, "HTTP requests ", h("b", { text: result.requests_made })), h("span", {}, "Scanner ", h("b", { text: `${result.tool} ${result.tool_version}` }))));

    const notices = result.errors.length || result.outcome !== "complete"
      ? h("div", { class: "notice" }, h("strong", { text: result.outcome === "partial" ? "Results are incomplete" : "Notes from this scan" }), h("ul", {}, ...result.errors.map((e) => h("li", { text: e })))) : null;

    // summary card: severity tiles act as filters
    const tiles = h("div", { class: "tiles", role: "group", "aria-label": "Filter findings by severity" });
    const statusRow = h("div", { class: "summary-row", role: "group", "aria-label": "Filter findings by status" });
    const findingsHost = h("div", {});
    const tabsHost = h("div", {});
    const refresh = () => {
      tiles.querySelectorAll(".tile").forEach((t) => t.setAttribute("aria-pressed", String(state.filter.severity === t.dataset.sev)));
      statusRow.querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(state.filter.status === b.dataset.status)));
      if (state.tab === "findings" || state.tab === "quality") drawTab();
    };
    SEVERITIES.forEach((s) => tiles.append(h("button", { type: "button", class: `tile sev-${slug(s)}`, "data-sev": s, "aria-pressed": "false", onclick: () => {
      state.filter.severity = state.filter.severity === s ? null : s; state.tab = "findings"; syncTabs(); refresh(); } },
      h("b", { text: sec.severity_breakdown[s] }), h("span", { text: s }))));
    STATUSES.forEach((s) => statusRow.append(h("button", { type: "button", class: "chip", "data-status": s, "aria-pressed": "false", onclick: () => {
      state.filter.status = state.filter.status === s ? null : s; state.tab = "findings"; syncTabs(); refresh(); },
      text: `${sec.status_breakdown[s]} ${s.toLowerCase()}` })));

    const total = sec.total;
    const bar = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    bar.setAttribute("viewBox", "0 0 100 10"); bar.setAttribute("preserveAspectRatio", "none"); bar.setAttribute("class", "sevbar");
    bar.setAttribute("role", "img"); bar.setAttribute("aria-label", "Severity distribution");
    let x = 0;
    for (const s of SEVERITIES) {
      const n = sec.severity_breakdown[s];
      if (!n || !total) continue;
      const w = (100 * n) / total, r = document.createElementNS("http://www.w3.org/2000/svg", "rect");
      r.setAttribute("class", `bar-${slug(s)}`); r.setAttribute("x", x.toFixed(2)); r.setAttribute("y", "0"); r.setAttribute("width", w.toFixed(2)); r.setAttribute("height", "10");
      bar.append(r); x += w;
    }
    const summary = h("div", { class: "panel" },
      h("div", { class: "summary-head" }, h("h2", { text: "Security summary" }),
        h("span", { class: "muted", text: total ? `${total} finding${total === 1 ? "" : "s"}` : "No findings" })),
      tiles, bar, statusRow,
      job.observations && job.observations.length ? h("ul", { class: "observations" }, ...job.observations.map((o) => h("li", { text: o }))) : null,
      qual.total ? h("p", { class: "muted", text: `Plus ${qual.total} site-quality / SEO note(s) in their own tab. They are not counted above.` }) : null);

    const tabs = [["findings", "Security findings", sec.total], ["quality", "Quality & SEO", qual.total], ["page", "Page & headers"], ["links", "Links", result.metadata.links ? result.metadata.links.broken_count : null], ["details", "Scan details"]];
    const tablist = h("div", { class: "tabs", role: "tablist" });
    function syncTabs() {
      tablist.querySelectorAll("button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === state.tab)));
    }
    function drawTab() {
      const t = state.tab;
      tabsHost.replaceChildren(t === "findings" ? findingsPanel(result, "security") : t === "quality" ? findingsPanel(result, "quality")
        : t === "page" ? pageTab(result) : t === "links" ? linksTab(result) : detailsTab(result));
    }
    tabs.forEach(([key, label, count]) => tablist.append(h("button", { type: "button", role: "tab", "data-tab": key, "aria-selected": "false", onclick: () => { state.tab = key; syncTabs(); drawTab(); } },
      label, count !== null && count !== undefined ? h("span", { class: "count", text: count }) : null)));
    findingsHost.append(tablist, tabsHost);

    root.replaceChildren(...[head, notices, scorePanel(result), summary, findingsHost].filter(Boolean)); // replaceChildren(null) would insert the text "null"
    syncTabs(); refresh();
    showPanels({ scan: false, results: true });
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  // ------------------------------------------------------------------ init
  document.addEventListener("click", (e) => {
    document.querySelectorAll("details.menu[open]").forEach((m) => { if (!m.contains(e.target)) m.open = false; });
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") document.querySelectorAll("details.menu[open]").forEach((m) => { m.open = false; });
  });

  async function init() {
    initTheme();
    $("#scan-form").addEventListener("submit", onSubmit);
    $("#cancel-btn").addEventListener("click", cancelScan);
    $("#error-dismiss").addEventListener("click", () => { showPanels({ scan: true, empty: true }); $("#target").focus(); });
    $("#target").addEventListener("input", () => { setError("#target-error", ""); $("#target").setAttribute("aria-invalid", "false"); scheduleDraftSave(); });
    $("#options-grid").addEventListener("input", scheduleDraftSave);
    $("#options-grid").addEventListener("change", scheduleDraftSave);
    window.addEventListener("pagehide", () => {
      saveDraft();  // nothing typed is lost if the tab is closed
      try { navigator.sendBeacon("/api/ui/closed", new Blob([JSON.stringify({ tab: TAB_ID })], { type: "application/json" })); } catch { /* best effort */ }
    });
    $("#home-btn").addEventListener("click", goHome);
    $("#brand").addEventListener("click", (e) => { e.preventDefault(); goHome(); });
    $("#authorized").addEventListener("change", () => setError("#authorized-error", ""));
    $("#target").value = store.get(STORE.target) || "";
    try {
      state.config = await api("/api/config");
    } catch (err) {
      return showFailure("Could not load the scanner", err.message);
    }
    $("#version").textContent = `v${state.config.version}`;
    buildOptionsForm();
    $("#options-reset").addEventListener("click", () => { store.set(STORE.options, "{}"); buildOptionsForm(); });
    showPanels({ scan: true, empty: true });
    ping(); setInterval(ping, 5000);
    // After a reload (or opening the app again) pick up where things were: a running scan, else the recent list.
    const recent = await loadRecent();
    const running = recent && recent.scans.find((x) => x.state === "queued" || x.state === "running");
    if (running) watchJob(running.id, running.target);
  }
  init();
})();
