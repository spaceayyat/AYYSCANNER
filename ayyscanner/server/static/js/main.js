// AYYSCANNER web UI: routing, Home, scan progress, history, Settings.
import { $, $$, api, ApiError, fmtDuration, fmtEpoch, h, KIND_LABEL, scoreBand, send, show, store, STORE } from "./util.js";
import { renderResults } from "./results.js";

const WEB_STEPS = ["Connect to the target", "Check headers, cookies & TLS", "Analyze page content", "Check well-known files", "SEO checks", "Check links", "Calculate score"];
const WEB_STAGE = { connecting: 0, parsing: 0, headers: 1, cors: 1, content: 2, probes: 3, seo: 4, links: 5, finalizing: 6, done: 7 };
const SYSTEM_STEPS = ["Operating system", "Open network ports", "Sensitive file permissions", "SSH server settings", "Firewall", "Calculate score"];
const PROJECT_STEPS = ["Read dependency files", "Check packages against OSV.dev", "Read vulnerability details", "Calculate score"];
const PROJECT_STAGE = { manifests: 0, osv: 1, details: 2, score: 3, done: 4 };
const STEPS = { web: WEB_STEPS, system: SYSTEM_STEPS, project: PROJECT_STEPS };
const stepIndex = (kind, stage) => {
  if (stage === "done") return STEPS[kind].length;
  if (kind === "web") return WEB_STAGE[stage] ?? 0;
  if (kind === "project") return PROJECT_STAGE[stage] ?? 0;
  const m = /^system(\d+)$/.exec(stage || "");
  return m ? Number(m[1]) : 0;
};
const PROGRESS_TITLE = { web: "Scanning website", system: "Scanning this computer", project: "Scanning project dependencies" };

const OPTION_FIELDS = [
  { group: "Requests" },
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

const state = { config: null, settings: null, view: null, watch: null, poll: null, history: [], showAllHistory: false };
const TAB_ID = (crypto.randomUUID ? crypto.randomUUID() : String(Math.random()).slice(2) + Date.now()).slice(0, 36);

// ------------------------------------------------------------------ theme and size
function applyTheme(choice) {
  if (choice === "light" || choice === "dark") document.documentElement.dataset.theme = choice;
  else delete document.documentElement.dataset.theme;
  store.set(STORE.theme, choice);
  $$("[data-theme-choice]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.themeChoice === choice)));
}
function applyScale(pct) {
  document.documentElement.style.setProperty("--ui-zoom", String(pct / 100));
  store.set(STORE.scale, String(pct));
  $("#scale-out").textContent = `${pct}%`;
}

// ------------------------------------------------------------------ routing
const VIEWS = ["home", "scan", "settings", "help"];
function showView(name) {
  state.view = name;
  VIEWS.forEach((v) => show($(`#view-${v}`), v === name));
  $$("[data-nav]").forEach((a) => { if (a.dataset.nav === name) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current"); });
  $("#home-btn").setAttribute("aria-current", name === "home" ? "page" : "false");
  document.title = { home: "AYYSCANNER - Security scanner", scan: "Scan - AYYSCANNER", settings: "Settings - AYYSCANNER", help: "Help - AYYSCANNER" }[name];
}
function stopWatching() { clearTimeout(state.poll); state.watch = null; }

async function route() {
  if (!state.config) return;
  const hash = location.hash.replace(/^#\/?/, "");
  const [page, arg] = hash.split("/");
  stopWatching();
  if (page === "settings") { showView("settings"); window.scrollTo(0, 0); return; }
  if (page === "help") { showView("help"); window.scrollTo(0, 0); return; }
  if (page === "scan" && arg) { showView("scan"); return openScan(decodeURIComponent(arg)); }
  showView("home");
  await loadHistory();
}
const go = (hash) => { if (location.hash === hash) route(); else location.hash = hash; };
function goHome() {
  if (state.view === "home") { window.scrollTo({ top: 0, behavior: "smooth" }); $("#quick-target").focus(); return; }
  go("#/");
}

// ------------------------------------------------------------------ confirm dialog
function confirmDialog({ title, text, target, ok }) {
  const dlg = $("#confirm-dialog");
  $("#confirm-title").textContent = title;
  $("#confirm-text").textContent = text;
  $("#confirm-target").textContent = target || "";
  show($("#confirm-target"), Boolean(target));
  $("#confirm-ok").textContent = ok;
  return new Promise((resolve) => {
    const done = (value) => { dlg.removeEventListener("cancel", onCancel); dlg.close(); resolve(value); };
    const onCancel = (e) => { e.preventDefault(); done(false); };
    $("#confirm-ok").onclick = () => done(true);
    $("#confirm-cancel").onclick = () => done(false);
    dlg.addEventListener("cancel", onCancel);
    if (typeof dlg.showModal === "function") dlg.showModal(); else resolve(window.confirm(`${title}\n\n${text}\n${target || ""}`));
    $("#confirm-cancel").focus();
  });
}
const CONFIRM = {
  web: (target) => ({ title: "Confirm you are allowed to scan this", text: "AYYSCANNER will send real requests to this target. Only continue if you own it or have explicit permission to test it.", target, ok: "I am authorized: start scan" }),
  system: () => ({ title: "Scan this computer?", text: "AYYSCANNER will read security settings on this computer: network ports, file permissions, SSH settings and firewall presence. It changes nothing and sends nothing anywhere.", target: "", ok: "Start system scan" }),
  project: (target) => ({ title: "Scan this project's dependencies?", text: "AYYSCANNER will read the dependency files in this folder and send package names and versions (never your code) to OSV.dev to look for known vulnerabilities.", target, ok: "Start project scan" }),
};

// ------------------------------------------------------------------ Home: scan forms
function setError(sel, message) { const el = $(sel); el.textContent = message || ""; show(el, Boolean(message)); }

function buildOptionsForm() {
  const grid = $("#options-grid");
  grid.replaceChildren(h("p", { class: "field-error", id: "options-error", role: "alert", hidden: true }));
  const saved = (() => { try { return JSON.parse(store.get(STORE.options) || "{}"); } catch { return {}; } })();
  const values = { ...state.config.defaults, ...saved };
  for (const f of OPTION_FIELDS) {
    if (f.group) { grid.append(h("div", { class: "options-group", text: f.group })); continue; }
    const id = `opt-${f.key}`, limit = state.config.limits[f.key];
    if (f.type === "checkbox") {
      grid.append(h("label", { class: "check", for: id }, h("input", { type: "checkbox", id, "data-option": f.key, checked: values[f.key] ? true : null }), h("span", { text: f.label })));
    } else {
      const input = h("input", { type: f.type, id, "data-option": f.key, autocomplete: "off", ...(f.type === "number" ? { min: limit.min, max: limit.max, step: f.step } : { maxlength: 200 }) });
      input.value = values[f.key];
      grid.append(h("div", {}, h("label", { for: id, text: f.label || limit.label }), input,
        limit ? h("small", { text: `${limit.min} to ${limit.max}` }) : f.help ? h("small", { text: f.help }) : null));
    }
  }
}
function readOptions() {
  const out = {};
  for (const el of $$("[data-option]")) {
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
    if (!(k in opts)) continue;
    const v = opts[k];
    if (typeof v !== "number" || Number.isNaN(v) || v < lim.min || v > lim.max) problems[k] = `${lim.label} must be between ${lim.min} and ${lim.max}.`;
  }
  if (!opts.user_agent || !opts.user_agent.trim()) problems.user_agent = "User agent must not be empty.";
  return problems;
}
function showOptionErrors(problems) {
  const box = $("#options-error"), msgs = Object.values(problems);
  box.textContent = msgs.join(" ");
  show(box, msgs.length > 0);
  $$("[data-option]").forEach((el) => el.setAttribute("aria-invalid", String(el.dataset.option in problems)));
  if (msgs.length) $("#options").open = true;
}

function setBusy(busy) {
  $$("#scan-cards button.primary, #quick-form button").forEach((b) => { b.disabled = busy; });
}

async function startScan(payload, errorTarget) {
  setBusy(true);
  try {
    const job = await send("POST", "/api/scans", { ...payload, authorized: true });
    go(`#/scan/${encodeURIComponent(job.id)}`);
  } catch (err) {
    if (err.code === "invalid_options") showOptionErrors(err.fields);
    else if (err.code === "invalid_url" && errorTarget) setError(errorTarget, `Invalid URL. ${err.message}`);
    else if (errorTarget) setError(errorTarget, err.message);
    else showFailure(err.code === "busy" ? "Too many scans are running" : "The scan could not be started", err.message, err.message);
  } finally { setBusy(false); }
}

async function onWebSubmit(event) {
  event.preventDefault();
  setError("#target-error", "");
  const url = $("#target").value.trim();
  const opts = readOptions(), problems = validateOptions(opts);
  showOptionErrors(problems);
  if (!url) { setError("#target-error", "Enter a website address, for example https://example.com"); $("#target").setAttribute("aria-invalid", "true"); $("#target").focus(); return; }
  if (Object.keys(problems).length) return;
  $("#target").setAttribute("aria-invalid", "false");
  if (!(await confirmDialog(CONFIRM.web(url)))) return;
  store.set(STORE.target, url);
  store.set(STORE.options, JSON.stringify(opts));
  await startScan({ kind: "web", url, options: { ...opts, timeout: state.settings.request_timeout } }, "#target-error");
}
async function onQuickSubmit(event) {
  event.preventDefault();
  setError("#quick-error", "");
  const url = $("#quick-target").value.trim();
  if (!url) { setError("#quick-error", "Enter a website address, for example example.com"); $("#quick-target").focus(); return; }
  if (!(await confirmDialog(CONFIRM.web(url)))) return;
  // Defaults for everything except link checking, so it is quick; request timeout comes from Settings.
  await startScan({ kind: "web", url, options: { check_internal_links: false, check_external_links: false, timeout: state.settings.request_timeout } }, "#quick-error");
}
async function onSystemClick() {
  if (!(await confirmDialog(CONFIRM.system()))) return;
  await startScan({ kind: "system" });
}
async function onProjectSubmit(event) {
  event.preventDefault();
  setError("#project-error", "");
  const directory = $("#project-dir").value.trim();
  if (!directory) { setError("#project-error", "Enter the folder of the project you want to scan."); $("#project-dir").focus(); return; }
  if (!(await confirmDialog(CONFIRM.project(directory)))) return;
  store.set(STORE.project, directory);
  await startScan({ kind: "project", directory }, "#project-error");
}

// ------------------------------------------------------------------ Home: history
const STATE_LABEL = { queued: "Queued", running: "Running", done: "Completed", failed: "Failed", cancelled: "Stopped" };
async function loadHistory() {
  let data;
  try { data = await api("/api/scans"); } catch { return; }
  state.history = data.scans;
  renderHistory(data.saved);
  const running = data.scans.find((s) => s.state === "queued" || s.state === "running");
  show($("#active-banner"), Boolean(running));
  if (running) { $("#active-target").textContent = running.target; $("#active-link").setAttribute("href", `#/scan/${encodeURIComponent(running.id)}`); }
}
function renderHistory(saved) {
  const rows = state.history;
  show($("#recent-panel"), rows.length > 0);
  $("#recent-note").textContent = saved ? "Saved on this computer" : "Not saved to disk";
  const visible = state.showAllHistory ? rows : rows.slice(0, 8);
  $("#recent-list").replaceChildren(...visible.map((s) => {
    const active = s.state === "queued" || s.state === "running";
    const when = s.finished || s.created;
    const stateBits = [STATE_LABEL[s.state] || s.state];
    if (!active && s.outcome === "partial") stateBits.push("partial");
    return h("li", {},
      h("div", { class: "what" },
        h("span", { class: "mono target", text: s.target }),
        h("span", { class: "when" }, h("span", { class: "chip kind", text: KIND_LABEL[s.kind] || s.kind }), ` ${fmtEpoch(when)} · ${stateBits.join(", ")}`)),
      h("div", { class: "numbers" },
        typeof s.score === "number" ? h("span", { class: `score-badge score-${scoreBand(s.score)}`, title: "Security score", text: `${s.score}/100` })
          : h("span", { class: "score-badge score-unrated", title: "Not rated", text: active ? `${s.percent}%` : "–" }),
        h("span", { class: "found", text: s.findings === null || s.findings === undefined ? "" : `${s.findings} finding${s.findings === 1 ? "" : "s"}` })),
      h("div", { class: "row-actions" },
        h("a", { class: "btn secondary", href: `#/scan/${encodeURIComponent(s.id)}`, text: active ? "View progress" : "Open" }),
        active ? null : h("button", { type: "button", class: "btn link danger", "aria-label": `Delete scan of ${s.target}`, text: "Delete", onclick: () => deleteScan(s) })));
  }));
  show($("#recent-more"), rows.length > 8);
  $("#recent-more").textContent = state.showAllHistory ? "Show fewer" : `Show all (${rows.length})`;
}
async function deleteScan(s) {
  if (!(await confirmDialog({ title: "Delete this scan?", text: "It will be removed from your history on this computer. This cannot be undone.", target: s.target, ok: "Delete" }))) return;
  try { await send("DELETE", `/api/scans/${encodeURIComponent(s.id)}`); } catch (err) { alert(err.message); }
  loadHistory();
}
async function clearHistory() {
  if (!(await confirmDialog({ title: "Clear scan history?", text: "Every finished scan will be removed from this computer. Running scans are not affected. This cannot be undone.", target: "", ok: "Clear history" }))) return false;
  try { await send("DELETE", "/api/scans"); } catch (err) { alert(err.message); return false; }
  await loadHistory();
  return true;
}

// ------------------------------------------------------------------ scan view: progress, errors, results
function showScanPanels({ progress = false, error = false, results = false }) {
  show($("#progress-panel"), progress); show($("#error-panel"), error); show($("#results"), results);
}
function renderSteps(kind, current) {
  $("#steps").replaceChildren(...STEPS[kind].map((label, i) =>
    h("li", { "data-state": i < current ? "done" : i === current ? "current" : "pending", "aria-current": i === current ? "step" : null, text: label })));
}
function showFailure(title, message, details) {
  stopWatching();
  showView("scan");
  $("#error-title").textContent = title;
  $("#error-message").textContent = message || "";
  $("#error-details").textContent = details || "";
  show($("#error-tech"), Boolean(details));
  showScanPanels({ error: true });
  window.scrollTo({ top: 0 });
}
function failureFromJob(job) {
  const info = job.error_info;
  if (info) return showFailure(info.title, info.message, info.details);
  showFailure("The scan could not be completed", job.error || "The scan failed.", job.error || "");
}

async function openScan(id) {
  const token = {};
  state.watch = { id, token };
  let job;
  try { job = await api(`/api/scans/${encodeURIComponent(id)}`); }
  catch (err) {
    if (state.watch && state.watch.token !== token) return;
    return showFailure(err.code === "not_found" ? "That scan is no longer available" : "Could not open the scan", err.code === "not_found" ? "It may have been deleted, or its history was turned off. Start a new scan from Home." : err.message, err.message);
  }
  if (!state.watch || state.watch.token !== token) return;
  applyJob(job, token);
}
function applyJob(job, token) {
  if (!state.watch || state.watch.token !== token) return;
  const kind = job.kind || "web";
  if (job.state === "queued" || job.state === "running") {
    const p = job.progress;
    $("#progress-title").textContent = PROGRESS_TITLE[kind];
    $("#progress-target").textContent = job.target;
    $("#progress-bar").value = p.percent;
    $("#progress-message").textContent = p.message || "Starting …";
    $("#progress-elapsed").textContent = p.elapsed_seconds ? `· ${fmtDuration(p.elapsed_seconds)}` : "";
    $("#cancel-btn").disabled = false;
    renderSteps(kind, stepIndex(kind, p.stage));
    showScanPanels({ progress: true });
    clearTimeout(state.poll);
    state.poll = setTimeout(() => pollJob(job.id, token, 0), p.elapsed_seconds > 30 ? 1500 : 700);
    return;
  }
  if (job.state === "failed" && !job.result) return failureFromJob(job);
  if (job.state === "failed") return failureFromJob(job);
  showScanPanels({ results: true });
  renderResults($("#results"), job, { settings: state.settings, config: state.config, onNewScan: () => { go("#/"); setTimeout(() => $("#quick-target").focus(), 50); } });
  window.scrollTo({ top: 0 });
}
async function pollJob(id, token, failures) {
  if (!state.watch || state.watch.token !== token) return;
  let job;
  try { job = await api(`/api/scans/${encodeURIComponent(id)}`); }
  catch (err) {
    if (err.code === "not_found") return showFailure("This scan is no longer available", "The server may have been restarted. Start a new scan.", err.message);
    if (failures >= 3) return showFailure("Lost connection to AYYSCANNER", "The program may have been stopped. Start it again and reload this page.", err.message);
    state.poll = setTimeout(() => pollJob(id, token, failures + 1), 1000);
    return;
  }
  applyJob(job, token);
}
async function cancelScan() {
  if (!state.watch) return;
  $("#cancel-btn").disabled = true;
  $("#progress-message").textContent = "Stopping …";
  try { await send("POST", `/api/scans/${encodeURIComponent(state.watch.id)}/cancel`); }
  catch (err) { $("#progress-message").textContent = err.message; $("#cancel-btn").disabled = false; }
}

// ------------------------------------------------------------------ Settings
let saveTimer = null;
function fillSettings() {
  const s = state.settings;
  $$("[data-setting]").forEach((el) => {
    const v = s[el.dataset.setting];
    if (el.type === "checkbox") el.checked = Boolean(v); else el.value = v;
  });
  applyTheme(s.theme);
  $("#scale-out").textContent = `${s.ui_scale}%`;
  const dir = state.config.data_dir;
  $("#data-location").textContent = dir ? `Scan history and these settings are stored in: ${dir}` : "Nothing is written to disk (disabled with AYYSCANNER_DATA_DIR=off). Settings last until AYYSCANNER stops.";
}
function flashStatus(text, isError) {
  const el = $("#save-status");
  el.textContent = text;
  el.className = `save-status${isError ? " bad" : ""}`;
  if (!isError) setTimeout(() => { if (el.textContent === text) el.textContent = ""; }, 2200);
}
async function saveSettings(patch) {
  clearTimeout(saveTimer);
  setError("#settings-error", "");
  try {
    const res = await send("PUT", "/api/settings", patch);
    state.settings = res.settings;
    flashStatus("Saved ✓");
  } catch (err) {
    setError("#settings-error", err.message);
    flashStatus("Not saved", true);
    fillSettings();  // show the real, still-saved values again
  }
}
function wireSettings() {
  $$("[data-setting]").forEach((el) => {
    const key = el.dataset.setting;
    const read = () => (el.type === "checkbox" ? el.checked : el.type === "number" || el.type === "range" ? Number(el.value) : el.value);
    el.addEventListener("input", () => {
      if (key === "ui_scale") applyScale(Number(el.value));
      if (el.type === "number" || el.type === "range") { clearTimeout(saveTimer); saveTimer = setTimeout(() => saveSettings({ [key]: read() }), 500); }
    });
    el.addEventListener("change", () => saveSettings({ [key]: read() }));
  });
  $$("[data-theme-choice]").forEach((b) => b.addEventListener("click", () => { applyTheme(b.dataset.themeChoice); saveSettings({ theme: b.dataset.themeChoice }); }));
  $("#reset-settings-btn").addEventListener("click", async () => {
    try {
      state.settings = (await send("POST", "/api/settings/reset")).settings;
      fillSettings(); applyScale(state.settings.ui_scale); flashStatus("Settings reset ✓");
    } catch (err) { setError("#settings-error", err.message); }
  });
  $("#clear-history-btn").addEventListener("click", async () => { if (await clearHistory()) $("#data-status").textContent = "Scan history cleared."; });
  $("#shortcut-btn").addEventListener("click", async () => {
    $("#data-status").textContent = "Creating the shortcut …";
    try { $("#data-status").textContent = (await send("POST", "/api/shortcut")).message; }
    catch (err) { $("#data-status").textContent = err.message; }
  });
}

// ------------------------------------------------------------------ start-up
const ping = () => send("POST", "/api/ui/ping", { tab: TAB_ID }).catch(() => {});

async function init() {
  $("#home-btn").addEventListener("click", goHome);
  $("#brand").addEventListener("click", (e) => { e.preventDefault(); goHome(); });
  $("#web-form").addEventListener("submit", onWebSubmit);
  $("#quick-form").addEventListener("submit", onQuickSubmit);
  $("#project-form").addEventListener("submit", onProjectSubmit);
  $("#system-btn").addEventListener("click", onSystemClick);
  $("#cancel-btn").addEventListener("click", cancelScan);
  $("#error-dismiss").addEventListener("click", () => go("#/"));
  $("#recent-more").addEventListener("click", () => { state.showAllHistory = !state.showAllHistory; renderHistory(true); });
  $("#recent-clear").addEventListener("click", clearHistory);
  $("#target").addEventListener("input", () => { setError("#target-error", ""); $("#target").setAttribute("aria-invalid", "false"); saveDraft(); });
  $("#quick-target").addEventListener("input", () => setError("#quick-error", ""));
  $("#project-dir").addEventListener("input", () => { setError("#project-error", ""); saveDraft(); });
  $("#options-grid").addEventListener("input", saveDraft);
  $("#options-grid").addEventListener("change", saveDraft);
  $("#target").value = store.get(STORE.target) || "";
  $("#project-dir").value = store.get(STORE.project) || "";
  window.addEventListener("hashchange", route);
  window.addEventListener("pagehide", () => {
    saveDraft();
    try { navigator.sendBeacon("/api/ui/closed", new Blob([JSON.stringify({ tab: TAB_ID })], { type: "application/json" })); } catch { /* best effort */ }
  });
  document.addEventListener("click", (e) => { $$("details.menu[open]").forEach((m) => { if (!m.contains(e.target)) m.open = false; }); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") $$("details.menu[open]").forEach((m) => { m.open = false; }); });
  wireSettings();

  try { state.config = await api("/api/config"); }
  catch (err) { showView("scan"); return showFailure("Could not load AYYSCANNER", err.message, err.message); }
  state.settings = state.config.settings;
  fillSettings(); applyScale(state.settings.ui_scale);
  $("#version").textContent = `v${state.config.version}`;
  $("#about-version").textContent = `Version ${state.config.version}`;
  buildOptionsForm();
  $("#options-reset").addEventListener("click", () => { store.set(STORE.options, "{}"); buildOptionsForm(); });
  ping(); setInterval(ping, 5000);
  route();
}
function saveDraft() {
  store.set(STORE.target, $("#target").value.trim());
  store.set(STORE.project, $("#project-dir").value.trim());
  if (!state.config) return;
  const opts = readOptions();
  if (!Object.keys(validateOptions(opts)).length) store.set(STORE.options, JSON.stringify(opts));
}
init();
