// Small helpers shared by every page of the UI.
// Security note: every piece of scanned-site content (titles, headers, URLs, evidence) is inserted with
// textContent / createTextNode only, never innerHTML, and links are created only for http(s) URLs.

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

export function h(tag, props, ...kids) {
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

const SVGNS = "http://www.w3.org/2000/svg";
export function svgEl(tag, attrs, text) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  if (text !== undefined) el.textContent = text;
  return el;
}

export const slug = (s) => s.toLowerCase().replace(/\s+/g, "-");
export const safeUrl = (u) => (typeof u === "string" && /^https?:\/\/[^\s]+$/i.test(u) ? u : null);
export const show = (el, visible) => { el.hidden = !visible; };

export const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* storage unavailable */ } },
};
export const STORE = { theme: "ayyscanner.theme", scale: "ayyscanner.scale", options: "ayyscanner.options", target: "ayyscanner.target", project: "ayyscanner.project" };

export function fmtDuration(s) {
  if (s === null || s === undefined) return "-";
  if (s < 60) return `${s.toFixed(1)} s`;
  return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;
}
export function fmtDate(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "-" : d.toLocaleString();
}
export const fmtEpoch = (seconds) => fmtDate(new Date(seconds * 1000).toISOString());

export const KIND_LABEL = { web: "Website", system: "System", project: "Project" };
export const scoreBand = (n) => (n >= 90 ? "excellent" : n >= 75 ? "good" : n >= 50 ? "fair" : n >= 25 ? "poor" : "critical");

export class ApiError extends Error {
  constructor(message, code, fields) { super(message); this.code = code; this.fields = fields || {}; }
}
export async function api(path, options) {
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
export const send = (method, path, body) => api(path, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body ?? {}) });

// Copy text to the clipboard; falls back to a hidden textarea where the async API is unavailable.
export async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(text); return true; }
  } catch { /* fall through */ }
  const ta = h("textarea", { "aria-hidden": "true", tabindex: "-1" });
  ta.value = text;
  ta.className = "offscreen";
  document.body.append(ta);
  ta.select();
  let ok = false;
  try { ok = document.execCommand("copy"); } catch { ok = false; }
  ta.remove();
  return ok;
}
// A button that copies text and says so.
export function copyButton(label, getText, cls = "btn secondary") {
  const btn = h("button", { type: "button", class: cls, text: label });
  let timer = null;
  btn.addEventListener("click", async (e) => {
    e.preventDefault(); e.stopPropagation();
    const ok = await copyText(getText());
    btn.textContent = ok ? "Copied ✓" : "Copy failed";
    clearTimeout(timer);
    timer = setTimeout(() => { btn.textContent = label; }, 1800);
  });
  return btn;
}
