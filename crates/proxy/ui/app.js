// The web UI: a live flow list, client-side filtering and a detail pane.
//
// Security rules (see docs/ui.md): flow data is attacker-controlled, so this file builds
// the DOM with createElement and textContent only. No HTML strings, no eval, no inline
// handlers; the control plane's CSP forbids them anyway.
"use strict";

// ---------------------------------------------------------------------------
// Token and API

const TOKEN_KEY = "token";
const fragment = new URLSearchParams(location.hash.slice(1));
let token = readToken();

/**
 * Reads the token from the URL fragment once, then from sessionStorage (this origin only).
 * The fragment may also carry `flow=ID`, `tab=NAME` and `q=FILTER`.
 */
function readToken() {
  if (location.hash) history.replaceState(null, "", location.pathname + location.search);
  const given = fragment.get("token");
  if (given && /^[0-9a-f]{32}$/.test(given)) {
    store(TOKEN_KEY, given);
    return given;
  }
  return load(TOKEN_KEY);
}

function store(key, value) {
  try { sessionStorage.setItem(key, value); } catch (_) { /* private mode: memory only */ }
}

function load(key) {
  try { return sessionStorage.getItem(key); } catch (_) { return null; }
}

function api(path, init) {
  const options = Object.assign({}, init);
  options.headers = Object.assign({ Authorization: "Bearer " + token }, options.headers);
  options.cache = "no-store";
  return fetch("/api/v1/" + path, options);
}

/** Reads a JSON answer; a non-2xx answer throws its `error` text (the server's message). */
async function apiJson(path, init) {
  const response = await api(path, init);
  let body = null;
  try { body = await response.json(); } catch (_) { /* not JSON */ }
  if (!response.ok) throw new Error((body && body.error) || "HTTP " + response.status);
  return body;
}

/** Server-side search with the query language (`GET /api/v1/flows?q=`). */
function serverQuery(q) {
  return apiJson("flows?q=" + encodeURIComponent(q));
}

/** Extension points for panels.js: pause events, (re)loads, the shown flow. */
const hooks = { pause: [], load: [], detail: [] };

// ---------------------------------------------------------------------------
// State

const ROW_H = 24;
const OVERSCAN = 8;
const SLOW_MS = 1000;

const flows = new Map();     // id -> row model
let view = [];               // filtered and sorted row models
let selectedId = null;
let clearedBelow = 0;        // client-side clear: ids at or below this are hidden
let follow = true;
let sort = { key: "id", dir: 1 };
let query = { tokens: [], text: [] };
const chips = new Set();
let tab = "overview";
let dirty = false;

const $ = (id) => document.getElementById(id);
const el = {
  search: $("search"), viewport: $("viewport"), spacer: $("spacer"), empty: $("empty"),
  count: $("count"), conn: $("conn"), follow: $("follow"), clear: $("clear"),
  panel: $("panel"), head: $("grid-head"), splitter: $("splitter"), toast: $("toast"),
  copyCurl: $("copy-curl"), copyUrl: $("copy-url"),
};

/** Element helper: tag, class, text, children. Never parses HTML. */
function h(tag, cls, text, children) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (children) for (const child of children) if (child) node.append(child);
  return node;
}

// ---------------------------------------------------------------------------
// Row model

function header(headers, name) {
  if (!headers) return "";
  const lower = name.toLowerCase();
  for (const [k, v] of headers) if (k.toLowerCase() === lower) return v;
  return "";
}

function clock(time) {
  const d = new Date(time);
  if (Number.isNaN(d.getTime())) return String(time).slice(11, 19);
  const p = (n, w) => String(n).padStart(w || 2, "0");
  return p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds()) + "." + p(d.getMilliseconds(), 3);
}

function splitUrl(url) {
  try {
    const u = new URL(url);
    return { host: u.host, path: u.pathname + u.search };
  } catch (_) {
    return { host: "", path: url };
  }
}

/** Broad content type from a Content-Type header: json, html, image, ... */
function kindOf(contentType) {
  const t = contentType.toLowerCase().split(";")[0].trim();
  if (!t) return "";
  if (t.includes("json")) return "json";
  if (t === "text/html" || t === "application/xhtml+xml") return "html";
  if (t.startsWith("image/")) return "image";
  if (t === "text/css") return "css";
  if (t.includes("javascript") || t.includes("ecmascript")) return "js";
  if (t.includes("xml")) return "xml";
  if (t === "application/x-www-form-urlencoded") return "form";
  if (t.startsWith("font/") || t.includes("font")) return "font";
  if (t.startsWith("video/") || t.startsWith("audio/")) return "media";
  if (t.startsWith("text/")) return "text";
  return "binary";
}

/** Normalises a stored flow (`{state, flow}`) or an SSE payload into a row model. */
function model(state, f) {
  const m = { id: f.id, state, raw: f, search: null };
  m.rules = (f.flags || []).filter((x) => x.startsWith("rule:")).map((x) => x.slice(5));
  m.time = clock(f.time);
  m.timeSort = f.time;
  if (state === "pending" || f.type === "exchange") {
    const parts = splitUrl(f.url);
    m.kind = "exchange";
    m.method = f.method;
    m.url = f.url;
    m.host = parts.host;
    m.path = parts.path;
    m.proto = f.client_version || "";
    m.client = f.tls && f.tls.client ? f.tls.client : "";
    m.status = f.status == null ? null : f.status;
    m.error = f.error || null;
    m.size = f.response_body ? f.response_body.size : null;
    m.duration = f.timing ? f.timing.total_ms : null;
    m.type = kindOf(header(f.response_headers, "content-type"));
  } else if (f.type === "tls_failure") {
    m.kind = "tls_failure";
    m.method = "TLS";
    m.host = f.sni || f.target;
    m.path = "handshake failed: " + f.reason;
    m.url = f.target;
    m.proto = "";
    m.client = f.known_client || "";
    m.status = null;
    m.error = f.reason;
    m.size = null;
    m.duration = null;
    m.type = "";
  } else {
    m.kind = "tunnel";
    m.method = "TUNNEL";
    m.host = f.target;
    m.path = "not TLS, passed through";
    m.url = f.target;
    m.proto = "tcp";
    m.client = "";
    m.status = null;
    m.error = f.error || null;
    m.size = f.bytes_down;
    m.duration = null;
    m.type = "";
  }
  return m;
}

function searchText(m) {
  if (m.search === null) {
    const f = m.raw;
    const parts = [m.url || "", m.host || "", m.error || ""];
    for (const list of [f.request_headers, f.response_headers]) {
      if (list) for (const [k, v] of list) parts.push(k + ": " + v);
    }
    m.search = parts.join("\n").toLowerCase();
  }
  return m.search;
}

function upsert(state, f) {
  if (f.id <= clearedBelow) return;
  const old = flows.get(f.id);
  if (old && old.state === "done" && state === "pending") return;
  flows.set(f.id, model(state, f));
  if (serverIds) requery();
  markDirty();
}

// ---------------------------------------------------------------------------
// Filtering

const FILTER_KEYS = new Set(["host", "method", "status", "type"]);

function parseQuery(text) {
  const tokens = [];
  const free = [];
  for (const word of text.trim().split(/\s+/)) {
    if (!word) continue;
    const i = word.indexOf(":");
    const key = i > 0 ? word.slice(0, i).toLowerCase() : "";
    if (FILTER_KEYS.has(key) && i < word.length - 1) {
      tokens.push({ key, value: word.slice(i + 1).toLowerCase() });
    } else {
      free.push(word.toLowerCase());
    }
  }
  return { tokens, text: free };
}

function statusMatches(m, value) {
  if (/^[1-5]xx$/.test(value)) return m.status != null && Math.floor(m.status / 100) === Number(value[0]);
  if (value === "err" || value === "error") return isError(m);
  if (value === "pending") return m.state === "pending";
  return m.status != null && String(m.status) === value;
}

function isError(m) {
  return m.kind === "tls_failure" || m.error != null || (m.status != null && m.status >= 400);
}

function matches(m) {
  if (serverIds) {
    if (!serverIds.has(m.id)) return false;
  } else {
    for (const t of query.tokens) {
      if (t.key === "host" && !(m.host || "").toLowerCase().includes(t.value)) return false;
      if (t.key === "method" && (m.method || "").toLowerCase() !== t.value) return false;
      if (t.key === "status" && !statusMatches(m, t.value)) return false;
      if (t.key === "type" && m.type !== t.value) return false;
    }
  }
  if (!serverIds && query.text.length) {
    const hay = searchText(m);
    for (const word of query.text) if (!hay.includes(word)) return false;
  }
  if (chips.has("errors") && !isError(m)) return false;
  if (chips.has("slow") && !(m.duration != null && m.duration >= SLOW_MS)) return false;
  if (chips.has("json") && m.type !== "json") return false;
  if (chips.has("images") && m.type !== "image") return false;
  if (chips.has("tls") && m.kind !== "tls_failure") return false;
  return true;
}

function compare(a, b) {
  const key = sort.key === "time" ? "timeSort" : sort.key;
  const x = a[key];
  const y = b[key];
  let c;
  if (x == null && y == null) c = 0;
  else if (x == null) c = 1;
  else if (y == null) c = -1;
  else if (typeof x === "number" && typeof y === "number") c = x - y;
  else c = String(x).localeCompare(String(y));
  return (c || a.id - b.id) * sort.dir;
}

function rebuild() {
  view = [];
  for (const m of flows.values()) if (matches(m)) view.push(m);
  view.sort(compare);
  el.spacer.style.height = view.length * ROW_H + "px";
  el.viewport.setAttribute("aria-rowcount", String(view.length));
  el.empty.hidden = view.length > 0;
  el.empty.textContent = flows.size ? "No flows match the filter." : "No flows yet. Send traffic through the proxy.";
  el.count.textContent = view.length === flows.size ? flows.size + " flows" : view.length + " of " + flows.size;
  if (follow && view.length) el.viewport.scrollTop = el.viewport.scrollHeight;
  renderRows(true);
  if (selectedId !== null) {
    const m = flows.get(selectedId);
    if (m && m.raw !== shownRaw) renderDetail();
  }
}

function markDirty() {
  if (dirty) return;
  dirty = true;
  requestAnimationFrame(() => {
    dirty = false;
    rebuild();
  });
}

// ---------------------------------------------------------------------------
// Virtualised list

const pool = [];
let lastRange = "";

function makeRow() {
  const row = h("div", "row");
  row.setAttribute("role", "row");
  row.cells = {};
  for (const c of ["id", "time", "method", "host", "path", "status", "proto", "size", "dur", "client"]) {
    const cell = h("span", "c-" + c);
    cell.setAttribute("role", "gridcell");
    row.cells[c] = cell;
    row.append(cell);
  }
  row.ruleBadges = h("span", "rule-badges");
  row.pathText = h("span");
  row.cells.path.append(row.ruleBadges, row.pathText);
  row.addEventListener("click", () => select(row.flowId, false));
  el.viewport.append(row);
  return row;
}

function fmtSize(n) {
  if (n == null) return "";
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / 1024 / 1024).toFixed(1) + " MB";
}

function fmtMs(ms) {
  if (ms == null) return "";
  return ms < 10 ? ms.toFixed(1) : String(Math.round(ms));
}

/** Status text and class: the number is the text alternative to the colour. */
function statusOf(m) {
  if (m.kind === "tls_failure") return ["TLS fail", "s-err"];
  if (m.kind === "tunnel") return [m.error ? "error" : "tunnel", m.error ? "s-err" : "s-pending"];
  if (m.status != null) return [String(m.status), "s-" + Math.floor(m.status / 100)];
  if (m.error) return ["error", "s-err"];
  return ["pending", "s-pending"];
}

function fillRow(row, m, index) {
  row.flowId = m.id;
  row.style.transform = "translateY(" + index * ROW_H + "px)";
  row.setAttribute("aria-rowindex", String(index + 1));
  row.setAttribute("aria-selected", String(m.id === selectedId));
  row.classList.toggle("odd", index % 2 === 1);
  row.classList.toggle("pending", m.state === "pending");
  row.classList.toggle("tls-fail", m.kind === "tls_failure");
  const c = row.cells;
  c.id.textContent = m.id;
  c.time.textContent = m.time;
  c.method.textContent = m.method;
  c.host.textContent = m.host;
  c.host.title = m.host;
  row.pathText.textContent = m.path;
  row.ruleBadges.replaceChildren(...m.rules.map((r) => h("span", "badge rule", r)));
  c.path.title = (m.rules.length ? "rules: " + m.rules.join(", ") + "\n" : "") + m.path;
  const [text, cls] = statusOf(m);
  c.status.textContent = text;
  c.status.className = "c-status " + cls;
  c.proto.textContent = m.proto;
  c.size.textContent = fmtSize(m.size);
  c.dur.textContent = fmtMs(m.duration);
  c.client.textContent = m.client;
  c.client.title = m.client;
}

function renderRows(force) {
  const top = el.viewport.scrollTop;
  const height = el.viewport.clientHeight;
  const first = Math.max(0, Math.floor(top / ROW_H) - OVERSCAN);
  const last = Math.min(view.length, Math.ceil((top + height) / ROW_H) + OVERSCAN);
  const range = first + ":" + last;
  if (!force && range === lastRange) return;
  lastRange = range;
  const needed = last - first;
  while (pool.length < needed) pool.push(makeRow());
  for (let i = 0; i < pool.length; i++) {
    const row = pool[i];
    if (i < needed) {
      row.hidden = false;
      fillRow(row, view[first + i], first + i);
    } else {
      row.hidden = true;
    }
  }
}

el.viewport.addEventListener("scroll", () => {
  const atBottom = el.viewport.scrollTop + el.viewport.clientHeight >= el.viewport.scrollHeight - ROW_H;
  setFollow(atBottom);
  renderRows(false);
}, { passive: true });
window.addEventListener("resize", () => renderRows(true));

function setFollow(on) {
  if (follow === on) return;
  follow = on;
  el.follow.setAttribute("aria-pressed", String(on));
}

el.follow.addEventListener("click", () => {
  setFollow(!follow);
  if (follow) el.viewport.scrollTop = el.viewport.scrollHeight;
});

el.clear.addEventListener("click", () => {
  for (const id of flows.keys()) clearedBelow = Math.max(clearedBelow, id);
  flows.clear();
  selectedId = null;
  shownRaw = null;
  renderDetail();
  rebuild();
});

el.head.addEventListener("click", (e) => {
  const button = e.target.closest("button[data-sort]");
  if (!button) return;
  const key = button.dataset.sort === "dur" ? "duration" : button.dataset.sort;
  sort = sort.key === key ? { key, dir: -sort.dir } : { key, dir: 1 };
  for (const b of el.head.querySelectorAll("button[data-sort]")) {
    const k = b.dataset.sort === "dur" ? "duration" : b.dataset.sort;
    if (k === sort.key) b.setAttribute("aria-sort", sort.dir > 0 ? "ascending" : "descending");
    else b.removeAttribute("aria-sort");
  }
  rebuild();
});

function select(id, scroll) {
  if (id == null) return;
  selectedId = id;
  renderRows(true);
  renderDetail();
  if (scroll) {
    const index = view.findIndex((m) => m.id === id);
    if (index >= 0) {
      const top = index * ROW_H;
      const vp = el.viewport;
      if (top < vp.scrollTop) vp.scrollTop = top;
      else if (top + ROW_H > vp.scrollTop + vp.clientHeight) vp.scrollTop = top + ROW_H - vp.clientHeight;
    }
  }
}

function move(delta) {
  if (!view.length) return;
  let index = view.findIndex((m) => m.id === selectedId);
  index = index < 0 ? (delta > 0 ? 0 : view.length - 1) : Math.min(view.length - 1, Math.max(0, index + delta));
  select(view[index].id, true);
}

// ---------------------------------------------------------------------------
// Search box and chips

// Plain words and the four simple tokens filter in the page; anything else in the query
// language goes to the server (debounced), which answers with the matching ids.

const FIELD_TOKEN = /(^|[\s(])-?(host|status|body|header|size|time|client|tls|flag|path|method|type):/i;

function needsServer(text) {
  return FIELD_TOKEN.test(text) || /[()]/.test(text) || /(^|\s)OR(\s|$)/.test(text) || /(^|\s)-\S/.test(text);
}

let searchTimer = 0;
let serverIds = null;   // ids from the last good server answer, or null when filtering here
let serverText = "";
let queryGen = 0;
let requeryTimer = 0;
const searchError = h("div", "search-error");
searchError.id = "search-error";
searchError.setAttribute("role", "alert");
searchError.hidden = true;
el.search.parentNode.append(searchError);

function setSearchError(text) {
  searchError.textContent = text;
  searchError.hidden = !text;
  el.search.setAttribute("aria-invalid", String(Boolean(text)));
}

function applySearch(text, delay) {
  clearTimeout(searchTimer);
  queryGen++;
  if (needsServer(text)) {
    searchTimer = setTimeout(() => runServerQuery(text), delay === undefined ? 250 : delay);
    return;
  }
  serverIds = null;
  serverText = "";
  setSearchError("");
  searchTimer = setTimeout(() => {
    query = parseQuery(text);
    rebuild();
  }, delay === undefined ? 80 : delay);
}

async function runServerQuery(text) {
  const gen = ++queryGen;
  try {
    const list = await serverQuery(text);
    if (gen !== queryGen) return;
    serverIds = new Set(list.map((item) => item.flow.id));
    serverText = text;
    query = parseQuery("");
    setSearchError("");
  } catch (e) {
    if (gen !== queryGen) return;
    // Keep the last good list on screen; the message carries the position.
    setSearchError(e.message);
  }
  rebuild();
}

/** New flows arrived while a server query is shown: ask again, at most once a second. */
function requery() {
  if (requeryTimer) return;
  requeryTimer = setTimeout(() => {
    requeryTimer = 0;
    if (serverIds && el.search.value === serverText) runServerQuery(serverText);
  }, 1000);
}

el.search.addEventListener("input", () => applySearch(el.search.value));

for (const chip of document.querySelectorAll(".chip")) {
  chip.addEventListener("click", () => {
    const name = chip.dataset.chip;
    if (chips.has(name)) chips.delete(name); else chips.add(name);
    chip.setAttribute("aria-pressed", String(chips.has(name)));
    rebuild();
  });
}

// ---------------------------------------------------------------------------
// Keyboard

document.addEventListener("keydown", (e) => {
  if (e.metaKey || e.ctrlKey || e.altKey) return;
  const target = e.target;
  const typing = target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement;
  if (e.key === "Escape") {
    if (target === el.search || !typing) {
      el.search.value = "";
      applySearch("", 0);
      for (const chip of document.querySelectorAll(".chip")) chip.setAttribute("aria-pressed", "false");
      chips.clear();
      rebuild();
      if (target === el.search) el.viewport.focus();
    }
    return;
  }
  if (typing) return;
  if (target === el.splitter && (e.key === "ArrowUp" || e.key === "ArrowDown")) return;
  switch (e.key) {
    case "/": e.preventDefault(); el.search.focus(); el.search.select(); break;
    case "j": case "ArrowDown": e.preventDefault(); move(1); break;
    case "k": case "ArrowUp": e.preventDefault(); move(-1); break;
    case "Home": if (target === el.viewport && view.length) { e.preventDefault(); select(view[0].id, true); } break;
    case "End": if (target === el.viewport && view.length) { e.preventDefault(); select(view[view.length - 1].id, true); } break;
    case "1": case "2": case "3": case "4": case "5": case "6": case "7": case "8": case "9": {
      const t = TABS[Number(e.key) - 1];
      if (t) setTab(t.id);
      break;
    }
    default: break;
  }
});

// ---------------------------------------------------------------------------
// Resizable split

const SPLIT_KEY = "detail-height";
function setDetailHeight(px) {
  const total = document.querySelector(".workspace").clientHeight;
  const clamped = Math.max(80, Math.min(total - 126, px));
  document.querySelector(".workspace").style.setProperty("--detail-h", clamped + "px");
  try { localStorage.setItem(SPLIT_KEY, String(clamped)); } catch (_) { /* optional */ }
  renderRows(true);
}
(() => {
  let saved = null;
  try { saved = Number(localStorage.getItem(SPLIT_KEY)); } catch (_) { /* optional */ }
  if (saved) document.querySelector(".workspace").style.setProperty("--detail-h", saved + "px");
})();
el.splitter.addEventListener("pointerdown", (e) => {
  e.preventDefault();
  el.splitter.setPointerCapture(e.pointerId);
  const bottom = document.querySelector(".workspace").getBoundingClientRect().bottom;
  const onMove = (ev) => setDetailHeight(bottom - ev.clientY);
  const onUp = () => {
    el.splitter.removeEventListener("pointermove", onMove);
    el.splitter.removeEventListener("pointerup", onUp);
  };
  el.splitter.addEventListener("pointermove", onMove);
  el.splitter.addEventListener("pointerup", onUp);
});
el.splitter.addEventListener("keydown", (e) => {
  if (e.key !== "ArrowUp" && e.key !== "ArrowDown") return;
  e.preventDefault();
  const current = $("detail").getBoundingClientRect().height;
  setDetailHeight(current + (e.key === "ArrowUp" ? 24 : -24));
});

// ---------------------------------------------------------------------------
// Detail pane

let shownRaw = null;

/**
 * Detail tabs, in key order (1-9). The four built-in buttons are in index.html; other
 * scripts add theirs with `registerTab({id, title, render(flow, container)})`.
 */
const TABS = [
  { id: "overview", own: (panel, m) => overview(panel, m) },
  { id: "tls", own: (panel, m) => clientTls(panel, m) },
  { id: "request", own: (panel, m) => requestTab(panel, m) },
  { id: "response", own: (panel, m) => responseTab(panel, m) },
];

for (const button of document.querySelectorAll("[role=tab]")) {
  button.addEventListener("click", () => setTab(button.dataset.tab));
}

/**
 * Adds a detail tab. `render(flow, container)` gets the raw flow record (as in
 * `GET /api/v1/flows/{id}`) and an empty element to fill with createElement/textContent.
 */
function registerTab(spec) {
  if (!spec || !/^[a-z][a-z0-9-]*$/.test(spec.id) || typeof spec.render !== "function") {
    throw new Error("registerTab needs {id, title, render(flow, container)}");
  }
  if (TABS.some((t) => t.id === spec.id)) return;
  const visible = typeof spec.visible === "function" ? spec.visible : null;
  TABS.push({ id: spec.id, render: spec.render, visible });
  const button = h("button", null, String(spec.title || spec.id));
  button.type = "button";
  button.id = "tab-" + spec.id;
  // A tab with a `visible(flow)` test stays hidden until a flow it applies to is selected.
  button.hidden = visible !== null;
  button.dataset.tab = spec.id;
  button.setAttribute("role", "tab");
  button.setAttribute("aria-selected", String(tab === spec.id));
  button.addEventListener("click", () => setTab(spec.id));
  document.querySelector("[role=tablist]").append(button);
  if (fragment.get("tab") === spec.id) setTab(spec.id);
}
window.registerTab = registerTab;

function setTab(name) {
  tab = name;
  for (const button of document.querySelectorAll("[role=tab]")) {
    button.setAttribute("aria-selected", String(button.dataset.tab === name));
  }
  $("panel").setAttribute("aria-labelledby", "tab-" + name);
  renderDetail();
}

/**
 * Shows the registered tabs that apply to the selected flow and hides the others. When the
 * tab on screen is one of the hidden ones, goes back to Overview.
 */
function syncTabVisibility(m) {
  for (const t of TABS) {
    if (!t.visible) continue;
    const button = document.getElementById("tab-" + t.id);
    if (!button) continue;
    let applies = false;
    try {
      applies = Boolean(m) && Boolean(t.visible(m.raw));
    } catch {
      applies = false;
    }
    button.hidden = !applies;
    // With no flow selected yet (a link such as #tab=messages&flow=1 while the list loads)
    // keep the requested tab; fall back only when a flow is shown and the tab does not fit it.
    if (!applies && m && tab === t.id) {
      tab = "overview";
      for (const other of document.querySelectorAll("[role=tab]")) {
        other.setAttribute("aria-selected", String(other.dataset.tab === tab));
      }
      $("panel").setAttribute("aria-labelledby", "tab-" + tab);
    }
  }
}

function renderDetail() {
  const m = selectedId === null ? null : flows.get(selectedId);
  shownRaw = m ? m.raw : null;
  syncTabVisibility(m);
  const panel = el.panel;
  const scroll = panel.scrollTop;
  const sameFlow = panel.dataset.flow === String(selectedId) && panel.dataset.tab === tab;
  panel.replaceChildren();
  panel.dataset.flow = String(selectedId);
  panel.dataset.tab = tab;
  el.copyCurl.disabled = !m || m.kind !== "exchange";
  el.copyUrl.disabled = !m;
  for (const fn of hooks.detail) fn(m);
  if (!m) {
    panel.append(h("p", "hint", "Select a flow. Keys: j / k or arrows move, / searches, Esc clears, 1-4 switch tabs."));
    return;
  }
  const spec = TABS.find((t) => t.id === tab) || TABS[0];
  if (spec.own) spec.own(panel, m);
  else {
    try { spec.render(m.raw, panel); } catch (e) { panel.append(h("div", "error-box", "Tab failed: " + e)); }
  }
  if (sameFlow) panel.scrollTop = scroll;
}

function kv(pairs) {
  const dl = h("dl", "kv");
  for (const [k, v, cls] of pairs) {
    if (v === null || v === undefined || v === "") continue;
    dl.append(h("dt", null, k));
    const dd = h("dd", cls || null);
    if (v instanceof Node) dd.append(v); else dd.textContent = String(v);
    dl.append(dd);
  }
  return dl;
}

const TLS_HINT = "The client does not trust the proxy CA, or it pins certificates. Install the CA " +
  "(open wirust.test through the proxy); an app that pins cannot be inspected.";

function overview(panel, m) {
  const f = m.raw;
  if (m.kind === "tls_failure") {
    panel.append(h("h3", null, "TLS handshake failed"));
    panel.append(h("div", "error-box", f.reason));
    panel.append(h("p", null, TLS_HINT));
    panel.append(kv([["Target", f.target, "mono"], ["SNI", f.sni, "mono"], ["Client", f.client, "mono"],
      ["Time", f.time], ["Known client", f.known_client], ["JA4", f.ja4, "mono"]]));
    return;
  }
  if (m.kind === "tunnel") {
    panel.append(h("h3", null, "Tunnel (not TLS, passed through without inspection)"));
    if (f.error) panel.append(h("div", "error-box", f.error));
    panel.append(kv([["Target", f.target, "mono"], ["Client", f.client, "mono"], ["Closed", f.time],
      ["Bytes up", fmtSize(f.bytes_up)], ["Bytes down", fmtSize(f.bytes_down)]]));
    return;
  }
  panel.append(h("h3", null, "Request"));
  panel.append(h("div", "url", (f.method || "") + " " + f.url));
  if (f.error) panel.append(h("div", "error-box", "Error: " + f.error));
  const status = f.status != null ? f.status + " " + (f.reason || "") : m.state === "pending" ? "in progress" : "";
  const flags = f.flags && f.flags.length
    ? h("span", null, null, f.flags.map((x) => h("span", x.startsWith("rule:") ? "badge rule" : "badge", x)))
    : null;
  panel.append(kv([
    ["Status", status],
    ["Time", f.time],
    ["Client", f.client, "mono"],
    ["Client leg", f.client_version],
    ["Server leg", f.upstream_version || (m.state === "pending" ? "" : "none")],
    ["Request body", f.request_body ? fmtSize(f.request_body.size) : null],
    ["Response body", f.response_body ? fmtSize(f.response_body.size) : null],
    ["Flags", flags],
  ]));
  if (f.timing) {
    panel.append(h("h3", null, "Timing"));
    panel.append(waterfall(f.timing));
  }
}

/** connect and tls are durations; first byte and total count from the request's arrival. */
function waterfall(t) {
  const total = Math.max(t.total_ms || 0, 0.001);
  const connect = t.connect_ms || 0;
  const tls = t.tls_ms || 0;
  const firstByte = t.first_byte_ms;
  const segments = [];
  if (t.connect_ms != null) segments.push(["Connect", 0, connect, "wf-connect"]);
  if (t.tls_ms != null) segments.push(["TLS", connect, tls, "wf-tls"]);
  if (firstByte != null) {
    const start = connect + tls;
    segments.push(["First byte", start, Math.max(0, firstByte - start), "wf-wait"]);
    segments.push(["Download", firstByte, Math.max(0, total - firstByte), "wf-recv"]);
  }
  segments.push(["Total", 0, total, "wf-recv"]);
  const box = h("div", "waterfall");
  box.setAttribute("role", "list");
  for (const [label, start, length, cls] of segments) {
    const bar = h("div", "wf-bar " + cls);
    bar.style.left = (100 * start / total).toFixed(2) + "%";
    bar.style.width = (100 * length / total).toFixed(2) + "%";
    const row = h("div", "wf-row", null, [h("span", null, label), h("div", "wf-track", null, [bar]),
      h("span", "wf-ms", fmtMs(length) + " ms")]);
    row.setAttribute("role", "listitem");
    box.append(row);
  }
  return box;
}

function clientTls(panel, m) {
  const f = m.raw;
  const tls = m.kind === "tls_failure"
    ? { sni: f.sni, ja4: f.ja4, client: f.known_client, version: null, alpn: null, ja3_hash: null }
    : f.tls;
  if (!tls) {
    panel.append(h("p", "hint", m.kind === "tunnel"
      ? "No TLS: the tunnel was not TLS." : "Plain HTTP: no TLS between the client and the proxy."));
    return;
  }
  const card = h("div", "fp-card");
  card.append(h("div", tls.client ? "fp-client" : "fp-client unknown", tls.client || "Unknown client"));
  const ja4 = h("div", "fp-ja4", tls.ja4);
  ja4.setAttribute("aria-label", "JA4 fingerprint " + tls.ja4);
  card.append(ja4);
  card.append(h("div", "body-bar", null, [copyButton("Copy JA4", () => tls.ja4),
    tls.ja3_hash ? copyButton("Copy JA3 hash", () => tls.ja3_hash) : null]));
  card.append(h("p", "fp-note",
    "How this client's TLS ClientHello looks to a server. JA4 names the TLS stack (library and version), " +
    "not the user agent string, so it shows what an app really uses."));
  panel.append(card);
  panel.append(kv([
    ["Matched client", tls.client || "no known client with this JA4"],
    ["TLS version", tls.version ? tls.version.replace("TLSv1_", "TLS 1.") : null],
    ["SNI", tls.sni || "(none)", "mono"],
    ["ALPN", tls.alpn || "(none)", "mono"],
    ["JA4", tls.ja4, "mono"],
    ["JA3 hash", tls.ja3_hash, "mono"],
  ]));
}

function requestTab(panel, m) {
  const f = m.raw;
  if (m.kind !== "exchange") {
    panel.append(h("p", "hint", "No HTTP request: see Overview."));
    return;
  }
  panel.append(h("h3", null, "Headers"));
  panel.append(headersTable(f.request_headers));
  panel.append(h("h3", null, "Body"));
  if (f.request_body) panel.append(bodyView(f.request_body, f.request_headers));
  else panel.append(h("p", "hint", "Not recorded yet: the exchange is in progress."));
}

function responseTab(panel, m) {
  const f = m.raw;
  if (m.kind !== "exchange") {
    panel.append(h("p", "hint", "No HTTP response: see Overview."));
    return;
  }
  if (m.state === "pending") {
    panel.append(h("p", "hint", "Waiting for the response."));
    return;
  }
  if (f.status != null) panel.append(h("div", "url", f.upstream_version + " " + f.status + " " + (f.reason || "")));
  if (f.error) panel.append(h("div", "error-box", "Error: " + f.error));
  panel.append(h("h3", null, "Headers"));
  panel.append(headersTable(f.response_headers));
  panel.append(h("h3", null, "Body"));
  if (f.response_body) panel.append(bodyView(f.response_body, f.response_headers));
  else panel.append(h("p", "hint", "No response body."));
}

function headersTable(headers) {
  if (!headers || !headers.length) return h("p", "hint", "No headers.");
  const table = h("table", "headers");
  const body = h("tbody");
  for (const [k, v] of headers) {
    const copy = copyButton("Copy", () => k + ": " + v, "mini");
    copy.setAttribute("aria-label", "Copy header " + k);
    body.append(h("tr", null, null, [h("td", "h-name", k), h("td", "h-value", v), h("td", "h-copy", null, [copy])]));
  }
  table.append(body);
  const all = copyButton("Copy all headers", () => headers.map(([k, v]) => k + ": " + v).join("\n"), "mini");
  return h("div", null, null, [table, h("div", "body-bar", null, [all])]);
}

// ---------------------------------------------------------------------------
// Body viewers

function bodyBytes(body) {
  if (body.encoding === "base64") {
    const bin = atob(body.data);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }
  return new TextEncoder().encode(body.data);
}

function bodyText(body) {
  return body.encoding === "base64" ? new TextDecoder().decode(bodyBytes(body)) : body.data;
}

const IMAGE_TYPES = new Set(["image/png", "image/jpeg", "image/gif", "image/webp", "image/avif",
  "image/bmp", "image/x-icon", "image/vnd.microsoft.icon", "image/svg+xml"]);
const HEX_LIMIT = 64 * 1024;

function bodyView(body, headers) {
  const box = h("div");
  if (!body.size) {
    box.append(h("p", "hint", "Empty body."));
    return box;
  }
  const contentType = header(headers, "content-type");
  const mime = contentType.toLowerCase().split(";")[0].trim();
  const encoding = header(headers, "content-encoding").toLowerCase();
  const kind = kindOf(contentType);
  const kept = body.encoding === "base64" ? Math.floor(body.data.length * 3 / 4) : new TextEncoder().encode(body.data).length;
  const bar = h("div", "body-bar", null, [
    h("span", "hint", fmtSize(body.size) + (mime ? " · " + mime : "") + (encoding ? " · " + encoding : "")),
    copyButton("Copy body", () => body.data, "mini"),
  ]);
  box.append(bar);
  if (body.truncated) {
    box.append(h("p", "notice", "Truncated: showing the first " + fmtSize(kept) + " of " + fmtSize(body.size) +
      " (raise --body-limit to keep more)."));
  }
  if (encoding && encoding !== "identity") {
    box.append(h("p", "notice", "Stored as sent: " + encoding + "-encoded, not decoded."));
    box.append(hexDump(bodyBytes(body)));
    return box;
  }
  if (kind === "image" && IMAGE_TYPES.has(mime)) {
    const img = h("img", "preview");
    img.alt = "Response image preview (" + mime + ")";
    const b64 = body.encoding === "base64" ? body.data : toBase64(bodyBytes(body));
    const size = h("span", "hint");
    img.addEventListener("load", () => {
      size.textContent = img.naturalWidth + " \u00d7 " + img.naturalHeight + " px";
      // Small images (icons, pixels) are scaled up so they can be seen.
      if (img.naturalWidth && img.naturalWidth < 64) {
        img.style.width = img.naturalWidth * 4 + "px";
        img.classList.add("scaled");
      }
    });
    img.addEventListener("error", () => { size.textContent = "The image does not decode" + (body.truncated ? " (truncated)." : "."); });
    img.src = "data:" + mime + ";base64," + b64;
    box.append(img, h("div", null, null, [size]));
    return box;
  }
  if (kind === "json") {
    try {
      box.append(jsonView(JSON.parse(bodyText(body))));
      return box;
    } catch (_) {
      box.append(h("p", "notice", "Not valid JSON" + (body.truncated ? " (cut by the limit)" : "") + ": shown as text."));
    }
  }
  if (kind === "form") {
    box.append(formTable(bodyText(body)));
    return box;
  }
  if (body.encoding === "utf8" && kind !== "image" && kind !== "font" && kind !== "media") {
    box.append(h("pre", "text", body.data));
    return box;
  }
  box.append(hexDump(bodyBytes(body)));
  return box;
}

function toBase64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

function formTable(text) {
  const table = h("table", "headers");
  const tbody = h("tbody");
  for (const [k, v] of new URLSearchParams(text)) {
    tbody.append(h("tr", null, null, [h("td", "h-name", k), h("td", "h-value", v)]));
  }
  table.append(tbody);
  return table;
}

function hexDump(bytes) {
  const lines = [];
  const n = Math.min(bytes.length, HEX_LIMIT);
  for (let off = 0; off < n; off += 16) {
    let hex = "";
    let ascii = "";
    for (let i = 0; i < 16; i++) {
      if (off + i < n) {
        const b = bytes[off + i];
        hex += b.toString(16).padStart(2, "0") + (i === 7 ? "  " : " ");
        ascii += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".";
      } else {
        hex += i === 7 ? "    " : "   ";
      }
    }
    lines.push(off.toString(16).padStart(8, "0") + "  " + hex + " " + ascii);
  }
  if (bytes.length > HEX_LIMIT) lines.push("... " + fmtSize(bytes.length - HEX_LIMIT) + " more not shown");
  return h("pre", "hex", lines.join("\n"));
}

// JSON tree: <details> nodes, children built when first opened; search expands matches.

const TREE_EAGER_LIMIT = 4000;

function jsonView(value) {
  const wrap = h("div");
  const input = h("input", "json-search");
  input.type = "search";
  input.placeholder = "Search JSON keys and values";
  input.setAttribute("aria-label", "Search JSON keys and values");
  const tree = h("div", "json");
  const draw = () => {
    const needle = input.value.trim().toLowerCase();
    tree.replaceChildren(jsonNode(null, value, needle, 0, { count: 0 }));
  };
  let timer = 0;
  input.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(draw, 120); });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && input.value) { e.stopPropagation(); input.value = ""; draw(); }
  });
  wrap.append(h("div", "body-bar", null, [input]), tree);
  draw();
  return wrap;
}

function containsNeedle(key, value, needle) {
  if (key !== null && String(key).toLowerCase().includes(needle)) return true;
  if (value !== null && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) if (containsNeedle(k, v, needle)) return true;
    return false;
  }
  return String(value).toLowerCase().includes(needle);
}

function keySpan(key, needle) {
  if (key === null) return null;
  const span = h("span", "k", (typeof key === "number" ? String(key) : JSON.stringify(key)) + ": ");
  if (needle && String(key).toLowerCase().includes(needle)) span.classList.add("hit");
  return span;
}

function jsonNode(key, value, needle, depth, budget) {
  budget.count++;
  if (value === null || typeof value !== "object") {
    const cls = typeof value === "string" ? "str" : typeof value === "number" ? "num" : "lit";
    const v = h("span", cls, typeof value === "string" ? JSON.stringify(value) : String(value));
    if (needle && String(value).toLowerCase().includes(needle)) v.classList.add("hit");
    return h("div", "leaf", null, [keySpan(key, needle), v]);
  }
  const isArray = Array.isArray(value);
  const entries = Object.entries(value);
  const details = h("details");
  const summary = h("summary", null, null, [keySpan(key, needle),
    h("span", "meta", isArray ? "[" + entries.length + "]" : "{" + entries.length + "}")]);
  details.append(summary);
  const fill = () => {
    if (details.filled) return;
    details.filled = true;
    for (const [k, v] of entries) details.append(jsonNode(isArray ? Number(k) : k, v, needle, depth + 1, budget));
  };
  const open = needle ? containsNeedle(null, value, needle) && budget.count < TREE_EAGER_LIMIT : depth < 2 && entries.length <= 200;
  if (open) {
    details.open = true;
    fill();
  }
  details.addEventListener("toggle", () => { if (details.open) fill(); });
  return details;
}

// ---------------------------------------------------------------------------
// Copy actions

function toast(text) {
  el.toast.textContent = text;
  el.toast.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => el.toast.classList.remove("show"), 1400);
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Copied");
  } catch (_) {
    const area = h("textarea", "visually-hidden", text);
    document.body.append(area);
    area.select();
    const ok = document.execCommand("copy");
    area.remove();
    toast(ok ? "Copied" : "Copy failed");
  }
}

function copyButton(label, getText, cls) {
  const button = h("button", cls || null, label);
  button.type = "button";
  button.addEventListener("click", () => copy(getText()));
  return button;
}

/** POSIX shell single quoting: 'it'\''s'. */
function shQuote(s) {
  return "'" + String(s).replace(/'/g, "'\\''") + "'";
}

const CURL_SKIP = new Set(["content-length", "host", "connection", "transfer-encoding", "keep-alive",
  "proxy-connection", "upgrade", "te"]);

/** A curl command that repeats the request as the client sent it. */
function curlCommand(f) {
  const parts = ["curl"];
  const body = f.request_body;
  const hasBody = body && body.size > 0;
  if (f.method !== "GET" || hasBody) parts.push("-X", shQuote(f.method));
  parts.push(shQuote(f.url));
  for (const [k, v] of f.request_headers || []) {
    if (k.startsWith(":") || CURL_SKIP.has(k.toLowerCase())) continue;
    parts.push("-H", shQuote(k + ": " + v));
  }
  let prefix = "";
  if (hasBody) {
    if (body.encoding === "utf8" && !body.data.includes("\0")) {
      parts.push("--data-binary", shQuote(body.data));
    } else {
      prefix = "printf %s " + shQuote(body.data) + " | base64 --decode | ";
      parts.push("--data-binary", "@-");
    }
  }
  let command = prefix + parts.join(" ");
  if (hasBody && body.truncated) command = "# the captured body was truncated: this sends only its start\n" + command;
  return command;
}

/** The server's cURL export (`GET /api/v1/flows/{id}/curl`), else the local builder. */
el.copyCurl.addEventListener("click", async () => {
  const m = flows.get(selectedId);
  if (!m || m.kind !== "exchange") return;
  let command = null;
  if (m.state === "done") {
    try {
      const response = await api("flows/" + m.id + "/curl");
      if (response.ok) command = await response.text();
    } catch (_) { /* fall back */ }
  }
  copy(command || curlCommand(m.raw));
});
el.copyUrl.addEventListener("click", () => {
  const m = flows.get(selectedId);
  if (m) copy(m.url);
});

// ---------------------------------------------------------------------------
// Live updates: fetch + ReadableStream SSE (EventSource cannot send the Bearer header)

function setConn(state, text) {
  el.conn.dataset.state = state;
  el.conn.textContent = text;
}

/** Breakpoint pause events (`paused`, `resumed`) go to panels.js. */
function onPause(event) {
  for (const fn of hooks.pause) fn(event.event, event.flow);
}

function dispatch(message) {
  const name = message.event;
  const f = message.flow;
  if (name === "started") upsert("pending", f);
  else if (name === "completed" || name === "failed" || name === "tls_failed") upsert("done", f);
  else if (typeof name === "string" && name.startsWith("pause")) onPause(message);
}

/** Loads flows newer than `after` from the store and merges them. */
async function loadFlows(after) {
  const response = await api("flows" + (after ? "?after=" + after : ""));
  if (response.status === 401) throw new TokenError();
  if (!response.ok) throw new Error("HTTP " + response.status);
  for (const item of await response.json()) upsert(item.state, item.flow);
}

class TokenError extends Error {}

/** The lowest id that might still change: the oldest pending flow, or the newest id. */
function resumePoint() {
  let low = Infinity;
  let high = clearedBelow;
  for (const m of flows.values()) {
    if (m.state === "pending") low = Math.min(low, m.id);
    high = Math.max(high, m.id);
  }
  return low === Infinity ? high : low - 1;
}

async function stream() {
  const response = await api("events", { headers: { Accept: "text/event-stream" } });
  if (response.status === 401) throw new TokenError();
  if (!response.ok || !response.body) throw new Error("HTTP " + response.status);
  return response.body.pipeThrough(new TextDecoderStream()).getReader();
}

async function consume(reader, onOpen) {
  let buffer = "";
  onOpen();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return;
    buffer += value;
    let end;
    while ((end = buffer.search(/\r?\n\r?\n/)) >= 0) {
      const block = buffer.slice(0, end);
      buffer = buffer.slice(end).replace(/^\r?\n\r?\n/, "");
      const data = [];
      for (const line of block.split(/\r?\n/)) {
        if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
        else if (line.startsWith(": lagged")) markLagged();
      }
      if (!data.length) continue;
      try { dispatch(JSON.parse(data.join("\n"))); } catch (_) { /* skip a malformed event */ }
    }
  }
}

let lagged = false;
function markLagged() {
  // Events were skipped: fetch the store again once the burst is over.
  if (lagged) return;
  lagged = true;
  setTimeout(() => { lagged = false; loadFlows(resumePoint()).catch(() => {}); }, 500);
}

async function live() {
  if (!token) {
    setConn("token", "token missing: open the link printed in the terminal");
    el.empty.textContent = "Token missing: open the link printed in the terminal (it ends in #token=...).";
    return;
  }
  let delay = 500;
  let first = true;
  for (;;) {
    try {
      setConn(first ? "connecting" : "reconnecting", first ? "connecting" : "reconnecting");
      // Subscribe first, then load the store, so nothing falls between the two.
      const reader = await stream();
      await loadFlows(first ? 0 : resumePoint());
      first = false;
      for (const fn of hooks.load) fn();
      await consume(reader, () => {
        delay = 500;
        setConn("live", "live");
      });
    } catch (e) {
      if (e instanceof TokenError) {
        setConn("token", "token rejected: open the link printed in the terminal");
        try { sessionStorage.removeItem(TOKEN_KEY); } catch (_) { /* ignore */ }
        return;
      }
    }
    for (let left = Math.ceil(delay / 1000); left > 0; left--) {
      setConn("reconnecting", "reconnecting in " + left + " s");
      await new Promise((r) => setTimeout(r, 1000));
    }
    delay = Math.min(delay * 2, 15000);
  }
}

rebuild();
live();
if (fragment.has("q")) {
  el.search.value = fragment.get("q");
  applySearch(el.search.value, 0);
}
if (fragment.has("tab") && TABS.some((t) => t.id === fragment.get("tab"))) setTab(fragment.get("tab"));
for (const spec of window.pendingTabs || []) registerTab(spec);
if (fragment.has("flow")) {
  const wanted = Number(fragment.get("flow"));
  const open = (tries) => {
    if (flows.has(wanted)) select(wanted, true);
    else if (tries > 0) setTimeout(() => open(tries - 1), 200);
  };
  open(50);
}
