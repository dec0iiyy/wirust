// Side panels and popovers on top of app.js: the breakpoint tray, the rules panel, the
// Connect popover, the search help, HAR export and "create rule from this flow".
//
// Same rules as app.js: createElement and textContent only (the h() helper), no HTML
// strings. This file uses app.js's top-level helpers (h, api, apiJson, flows, select, ...),
// so it starts on DOMContentLoaded, after every deferred script ran.
"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const slot = document.getElementById("rules-slot");
  const actions = document.querySelector(".toolbar .actions");
  const searchBox = document.querySelector(".toolbar .search");
  let appName = "Flows";

  function button(label, cls, onClick) {
    const b = h("button", cls || null, label);
    b.type = "button";
    if (onClick) b.addEventListener("click", onClick);
    return b;
  }

  function isTyping(target) {
    return target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement ||
      target instanceof HTMLSelectElement;
  }

  // -------------------------------------------------------------------------
  // Popovers (Connect, search help): one open at a time, Esc or a click outside closes.

  let openPopover = null;
  function popover(anchor, id, label) {
    const box = h("div", "popover");
    box.id = id;
    box.hidden = true;
    box.setAttribute("role", "dialog");
    box.setAttribute("aria-label", label);
    anchor.setAttribute("aria-controls", id);
    anchor.setAttribute("aria-expanded", "false");
    document.body.append(box);
    return box;
  }
  function togglePopover(anchor, box, fill) {
    const opening = box.hidden;
    closePopover();
    if (!opening) return;
    fill(box);
    const r = anchor.getBoundingClientRect();
    box.style.top = Math.round(r.bottom + 6) + "px";
    box.hidden = false;
    box.style.left = Math.round(Math.max(8, Math.min(r.left, window.innerWidth - box.offsetWidth - 8))) + "px";
    anchor.setAttribute("aria-expanded", "true");
    openPopover = { anchor, box };
  }
  function closePopover() {
    if (!openPopover) return;
    openPopover.box.hidden = true;
    openPopover.anchor.setAttribute("aria-expanded", "false");
    openPopover = null;
  }
  document.addEventListener("pointerdown", (e) => {
    if (openPopover && !openPopover.box.contains(e.target) && !openPopover.anchor.contains(e.target)) closePopover();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && openPopover) { closePopover(); e.stopPropagation(); }
  }, true);

  // -------------------------------------------------------------------------
  // Search help (the grammar from docs/interchange.md)

  const GRAMMAR = [
    "query   := or",
    "or      := and ( \"OR\" and )*",
    "and     := unary ( [\"AND\"] unary )*        terms side by side are ANDed",
    "unary   := \"-\" unary | primary              \"-\" negates",
    "primary := \"(\" or \")\" | field \":\" value | word | \"\\\"\" text \"\\\"\"",
  ].join("\n");
  const TERMS = [
    ["host:example.com", "host contains the text (tunnels: the target; failed handshakes: the SNI)"],
    ["path:/api/*", "path (no query string) matches the glob; without *, path starts with it"],
    ["method:POST", "exact method"],
    ["status:404, status:5xx, status:>=400", "exact code, class, or comparison (>, >=, <, <=, =)"],
    ["type:json", "response Content-Type contains it (js = javascript, image/img = image/)"],
    ["header:content-type=json", "a request or response header with that name whose value contains the text"],
    ["header:authorization", "the header is present"],
    ["body:\"free text\"", "request or response body contains it (first 1 MiB of each body)"],
    ["size:>10k", "response body size; b, k, m, g (powers of 1024)"],
    ["time:>500ms", "total time; ms (default) or s"],
    ["client:curl", "the known TLS client or the User-Agent contains it"],
    ["tls:failed, tls:yes, tls:none, tls:1.3", "failed handshake, intercepted TLS, plain HTTP, version"],
    ["flag:pause_timed_out", "the flow carries this flag (rule:NAME, responded, aborted, ...)"],
    ["word, \"two words\"", "the URL contains it"],
  ];
  const EXAMPLES = [
    "host:api.example.com status:5xx",
    "method:POST -header:authorization (path:/login OR path:/token)",
    "type:json time:>500ms OR size:>1m",
  ];

  const helpButton = button("?", "help-button");
  helpButton.title = "Search syntax";
  helpButton.setAttribute("aria-label", "Search syntax");
  searchBox.classList.add("with-help");
  searchBox.append(helpButton);
  const helpBox = popover(helpButton, "search-syntax", "Search syntax");
  helpButton.addEventListener("click", () => togglePopover(helpButton, helpBox, fillHelp));
  function fillHelp(box) {
    const rows = TERMS.map(([term, meaning]) => h("tr", null, null, [h("td", "h-name", term), h("td", null, meaning)]));
    box.replaceChildren(
      h("h3", null, "Search"),
      h("p", null, "Plain words and host:, method:, status:, type: filter in the page (words also match " +
        "headers). Any other field, parentheses, OR or a leading - asks the server. AND binds tighter " +
        "than OR; text comparisons ignore case; quote values with spaces."),
      h("table", "headers", null, [h("tbody", null, null, rows)]),
      h("h3", null, "Grammar"),
      h("pre", "text", GRAMMAR),
      h("h3", null, "Examples"),
      h("pre", "text", EXAMPLES.join("\n")),
    );
  }

  // -------------------------------------------------------------------------
  // Toolbar: Export HAR, Connect, Breakpoints, Rules

  const exportButton = button("Export HAR", null, exportHar);
  exportButton.title = "Download the flows matching the search as a HAR file";
  const connectButton = button("Connect", null);
  connectButton.title = "How to point a client at the proxy";
  const pauseButton = button("Breakpoints", "pause-button", () => openSide("pauses"));
  const pauseCount = h("span", "pill", "0");
  pauseCount.hidden = true;
  pauseButton.append(" ", pauseCount);
  const rulesButton = button("Rules", null, () => openSide("rules"));
  for (const b of [pauseButton, rulesButton]) b.setAttribute("aria-controls", "rules-slot");
  actions.prepend(exportButton, connectButton, pauseButton, rulesButton);

  /** The token stays in the Authorization header: fetch, then save through a Blob. */
  async function exportHar() {
    const q = el.search.value.trim();
    try {
      const response = await api("har" + (q ? "?q=" + encodeURIComponent(q) : ""));
      if (!response.ok) {
        let message = "HTTP " + response.status;
        try { message = (await response.json()).error || message; } catch (_) { /* keep */ }
        toast("Export failed: " + message);
        return;
      }
      const disposition = response.headers.get("content-disposition") || "";
      const match = /filename="?([A-Za-z0-9._-]+)"?/.exec(disposition);
      const url = URL.createObjectURL(await response.blob());
      const a = h("a");
      a.href = url;
      a.download = match ? match[1] : appName + ".har";
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
      toast("HAR saved");
    } catch (e) {
      toast("Export failed: " + e.message);
    }
  }

  // -------------------------------------------------------------------------
  // Connect popover (GET /api/v1/info)

  let info = null;
  async function loadInfo() {
    try {
      info = await apiJson("info");
      appName = info.name;
      updateTitle();
    } catch (_) { /* the popover says so */ }
  }
  const connectBox = popover(connectButton, "connect", "Connect a client");
  connectButton.addEventListener("click", () => togglePopover(connectButton, connectBox, fillConnect));

  function codeLine(text) {
    return h("div", "code-line", null, [h("code", null, text), copyButton("Copy", () => text, "mini")]);
  }

  function fillConnect(box) {
    if (!info) {
      box.replaceChildren(h("p", "hint", "Could not load /api/v1/info."));
      return;
    }
    // Built from parts: the UI files carry no literal URLs (tests/ui.rs).
    const proxyUrl = ["http:", "", info.proxy_addr].join("/");
    const caUrl = ["http:", "", info.magic_host, "ca.pem"].join("/");
    const caLink = h("a", null, caUrl);
    caLink.href = caUrl;
    caLink.target = "_blank";
    caLink.rel = "noopener noreferrer";
    box.replaceChildren(
      h("h3", null, info.name + " " + info.version),
      h("p", null, "Proxy listening on " + info.proxy_addr +
        (info.listen_is_loopback ? " (this machine only)." : " (reachable from the network).")),
      h("h3", null, "Point a client at it"),
      codeLine("curl -x " + proxyUrl + " " + ["https:", "", "example.com/"].join("/")),
      codeLine("export HTTPS_PROXY=" + proxyUrl + " HTTP_PROXY=" + proxyUrl),
      h("h3", null, "Trust the CA"),
      h("p", null, null, ["Through the proxy, open ", caLink,
        " and install it (a browser not using the proxy cannot reach this address). Or ",
        button("download it here", "linkish", downloadCa), "."]),
      h("p", null, "After installing, compare the SHA-256 fingerprint the system shows with:"),
      codeLine(info.ca_fingerprint_sha256),
      h("h3", null, "Phones"),
      h("p", null, null, ["Run ", h("code", null, info.name + " connect"),
        " for a QR code that sets up Android or iOS (see docs/mobile.md)."]),
      kv([["Rules file", info.rules_file || "none (rules only from this UI)", "mono"],
        ["Session file", info.session_file || "none", "mono"]]),
    );
  }

  async function downloadCa() {
    try {
      const response = await api("ca.pem");
      if (!response.ok) throw new Error("HTTP " + response.status);
      const url = URL.createObjectURL(await response.blob());
      const a = h("a");
      a.href = url;
      a.download = appName + "-ca.pem";
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
    } catch (e) {
      toast("Download failed: " + e.message);
    }
  }

  // -------------------------------------------------------------------------
  // Side panel: Breakpoints | Rules

  slot.hidden = true;
  const sideTabs = h("div", "side-tabs");
  sideTabs.setAttribute("role", "tablist");
  sideTabs.setAttribute("aria-label", "Side panel");
  const pauseTab = button("Breakpoints", null, () => openSide("pauses"));
  const rulesTab = button("Rules", null, () => openSide("rules"));
  const closeSide = button("×", "side-close", () => { slot.hidden = true; renderRows(true); });
  closeSide.setAttribute("aria-label", "Close the side panel");
  for (const [b, name] of [[pauseTab, "pauses"], [rulesTab, "rules"]]) {
    b.setAttribute("role", "tab");
    b.dataset.side = name;
  }
  sideTabs.append(pauseTab, rulesTab, closeSide);
  const pauseView = h("div", "side-view");
  pauseView.tabIndex = -1;
  const pauseListBox = h("div");
  const pauseEditorBox = h("div");
  pauseView.append(pauseListBox, pauseEditorBox);
  const rulesView = h("div", "side-view");
  const rulesHead = h("div");
  rulesView.append(rulesHead);
  slot.append(sideTabs, pauseView, rulesView);
  let side = "pauses";

  function openSide(name) {
    side = name;
    slot.hidden = false;
    pauseView.hidden = name !== "pauses";
    rulesView.hidden = name !== "rules";
    pauseTab.setAttribute("aria-selected", String(name === "pauses"));
    rulesTab.setAttribute("aria-selected", String(name === "rules"));
    if (name === "rules") loadRules(false);
    else renderPauses();
    renderRows(true);
  }

  // -------------------------------------------------------------------------
  // Breakpoints

  const pauses = new Map();   // pause id -> {id, flow_id, phase}
  let pauseSel = null;
  let pauseError = "";
  let draft = null;           // editor state for the selected pause

  function updateTitle() {
    const n = pauses.size;
    document.title = (n ? "(" + n + ") " : "") + appName;
    pauseCount.textContent = String(n);
    pauseCount.hidden = n === 0;
    pauseTab.textContent = n ? "Breakpoints (" + n + ")" : "Breakpoints";
    pauseButton.classList.toggle("attention", n > 0);
    pauseButton.setAttribute("aria-label", n ? n + " paused exchanges" : "Breakpoints");
  }

  async function loadPauses() {
    try {
      const list = await apiJson("pauses");
      pauses.clear();
      for (const p of list) pauses.set(p.id, p);
      if (pauseSel !== null && !pauses.has(pauseSel)) pauseSel = null;
      if (pauseSel === null && pauses.size) pauseSel = pauses.keys().next().value;
      updateTitle();
      if (pauses.size && slot.hidden) openSide("pauses");
      else if (!slot.hidden && side === "pauses") renderPauses();
    } catch (_) { /* the next load retries */ }
  }

  hooks.load.push(loadPauses);
  hooks.load.push(loadInfo);
  hooks.pause.push((name, p) => {
    if (!p || typeof p.pause_id !== "number") return;
    if (name === "paused") {
      pauses.set(p.pause_id, { id: p.pause_id, flow_id: p.flow_id, phase: p.phase });
      if (pauseSel === null) { pauseSel = p.pause_id; draft = null; }
      if (slot.hidden || side !== "pauses") openSide("pauses");
      else renderPauses(editing());
    } else if (name === "resumed") {
      pauses.delete(p.pause_id);
      if (pauseSel === p.pause_id) {
        pauseSel = pauses.size ? pauses.keys().next().value : null;
        draft = null;
        pauseError = "";
        if (p.resolution === "timed_out") toast("Pause " + p.pause_id + " timed out");
      }
      if (!slot.hidden && side === "pauses") renderPauses(editing());
    }
    updateTitle();
  });

  /** True while the user types in the editor of a pause that is still pending. */
  function editing() {
    const a = document.activeElement;
    return pauseEditorBox.contains(a) && isTyping(a) && draft !== null && pauses.has(draft.pauseId) &&
      draft.pauseId === pauseSel;
  }

  function flowLabel(flowId) {
    const m = flows.get(flowId);
    if (!m) return "flow " + flowId;
    return m.method + " " + (m.host || "") + (m.path || "");
  }

  /** Redraws the list and, unless `listOnly`, the editor (keeping typed text in `draft`). */
  function renderPauses(listOnly) {
    const keepFocus = pauseView.contains(document.activeElement) && !isTyping(document.activeElement);
    pauseListBox.replaceChildren();
    if (!listOnly) pauseEditorBox.replaceChildren();
    if (!pauses.size) {
      pauseListBox.append(h("p", "hint", "No paused exchanges. A rule with action breakpoint stops matching " +
        "requests or responses here (see Rules)."));
      return;
    }
    const list = h("ul", "pause-list");
    list.setAttribute("role", "listbox");
    list.setAttribute("aria-label", "Paused exchanges");
    for (const p of pauses.values()) {
      const item = h("li", "pause-item", null, [
        h("span", "phase phase-" + p.phase, p.phase),
        h("span", "pause-flow", "#" + p.flow_id + " " + flowLabel(p.flow_id)),
      ]);
      item.tabIndex = 0;
      item.setAttribute("role", "option");
      item.setAttribute("aria-selected", String(p.id === pauseSel));
      item.addEventListener("click", () => choosePause(p.id));
      item.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); choosePause(p.id); } });
      list.append(item);
    }
    pauseListBox.append(list);
    if (listOnly) return;
    const p = pauses.get(pauseSel);
    if (p) pauseEditorBox.append(editor(p));
    pauseEditorBox.append(h("p", "hint keys", "Keys while the tray has focus: r resume, a abort."));
    if (keepFocus) pauseView.focus();
  }

  function choosePause(id) {
    if (pauseSel !== id) { draft = null; pauseError = ""; }
    pauseSel = id;
    const p = pauses.get(id);
    if (p && flows.has(p.flow_id)) select(p.flow_id, true);
    renderPauses();
    pauseView.focus();
  }

  /** The editable copy of the paused half, made once per pause. */
  function makeDraft(p) {
    const m = flows.get(p.flow_id);
    const f = m ? m.raw : {};
    const headers = p.phase === "request"
      ? (f.request_headers || []).filter(([k]) => !k.startsWith(":")).map(([k, v]) => ({ name: k, value: v }))
      : [];
    return {
      pauseId: p.id,
      incomplete: !m,   // the flow was not loaded yet: build again once it is
      method: p.phase === "request" ? f.method || "" : "",
      url: p.phase === "request" ? f.url || "" : "",
      status: "",
      original: headers.map((x) => ({ name: x.name, value: x.value })),
      headers,
      removed: [],
      replaceBody: false,
      bodyMode: "text",
      body: "",
    };
  }

  function editor(p) {
    if (!draft || draft.pauseId !== p.id || (draft.incomplete && flows.has(p.flow_id))) draft = makeDraft(p);
    const d = draft;
    const box = h("div", "pause-editor");
    box.append(h("h3", null, (p.phase === "request" ? "Request" : "Response") + " of flow #" + p.flow_id));
    if (p.phase === "request") {
      const method = input(d.method, (v) => { d.method = v; }, "method-input");
      method.setAttribute("aria-label", "Method");
      const url = input(d.url, (v) => { d.url = v; }, "url-input");
      url.setAttribute("aria-label", "URL");
      box.append(h("div", "field-row", null, [method, url]));
      box.append(h("p", "hint", "A different scheme or host sends the request to that server."));
    } else {
      const status = input(d.status, (v) => { d.status = v; }, "status-input");
      status.placeholder = "unchanged";
      status.inputMode = "numeric";
      status.setAttribute("aria-label", "Status");
      box.append(h("div", "field-row", null, [h("label", null, "Status "), status]));
      box.append(h("p", "hint", "The response is shown only after it is released: headers you add here " +
        "are set, names under Remove are removed, the rest stays as the server sent it."));
    }
    box.append(h("h3", null, p.phase === "request" ? "Headers" : "Set headers"));
    box.append(headerEditor(d, p.phase));
    box.append(h("h3", null, "Body"));
    const replace = h("input");
    replace.type = "checkbox";
    replace.checked = d.replaceBody;
    replace.id = "replace-body";
    const mode = h("select");
    for (const [value, label] of [["text", "text"], ["base64", "base64 (binary)"]]) {
      const o = h("option", null, label);
      o.value = value;
      mode.append(o);
    }
    mode.value = d.bodyMode;
    mode.setAttribute("aria-label", "Body encoding");
    const area = h("textarea", "body-input");
    area.value = d.body;
    area.spellcheck = false;
    area.setAttribute("aria-label", "New body");
    area.disabled = !d.replaceBody;
    mode.disabled = !d.replaceBody;
    area.placeholder = d.bodyMode === "base64" ? "base64 of the new body" : "the new body";
    replace.addEventListener("change", () => {
      d.replaceBody = replace.checked;
      area.disabled = mode.disabled = !replace.checked;
      if (replace.checked) area.focus();
    });
    mode.addEventListener("change", () => {
      d.bodyMode = mode.value;
      area.placeholder = d.bodyMode === "base64" ? "base64 of the new body" : "the new body";
    });
    area.addEventListener("input", () => { d.body = area.value; });
    const label = h("label", null, "Replace the body");
    label.htmlFor = "replace-body";
    box.append(h("div", "field-row", null, [replace, label, mode]));
    box.append(h("p", "hint", "The current body is not visible while paused; leave this off to keep it."));
    box.append(area);
    const err = h("div", "error-box", pauseError);
    err.setAttribute("role", "alert");
    err.hidden = !pauseError;
    box.append(err);
    box.append(h("div", "pause-actions", null, [
      button("Resume", null, () => resolvePause(p, "resume")),
      button("Edit and resume", "primary", () => sendEdit(p)),
      button("Abort", "danger", () => resolvePause(p, "abort")),
    ]));
    return box;
  }

  function input(value, onInput, cls) {
    const i = h("input", cls || null);
    i.value = value;
    i.spellcheck = false;
    i.autocomplete = "off";
    i.addEventListener("input", () => onInput(i.value));
    return i;
  }

  function headerEditor(d, phase) {
    const table = h("table", "headers edit");
    const tbody = h("tbody");
    d.headers.forEach((row, index) => {
      const name = input(row.name, (v) => { row.name = v; }, "h-name-input");
      name.setAttribute("aria-label", "Header name");
      const value = input(row.value, (v) => { row.value = v; }, "h-value-input");
      value.setAttribute("aria-label", "Value of " + row.name);
      const del = button("×", "mini", () => { d.headers.splice(index, 1); renderPauses(); });
      del.setAttribute("aria-label", "Delete header " + row.name);
      tbody.append(h("tr", null, null, [h("td", null, null, [name]), h("td", null, null, [value]), h("td", "h-copy", null, [del])]));
    });
    table.append(tbody);
    const add = button("Add header", "mini", () => { d.headers.push({ name: "", value: "" }); renderPauses(); });
    const parts = [table, h("div", "body-bar", null, [add])];
    if (phase === "response") {
      const removed = input(d.removed.join(", "), (v) => { d.removed = v.split(",").map((s) => s.trim()).filter(Boolean); }, "remove-input");
      removed.placeholder = "set-cookie, x-powered-by";
      removed.setAttribute("aria-label", "Headers to remove, comma separated");
      parts.push(h("div", "field-row", null, [h("label", null, "Remove "), removed]));
    }
    return h("div", null, null, parts);
  }

  /** The edit body: only what changed (see docs/rules.md). */
  function editBody(p, d) {
    const body = {};
    const m = flows.get(p.flow_id);
    const f = m ? m.raw : {};
    if (p.phase === "request") {
      if (d.method.trim() && d.method.trim() !== f.method) body.method = d.method.trim();
      if (d.url.trim() && d.url.trim() !== f.url) body.url = d.url.trim();
    } else if (d.status.trim()) {
      body.status = Number(d.status.trim());
    }
    const finalRows = d.headers.filter((x) => x.name.trim());
    const grouped = new Map();
    for (const x of finalRows) {
      const key = x.name.trim().toLowerCase();
      grouped.set(key, grouped.has(key) ? grouped.get(key) + (key === "cookie" ? "; " : ", ") + x.value : x.value);
    }
    const before = new Map();
    for (const x of d.original) {
      const key = x.name.toLowerCase();
      before.set(key, before.has(key) ? before.get(key) + (key === "cookie" ? "; " : ", ") + x.value : x.value);
    }
    const set = {};
    for (const [k, v] of grouped) if (before.get(k) !== v) set[k] = v;
    const remove = [...before.keys()].filter((k) => !grouped.has(k)).concat(d.removed);
    if (Object.keys(set).length) body.set_headers = set;
    if (remove.length) body.remove_headers = remove;
    if (d.replaceBody) {
      if (d.bodyMode === "base64") body.body_base64 = d.body.replace(/\s+/g, "");
      else body.body = d.body;
    }
    return body;
  }

  async function resolvePause(p, verb) {
    try {
      await apiJson("pauses/" + p.id + "/" + verb, { method: "POST" });
      pauseError = "";
    } catch (e) {
      pauseError = e.message;
      if (/no such pending pause/.test(e.message)) pauses.delete(p.id);
    }
    afterResolve(p);
  }

  async function sendEdit(p) {
    const body = editBody(p, draft);
    try {
      await apiJson("pauses/" + p.id + "/edit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      pauseError = "";
      pauses.delete(p.id);
    } catch (e) {
      // 400: the pause stays pending and the editor keeps what was typed.
      pauseError = e.message;
      if (/no such pending pause/.test(e.message)) pauses.delete(p.id);
    }
    afterResolve(p);
  }

  function afterResolve(p) {
    if (!pauseError) pauses.delete(p.id);
    if (!pauses.has(p.id) && pauseSel === p.id) {
      pauseSel = pauses.size ? pauses.keys().next().value : null;
      draft = null;
    }
    updateTitle();
    renderPauses();
    pauseView.focus();
  }

  slot.addEventListener("keydown", (e) => {
    if (side !== "pauses" || e.metaKey || e.ctrlKey || e.altKey || isTyping(e.target)) return;
    const p = pauses.get(pauseSel);
    if (!p) return;
    if (e.key === "r") { e.preventDefault(); e.stopPropagation(); resolvePause(p, "resume"); }
    else if (e.key === "a") { e.preventDefault(); e.stopPropagation(); resolvePause(p, "abort"); }
  });

  // -------------------------------------------------------------------------
  // Rules

  let report = null;
  let rulesError = "";
  let editorDirty = false;
  let editorNote = "";
  let applyError = "";
  const ruleArea = h("textarea", "rules-json");
  ruleArea.spellcheck = false;
  ruleArea.setAttribute("aria-label", "Rule set as JSON");
  ruleArea.addEventListener("input", () => { editorDirty = true; });
  // The editor section stays in the DOM so polling never steals focus from the textarea.
  const noteLine = h("p", "notice");
  const applyErr = h("div", "error-box");
  applyErr.setAttribute("role", "alert");
  rulesView.append(
    h("h3", null, "Edit the rule set (JSON)"), noteLine, ruleArea, applyErr,
    h("div", "pause-actions", null, [
      button("Apply", "primary", () => applyRules()),
      button("Reload from server", null, () => { applyError = ""; editorNote = ""; loadRules(true); }),
    ]),
    h("p", "hint", "Apply sends the whole set to the server, which validates it; an error leaves the " +
      "rules unchanged."),
  );

  async function loadRules(force) {
    try {
      report = await apiJson("rules");
      rulesError = "";
      if (force || !editorDirty) {
        ruleArea.value = JSON.stringify({ rules: report.rules }, null, 2);
        editorDirty = false;
      }
    } catch (e) {
      rulesError = e.message;
    }
    renderRules();
  }

  setInterval(() => { if (!slot.hidden && side === "rules" && !document.hidden) loadRules(false); }, 5000);

  function matcherSummary(match) {
    const parts = [];
    if (!match) return "every exchange";
    for (const key of ["scheme", "host", "port", "path", "path_regex", "status"]) {
      if (match[key] != null) parts.push(key + " " + match[key]);
    }
    if (match.method && match.method.length) parts.push(match.method.join("|"));
    if (match.header) parts.push("header " + match.header.name + (match.header.value ? "~" + match.header.value : ""));
    return parts.length ? parts.join(" ") : "every exchange";
  }

  function actionSummary(a) {
    switch (a.type) {
      case "block": return "block " + a.status;
      case "status": return "status " + a.status;
      case "map_local": return "map local " + a.path;
      case "map_remote": return "map remote " + [a.scheme, a.host, a.port].filter((x) => x != null).join(" ");
      case "rewrite_headers": {
        const n = Object.keys(a.set || {}).length + Object.keys(a.add || {}).length + (a.remove || []).length + (a.replace || []).length;
        return "rewrite " + (a.phase || "request") + " headers (" + n + ")";
      }
      case "rewrite_body": return "rewrite " + (a.phase || "request") + " body";
      case "delay": return "delay " + a.ms + " ms";
      case "throttle": return "throttle " + a.bytes_per_second + " B/s";
      case "breakpoint": return "breakpoint " + [a.request !== false ? "request" : "", a.response ? "response" : ""].filter(Boolean).join("+");
      default: return String(a.type);
    }
  }

  function renderRules() {
    const rulesView = rulesHead;
    rulesView.replaceChildren();
    noteLine.textContent = editorNote;
    noteLine.hidden = !editorNote;
    applyErr.textContent = applyError;
    applyErr.hidden = !applyError;
    if (rulesError) rulesView.append(h("div", "error-box", "Rules unavailable: " + rulesError));
    if (report && report.error) {
      rulesView.append(h("div", "error-box load-error", null, [
        h("strong", null, "The rules file failed to load; the previous rules stay in force."),
        h("div", "mono", report.file || ""),
        h("pre", "text", report.error),
      ]));
    }
    if (report) {
      rulesView.append(h("p", "hint", report.file ? "Watching " + report.file + " (it wins again on its next change)."
        : "No rules file: rules live in this proxy run only."));
      if (!report.rules.length) rulesView.append(h("p", "hint", "No rules yet."));
      const list = h("ul", "rule-list");
      for (const rule of report.rules) {
        const toggle = button(rule.enabled ? "on" : "off", "toggle switch", () => toggleRule(rule.name));
        toggle.setAttribute("aria-pressed", String(rule.enabled));
        toggle.setAttribute("aria-label", "Enable rule " + rule.name);
        list.append(h("li", rule.enabled ? "rule-item" : "rule-item disabled", null, [
          toggle,
          h("div", "rule-text", null, [
            h("div", "rule-name", rule.name),
            h("div", "rule-summary", matcherSummary(rule.match) + " → " + actionSummary(rule.action)),
          ]),
        ]));
      }
      rulesView.append(list);
    }
  }

  async function toggleRule(name) {
    try {
      await apiJson("rules/" + encodeURIComponent(name) + "/toggle", { method: "POST" });
    } catch (e) {
      toast("Toggle failed: " + e.message);
    }
    loadRules(false);
  }

  async function applyRules() {
    let parsed;
    try {
      parsed = JSON.parse(ruleArea.value);
    } catch (e) {
      applyError = "Not valid JSON: " + e.message;
      renderRules();
      return;
    }
    try {
      report = await apiJson("rules", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(parsed),
      });
      applyError = "";
      editorNote = "";
      editorDirty = false;
      ruleArea.value = JSON.stringify({ rules: report.rules }, null, 2);
      toast("Rules applied");
    } catch (e) {
      applyError = e.message;
    }
    renderRules();
  }

  // -------------------------------------------------------------------------
  // Create a rule from the selected flow (inserted into the editor, never applied)

  const ruleMenuButton = button("Create rule", null);
  ruleMenuButton.disabled = true;
  ruleMenuButton.title = "Insert a rule template for this flow into the Rules editor";
  const replaySlot = document.getElementById("replay-slot");
  if (replaySlot && window.WIRUST_REPLAY) replaySlot.hidden = false;
  document.querySelector(".detail-actions").prepend(ruleMenuButton);
  const ruleMenu = popover(ruleMenuButton, "rule-menu", "Rule templates");
  ruleMenu.classList.add("menu");
  let shown = null;
  hooks.detail.push((m) => {
    shown = m && m.kind === "exchange" ? m : null;
    ruleMenuButton.disabled = !shown;
  });
  ruleMenuButton.addEventListener("click", () => togglePopover(ruleMenuButton, ruleMenu, (box) => {
    box.replaceChildren(
      button("Block this host", null, () => insertRule("block")),
      button("Delay this URL", null, () => insertRule("delay")),
      button("Rewrite a request header", null, () => insertRule("header")),
      button("Breakpoint on this URL", null, () => insertRule("breakpoint")),
    );
  }));

  function ruleName(base, taken) {
    const clean = base.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 56) || "rule";
    let name = clean;
    for (let i = 2; taken.has(name); i++) name = clean + "-" + i;
    return name;
  }

  async function insertRule(kind) {
    closePopover();
    if (!shown) return;
    if (!report) await loadRules(false);
    let set;
    try {
      set = JSON.parse(ruleArea.value || "{\"rules\": []}");
      if (!set || !Array.isArray(set.rules)) throw new Error("expected {\"rules\": [...]}");
    } catch (e) {
      openSide("rules");
      applyError = "Fix the JSON first: " + e.message;
      renderRules();
      return;
    }
    const f = shown.raw;
    let host = "";
    let path = "/";
    try {
      const u = new URL(f.url);
      host = u.hostname;
      path = u.pathname;
    } catch (_) { /* keep defaults */ }
    const taken = new Set(set.rules.map((r) => r.name));
    const templates = {
      block: { name: "block-" + host, match: { host }, action: { type: "block", status: 403, body: "blocked by " + appName } },
      delay: { name: "delay-" + host, match: { host, path }, action: { type: "delay", ms: 1000 } },
      header: { name: "header-" + host, match: { host, path },
        action: { type: "rewrite_headers", phase: "request", set: { "x-debug": "1" } } },
      breakpoint: { name: "break-" + host, match: { host, path }, action: { type: "breakpoint", request: true, response: false } },
    };
    const rule = templates[kind];
    rule.name = ruleName(rule.name, taken);
    rule.enabled = true;
    set.rules.push({ name: rule.name, enabled: true, match: rule.match, action: rule.action });
    ruleArea.value = JSON.stringify(set, null, 2);
    editorDirty = true;
    applyError = "";
    editorNote = "Inserted rule “" + rule.name + "” at the end. Review it, then press Apply.";
    openSide("rules");
    renderRules();
    ruleArea.focus();
    const at = ruleArea.value.lastIndexOf("\"" + rule.name + "\"");
    if (at >= 0) ruleArea.setSelectionRange(at + 1, at + 1 + rule.name.length);
  }

  updateTitle();
  if (!token) return;
  loadPauses();
  // `#...&panel=rules|pauses|connect|help` opens a panel at start (links, screenshots).
  const wanted = fragment.get("panel");
  if (wanted === "rules" || wanted === "pauses") openSide(wanted);
  loadInfo().then(() => {
    if (wanted === "connect") togglePopover(connectButton, connectBox, fillConnect);
    else if (wanted === "help") togglePopover(helpButton, helpBox, fillHelp);
  });
});
