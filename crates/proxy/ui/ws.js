"use strict";
// The "Messages" tab: WebSocket messages of an upgraded flow (docs/websocket.md).
//
// Contract with app.js: when `window.registerTab` exists, this file calls it once with
//   { id: "messages", title: "Messages", visible(flow), render(flow, container) }
// where `flow` is the UI model (its `raw` field holds the flow JSON) or the flow JSON itself,
// and `container` is an empty element the tab owns until the next render. Without a registry
// (older app.js) it adds its own tab button and renders into #panel when that button is used.
// Data: GET /api/v1/flows/{id}/messages for history, then its own SSE stream for `ws` events.
// DOM only through createElement/textContent; no HTML strings.

(function () {
  const PAGE = 1000;
  const MAX_ROWS = 5000;

  function readToken() {
    try {
      const fragment = new URLSearchParams(location.hash.slice(1));
      return fragment.get("token") || sessionStorage.getItem("token") || "";
    } catch (_) {
      return "";
    }
  }

  function request(path, init) {
    // Prefer app.js's helper (same token handling) when it is loaded.
    if (typeof api === "function") return api(path, init);
    const options = Object.assign({}, init);
    options.headers = Object.assign({ Authorization: "Bearer " + readToken() }, options.headers);
    return fetch("/api/v1/" + path, options);
  }

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function rawOf(flow) {
    return flow && flow.raw ? flow.raw : flow;
  }

  function isWebSocket(flow) {
    const raw = rawOf(flow);
    if (!raw) return false;
    if (typeof raw.ws_messages === "number") return true;
    const flags = raw.flags || [];
    return flags.includes("ws_extensions_stripped") || flags.includes("ws_compressed");
  }

  function fmtSize(n) {
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KiB";
    return (n / 1024 / 1024).toFixed(1) + " MiB";
  }

  function bytesOf(m) {
    if (m.encoding !== "base64") return new TextEncoder().encode(m.data);
    try {
      const bin = atob(m.data);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    } catch (_) {
      return new Uint8Array(0);
    }
  }

  function hex(bytes) {
    const lines = [];
    const max = Math.min(bytes.length, 64 * 1024);
    for (let off = 0; off < max; off += 16) {
      const row = bytes.subarray(off, Math.min(off + 16, max));
      const hexes = Array.from(row, (b) => b.toString(16).padStart(2, "0")).join(" ");
      const text = Array.from(row, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
      lines.push(off.toString(16).padStart(8, "0") + "  " + hexes.padEnd(48) + "  " + text);
    }
    if (bytes.length > max) lines.push("... " + (bytes.length - max) + " more bytes");
    return el("pre", "ws-hex", lines.join("\n"));
  }

  function jsonTree(value, depth) {
    if (value === null || typeof value !== "object") {
      return el("span", "ws-json-" + (value === null ? "null" : typeof value), JSON.stringify(value));
    }
    const list = el("ul", "ws-json");
    const entries = Array.isArray(value) ? value.map((v, i) => [i, v]) : Object.entries(value);
    for (const [key, child] of entries.slice(0, 500)) {
      const item = el("li");
      item.append(el("span", "ws-json-key", key + ": "));
      item.append(depth > 20 ? el("span", null, "...") : jsonTree(child, depth + 1));
      list.append(item);
    }
    return list;
  }

  function bodyView(m) {
    const box = el("div", "ws-body");
    if (m.decode_failed) {
      box.append(el("p", "ws-note", "Compressed, but it could not be decompressed: the raw payload is shown."));
    } else if (m.compressed) {
      const wire = typeof m.wire_size === "number" ? " (" + fmtSize(m.wire_size) + " on the wire)" : "";
      box.append(el("p", "ws-note", "Decompressed from permessage-deflate" + wire + "."));
    }
    if (m.kind === "close") {
      const code = m.close_code === undefined ? "no code" : "code " + m.close_code;
      box.append(el("p", "ws-close", "Close, " + code + (m.close_reason ? ": " + m.close_reason : "")));
      return box;
    }
    if (m.encoding === "utf8") {
      const text = m.data;
      const trimmed = text.trim();
      if (!m.truncated && (trimmed.startsWith("{") || trimmed.startsWith("["))) {
        try {
          box.append(jsonTree(JSON.parse(trimmed), 0));
          return box;
        } catch (_) { /* not JSON: show the text */ }
      }
      box.append(el("pre", "ws-text", text));
    } else {
      box.append(hex(bytesOf(m)));
    }
    if (m.truncated) {
      box.append(el("p", "ws-note", "Truncated: " + fmtSize(m.data.length) + " kept of " +
        fmtSize(m.size) + " (--ws-body-limit)."));
    }
    return box;
  }

  function option(value, label) {
    const o = el("option", null, label);
    o.value = value;
    return o;
  }

  /** The composer: POST /api/v1/flows/{id}/messages into the live connection. */
  function composer(id) {
    const form = el("form", "ws-composer");
    form.setAttribute("aria-label", "Send a message");
    const direction = el("select");
    direction.setAttribute("aria-label", "Send to");
    direction.append(option("server_to_client", "To the client"), option("client_to_server", "To the server"));
    const type = el("select");
    type.setAttribute("aria-label", "Message type");
    type.append(option("text", "Text"), option("binary", "Binary (hex)"));
    const data = el("textarea");
    data.setAttribute("aria-label", "Message");
    data.placeholder = "Message text, or hex bytes such as 01 ff 7a";
    const send = el("button", null, "Send");
    send.type = "submit";
    const status = el("p", "ws-send-status");
    status.setAttribute("role", "status");
    type.addEventListener("change", () => {
      data.placeholder = type.value === "text" ? "Message text" : "Hex bytes, such as 01 ff 7a";
    });
    form.append(direction, type, data, send, status);
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      send.disabled = true;
      status.classList.remove("error");
      status.textContent = "Sending...";
      try {
        const response = await request("flows/" + id + "/messages", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ direction: direction.value, type: type.value, data: data.value }),
        });
        if (response.ok) {
          status.textContent = "Sent. It shows up in the list marked (sent by you).";
        } else {
          let reason = "the proxy refused it (" + response.status + ")";
          try {
            const body = await response.json();
            if (body && body.error) reason = body.error;
          } catch (_) { /* keep the status code */ }
          if (response.status === 409) reason = "The connection is closed, so nothing can be sent.";
          status.classList.add("error");
          status.textContent = "Not sent: " + reason;
        }
      } catch (_) {
        status.classList.add("error");
        status.textContent = "Not sent: the proxy did not answer.";
      } finally {
        send.disabled = false;
      }
    });
    return form;
  }

  /** One mounted view: history from the API, live rows from SSE, filters. */
  function mount(flow, container) {
    const raw = rawOf(flow);
    const id = raw.id;
    const state = { messages: [], dropped: 0, first: null, filter: "", direction: "all", open: null };
    const controller = new AbortController();

    container.replaceChildren();
    container.classList.add("ws-tab");
    const bar = el("div", "ws-bar");
    const search = el("input", "ws-filter");
    search.type = "search";
    search.placeholder = "Filter messages";
    search.setAttribute("aria-label", "Filter messages");
    const dirs = el("div", "ws-dirs");
    dirs.setAttribute("role", "group");
    dirs.setAttribute("aria-label", "Direction");
    const buttons = [];
    for (const [value, label] of [["all", "Both"], ["client_to_server", "Sent"], ["server_to_client", "Received"]]) {
      const b = el("button", "chip", label);
      b.type = "button";
      b.dataset.dir = value;
      b.setAttribute("aria-pressed", String(value === "all"));
      b.addEventListener("click", () => {
        state.direction = value;
        for (const other of buttons) other.setAttribute("aria-pressed", String(other === b));
        draw();
      });
      buttons.push(b);
      dirs.append(b);
    }
    const count = el("span", "ws-count");
    bar.append(search, dirs, count);
    const notice = el("p", "ws-note");
    notice.hidden = true;
    const list = el("div", "ws-list");
    list.setAttribute("role", "list");
    const detail = el("div", "ws-detail");
    container.append(bar, notice, list, composer(id), detail);
    search.addEventListener("input", () => { state.filter = search.value.toLowerCase(); draw(); });

    function visible(m) {
      if (state.direction !== "all" && m.direction !== state.direction) return false;
      if (!state.filter) return true;
      return (m.encoding === "utf8" ? m.data : "").toLowerCase().includes(state.filter) ||
        m.kind.includes(state.filter) || String(m.close_reason || "").toLowerCase().includes(state.filter);
    }

    function row(m) {
      const r = el("div", "ws-row");
      r.setAttribute("role", "listitem");
      r.tabIndex = 0;
      const sent = m.direction === "client_to_server";
      r.append(el("span", sent ? "ws-dir ws-sent" : "ws-dir ws-recv", sent ? "↑ sent" : "↓ recv"));
      const offset = state.first === null ? 0 : m.timestamp - state.first;
      r.append(el("span", "ws-time", "+" + offset.toFixed(3) + " s"));
      const kind = el("span", "ws-kind ws-kind-" + m.kind, m.kind);
      if (m.injected) kind.append(el("span", "ws-injected", "(sent by you)"));
      r.append(kind);
      r.append(el("span", "ws-size", fmtSize(m.size) + (m.truncated ? " (truncated)" : "")));
      let preview = m.kind === "close"
        ? "code " + (m.close_code === undefined ? "-" : m.close_code) + (m.close_reason ? " " + m.close_reason : "")
        : m.encoding === "utf8" ? m.data.slice(0, 200) : "binary, " + fmtSize(m.size);
      r.append(el("span", "ws-preview", preview));
      const show = () => {
        state.open = m.seq;
        for (const other of list.children) other.classList.toggle("selected", other === r);
        detail.replaceChildren(bodyView(m));
      };
      r.addEventListener("click", show);
      r.addEventListener("keydown", (e) => { if (e.key === "Enter") show(); });
      if (state.open === m.seq) r.classList.add("selected");
      return r;
    }

    function draw() {
      const shown = state.messages.filter(visible);
      list.replaceChildren(...shown.map(row));
      count.textContent = shown.length + " of " + state.messages.length + " messages";
      const notes = [];
      if (state.dropped > 0) notes.push(state.dropped + " older messages were dropped (--ws-max-messages).");
      notice.textContent = notes.join(" ");
      notice.hidden = notes.length === 0;
      if (!state.messages.length) list.append(el("p", "hint", "No messages yet."));
    }

    function add(m) {
      if (state.messages.length && m.seq <= state.messages[state.messages.length - 1].seq) return;
      if (state.first === null) state.first = m.timestamp;
      state.messages.push(m);
      if (state.messages.length > MAX_ROWS) {
        state.messages.shift();
        state.dropped++;
      }
    }

    async function history() {
      let after = null;
      for (;;) {
        const q = "flows/" + id + "/messages?limit=" + PAGE + (after === null ? "" : "&after=" + after);
        const response = await request(q, { signal: controller.signal });
        if (!response.ok) return;
        const page = await response.json();
        state.dropped = page.dropped;
        for (const m of page.messages) add(m);
        if (page.messages.length < PAGE) return;
        after = page.messages[page.messages.length - 1].seq;
      }
    }

    async function live() {
      const response = await request("events", { headers: { Accept: "text/event-stream" }, signal: controller.signal });
      if (!response.ok || !response.body) return;
      const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
      let buffer = "";
      let pending = false;
      for (;;) {
        const { value, done } = await reader.read();
        if (done) return;
        buffer += value;
        let end;
        while ((end = buffer.search(/\r?\n\r?\n/)) >= 0) {
          const block = buffer.slice(0, end);
          buffer = buffer.slice(end).replace(/^\r?\n\r?\n/, "");
          for (const line of block.split(/\r?\n/)) {
            if (!line.startsWith("data:")) continue;
            try {
              const event = JSON.parse(line.slice(5));
              if (event.event === "ws" && event.flow && event.flow.flow_id === id) {
                add(event.flow);
                if (!pending) {
                  pending = true;
                  requestAnimationFrame(() => { pending = false; draw(); });
                }
              }
            } catch (_) { /* skip a malformed event */ }
          }
        }
        if (!container.isConnected) {
          controller.abort();
          return;
        }
      }
    }

    draw();
    // Subscribe first, then load the history, so nothing falls between the two.
    live().catch(() => {});
    history().then(draw).catch(() => {});
    return controller;
  }

  let current = null;
  function render(flow, container) {
    if (current) current.abort();
    current = null;
    if (!isWebSocket(flow)) {
      container.replaceChildren(el("p", "hint", "Not a WebSocket flow."));
      return;
    }
    current = mount(flow, container);
  }

  const tab = { id: "messages", title: "Messages", visible: isWebSocket, render: render };

  /** Without a tab registry: a tab button of our own that renders into #panel. */
  function standalone() {
    const tablist = document.querySelector("[role=tablist]");
    const panel = document.getElementById("panel");
    if (!tablist || !panel) return;
    const button = el("button", null, tab.title);
    button.type = "button";
    button.id = "tab-messages";
    button.setAttribute("role", "tab");
    button.dataset.tab = "messages";
    button.setAttribute("aria-selected", "false");
    tablist.append(button);
    const selected = () => (typeof flows !== "undefined" && typeof selectedId !== "undefined" && selectedId !== null
      ? flows.get(selectedId) : null);
    const show = () => {
      for (const other of tablist.querySelectorAll("[role=tab]")) {
        other.setAttribute("aria-selected", String(other === button));
      }
      panel.setAttribute("aria-labelledby", "tab-messages");
      panel.replaceChildren();
      panel.dataset.tab = "messages";
      const m = selected();
      if (m) render(m, panel);
      else panel.append(el("p", "hint", "Select a flow."));
    };
    button.addEventListener("click", show);
    // Show the button only for WebSocket flows; follow selection changes.
    const refresh = () => {
      const m = selected();
      button.hidden = !isWebSocket(m);
      if (button.hidden && button.getAttribute("aria-selected") === "true") {
        const first = tablist.querySelector("[role=tab]");
        if (first) first.click();
      }
    };
    setInterval(refresh, 500);
    const fragment = new URLSearchParams(location.hash.slice(1));
    if (fragment.get("tab") === "messages") {
      const wait = (tries) => {
        if (isWebSocket(selected())) { refresh(); show(); } else if (tries > 0) setTimeout(() => wait(tries - 1), 200);
      };
      wait(50);
    }
  }

  function connect() {
    if (typeof window.registerTab === "function") window.registerTab(tab);
    else standalone();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", connect);
  else connect();
})();
