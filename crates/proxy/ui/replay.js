// Replay and compose on top of app.js: "Replay" sends the selected exchange again as it
// was, "Edit & replay" opens it in an editor first, "New request" composes one from
// scratch. The answer is a new flow flagged `replay`; the Replay tab links it back.
//
// Same rules as app.js: createElement and textContent only (the h() helper), no HTML
// strings, no inline handlers. Uses app.js's top-level helpers (h, api, flows, select,
// hooks, toast, registerTab, hexDump, bodyBytes, fmtSize).
"use strict";

// panels.js shows #replay-slot when this is set.
window.WIRUST_REPLAY = true;

document.addEventListener("DOMContentLoaded", () => {
  const slot = document.getElementById("replay-slot");
  if (!slot) return;
  slot.hidden = false;

  function button(label, cls, onClick) {
    const b = h("button", cls || null, label);
    b.type = "button";
    b.addEventListener("click", onClick);
    return b;
  }

  /** The error text for a refused replay or compose, in plain words. */
  function refusal(status, message) {
    if (status === 429) {
      return "Too many replays at once (at most 8 in flight and 20 per second). Wait a moment " +
        "and send again. (" + message + ")";
    }
    if (status === 409) return "Cannot replay as is: " + message;
    if (status === 403) return "Refused: " + message;
    return message || "HTTP " + status;
  }

  /** POSTs `body` to `path`; returns the new flow id or throws a readable Error. */
  async function send(path, body) {
    const response = await api(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    let answer = null;
    try { answer = await response.json(); } catch (_) { /* not JSON */ }
    if (!response.ok) throw new Error(refusal(response.status, answer && answer.error));
    return answer.flow_id;
  }

  /** Selects flow `id` once the event stream has delivered it. */
  function showWhenLoaded(id) {
    const open = (tries) => {
      if (flows.has(id)) select(id, true);
      else if (tries > 0) setTimeout(() => open(tries - 1), 100);
    };
    open(50);
  }

  function current() {
    const m = selectedId === null ? null : flows.get(selectedId);
    return m && m.kind === "exchange" && m.state === "done" ? m : null;
  }

  const replayButton = button("Replay", null, async () => {
    const m = current();
    if (!m) return;
    try {
      const id = await send("flows/" + m.id + "/replay", {});
      toast("Replayed #" + m.id + " as #" + id);
      showWhenLoaded(id);
    } catch (e) {
      toast(e.message);
    }
  });
  replayButton.title = "Send the selected request again as it was";
  const editButton = button("Edit & replay", null, () => {
    const m = current();
    // The list holds summaries; the editor needs the whole record (headers, body).
    if (m) fullFlow(m.id).then(openEditor, (e) => toast(e.message));
  });
  editButton.title = "Change method, URL, headers or body, then send";
  const composeButton = button("New request", null, () => openEditor(null));
  composeButton.title = "Compose a request from scratch";
  replayButton.disabled = editButton.disabled = true;
  slot.append(replayButton, editButton, composeButton);

  hooks.detail.push(() => {
    replayButton.disabled = editButton.disabled = !current();
  });

  // -------------------------------------------------------------------------
  // The editor: one <dialog>, built again for each request.

  const dialog = h("dialog", "replay-dialog");
  dialog.setAttribute("aria-label", "Edit and send a request");
  document.body.append(dialog);

  /** `[name, value]` pairs grouped by lower-case name, joined as the edit API expects. */
  function grouped(rows) {
    const map = new Map();
    for (const { name, value } of rows) {
      const key = name.trim().toLowerCase();
      if (!key) continue;
      map.set(key, map.has(key) ? map.get(key) + (key === "cookie" ? "; " : ", ") + value : value);
    }
    return map;
  }

  /** The editor state for flow `f`, or an empty request when `f` is null. */
  function makeDraft(f) {
    const rows = f
      ? (f.request_headers || []).filter(([k]) => !k.startsWith(":")).map(([k, v]) => ({ name: k, value: v }))
      : [{ name: "content-type", value: "application/json" }];
    const body = f ? f.request_body : null;
    const textBody = !body || (body.encoding !== "base64" && !body.truncated);
    return {
      flow: f,
      method: f ? f.method : "GET",
      url: f ? f.url : "",
      headers: rows,
      original: rows.map((x) => ({ name: x.name, value: x.value })),
      stored: body,
      bodyEditable: textBody,
      body: textBody && body ? body.data : "",
      origBody: textBody && body ? body.data : "",
      replaceBody: false,
      applyRules: false,
      error: "",
      busy: false,
    };
  }

  let draft = null;

  function openEditor(f) {
    draft = makeDraft(f);
    render();
    if (!dialog.open) dialog.showModal();
  }

  function input(value, onInput, cls, label) {
    const i = h("input", cls || null);
    i.value = value;
    i.spellcheck = false;
    i.autocomplete = "off";
    i.setAttribute("aria-label", label);
    i.addEventListener("input", () => onInput(i.value));
    return i;
  }

  function render() {
    const d = draft;
    dialog.replaceChildren();
    const title = d.flow ? "Edit & replay flow #" + d.flow.id : "New request";
    dialog.append(h("h2", null, title));
    const method = input(d.method, (v) => { d.method = v; }, "method-input", "Method");
    const url = input(d.url, (v) => { d.url = v; }, "url-input", "URL");
    url.placeholder = "absolute URL: scheme://host/path";
    dialog.append(h("div", "field-row", null, [method, url]));

    dialog.append(h("h3", null, "Headers"));
    const tbody = h("tbody");
    d.headers.forEach((row, index) => {
      const name = input(row.name, (v) => { row.name = v; }, "h-name-input", "Header name");
      const value = input(row.value, (v) => { row.value = v; }, "h-value-input", "Value of " + row.name);
      const del = button("×", "mini", () => {
        d.headers.splice(index, 1);
        render();
        // The rows were rebuilt: keep focus on the next delete button, or on "Add header".
        const dels = dialog.querySelectorAll("table.headers button.mini");
        (dels[Math.min(index, dels.length - 1)] || dialog.querySelector(".body-bar .mini")).focus();
      });
      del.setAttribute("aria-label", "Delete header " + row.name);
      tbody.append(h("tr", null, null, [h("td", null, null, [name]), h("td", null, null, [value]), h("td", null, null, [del])]));
    });
    dialog.append(h("table", "headers edit", null, [tbody]));
    dialog.append(h("div", "body-bar", null, [
      button("Add header", "mini", () => {
        d.headers.push({ name: "", value: "" });
        render();
        const names = dialog.querySelectorAll(".h-name-input");
        names[names.length - 1].focus();
      }),
    ]));

    dialog.append(h("h3", null, "Body"));
    const area = h("textarea", "body-input");
    area.spellcheck = false;
    area.setAttribute("aria-label", "Body");
    area.value = d.body;
    area.addEventListener("input", () => { d.body = area.value; });
    if (!d.bodyEditable) {
      const s = d.stored;
      if (s.truncated) {
        dialog.append(h("p", "notice", "The stored body was cut at " + fmtSize(s.size) + " by --body-limit; " +
          "a replay needs a new body."));
      } else {
        dialog.append(h("p", "notice", "binary, " + s.size + " bytes, not editable: it is sent as recorded " +
          "unless you replace it."));
        dialog.append(hexDump(bodyBytes(s)));
      }
      const replace = h("input");
      replace.type = "checkbox";
      replace.id = "replay-replace-body";
      replace.checked = d.replaceBody;
      area.disabled = !d.replaceBody;
      replace.addEventListener("change", () => {
        d.replaceBody = replace.checked;
        area.disabled = !replace.checked;
        if (replace.checked) area.focus();
      });
      const label = h("label", null, "Replace the body with this text");
      label.htmlFor = replace.id;
      dialog.append(h("div", "field-row", null, [replace, label]));
    }
    dialog.append(area);

    const rules = h("input");
    rules.type = "checkbox";
    rules.id = "replay-apply-rules";
    rules.checked = d.applyRules;
    rules.addEventListener("change", () => { d.applyRules = rules.checked; });
    const rulesLabel = h("label", null, "Apply rules and breakpoints");
    rulesLabel.htmlFor = rules.id;
    dialog.append(h("div", "field-row", null, [rules, rulesLabel]));

    const err = h("div", "error-box", d.error);
    err.setAttribute("role", "alert");
    err.hidden = !d.error;
    dialog.append(err);
    const sendButton = button(d.flow ? "Send replay" : "Send", "primary", submit);
    sendButton.disabled = d.busy;
    dialog.append(h("div", "pause-actions", null, [sendButton, button("Cancel", null, () => dialog.close())]));
  }

  /** The replay edit: only what changed (the pause edit format, see docs/replay.md). */
  function replayBody(d) {
    const f = d.flow;
    const body = { apply_rules: d.applyRules };
    if (d.method.trim() && d.method.trim() !== f.method) body.method = d.method.trim();
    if (d.url.trim() && d.url.trim() !== f.url) body.url = d.url.trim();
    const now = grouped(d.headers);
    const before = grouped(d.original);
    const set = {};
    for (const [k, v] of now) if (before.get(k) !== v) set[k] = v;
    const remove = [...before.keys()].filter((k) => !now.has(k));
    if (Object.keys(set).length) body.set_headers = set;
    if (remove.length) body.remove_headers = remove;
    if (d.bodyEditable ? d.body !== d.origBody : d.replaceBody) body.body = d.body;
    return body;
  }

  function composeBody(d) {
    const body = {
      method: d.method.trim(),
      url: d.url.trim(),
      headers: d.headers.filter((x) => x.name.trim()).map((x) => [x.name.trim(), x.value]),
      apply_rules: d.applyRules,
    };
    if (d.body) body.body = d.body;
    return body;
  }

  async function submit() {
    const d = draft;
    d.busy = true;
    d.error = "";
    render();
    try {
      const id = d.flow
        ? await send("flows/" + d.flow.id + "/replay", replayBody(d))
        : await send("compose", composeBody(d));
      if (draft === d) dialog.close();
      toast((d.flow ? "Replayed #" + d.flow.id + " as #" : "Sent as #") + id);
      showWhenLoaded(id);
    } catch (e) {
      d.error = e.message;
    }
    d.busy = false;
    if (draft === d && dialog.open) {
      render();
      // render() rebuilt the dialog, so focus went with the old Send button; put it back.
      dialog.querySelector(".pause-actions .primary").focus();
    }
  }

  // Links: #panel=compose opens New request; #panel=edit-replay&flow=N opens Edit & replay.
  if (fragment.get("panel") === "compose") openEditor(null);
  if (fragment.get("panel") === "edit-replay" && fragment.has("flow")) {
    const wanted = Number(fragment.get("flow"));
    const open = (tries) => {
      const m = flows.get(wanted);
      if (m && m.kind === "exchange" && m.state === "done") fullFlow(wanted).then(openEditor, (e) => toast(e.message));
      else if (tries > 0) setTimeout(() => open(tries - 1), 200);
    };
    open(50);
  }

  // -------------------------------------------------------------------------
  // The Replay tab: links a replay to its original and an original to its replays.

  function replaysOf(id) {
    const out = [];
    for (const m of flows.values()) if (m.raw && m.raw.replay_of === id) out.push(m.id);
    return out.sort((a, b) => a - b);
  }

  function link(id) {
    const b = button("#" + id, "link", () => select(id, true));
    const m = flows.get(id);
    b.title = m ? m.method + " " + m.url : "flow " + id;
    return b;
  }

  registerTab({
    id: "replay",
    title: "Replay",
    visible: (f) => f.type === "exchange" && (f.replay_of != null || (f.flags || []).includes("replay") ||
      replaysOf(f.id).length > 0),
    render: (f, panel) => {
      if (f.replay_of != null) {
        const parts = [h("span", null, "A replay of flow ")];
        parts.push(flows.has(f.replay_of) ? link(f.replay_of) : h("span", null, "#" + f.replay_of + " (not loaded)"));
        panel.append(h("p", null, null, parts));
        const orig = flows.get(f.replay_of);
        if (orig) {
          const table = h("table", "headers");
          const tbody = h("tbody");
          const row = (k, a, b, cls) => tbody.append(h("tr", cls, null,
            [h("td", "h-name", k), h("td", "h-value", a), h("td", "h-value", b)]));
          row("", "original #" + orig.id, "this replay #" + f.id, null);
          const diff = (k, a, b) => row(k, a, b, a === b ? null : "changed");
          diff("Method", orig.method, f.method);
          diff("URL", orig.url, f.url);
          diff("Status", orig.status == null ? "-" : String(orig.status), f.status == null ? "-" : String(f.status));
          diff("Size", orig.size == null ? "-" : fmtSize(orig.size), f.response_body ? fmtSize(f.response_body.size) : "-");
          table.append(tbody);
          panel.append(table);
        }
      } else if ((f.flags || []).includes("replay")) {
        panel.append(h("p", null, "Composed from scratch (New request); it replays no stored flow."));
      }
      const later = replaysOf(f.id);
      if (later.length) {
        const parts = [h("span", null, "Replayed as ")];
        later.forEach((id, i) => { if (i) parts.push(h("span", null, ", ")); parts.push(link(id)); });
        panel.append(h("p", null, null, parts));
      }
      panel.append(h("div", "body-bar", null, [
        button("Replay again", null, () => replayButton.click()),
        button("Edit & replay", null, () => openEditor(f)),
      ]));
    },
  });
});
