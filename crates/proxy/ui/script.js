// The Scripts panel: the `--script` files (name, hooks, last error) and the script log.
//
// Same rules as app.js: createElement and textContent only (the h() helper), no HTML
// strings. Uses app.js's top-level helpers (h, apiJson). Shows a "Scripts" toolbar button
// only when the proxy runs with at least one --script file (`GET /api/v1/script`).
"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const actions = document.querySelector(".toolbar .actions");
  if (!actions) return;
  const REFRESH_MS = 2000;
  let entries = [];
  let lastSeq = 0;
  let timer = null;

  const box = h("div", "script-panel");
  box.id = "script-panel";
  box.hidden = true;
  box.setAttribute("role", "dialog");
  box.setAttribute("aria-label", "Scripts");
  Object.assign(box.style, {
    position: "fixed", right: "16px", top: "56px", zIndex: "50",
    width: "min(560px, calc(100vw - 32px))", maxHeight: "70vh", overflow: "auto",
    padding: "12px", background: "var(--bg)", color: "var(--fg)",
    border: "1px solid var(--fg-dim)", borderRadius: "6px",
  });
  document.body.append(box);

  const button = h("button", null, "Scripts");
  button.type = "button";
  button.hidden = true;
  button.setAttribute("aria-controls", box.id);
  button.setAttribute("aria-expanded", "false");
  button.addEventListener("click", () => (box.hidden ? open() : close()));
  actions.prepend(button);

  function close() {
    box.hidden = true;
    button.setAttribute("aria-expanded", "false");
    clearInterval(timer);
    timer = null;
  }

  function open() {
    box.hidden = false;
    button.setAttribute("aria-expanded", "true");
    refresh();
    timer = setInterval(refresh, REFRESH_MS);
  }

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !box.hidden) close();
  });

  function hookText(name, hook) {
    if (!hook || !hook.defined) return null;
    return name + (hook.body ? " (body)" : "");
  }

  function render(scripts) {
    const files = scripts.map((s) => {
      const hooks = [hookText("on_request", s.request), hookText("on_response", s.response)]
        .filter(Boolean).join(", ") || "no hooks";
      const status = s.error ? "error" : (s.loaded ? "loaded" : "not loaded");
      const row = h("li", null, null, [
        h("strong", null, s.file),
        h("span", null, " — " + status + " — " + hooks),
      ]);
      if (s.error) {
        const err = h("pre", null, s.error);
        err.style.whiteSpace = "pre-wrap";
        err.style.color = "var(--fg-dim)";
        row.append(err);
      }
      return row;
    });
    const log = h("pre", null, entries.length
      ? entries.map((e) => e.time + "  " + e.file + "  " + e.level + "  " + e.text).join("\n")
      : "No log lines yet.");
    log.style.whiteSpace = "pre-wrap";
    log.setAttribute("aria-live", "polite");
    box.replaceChildren(
      h("h2", null, "Scripts"),
      h("ul", null, null, files),
      h("h3", null, "Log"),
      log,
    );
  }

  async function refresh() {
    try {
      const [report, log] = await Promise.all([
        apiJson("script"),
        apiJson("script/log?after=" + lastSeq),
      ]);
      for (const entry of log.entries) {
        entries.push(entry);
        lastSeq = Math.max(lastSeq, entry.seq);
      }
      entries = entries.slice(-500);
      render(report.scripts);
    } catch (e) {
      box.replaceChildren(h("p", null, "Could not load scripts: " + e.message));
    }
  }

  apiJson("script")
    .then((report) => { button.hidden = !(report.scripts && report.scripts.length); })
    .catch(() => { /* older proxy or no token yet: no button */ });
});
