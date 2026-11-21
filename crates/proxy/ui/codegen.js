// "Copy as..." next to "Copy as cURL": a button that opens a list of languages and copies the
// selected request as code from the server (`GET /api/v1/flows/{id}/code?lang=`). Keyboard:
// Down opens the list, arrows move, Home and End jump, Enter picks, Escape closes.
//
// Same rules as app.js: createElement and textContent only (the h() helper), no HTML strings,
// no inline handlers. Uses app.js's top-level helpers (h, api, flows, selectedId, copy, toast).
"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const anchor = document.getElementById("copy-curl");
  if (!anchor) return;

  const LANGUAGES = [
    ["python", "Python (requests)"],
    ["fetch", "JavaScript (fetch)"],
    ["okhttp", "Kotlin (OkHttp)"],
    ["urlsession", "Swift (URLSession)"],
    ["httpie", "HTTPie"],
    ["powershell", "PowerShell"],
  ];

  const trigger = h("button", null, "Copy as…");
  trigger.type = "button";
  trigger.id = "copy-code";
  trigger.disabled = anchor.disabled;
  trigger.setAttribute("aria-haspopup", "menu");
  trigger.setAttribute("aria-expanded", "false");

  const menu = h("div", "codegen-menu");
  menu.setAttribute("role", "menu");
  menu.setAttribute("aria-label", "Copy the request as code");
  menu.hidden = true;

  const items = LANGUAGES.map(([lang, label]) => {
    const item = h("button", "codegen-item", label);
    item.type = "button";
    item.dataset.lang = lang;
    item.setAttribute("role", "menuitem");
    item.tabIndex = -1;
    item.addEventListener("click", () => pick(lang));
    return item;
  });
  menu.append(...items);

  const wrap = h("span", "codegen", null, [trigger, menu]);
  anchor.after(wrap);

  // app.js enables and disables "Copy as cURL" with the selection; follow it.
  new MutationObserver(() => {
    trigger.disabled = anchor.disabled;
    if (trigger.disabled) close(false);
  }).observe(anchor, { attributes: true, attributeFilter: ["disabled"] });

  function isOpen() {
    return !menu.hidden;
  }

  function open() {
    if (trigger.disabled) return;
    menu.hidden = false;
    trigger.setAttribute("aria-expanded", "true");
    items[0].focus();
  }

  function close(refocus) {
    menu.hidden = true;
    trigger.setAttribute("aria-expanded", "false");
    if (refocus) trigger.focus();
  }

  function move(step) {
    const at = items.indexOf(document.activeElement);
    const next = at < 0 ? (step > 0 ? 0 : items.length - 1) : (at + step + items.length) % items.length;
    items[next].focus();
  }

  async function pick(lang) {
    close(true);
    const m = selectedId === null ? null : flows.get(selectedId);
    if (!m || m.kind !== "exchange") return;
    if (m.state !== "done") {
      toast("The exchange is still running");
      return;
    }
    try {
      const response = await api("flows/" + m.id + "/code?lang=" + encodeURIComponent(lang));
      if (!response.ok) {
        let reason = "HTTP " + response.status;
        try { reason = (await response.json()).error || reason; } catch (_) { /* not JSON */ }
        toast(reason);
        return;
      }
      copy(await response.text());
    } catch (_) {
      toast("Could not reach the proxy");
    }
  }

  trigger.addEventListener("click", () => (isOpen() ? close(false) : open()));
  trigger.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      e.stopPropagation();
      open();
    }
  });
  menu.addEventListener("keydown", (e) => {
    switch (e.key) {
      case "ArrowDown": move(1); break;
      case "ArrowUp": move(-1); break;
      case "Home": items[0].focus(); break;
      case "End": items[items.length - 1].focus(); break;
      case "Escape": close(true); break;
      case "Tab": close(false); return;
      default: return; // Enter and Space click the focused item by themselves
    }
    e.preventDefault();
    e.stopPropagation();
  });
  document.addEventListener("click", (e) => {
    if (isOpen() && !wrap.contains(e.target)) close(false);
  });
});
