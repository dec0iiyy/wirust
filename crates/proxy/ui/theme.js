// The theme override: system (default), light or dark. Loaded without `defer` in <head> so
// the stored choice is on <html> before the first paint; style.css reads `data-theme`.
// localStorage may be missing or throw (private windows, blocked storage): the page then
// follows the system setting and the toggle still works for this page.
"use strict";

(() => {
  const KEY = "wirust.theme";
  const MODES = ["system", "light", "dark"];
  const root = document.documentElement;

  function stored() {
    try {
      const value = window.localStorage.getItem(KEY);
      return MODES.includes(value) ? value : "system";
    } catch (_) {
      return "system";
    }
  }

  function apply(mode) {
    if (mode === "system") delete root.dataset.theme;
    else root.dataset.theme = mode;
    const button = document.getElementById("theme-toggle");
    if (button) {
      const label = "Theme: " + mode + " (click to change)";
      button.title = label;
      button.setAttribute("aria-label", label);
      button.dataset.mode = mode;
    }
  }

  let mode = stored();
  apply(mode);
  document.addEventListener("DOMContentLoaded", () => {
    apply(mode);
    const button = document.getElementById("theme-toggle");
    if (!button) return;
    button.addEventListener("click", () => {
      mode = MODES[(MODES.indexOf(mode) + 1) % MODES.length];
      apply(mode);
      try {
        if (mode === "system") window.localStorage.removeItem(KEY);
        else window.localStorage.setItem(KEY, mode);
      } catch (_) {
        // Not stored: the choice lasts until the page reloads.
      }
    });
  });
})();
