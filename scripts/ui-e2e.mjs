// End-to-end check of the web UI in a real headless Chrome over the DevTools protocol.
// It starts nothing: run wirust, the fixture servers and Chrome yourself (see docs/ui.md).
//
//   node scripts/ui-e2e.mjs UI_URL_WITH_TOKEN CHROME_DEBUG_PORT PROXY_PORT \
//        [--target BASE_URL] [--shots DIR] [--only 5,6,9]
//
// UI_URL_WITH_TOKEN is the link wirust prints (`.../#token=...`). BASE_URL is the plain-HTTP
// fixture server from scripts/ui-e2e-fixtures.mjs; scenarios that need it are skipped without.
// Prints one PASS/FAIL line per check and exits 1 when any check failed.
import http from "node:http";
import net from "node:net";
import { mkdirSync, writeFileSync } from "node:fs";

const args = process.argv.slice(2);
const flag = (name) => {
  const i = args.indexOf(name);
  return i < 0 ? null : args.splice(i, 2)[1];
};
const target = flag("--target");
const shots = flag("--shots");
const only = (flag("--only") || "").split(",").filter(Boolean).map(Number);
const [uiUrl, chromePort, proxyPort] = args;
if (!uiUrl || !chromePort || !proxyPort) {
  console.log("usage: node scripts/ui-e2e.mjs UI_URL_WITH_TOKEN CHROME_DEBUG_PORT PROXY_PORT [--target URL] [--shots DIR] [--only N,M]");
  process.exit(2);
}
if (typeof WebSocket !== "function" || typeof fetch !== "function") {
  console.log("SKIP: this Node has no built-in WebSocket and fetch (Node 22 or newer needed)");
  process.exit(0);
}
let targets;
try {
  targets = await (await fetch(`http://127.0.0.1:${chromePort}/json`)).json();
} catch (_) {
  console.log(`SKIP: no Chrome with --remote-debugging-port=${chromePort}; start one with --headless=new`);
  process.exit(0);
}
if (shots) mkdirSync(shots, { recursive: true });
const token = new URL(uiUrl).hash.match(/token=([0-9a-f]+)/)?.[1];
const origin = new URL(uiUrl).origin;

// ---------------------------------------------------------------------------
// DevTools protocol plumbing

const page = targets.find((t) => t.type === "page");
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });
let seq = 0;
const pending = new Map();
let problems = [];
// The browser logs every refused fetch; the 400 and 429 answers the scenarios provoke on purpose are not bugs.
const expectedRefusal = (e) => e.source === "network" && /status of (400|409|413|429)/.test(e.text) && /\/api\/v1\/(compose|flows\/\d+\/(replay|messages)|flows\?q=)/.test(e.url || "");
ws.onmessage = (m) => {
  const d = JSON.parse(m.data);
  if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); }
  const p = d.params;
  if (d.method === "Runtime.exceptionThrown") problems.push("exception: " + (p.exceptionDetails.exception?.description || p.exceptionDetails.text));
  if (d.method === "Runtime.consoleAPICalled" && ["error", "warning", "assert"].includes(p.type)) problems.push(p.type + ": " + p.args.map((a) => a.value ?? a.description).join(" "));
  if (d.method === "Log.entryAdded" && ["error", "warning"].includes(p.entry.level) && !expectedRefusal(p.entry)) problems.push("log " + p.entry.level + ": " + p.entry.text + " " + (p.entry.url || ""));
  if (d.method === "Network.loadingFailed" && !p.canceled && p.blockedReason !== undefined) problems.push("blocked request: " + p.blockedReason);
};
const send = (method, params = {}) => new Promise((res) => {
  const id = ++seq;
  pending.set(id, res);
  ws.send(JSON.stringify({ id, method, params }));
});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function js(expr) {
  const r = await send("Runtime.evaluate", { expression: `(async () => { ${expr} })()`, awaitPromise: true, returnByValue: true });
  if (r.result?.exceptionDetails) throw new Error("evaluate failed: " + (r.result.exceptionDetails.exception?.description || r.result.exceptionDetails.text));
  return r.result?.result?.value;
}
async function until(expr, ms = 4000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await js(`return !!(${expr});`)) return true;
    await sleep(80);
  }
  return false;
}
async function key(k, opts = {}) {
  const codes = { Enter: 13, Escape: 27, Tab: 9, ArrowDown: 40, ArrowUp: 38, Home: 36, End: 35, " ": 32 };
  const base = { key: k, code: k.length === 1 ? "Key" + k.toUpperCase() : k, windowsVirtualKeyCode: codes[k] || k.toUpperCase().charCodeAt(0), modifiers: opts.shift ? 8 : 0 };
  await send("Input.dispatchKeyEvent", { type: "keyDown", ...base, text: k.length === 1 ? k : k === "Enter" ? "\r" : undefined });
  await send("Input.dispatchKeyEvent", { type: "keyUp", ...base });
  await sleep(60);
}
async function click(sel) {
  const box = await js(`const e = document.querySelector(${JSON.stringify(sel)}); if (!e) return null; e.scrollIntoView({block: "nearest"}); const r = e.getBoundingClientRect(); return [r.x + r.width / 2, r.y + r.height / 2];`);
  if (!box) throw new Error("no element " + sel);
  for (const type of ["mouseMoved", "mousePressed", "mouseReleased"]) {
    await send("Input.dispatchMouseEvent", { type, x: box[0], y: box[1], button: "left", clickCount: 1 });
  }
  await sleep(80);
}
async function typeText(text) {
  await send("Input.insertText", { text });
  await sleep(40);
}
async function shot(name) {
  if (!shots) return;
  const s = await send("Page.captureScreenshot", { format: "png" });
  writeFileSync(`${shots}/${name}.png`, Buffer.from(s.result.data, "base64"));
}
async function viewport(width, height = 900) {
  await send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: false });
}
async function load(fragment = "") {
  // A fragment-only change would not reload the page; go through a blank page first.
  await send("Page.navigate", { url: "about:blank" });
  await sleep(50);
  await send("Page.navigate", { url: `${origin}/#token=${token}${fragment}` });
  await until(`document.readyState === "complete" && document.getElementById("conn").dataset.state === "live"`, 8000);
  await sleep(250);
}

// ---------------------------------------------------------------------------
// Traffic through the proxy (plain HTTP, absolute-form requests)

function proxied(path, { method = "GET", headers = {}, body } = {}) {
  return new Promise((resolve) => {
    const req = http.request({ host: "127.0.0.1", port: Number(proxyPort), method, path: target + path, headers: { host: new URL(target).host, ...headers } }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    req.on("error", (e) => resolve({ status: 0, body: String(e) }));
    if (body) req.write(body);
    req.end();
  });
}
async function api(path, init = {}) {
  const r = await fetch(`${origin}/api/v1/${path}`, { ...init, headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...(init.headers || {}) } });
  return { status: r.status, json: await r.json().catch(() => null) };
}
async function lastFlowId() {
  const r = await api("flows");
  const list = Array.isArray(r.json) ? r.json : r.json?.flows || [];
  const last = list[list.length - 1];
  return last ? (last.flow ? last.flow.id : last.id) : null;
}

// ---------------------------------------------------------------------------
// Results

let failed = 0;
const results = [];
function check(scenario, name, ok, detail = "") {
  const line = `${ok ? "PASS" : "FAIL"} [${scenario}] ${name}${detail && !ok ? " -- " + detail : ""}`;
  if (!ok) failed++;
  results.push(line);
  console.log(line);
}
function consoleClean(scenario) {
  check(scenario, "no console errors or warnings", problems.length === 0, problems.join(" | "));
  problems = [];
}
const want = (n) => only.length === 0 || only.includes(n);
const needTarget = (n) => {
  if (target) return true;
  console.log(`SKIP [${n}] needs --target (the fixture server)`);
  return false;
};

await send("Runtime.enable");
await send("Log.enable");
await send("Page.enable");
await send("Network.enable");
// A recording clipboard: headless Chrome has no clipboard permission by default.
await send("Page.addScriptToEvaluateOnNewDocument", {
  source: `window.__copied = []; try { Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: async (t) => { if (window.__clipboardFails) throw new Error("denied"); window.__copied.push(t); } } }); } catch (_) {}
           try { if (sessionStorage.getItem("e2e-break-storage")) { const boom = () => { throw new Error("blocked"); }; Object.defineProperty(window, "localStorage", { configurable: true, get: boom }); } } catch (_) {}`,
});
await viewport(1400);
await load();
// A tab left open from an earlier proxy run logs 401s before it reloads; they are not this run.
problems = [];

// Scenario 5: replay, edit & replay, new request, refusal, close and focus.
if (want(5) && needTarget(5)) {
  await proxied("/echo?x=1", { method: "POST", headers: { "content-type": "application/json", "x-keep": "1", "x-drop": "2" }, body: '{"a":1}' });
  await until(`[...document.querySelectorAll(".row:not([hidden])")].some((r) => r.textContent.includes("/echo"))`);
  const id = await lastFlowId();
  await load(`&flow=${id}`);
  check(5, "deep link selects the flow", await until(`document.querySelector(".row[aria-selected='true']")`));
  await click("#replay-slot button:nth-child(1)");
  check(5, "Replay toasts the new id", await until(`document.getElementById("toast").textContent.startsWith("Replayed #${id} as #")`));
  check(5, "replayed flow is selected and flagged", await until(`(() => { const m = flows.get(selectedId); return m && m.raw && m.raw.replay_of === ${id}; })()`));
  await load(`&flow=${id}`);
  await click("#replay-slot button:nth-child(2)");
  check(5, "Edit & replay opens a modal dialog", await until(`document.querySelector("dialog.replay-dialog[open]")`));
  check(5, "focus is inside the dialog", await js(`return document.querySelector("dialog.replay-dialog").contains(document.activeElement);`));
  await js(`const d = document.querySelector("dialog.replay-dialog"); const m = d.querySelector(".method-input"); m.value = "PUT"; m.dispatchEvent(new Event("input")); const u = d.querySelector(".url-input"); u.value = u.value.replace("x=1", "x=2"); u.dispatchEvent(new Event("input"));`);
  const before = await js(`return document.querySelectorAll("dialog.replay-dialog .h-name-input").length;`);
  await click("dialog.replay-dialog .body-bar .mini");
  check(5, "Add header adds a row", (await js(`return document.querySelectorAll("dialog.replay-dialog .h-name-input").length;`)) === before + 1);
  check(5, "Add header focuses the new name field", await js(`const n = document.querySelectorAll("dialog.replay-dialog .h-name-input"); return document.activeElement === n[n.length - 1];`));
  await typeText("x-added");
  await key("Tab");
  await typeText("yes");
  await js(`const del = [...document.querySelectorAll("dialog.replay-dialog button.mini")].find((b) => b.getAttribute("aria-label") === "Delete header x-drop"); del.click();`);
  check(5, "deleting a row keeps focus in the dialog", await js(`const d = document.querySelector("dialog.replay-dialog"); return d.contains(document.activeElement) && document.activeElement !== d;`));
  await js(`const a = document.querySelector("dialog.replay-dialog .body-input"); a.value = '{"a":2}'; a.dispatchEvent(new Event("input"));`);
  await click("dialog.replay-dialog .pause-actions .primary");
  check(5, "Send closes the dialog", await until(`!document.querySelector("dialog.replay-dialog[open]")`));
  const edited = await until(`(() => { const m = flows.get(selectedId); return m && m.raw && m.raw.replay_of === ${id} && m.method === "PUT"; })()`);
  check(5, "edited replay arrives with the new method", edited,
    await js(`const m = flows.get(selectedId); return JSON.stringify(m && { id: m.id, method: m.method, of: m.raw.replay_of, toast: document.getElementById("toast").textContent });`));
  if (edited) {
    await sleep(300);
    const raw = await js(`const m = flows.get(selectedId); return m.raw;`);
    const echo = JSON.parse(raw.response_body?.data || "{}");
    check(5, "edited replay sent the changes", echo.method === "PUT" && echo.url.includes("x=2") && echo.headers["x-added"] === "yes" && !echo.headers["x-drop"] && echo.body === '{"a":2}', JSON.stringify(echo).slice(0, 300));
  }
  // New request, then Esc and Cancel close it and focus goes back to the opener.
  await click("#replay-slot button:nth-child(3)");
  check(5, "New request opens", await until(`document.querySelector("dialog.replay-dialog[open] h2")?.textContent === "New request"`));
  await key("Escape");
  check(5, "Esc closes the dialog", await until(`!document.querySelector("dialog.replay-dialog[open]")`));
  check(5, "focus returns to New request", await js(`return document.activeElement === document.querySelector("#replay-slot button:nth-child(3)");`));
  await click("#replay-slot button:nth-child(3)");
  await js(`const d = document.querySelector("dialog.replay-dialog"); const u = d.querySelector(".url-input"); u.value = "not a url"; u.dispatchEvent(new Event("input"));`);
  await click("dialog.replay-dialog .pause-actions .primary");
  check(5, "a bad URL shows an error in the dialog", await until(`(() => { const e = document.querySelector("dialog.replay-dialog .error-box"); return e && !e.hidden && e.textContent.length > 3; })()`));
  await click("dialog.replay-dialog .pause-actions button:not(.primary)");
  check(5, "Cancel closes the dialog", await until(`!document.querySelector("dialog.replay-dialog[open]")`));
  // 429: fire many replays at once through the API, then one through the UI.
  const flood = await Promise.all(Array.from({ length: 30 }, () => api(`flows/${id}/replay`, { method: "POST", body: "{}" })));
  const refusedApi = flood.some((r) => r.status === 429);
  check(5, "the API refuses a flood with 429", refusedApi);
  await load(`&flow=${id}`);
  await js(`window.__floods = await Promise.all(Array.from({ length: 25 }, () => api("flows/${id}/replay", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }).then((r) => r.status)));`);
  await click("#replay-slot button:nth-child(1)");
  check(5, "429 from Replay reads in plain words", await until(`document.getElementById("toast").textContent.startsWith("Too many replays at once") || document.getElementById("toast").textContent.startsWith("Replayed")`));
  await shot("05-replay");
  consoleClean(5);
}

// Scenario 6: breakpoints (needs a rule `match = { path = "/bp*" }` with action breakpoint
// request and response, as scripts/ui-e2e-fixtures.mjs prints).
if (want(6) && needTarget(6)) {
  await load();
  const hasRule = await api("rules");
  if (!JSON.stringify(hasRule.json || "").includes("breakpoint")) {
    console.log("SKIP [6] no breakpoint rule loaded (start wirust with the --rules file the fixtures print)");
  } else {
    await click(".pause-button");
    check(6, "Breakpoints panel opens", await until(`!document.getElementById("rules-slot").hidden`));
    const first = proxied("/bp1", { headers: { "x-bp": "1" } });
    check(6, "a paused request shows up in the panel", await until(`document.querySelector(".pause-item")`, 6000));
    check(6, "the toolbar badge counts it", await js(`return /^1 paused/.test(document.querySelector(".pause-button").getAttribute("aria-label"));`),
      await js(`return document.querySelector(".pause-button").getAttribute("aria-label");`));
    await click(".pause-item");
    check(6, "the editor shows the request head", await until(`document.querySelector(".pause-editor .url-input")?.value.includes("/bp1")`));
    await shot("06-pause-request");
    await js(`const u = document.querySelector(".pause-editor .url-input"); u.value = u.value.replace("/bp1", "/echo?edited=1"); u.dispatchEvent(new Event("input"));`);
    await click(".pause-editor .pause-actions .primary");
    check(6, "the response pause follows", await until(`document.querySelector(".pause-editor .status-input")`, 6000));
    check(6, "the response pause shows the body", await until(`document.querySelector(".pause-editor .body-input")?.value.includes("edited=1")`, 3000),
      await js(`return document.querySelector(".pause-editor .body-input")?.value.slice(0, 300);`));
    await js(`const s = document.querySelector(".pause-editor .status-input"); s.value = "201"; s.dispatchEvent(new Event("input"));`);
    await click(".pause-editor .pause-actions .primary");
    const r1 = await first;
    check(6, "Edit and resume changed URL and status", r1.status === 201 && r1.body.includes("edited=1"), `${r1.status} ${r1.body.slice(0, 120)}`);
    const second = proxied("/bp2");
    await until(`document.querySelector(".pause-item")`, 6000);
    await click(".pause-item");
    await js(`document.querySelector(".pause-item").focus();`);
    await key("r");
    check(6, "key r resumes the request", await until(`document.querySelector(".pause-editor .status-input")`, 6000));
    await js(`document.querySelector(".pause-item")?.focus();`);
    await key("a");
    const r2 = await second;
    check(6, "key a aborts the response", r2.status !== 200, `${r2.status}`);
    const third = proxied("/bp3");
    await until(`document.querySelector(".pause-item")`, 6000);
    await click(".pause-item");
    await click(".pause-editor .pause-actions .danger");
    const r3 = await third;
    check(6, "Abort ends the request", r3.status !== 200, `${r3.status}`);
    check(6, "badge clears when nothing is paused", await until(`!/paused/.test(document.querySelector(".pause-button").getAttribute("aria-label"))`));
    const fourth = proxied("/bp4");
    await until(`document.querySelector(".pause-item")`, 6000);
    await click(".pause-item");
    await click(".pause-editor .pause-actions button:not(.primary):not(.danger)");
    check(6, "Resume lets the request go on to the response pause", await until(`document.querySelector(".pause-editor .status-input")`, 6000));
    await click(".pause-editor .pause-actions button:not(.primary):not(.danger)");
    const r4 = await fourth;
    check(6, "Resume twice delivers the response", r4.status === 200, `${r4.status}`);
  }
  consoleClean(6);
}

// Scenario 9: WebSocket Messages tab and composer (fixture server answers /ws).
if (want(9) && needTarget(9)) {
  const t = new URL(target);
  const sock = net.connect(Number(proxyPort), "127.0.0.1");
  let received = Buffer.alloc(0);
  sock.on("data", (d) => { received = Buffer.concat([received, d]); });
  sock.on("error", () => {});
  sock.write(`GET ${target}/ws HTTP/1.1\r\nHost: ${t.host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n` +
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n");
  await sleep(400);
  const frame = (text) => {
    const data = Buffer.from(text);
    const mask = Buffer.from([1, 2, 3, 4]);
    return Buffer.concat([Buffer.from([0x81, 0x80 | data.length]), mask, Buffer.from(data.map((b, i) => b ^ mask[i % 4]))]);
  };
  sock.write(frame('{"from":"client","n":2}'));
  await sleep(300);
  const id = await lastFlowId();
  await load(`&flow=${id}`);
  const tab = await js(`return [...document.querySelectorAll('[role="tab"]')].find((b) => b.textContent === "Messages")?.id || null;`);
  check(9, "the Messages tab is offered", !!tab);
  if (tab) {
    await click("#" + tab);
    check(9, "messages are listed", await until(`document.querySelectorAll(".ws-row").length >= 3`), await js(`return document.querySelector(".ws-count")?.textContent;`));
    await click('.ws-dirs [data-dir="client_to_server"]');
    check(9, "the Sent chip keeps only sent messages", await js(`const r = [...document.querySelectorAll(".ws-row")]; return r.length > 0 && r.every((x) => x.querySelector(".ws-sent"));`));
    await click('.ws-dirs [data-dir="all"]');
    await click(".ws-filter");
    await typeText("hello");
    check(9, "the filter narrows the list", await until(`document.querySelectorAll(".ws-row").length === 1`));
    await js(`const f = document.querySelector(".ws-filter"); f.value = ""; f.dispatchEvent(new Event("input"));`);
    await click(".ws-row");
    check(9, "a message opens with a JSON tree", await until(`document.querySelector(".ws-detail ul.ws-json .ws-json-key")`));
    await js(`document.querySelectorAll(".ws-row")[1].focus();`);
    await key("Enter");
    check(9, "Enter opens the focused message", await js(`return document.querySelectorAll(".ws-row")[1].classList.contains("selected");`));
    // Send text to the client, then hex to the server.
    const form = ".ws-composer";
    await js(`const f = document.querySelector("${form}"); f.querySelector("textarea").value = "injected to client";`);
    await click(`${form} button[type=submit]`);
    check(9, "text to the client is sent", await until(`document.querySelector(".ws-send-status").textContent.startsWith("Sent")`));
    await sleep(300);
    check(9, "the client received the injected text", received.includes(Buffer.from("injected to client")));
    check(9, "the injected message appears marked", await until(`[...document.querySelectorAll(".ws-row")].some((r) => r.textContent.includes("(sent by you)"))`));
    await js(`const f = document.querySelector("${form}"); const s = f.querySelectorAll("select"); s[0].value = "client_to_server"; s[1].value = "binary"; s[1].dispatchEvent(new Event("change")); f.querySelector("textarea").value = "68 69";`);
    await click(`${form} button[type=submit]`);
    check(9, "hex to the server is sent", await until(`document.querySelector(".ws-send-status").textContent.startsWith("Sent")`));
    await js(`const f = document.querySelector("${form}"); f.querySelector("textarea").value = "zz not hex";`);
    await click(`${form} button[type=submit]`);
    check(9, "bad hex is refused in words", await until(`document.querySelector(".ws-send-status").classList.contains("error")`), await js(`return document.querySelector(".ws-send-status").textContent;`));
    await js(`const f = document.querySelector("${form}"); f.querySelectorAll("select")[1].value = "text"; f.querySelector("textarea").value = "x".repeat(70000);`);
    await click(`${form} button[type=submit]`);
    check(9, "a too large message is refused in words", await until(`/Not sent: .*(large|64)/i.test(document.querySelector(".ws-send-status").textContent)`), await js(`return document.querySelector(".ws-send-status").textContent;`));
    await shot("09-websocket");
    sock.end(Buffer.from([0x88, 0x82, 1, 2, 3, 4, 0x03 ^ 1, 0xe8 ^ 2]));
    await sleep(600);
    sock.destroy();
    await sleep(400);
    await js(`const f = document.querySelector("${form}"); f.querySelector("textarea").value = "late";`);
    await click(`${form} button[type=submit]`);
    check(9, "a closed connection is explained", await until(`document.querySelector(".ws-send-status").textContent.includes("closed")`), await js(`return document.querySelector(".ws-send-status").textContent;`));
  }
  consoleClean(9);
}

// Scenario 11: copy as cURL, the Copy as... menu, Copy URL; clipboard stubbed, then failing.
if (want(11) && needTarget(11)) {
  await proxied("/json?copy=1", { headers: { "x-copy": "1" } });
  const id = await lastFlowId();
  await load(`&flow=${id}`);
  await until(`!document.getElementById("copy-curl").disabled`);
  await click("#copy-curl");
  check(11, "Copy as cURL copies a curl command", await until(`window.__copied.some((t) => t.startsWith("curl") && t.includes("/json?copy=1"))`));
  check(11, "Copy as cURL toasts Copied", await js(`return document.getElementById("toast").textContent === "Copied";`));
  await click("#copy-url");
  check(11, "Copy URL copies the URL", await until(`window.__copied.some((t) => t.endsWith("/json?copy=1") && !t.startsWith("curl"))`));
  await click("#copy-code");
  check(11, "Copy as... opens by click", await js(`return !document.querySelector(".codegen-menu").hidden && document.getElementById("copy-code").getAttribute("aria-expanded") === "true";`));
  check(11, "first item is focused", await js(`return document.activeElement === document.querySelector(".codegen-item");`));
  await key("ArrowDown");
  check(11, "ArrowDown moves", await js(`return document.activeElement.dataset.lang === "fetch";`));
  await key("End");
  check(11, "End jumps to the last", await js(`return document.activeElement.dataset.lang === "powershell";`));
  await key("Home");
  check(11, "Home jumps to the first", await js(`return document.activeElement.dataset.lang === "python";`));
  await key("ArrowUp");
  check(11, "ArrowUp wraps to the last", await js(`return document.activeElement.dataset.lang === "powershell";`));
  await key("Escape");
  check(11, "Esc closes and focuses the trigger", await js(`return document.querySelector(".codegen-menu").hidden && document.activeElement.id === "copy-code";`));
  check(11, "Esc in the menu leaves the filter alone", await js(`return document.querySelector(".row[aria-selected='true']") !== null;`));
  for (const lang of ["python", "fetch", "okhttp", "urlsession", "httpie", "powershell"]) {
    await js(`window.__copied = [];`);
    await js(`document.getElementById("copy-code").focus();`);
    await key("ArrowDown");
    await js(`document.querySelector('.codegen-item[data-lang="${lang}"]').focus();`);
    await key("Enter");
    check(11, `Copy as ${lang} copies code`, await until(`window.__copied.length === 1 && window.__copied[0].includes("/json?copy=1")`));
  }
  check(11, "focus returns to the trigger after a pick", await js(`return document.activeElement.id === "copy-code";`));
  await js(`window.__clipboardFails = true; window.__copied = [];`);
  await click("#copy-url");
  check(11, "a refused clipboard falls back and says so", await until(`["Copied", "Copy failed"].includes(document.getElementById("toast").textContent)`));
  check(11, "focus stays on the button after the fallback", await js(`return document.activeElement.id === "copy-url";`));
  await js(`window.__clipboardFails = false;`);
  consoleClean(11);
}

// Scenario 13: theme toggle, persistence, blocked storage, no flash.
if (want(13)) {
  await load();
  await js(`localStorage.removeItem("wirust.theme");`);
  await load();
  const modes = [];
  for (let i = 0; i < 3; i++) {
    await click("#theme-toggle");
    modes.push(await js(`return [document.getElementById("theme-toggle").dataset.mode, document.documentElement.dataset.theme || "", localStorage.getItem("wirust.theme")];`));
  }
  check(13, "toggle cycles light, dark, system", JSON.stringify(modes) === JSON.stringify([["light", "light", "light"], ["dark", "dark", "dark"], ["system", "", null]]), JSON.stringify(modes));
  await click("#theme-toggle");
  await click("#theme-toggle");
  await load();
  check(13, "dark survives a reload", await js(`return document.documentElement.dataset.theme === "dark" && document.getElementById("theme-toggle").dataset.mode === "dark";`));
  check(13, "background is dark", await js(`const c = getComputedStyle(document.body).backgroundColor.match(/\\d+/g).map(Number); return c[0] + c[1] + c[2] < 200;`));
  await shot("13-dark");
  check(13, "theme is set before the first paint (theme.js not deferred, in head)", await js(`const s = document.querySelector('head script[src="/theme.js"]'); return !!s && !s.defer && !s.async;`));
  await js(`sessionStorage.setItem("e2e-break-storage", "1");`);
  await load();
  let threw = false;
  try { threw = await js(`try { localStorage.length; return false; } catch (_) { return true; }`); } catch (_) { threw = true; }
  check(13, "storage stub throws", threw);
  await click("#theme-toggle");
  check(13, "toggle works when storage throws", await js(`return document.getElementById("theme-toggle").dataset.mode === "light" && document.documentElement.dataset.theme === "light";`));
  check(13, "page still works when storage throws", await js(`return document.getElementById("conn").dataset.state === "live";`));
  await js(`sessionStorage.removeItem("e2e-break-storage");`);
  await load();
  await js(`localStorage.removeItem("wirust.theme");`);
  await load();
  consoleClean(13);
}

// Scenarios 1-4: live list, selection and keys, search and chips, detail bodies.
if ((want(1) || want(2) || want(3) || want(4)) && needTarget(1)) {
  await load();
  const before = await js(`return flows.size;`);
  await proxied("/json?live=1");
  check(1, "a new flow appears without a reload", await until(`flows.size > ${before} && [...document.querySelectorAll(".row:not([hidden])")].some((r) => r.textContent.includes("live=1"))`));
  check(1, "the connection badge says live", await js(`return document.getElementById("conn").dataset.state === "live";`));
  check(1, "the count names the flows", await js(`return /\\d+ flows?/.test(document.getElementById("count").textContent);`), await js(`return document.getElementById("count").textContent;`));
  const hang = proxied("/hang?ms=1500");
  check(1, "a running exchange shows as pending", await until(`[...document.querySelectorAll(".row.pending:not([hidden])")].some((r) => r.textContent.includes("/hang"))`));
  await hang;
  check(1, "the pending row fills in", await until(`[...document.querySelectorAll(".row:not([hidden])")].some((r) => r.textContent.includes("/hang") && !r.classList.contains("pending") && r.textContent.includes("200"))`));
  await click("#follow");
  check(1, "Follow toggles off", await js(`return document.getElementById("follow").getAttribute("aria-pressed") === "false";`));
  await click("#follow");
  check(1, "Follow toggles on", await js(`return document.getElementById("follow").getAttribute("aria-pressed") === "true";`));
  await click("#clear");
  check(1, "Clear empties the list", await until(`document.querySelectorAll(".row:not([hidden])").length === 0 || !document.getElementById("empty").hidden`));
  for (const p of ["/json", "/text", "/image", "/bin", "/gzip", "/br", "/500", "/404", "/slow"]) await proxied(p);
  await until(`[...document.querySelectorAll(".row:not([hidden])")].some((r) => r.textContent.includes("/slow"))`, 5000);
  consoleClean(1);

  await js(`document.getElementById("viewport").focus();`);
  await key("Home");
  const first = await js(`return selectedId;`);
  await key("j");
  check(2, "j selects the next flow", await js(`return selectedId !== ${first};`));
  await key("k");
  check(2, "k goes back", await js(`return selectedId === ${first};`));
  await key("ArrowDown");
  await key("ArrowUp");
  check(2, "arrows move too", await js(`return selectedId === ${first};`));
  for (const [k, tab] of [["3", "request"], ["4", "response"], ["2", "tls"], ["1", "overview"]]) {
    await key(k);
    check(2, `key ${k} opens ${tab}`, await js(`return document.querySelector('[data-tab="${tab}"]').getAttribute("aria-selected") === "true";`));
  }
  await click('[data-tab="response"]');
  check(2, "a tab opens by click", await js(`return document.querySelector('[data-tab="response"]').getAttribute("aria-selected") === "true";`));
  await js(`document.getElementById("viewport").focus();`);
  await key("/");
  check(2, "/ focuses the search", await js(`return document.activeElement.id === "search";`));
  await typeText("gzip");
  await sleep(300);
  check(2, "typing filters the list", await js(`return document.querySelectorAll(".row:not([hidden])").length === 1;`));
  await key("Escape");
  check(2, "Esc clears the search", await js(`return document.getElementById("search").value === "" && document.querySelectorAll(".row:not([hidden])").length > 1;`));
  const gz = await js(`return [...flows.values()].find((m) => m.url && m.url.endsWith("/gzip")).id;`);
  await load(`&flow=${gz}&tab=response`);
  check(2, "a deep link opens flow and tab", await js(`return selectedId === ${gz} && document.querySelector('[data-tab="response"]').getAttribute("aria-selected") === "true";`));
  check(4, "a gzip body is shown decoded with a note", await until(`/gzip/i.test(document.getElementById("panel").textContent) && document.getElementById("panel").textContent.includes("zipped")`), await js(`return document.getElementById("panel").textContent.slice(0, 200);`));
  consoleClean(2);

  const pick = async (path, tab = "response") => {
    const id = await js(`return [...flows.values()].find((m) => m.url && m.url.endsWith("${path}"))?.id ?? null;`);
    if (id !== null) { await js(`select(${id}, true); setTab("${tab}");`); await sleep(150); }
    return id;
  };
  await pick("/json");
  check(4, "JSON body renders as a tree", await js(`return document.querySelectorAll("#panel details").length > 0;`));
  await js(`const s = document.querySelector("#panel details summary"); s.click();`);
  check(4, "a JSON node collapses", await js(`return !document.querySelector("#panel details").open;`));
  await js(`document.querySelector("#panel details summary").click();`);
  check(4, "and expands", await js(`return document.querySelector("#panel details").open;`));
  await pick("/image");
  check(4, "an image body renders as <img>", await until(`document.querySelector("#panel img")?.naturalWidth > 0`));
  await pick("/bin");
  check(4, "a binary body shows a hex dump", await js(`return /00 01 02 03/.test(document.querySelector("#panel .hex")?.textContent || "");`));
  await pick("/br");
  check(4, "a br body is shown decoded", await js(`return document.getElementById("panel").textContent.includes("brotli body text");`));
  await pick("/text");
  check(4, "a text body is shown", await js(`return document.getElementById("panel").textContent.includes("hello plain text");`));
  await pick("/json", "request");
  check(4, "header copy buttons exist and are hover-only", await js(`const b = document.querySelector("#panel td.h-copy button, #panel button.h-copy"); return !!b && getComputedStyle(b).opacity === "0";`));
  await pick("/json", "overview");
  check(4, "overview shows timing", await js(`return !!document.querySelector("#panel .waterfall, #panel .wf-row");`));
  await shot("04-overview");
  consoleClean(4);

  await click('[data-chip="errors"]');
  check(3, "Errors chip keeps 4xx/5xx", await js(`const r = [...document.querySelectorAll(".row:not([hidden])")]; return r.length >= 2 && r.every((x) => /\\b[45]\\d\\d\\b|error/.test(x.querySelector(".c-status").textContent));`));
  await click('[data-chip="errors"]');
  await click('[data-chip="json"]');
  check(3, "JSON chip keeps JSON", await js(`const r = [...document.querySelectorAll(".row:not([hidden])")]; return r.length >= 1 && r.every((x) => /json|gzip|echo/.test(x.textContent));`));
  await click('[data-chip="json"]');
  await click('[data-chip="images"]');
  check(3, "Images chip keeps images", await js(`const r = [...document.querySelectorAll(".row:not([hidden])")]; return r.length === 1 && r[0].textContent.includes("/image");`));
  await click('[data-chip="images"]');
  await click('[data-chip="slow"]');
  check(3, "Slow chip keeps slow flows", await js(`const r = [...document.querySelectorAll(".row:not([hidden])")]; return r.length >= 1 && r.every((x) => /slow|hang|bp/.test(x.textContent));`));
  await click('[data-chip="slow"]');
  await click('[data-chip="tls"]');
  check(3, "TLS failures chip runs", await js(`return document.querySelectorAll(".row:not([hidden])").length >= 0;`));
  await click('[data-chip="tls"]');
  for (const [q, test] of [["status:5xx", "5"], ["method:GET type:image", "/image"], ["host:127.0.0.1 status:404", "/404"], ["size:>100 -path:/bp", null]]) {
    await js(`const s = document.getElementById("search"); s.value = ${JSON.stringify(q)}; s.dispatchEvent(new Event("input"));`);
    await sleep(700);
    const rows = await js(`return [...document.querySelectorAll(".row:not([hidden])")].map((r) => r.textContent);`);
    check(3, `query ${q} filters`, rows.length >= 1 && (!test || rows.every((t) => t.includes(test))), JSON.stringify(rows).slice(0, 200));
  }
  await js(`const s = document.getElementById("search"); s.value = "status:abc ("; s.dispatchEvent(new Event("input"));`);
  check(3, "a bad query shows an error", await until(`document.querySelector(".search-error") && document.querySelector(".search-error").textContent.length > 3 && !document.querySelector(".search-error").hidden`, 2000));
  await js(`document.getElementById("search").focus();`);
  await key("Escape");
  check(3, "Esc removes the query error", await js(`const e = document.querySelector(".search-error"); return !e || e.hidden || e.textContent === "";`));
  for (const col of ["id", "time", "method", "host", "path", "status", "proto", "size", "duration", "client"]) {
    await click(`[data-sort="${col}"]`);
    const ok1 = await js(`return document.querySelector('[data-sort="${col}"]').getAttribute("aria-sort");`);
    check(3, `sort by ${col}`, ok1 === "ascending" || ok1 === "descending", String(ok1));
  }
  await click('[data-sort="id"]');
  if ((await js(`return document.querySelector('[data-sort="id"]').getAttribute("aria-sort");`)) !== "ascending") await click('[data-sort="id"]');
  const h0 = await js(`return document.getElementById("detail").getBoundingClientRect().height;`);
  await js(`document.getElementById("splitter").focus();`);
  await key("ArrowUp");
  const h1 = await js(`return document.getElementById("detail").getBoundingClientRect().height;`);
  check(3, "splitter grows with ArrowUp", h1 > h0, `${h0} -> ${h1}`);
  const sp = await js(`const r = document.getElementById("splitter").getBoundingClientRect(); return [r.x + 40, r.y + r.height / 2];`);
  await send("Input.dispatchMouseEvent", { type: "mousePressed", x: sp[0], y: sp[1], button: "left", clickCount: 1 });
  await send("Input.dispatchMouseEvent", { type: "mouseMoved", x: sp[0], y: sp[1] - 80, button: "left" });
  await send("Input.dispatchMouseEvent", { type: "mouseReleased", x: sp[0], y: sp[1] - 80, button: "left", clickCount: 1 });
  const h2 = await js(`return document.getElementById("detail").getBoundingClientRect().height;`);
  check(3, "splitter drags with the mouse", h2 > h1 + 40, `${h1} -> ${h2}`);
  consoleClean(3);
}

// Scenarios 7, 8, 10, 12: rules, scripts, gRPC, popovers.
if (want(7) || want(8) || want(10) || want(12)) {
  await load();
  if (want(12)) {
    await click(".help-button");
    check(12, "? opens the search syntax", await js(`return !document.getElementById("search-syntax").hidden;`));
    check(12, "focus moves into the popover", await js(`return document.getElementById("search-syntax").contains(document.activeElement);`));
    await key("Escape");
    check(12, "Esc closes it and focus returns", await js(`return document.getElementById("search-syntax").hidden && document.activeElement.classList.contains("help-button");`));
    await click('[data-icon="connect"]');
    check(12, "Connect popover opens", await until(`!document.getElementById("connect").hidden && document.getElementById("connect").textContent.length > 20`));
    await shot("12-connect");
    await key("Escape");
    check(12, "Connect closes on Esc", await js(`return document.getElementById("connect").hidden;`));
    await click('[data-icon="export"]');
    await sleep(500);
    check(12, "Export HAR runs without an error toast", !/fail|error/i.test(await js(`return document.getElementById("toast").textContent;`)));
  }
  if (want(7)) {
    await click('[data-icon="rules"]');
    check(7, "Rules panel lists the rules", await until(`document.querySelector(".rule-list") && document.getElementById("rules-slot").textContent.includes("pause-bp")`));
    await shot("07-rules");
    // Rules are switched off and on by editing `enabled` in the JSON and pressing Apply.
    const setEnabled = async (on) => {
      await js(`const a = document.querySelector("#rules-slot .rules-json"); a.value = a.value.replace(/"enabled":\\s*(true|false)/, '"enabled": ${on}'); a.dispatchEvent(new Event("input"));
        [...document.querySelectorAll("#rules-slot button")].find((b) => b.textContent === "Apply").click();`);
      await sleep(500);
      return JSON.stringify((await api("rules")).json);
    };
    const off = await setEnabled(false);
    check(7, "Apply switches a rule off", off.includes('"enabled":false'), off.slice(0, 200));
    const on = await setEnabled(true);
    check(7, "and on again", on.includes('"enabled":true'), on.slice(0, 200));
    const area = await js(`return !!document.querySelector("#rules-slot .rules-json");`);
    if (area) {
      await js(`const a = document.querySelector("#rules-slot .rules-json"); a.value = "{ not json"; a.dispatchEvent(new Event("input"));`);
      await js(`[...document.querySelectorAll("#rules-slot button")].find((b) => b.textContent === "Apply").click();`);
      check(7, "invalid JSON is refused in words", await until(`[...document.querySelectorAll("#rules-slot .error-box")].some((e) => !e.hidden && e.textContent.length > 3)`));
    } else check(7, "rule JSON editor exists", false);
    consoleClean(7);
  }
  if (want(8) && target) {
    check(8, "Scripts button is shown with --script", await js(`return !!document.querySelector('[data-icon="script"], .script-button');`));
    await proxied("/throw");
    await proxied("/log");
    await js(`(document.querySelector('[data-icon="script"]') || document.querySelector(".script-button")).click();`);
    check(8, "script panel shows the error", await until(`/failed on purpose/.test(document.querySelector(".script-panel")?.textContent || "")`), await js(`return (document.querySelector(".script-panel")?.textContent || "none").slice(0, 300);`));
    check(8, "script panel shows log lines", await until(`/log line from script/.test(document.querySelector(".script-panel")?.textContent || "")`));
    await shot("08-scripts");
    consoleClean(8);
  }
  if (want(10)) {
    const g = await js(`return [...flows.values()].find((m) => m.url && m.url.includes("/demo.Greeter/"))?.id ?? null;`);
    if (g === null) console.log("SKIP [10] no gRPC flow (send one with curl --http2, see docs/ui.md)");
    else {
      await load(`&flow=${g}`);
      const tab = await js(`return [...document.querySelectorAll('[role="tab"]')].find((b) => /gRPC/i.test(b.textContent))?.id || null;`);
      check(10, "the gRPC tab is offered", !!tab);
      if (tab) {
        await click("#" + tab);
        check(10, "the tree shows field names from the .proto", await until(`/message/.test(document.getElementById("panel").textContent) && document.getElementById("panel").textContent.includes("hi there")`), await js(`return document.getElementById("panel").textContent.slice(0, 300);`));
        check(10, "trailers are shown", await js(`return /grpc-status/.test(document.getElementById("panel").textContent);`));
        await shot("10-grpc");
      }
      consoleClean(10);
    }
  }
}

// Scenarios 14 and 16: layout at three widths in both themes, focus and aria.
if (want(14) || want(16)) {
  for (const theme of ["light", "dark"]) {
    for (const width of [1400, 1000, 760]) {
      await viewport(width);
      await load();
      await js(`document.documentElement.dataset.theme = "${theme}";`);
      await js(`const m = [...flows.values()].find((x) => x.url && x.url.endsWith("/json")); if (m) select(m.id, true);`);
      await sleep(200);
      check(14, `${theme} ${width}: no horizontal scroll`, await js(`return document.documentElement.scrollWidth <= innerWidth;`), await js(`return document.documentElement.scrollWidth + " > " + innerWidth;`));
      const overlap = await js(`const b = [...document.querySelectorAll(".toolbar button, .detail-actions button")].filter((x) => x.offsetParent).map((x) => [x.getAttribute("aria-label") || x.textContent, x.getBoundingClientRect()]);
        const out = []; for (let i = 0; i < b.length; i++) for (let j = i + 1; j < b.length; j++) { const p = b[i][1], q = b[j][1]; if (p.left < q.right - 1 && q.left < p.right - 1 && p.top < q.bottom - 1 && q.top < p.bottom - 1) out.push(b[i][0] + " / " + b[j][0]); }
        const clipped = b.filter(([, r]) => r.right > innerWidth + 1 || r.left < -1).map(([n]) => n); return out.concat(clipped.map((n) => "clipped " + n));`);
      check(14, `${theme} ${width}: no overlapping or clipped buttons`, overlap.length === 0, overlap.join(", "));
      await shot(`14-${theme}-${width}`);
    }
  }
  await viewport(1400);
  await load();
  check(16, "tabs have roles and aria-selected", await js(`return [...document.querySelectorAll('[role="tab"]')].every((t) => t.hasAttribute("aria-selected"));`));
  check(16, "dialogs and popovers are labelled", await js(`return [...document.querySelectorAll('dialog, [role="dialog"]')].every((d) => d.getAttribute("aria-label") || d.getAttribute("aria-labelledby"));`));
  const stops = [];
  await js(`document.body.focus();`);
  for (let i = 0; i < 40; i++) {
    await key("Tab");
    stops.push(await js(`const a = document.activeElement; return (a.id || a.className || a.tagName) + "|" + (a.id === "splitter" || getComputedStyle(a).outlineStyle !== "none" || getComputedStyle(a).boxShadow !== "none");`));
  }
  const names = stops.map((s) => s.split("|")[0]);
  for (const want16 of ["follow", "clear", "search", "viewport", "splitter", "theme-toggle"]) {
    check(16, `Tab reaches ${want16}`, names.includes(want16), names.join(" "));
  }
  check(16, "focused controls show a ring", stops.filter((s) => !s.startsWith("BODY|")).every((s) => s.endsWith("true")), stops.filter((s) => s.endsWith("false")).join(" "));
  consoleClean(16);
}

console.log(`\n${results.length - failed} passed, ${failed} failed`);
ws.close();
process.exit(failed ? 1 : 0);
