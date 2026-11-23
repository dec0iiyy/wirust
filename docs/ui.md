# Web UI

Start the proxy with `--ui 127.0.0.1:8081` and open the link it prints
(`http://127.0.0.1:8081/#token=...`). The UI is static files in `crates/proxy/ui/`
(`index.html`, `app.js` for the list and detail pane, `panels.js` for the side panel and
popovers, `style.css` with the design tokens, `theme.js` for the theme override, `ws.js`
with `ws.css` for the WebSocket Messages tab and its composer that sends messages,
`grpc.js` with `grpc.css` for the gRPC tab (see `docs/grpc.md`), `replay.js` with
`replay.css`, `script.js` for the Scripts panel (see `docs/scripting.md`) and `codegen.js`
with `codegen.css` for the "Copy as" menu), embedded in the binary and listed in
`control::ASSETS`. No build step, no dependencies.

## What it shows

- **Flow list**: number, time, method, host, path, status, protocol, response size,
  duration, and the client name matched from the TLS fingerprint (`curl 8.7.1`), or its
  JA4 when no known client matches. The protocol is the client leg (`h2`, `http/1.1`), and
  when the server leg differs it follows an arrow (`h2→http/1.1`: an HTTP/2 client whose
  server speaks HTTP/1.1); the terminal log prints the same text. A row appears when the
  request starts (grey, `pending`) and fills in when it ends. The method is coloured
  (GET, POST, PUT, PATCH, DELETE), the status is a pill coloured by class and always
  written out as text, and the host dims its subdomains and port so the domain stands out
  (the full host is the cell's tooltip). TLS handshake failures have a red bar at the left
  edge and the reason in red in the Path column;
  tunnels say `tunnel`, and a TLS tunnel relayed by `--passthrough` shows the client from
  its ClientHello like a decrypted flow does.
- Up to the store's 5000 flows stay smooth: only the visible rows are in the DOM.
  **Follow** keeps the newest row in view; scrolling up turns it off, scrolling to the
  bottom turns it on. **Clear** hides the flows loaded so far, in this page only (the
  server has no delete). Click a header to sort, again to reverse.
- **Filter box**: plain words must all appear in the URL or a header, filtered in the page,
  as are the simple tokens `host:api`, `method:post`, `status:404` / `status:4xx` /
  `status:error` / `status:pending` and `type:json|html|...` when nothing else is typed.
  Any other field of the query language (`path:`, `body:`, `header:`, `size:`, `time:`,
  `client:`, `tls:`, `flag:`, `ws:`), parentheses, `OR` or a leading `-` sends the whole text to
  `GET /api/v1/flows?q=` after 250 ms; the list then shows the server's matches and asks
  again (at most once a second) while new flows arrive. A `400` shows the server's message
  with its position under the box and keeps the last good list. The `?` button lists the
  grammar (from `docs/interchange.md`). Chips (Errors, Slow, JSON, Images, TLS failures)
  apply on top in both modes.
- **Rule badges**: a flow that a rule touched shows each `rule:<name>` flag as a blue badge
  before the path and in Overview's Flags.
- **Export HAR** (toolbar) downloads `GET /api/v1/har?q=<the search text>` through `fetch`
  with the Bearer header and a Blob link with `download`, so the token never appears in a
  URL. **Copy as cURL** uses `GET /api/v1/flows/{id}/curl` and falls back to the page's own
  builder (pending flows, older servers). **Copy as...** (`codegen.js`, next to it) opens a
  list of languages and copies the request as code from `GET /api/v1/flows/{id}/code?lang=`
  (see [interchange.md](interchange.md#code-export)): Python (requests), JavaScript (fetch),
  Kotlin (OkHttp), Swift (URLSession), HTTPie and PowerShell. Down opens the list, arrows,
  Home and End move, Enter picks, Escape closes; pending flows give a message instead.
- **Breakpoints** (side panel; the toolbar button shows the count, the tab title becomes
  `(2) wirust`, and the button is outlined red while anything is paused; no sound, no
  notifications). Pending pauses come from `GET /api/v1/pauses` on start and on every
  reconnect, then live from the `paused` / `resumed` events; a new pause opens the panel.
  Selecting one selects its flow. The editor is filled from `GET /api/v1/pauses/{id}`, so
  it shows what the pause really holds (after earlier rules ran):
  - request phase: method, URL (a different scheme or host sends the request there), the
    request headers as an editable table (edit value, delete row, add row; HTTP/2 pseudo
    headers are not listed), and the body;
  - response phase: status, the response headers as the same table, and the body;
  - body: UTF-8 text up to 256 KB is editable in place. A binary body shows
    `binary, N bytes, not editable` and a hex dump of its first 4 KB; a longer text body
    shows its start read-only; a body over `--body-limit` is not shown at all. In those
    three cases the body goes on unchanged unless **Replace the body** is ticked (text or
    base64). Breakpoint rules make the proxy buffer bodies up to `--body-limit`, like body
    rewrites do. When the detail cannot be loaded the editor falls back to the flow
    record, headers to set or remove, and a replacement body.
  - **Resume**, **Edit and resume** (sends only what changed to
    `POST /api/v1/pauses/{id}/edit`; repeated header names are joined with `, `, or `; `
    for `Cookie`), **Abort**. A `400` shows the server's message in the editor and the pause
    stays pending with the typed values kept.
  - No countdown: `GET /api/v1/pauses` does not expose the deadline (`--pause-timeout`,
    default 5 min). A timed-out pause disappears with a toast.
- **Rules** (side panel): the rules from `GET /api/v1/rules` with an on/off switch
  (`POST /api/v1/rules/{name}/toggle`) and a one-line summary (`path /api/* → block 403`).
  A failed load of the rules file is shown in red with the file and the error (the previous
  rules stay in force). Below, the whole set as JSON: **Apply** sends it with
  `PUT /api/v1/rules` (the only client-side check is JSON syntax; the server's `400` text is
  shown as is), **Reload from server** discards local edits. The list refreshes every 5 s
  while visible (the file may change); the editor is not overwritten while it has edits.
- **Create rule** (detail pane, HTTP flows): templates filled from the selected flow:
  block this host, delay this URL, rewrite a request header, breakpoint on this URL. The
  template is appended to the JSON editor with a unique name and selected; nothing is
  applied until **Apply**. (Map-local from a captured response is not offered: the browser
  cannot write the file the rule would serve.)
- **Connect** (toolbar popover, from `GET /api/v1/info`): the proxy address and whether it
  is loopback only, `curl -x` and `HTTPS_PROXY` lines to copy, the CA address
  `http://wirust.test/ca.pem` (reachable through the proxy) and a direct download through the
  API, the CA's SHA-256 fingerprint to compare after installing, the rules and session
  files, and a pointer to `wirust connect` for phones.
- **Replay / Compose** (`ui/replay.js`, buttons in the detail pane toolbar):
  - **Replay** sends the selected finished exchange again as it was
    (`POST /api/v1/flows/{id}/replay`), then selects the new flow.
  - **Edit & replay** opens a dialog with method, URL, headers and body taken from the flow
    and sends only what changed. A stored binary body is shown as a hex dump and sent as
    recorded unless replaced; a body cut by `--body-limit` must be replaced (the server
    answers `409` otherwise).
  - **New request** composes one from scratch (`POST /api/v1/compose`): method, absolute
    URL, headers in order, text body.
  - Both dialogs have **Apply rules and breakpoints** (off by default). A refusal is shown
    in the dialog in plain words: `429` says at most 8 replays are in flight and 20 start
    per second, `409` and `403` show the server's reason.
  - The **Replay** tab appears on a replay (flag `replay`): it links to the original flow
    and compares method, URL, status and size side by side (differences highlighted). An
    original that has replays lists them.
  - The passthrough lists stay API and CLI only (`docs/passthrough.md`).
- **Detail pane** (drag or arrow-key the bar above it to resize):
  - Overview: URL, status, client address, HTTP version on each leg, body sizes, flags
    (`pause_timed_out`, ...), error, and a timing waterfall (connect, TLS, first byte,
    download, total). Connect and TLS are shown only when the exchange opened the server
    connection. A TLS failure shows the reason and what usually causes it.
  - Client TLS: the matched client, JA4 and JA3 hash (with copy buttons), TLS version,
    SNI, ALPN (for a passthrough tunnel, the ALPN protocols the client offered). This is
    how the app's own TLS stack looks to servers.
  - Request / Response: headers with copy buttons, then the body by content type: JSON as
    a collapsible tree with search, form-urlencoded as a table, text as monospace, images
    as a preview, everything else as a hex dump (first 64 KB). Compressed bodies
    (`Content-Encoding`) are shown decoded, with a note such as "Decoded from br (wire:
    334 B)"; one that could not be decoded is shown as stored, with the reason. A truncated
    body says how much was kept (`--body-limit`).
  - Copy as cURL (POSIX shell quoting; binary bodies go through `base64 --decode`), Copy
    URL, Copy body. There is deliberately no "open body in a new tab": it would run the
    body as active content on this origin.
- The connection badge says `live`, `reconnecting in N s` (backoff 0.5 s doubling to
  15 s), or `token missing` / `token rejected: open the link printed in the terminal`.
- `app.js` exposes `hooks.pause` (SSE events whose name starts with `pause`), `hooks.load`
  (after each load of the store) and `hooks.detail` (the shown flow) for `panels.js`.
- **Toolbar**: the top row has the name, the buttons grouped by meaning (capture: Follow,
  Clear; share: Export HAR, Connect; control: Breakpoints, Rules, and Scripts when the proxy
  runs with `--script`), the connection badge and
  the theme button; the row below has the filter box (`/` focuses it), the quick filters and
  the flow count. Below 1180 px the share and control buttons show only their icons (the
  name stays in the tooltip and the accessible label), below 980 px the capture buttons
  too, the `#` and Proto columns are dropped and the side panel floats over the list. The
  page works down to about 760 px wide.
- **Theme**: the page follows the system light or dark setting. The button at the right of
  the toolbar cycles system, light, dark; `theme.js` sets `data-theme` on `<html>` before
  the first paint and keeps the choice in `localStorage` (`wirust.theme`). When storage is
  unavailable the choice lasts until the page reloads. Transitions are off under
  `prefers-reduced-motion`.

## Adding a detail tab

Another UI file (like `ui/ws.js`, loaded with `<script src="/ws.js" defer>` after `app.js`)
adds a tab with:

```js
window.registerTab({
  id: "ws",                       // lowercase, used in #tab=ws
  title: "Messages",
  render(flow, container) {       // flow: the raw record, as GET /api/v1/flows/{id}
    container.append(document.createElement("p"));   // createElement/textContent only
  },
});
```

The tab gets the next number key (5, 6, ...). A script that runs before `app.js` pushes the
same object onto `window.pendingTabs = []` instead. An exception in `render` is shown in the
pane, not thrown.

## Styling extensions

A new panel, tab, menu or composer should look like the rest without its own colours.
`style.css` defines the tokens on `:root`; each colour token holds both themes through
`light-dark()`, so a rule that uses `var(--…)` follows the system setting and the theme
button. Hard-coded colours and `@media (prefers-color-scheme)` blocks do not follow the
button.

- Surfaces: `--bg` (page), `--surface`, `--surface-2`, `--surface-3`, `--surface-overlay`
  (popovers, dialogs), `--code-bg`; lines `--line`, `--line-strong`, `--field-border` (form
  fields, 3:1 against the surfaces); rows `--row-alt`, `--row-hover`, `--sel`, `--sel-fg`.
- Text: `--fg`, `--fg-muted`, `--fg-subtle` (all at least 4.5:1 on the surfaces), `--accent`.
- Meaning: `--ok`, `--redirect`, `--client-err`, `--server-err` (`--danger`), `--pending`,
  `--fail-bg`/`--fail-fg`, `--warn-bg`, `--hit`; methods `--m-get`, `--m-post`, `--m-put`,
  `--m-patch`, `--m-delete`, `--m-other`; syntax `--syn-key`, `--syn-str`, `--syn-num`,
  `--syn-lit`, `--syn-punct`.
- Scale: spacing `--sp-1` to `--sp-7` (2, 4, 6, 8, 12, 16, 24 px), radii `--r-1`, `--r-2`,
  `--r-3`, `--r-pill`, type `--fs-xs` to `--fs-xl` (11 to 18 px), fonts `--sans`, `--mono`,
  elevation `--shadow-1`, `--shadow-2`, motion `--t-fast`, `--t-med`, `--ease`.

Generic classes to reuse instead of new one-off selectors:

| Class | Use |
|---|---|
| plain `<button>` | the default bordered button; add `primary`, `danger`, `ghost` or `mini` |
| `data-icon="export"` (`follow`, `clear`, `connect`, `pause`, `rules`) | a 16 px icon before the label |
| `toggle` with `aria-pressed` | an on/off button; `toggle switch` for the rule switches |
| `segmented` (or `chips`) holding `chip` buttons with `aria-pressed` | a quiet segmented filter |
| `surface` | a raised box: overlay background, border, `--r-3` radius, `--shadow-2` |
| `popover`, `popover menu` (or `menu`) | a floating panel; a list of actions in it |
| `badge`, `badge rule` | a small rounded label |
| `hint`, `notice`, `error-box` | muted text, a warning line, an error block |
| `url`, `pre.text`, `pre.hex`, `json` | code-like blocks |
| `table.headers` with `h-name`, `h-value`, `h-copy` | a name/value table (the copy button shows on hover or focus) |
| `dl.kv` | label and value pairs |
| `kbd` | a key hint |
| `field` on `input`/`select` | a compact form field (inputs without a class get the same look) |

A button in the detail pane's toolbar (next to Copy as cURL) goes into `.detail-actions`
and needs no class; a toolbar button goes into the matching `.btn-group[data-group]`
(`capture`, `share`, `control`) with `data-icon` and its label in `<span class="btn-label">`
so narrow windows can hide the label.

## Keys

| Key | Action |
|---|---|
| `j` / `ArrowDown`, `k` / `ArrowUp` | next / previous flow |
| `Home` / `End` (list focused) | first / last flow |
| `/` | focus the filter box |
| `Esc` | close a popover; else clear the filter and chips |
| `1` to `4` | Overview, Client TLS, Request, Response (`5`+ for registered tabs) |
| `r` / `a` (Breakpoints panel focused, not typing) | resume / abort the selected pause |

## Token flow

1. The token is in the URL fragment, which browsers never send to the server.
2. `app.js` reads it once, removes the fragment with `history.replaceState`, and keeps the
   token in `sessionStorage` (this tab and this origin only, so a reload keeps working).
   It does not set the `token` cookie: cookies are not scoped by port, so every other
   local server on `127.0.0.1` would receive it.
3. Every request sends `Authorization: Bearer TOKEN`. Live updates read
   `GET /api/v1/events` with `fetch` and a stream parser, because `EventSource` cannot send
   headers. On connect the page subscribes first, then loads `GET /api/v1/flows`
   (on reconnect only `?after=` the oldest pending flow) and merges by id. The list and the
   stream are read with `?view=summary` (below), so the page never holds every body: the
   selected flow's whole record comes from `GET /api/v1/flows/{id}` when it is selected and
   again when its state changes, and goes back to a summary when another flow is selected.
   Plain words in the search box match the URL, host and error text of every row, and the
   headers of the selected one; the query language runs on the server over whole flows.
4. A `401` drops the stored token and says so; the proxy makes a new token at each start.

The fragment may also carry `flow=ID`, `tab=overview|tls|request|response`, `q=FILTER` and
`panel=pauses|rules|connect|help` to open a flow, a tab, a filter or a panel:
`/#token=...&flow=12&tab=tls&panel=rules`. `panel=compose` opens **New request** and
`panel=edit-replay` (with `flow=ID`) opens **Edit & replay** for that flow.

### Summary view

`GET /api/v1/flows?view=summary` (with any of `host`, `method`, `status`, `limit`, `after`,
`q`) and `GET /api/v1/events?view=summary` answer flows in summary form: every field the list
shows, with the names and order of the whole record, plus `"summary": true`. An exchange
summary drops `request_headers`, `response_headers` and `response_trailers`, keeps
`request_body` and `response_body` as `{"size", "truncated", "encoding", "content_encoding"?}`
without `data`, and adds `response_content_type` (the response's `Content-Type`, for the Type
column) when there is one. A pending flow drops `request_headers`. Failed handshakes and
tunnels hold no headers or bodies, so their summary is the whole record plus the marker. On
the stream, `started`, `completed`, `failed` and `tls_failed` carry summaries; pause and `ws`
events are unchanged. `?q=` still searches whole flows on the server. Without `view` (or
with `view=full`) both answers are as before; any other value is a `400`. The whole record
stays at `GET /api/v1/flows/{id}`.

`GET /api/v1/info` (same token, `Host` and `Origin` checks) answers
`{"name", "version", "proxy_addr", "magic_host", "ca_fingerprint_sha256", "rules_file",
"session_file", "listen_is_loopback", "flows", "memory_bytes", "max_memory_bytes"}`
(`flows`: how many flows the store holds; `memory_bytes`: the estimated bytes of flow data
it holds; `max_memory_bytes`: the `--max-memory` budget);
the fingerprint is the SHA-256 of the CA
certificate's DER as colon-separated upper-case hex, as certificate viewers show it.
`rules_file` and `session_file` are file names only (`rules.toml`), never the path as
typed, so an absolute path does not show the home directory.

## Rules for contributors

The control plane serves the page with
`default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'`.
Keep it that way:

- Flow data (URLs, headers, bodies) is attacker-controlled. Build the DOM with
  `createElement` and `textContent` (the `h()` helper). Never `innerHTML`, `outerHTML`,
  `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, `javascript:` URLs.
- No inline `<script>`, `style=` attributes or `on...=` handlers in HTML; set styles from
  JS through `element.style` (CSSOM is allowed by the CSP) or classes.
- No external URLs: no CDN, fonts or images from elsewhere. Images in bodies are shown
  only through `data:` URLs in `<img>`, which do not run scripts. URLs the page displays
  (the proxy address, the CA address) are built from parts at run time.
- A new file goes in `crates/proxy/ui/` and gets one line in `control::ASSETS`.

`crates/proxy/tests/ui.rs` enforces this: it fetches every file in `ui/` with the token,
checks its content type, that the served copy matches the file, the CSP directives, and
that no file contains the forbidden text above or an `http(s)://` URL.

## Browser end-to-end check

`scripts/ui-e2e.mjs` clicks through the page in a real headless Chrome over the DevTools
protocol (Node 22 or newer, no packages) and prints one `PASS` or `FAIL` line per check:
replay and its editor, breakpoints, WebSocket messages, copy menus, theme, the live list,
keys, search, bodies, rules, scripts, gRPC, popovers, layout at 1400, 1000 and 760 px and
keyboard focus, and it fails on any console error or warning. It starts nothing and
skips with a message when Chrome is not reachable. By hand, in separate terminals:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 2 -subj /CN=localhost
node scripts/ui-e2e-fixtures.mjs 47311 47312 cert.pem key.pem
wirust --listen 127.0.0.1:47313 --ui 127.0.0.1:47314 --upstream-insecure \
  --rules rules.toml --script script.rhai --proto demo.proto --config-dir ./cfg
"Google Chrome" --headless=new --remote-debugging-port=47315 --user-data-dir=./chrome
node scripts/ui-e2e.mjs 'UI_LINK_WITH_TOKEN' 47315 47313 \
  --target 'http://127.0.0.1:47311' --shots ./shots [--only 5,6,9]
```

`rules.toml` needs a rule with `match = { path = "/bp*" }` and
`action = { type = "breakpoint", request = true, response = true }`; `script.rhai` should
`throw` on the path `/throw` and `print` on `/log`; `demo.proto` declares
`demo.Greeter/SayHello` returning `HelloReply { string message = 1; int32 count = 2; }`.
The gRPC and Client TLS checks need one HTTPS and one gRPC request sent with
`curl --cacert` through the proxy first (`--http2 -H 'content-type: application/grpc'` to
`https://localhost:47312/demo.Greeter/SayHello`).
