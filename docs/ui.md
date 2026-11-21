# Web UI

Start the proxy with `--ui 127.0.0.1:8081` and open the link it prints
(`http://127.0.0.1:8081/#token=...`). The UI is static files in `crates/proxy/ui/`
(`index.html`, `app.js` for the list and detail pane, `panels.js` for the side panel and
popovers, `style.css`, `ws.js` with `ws.css` for the WebSocket Messages tab, and `grpc.js`
with `grpc.css` for the gRPC tab, see `docs/grpc.md`), embedded
in the binary and listed in `control::ASSETS`. No build step, no dependencies.

## What it shows

- **Flow list**: number, time, method, host, path, status, client-leg protocol (`h2`,
  `http/1.1`), response size, duration, and the client name matched from the TLS
  fingerprint (`curl 8.7.1`). A row appears when the request starts (grey, `pending`) and
  fills in when it ends. Status is coloured by class and always written out as text. TLS
  handshake failures are red rows with the reason; tunnels say `tunnel`.
- Up to the store's 5000 flows stay smooth: only the visible rows are in the DOM.
  **Follow** keeps the newest row in view; scrolling up turns it off, scrolling to the
  bottom turns it on. **Clear** hides the flows loaded so far, in this page only (the
  server has no delete). Click a header to sort, again to reverse.
- **Filter box**: plain words must all appear in the URL or a header, filtered in the page,
  as are the simple tokens `host:api`, `method:post`, `status:404` / `status:4xx` /
  `status:error` / `status:pending` and `type:json|html|...` when nothing else is typed.
  Any other field of the query language (`path:`, `body:`, `header:`, `size:`, `time:`,
  `client:`, `tls:`, `flag:`), parentheses, `OR` or a leading `-` sends the whole text to
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
  builder (pending flows, older servers).
- **Breakpoints** (side panel; the toolbar button shows the count, the tab title becomes
  `(2) wirust`, and the button is outlined red while anything is paused; no sound, no
  notifications). Pending pauses come from `GET /api/v1/pauses` on start and on every
  reconnect, then live from the `paused` / `resumed` events; a new pause opens the panel.
  Selecting one selects its flow. The editor:
  - request phase: method, URL (a different scheme or host sends the request there), the
    request headers as an editable table (edit value, delete row, add row; HTTP/2 pseudo
    headers are not listed), and an optional replacement body as text or base64;
  - response phase: status (empty keeps it), headers to set, header names to remove, an
    optional body. The response itself is not visible until it is released (the flow
    record only arrives on completion), and neither is a paused request's body.
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
- **Replay / Compose slot**: `<span id="replay-slot">` in the detail pane toolbar stays
  hidden unless `window.WIRUST_REPLAY` is set when the page loads; its owner fills it. No
  UI file sets it yet: replay, compose and the passthrough lists are API and CLI only
  (`docs/replay.md`, `docs/passthrough.md`).
- **Detail pane** (drag or arrow-key the bar above it to resize):
  - Overview: URL, status, client address, HTTP version on each leg, body sizes, flags
    (`pause_timed_out`, ...), error, and a timing waterfall (connect, TLS, first byte,
    download, total). Connect and TLS are shown only when the exchange opened the server
    connection. A TLS failure shows the reason and what usually causes it.
  - Client TLS: the matched client, JA4 and JA3 hash (with copy buttons), TLS version,
    SNI, ALPN. This is how the app's own TLS stack looks to servers.
  - Request / Response: headers with copy buttons, then the body by content type: JSON as
    a collapsible tree with search, form-urlencoded as a table, text as monospace, images
    as a preview, everything else as a hex dump (first 64 KB). Compressed bodies
    (`Content-Encoding`) are shown as stored, not decoded. A truncated body says how much
    was kept (`--body-limit`).
  - Copy as cURL (POSIX shell quoting; binary bodies go through `base64 --decode`), Copy
    URL, Copy body. There is deliberately no "open body in a new tab": it would run the
    body as active content on this origin.
- The connection badge says `live`, `reconnecting in N s` (backoff 0.5 s doubling to
  15 s), or `token missing` / `token rejected: open the link printed in the terminal`.
- `app.js` exposes `hooks.pause` (SSE events whose name starts with `pause`), `hooks.load`
  (after each load of the store) and `hooks.detail` (the shown flow) for `panels.js`.

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
   (on reconnect only `?after=` the oldest pending flow) and merges by id.
4. A `401` drops the stored token and says so; the proxy makes a new token at each start.

The fragment may also carry `flow=ID`, `tab=overview|tls|request|response`, `q=FILTER` and
`panel=pauses|rules|connect|help` to open a flow, a tab, a filter or a panel:
`/#token=...&flow=12&tab=tls&panel=rules`.

`GET /api/v1/info` (same token, `Host` and `Origin` checks) answers
`{"name", "version", "proxy_addr", "magic_host", "ca_fingerprint_sha256", "rules_file",
"session_file", "listen_is_loopback"}`; the fingerprint is the SHA-256 of the CA
certificate's DER as colon-separated upper-case hex, as certificate viewers show it.

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
