# Architecture

One crate, `crates/proxy` (library `wirust` plus the `wirust` binary). This page maps who
owns what, how one exchange flows, and where each feature plugs in, so features can be
built in parallel without editing the same functions.

## Modules

| Module | Owns |
|---|---|
| `lib.rs` | `NAME`, `MAGIC_HOST`, `DEFAULT_BODY_LIMIT`, module list |
| `main.rs` | flags, start-up banner, the log printer (`print_flows`) |
| `logfold.rs` | `Folder`: folds repeated `TLS-FAIL` console lines for the same host and error into one summary line (console only) |
| `clock.rs` | UTC wall-clock formatting for record timestamps, without a date-time dependency |
| `proxy.rs` | `Config`, `Proxy`: listener, CONNECT, TLS interception, forwarding, running the chain |
| `hello.rs` | reads and replays the raw ClientHello (`peek`, `Prefixed`) |
| `ca.rs`, `certs.rs` | the local CA, per-host leaf certificates and their cache |
| `upstream.rs` | server connections (TLS, ALPN, timings) |
| `upstream_proxy.rs` | `--upstream-proxy`: URL and redaction, bypass list, HTTP CONNECT and SOCKS5 clients |
| `body.rs` | `Tee` (bounded body copy for the log), `buffer`/`Prepend` (bounded buffering) |
| `flow.rs` | the record types (`Event`, `Exchange`, `TlsFailure`, `Tunnel`, `Flag`) and the text log line |
| `decode.rs` | `decode`: undoes `Content-Encoding` (gzip, deflate, br, zstd) on the captured copy of a body, capped by the body limit and an expansion ratio; `BodyRecord::from_capture` |
| `events.rs` | `FlowEvent`, `Bus` (broadcast), `Flow` (record plus `schema_version`), `FlowStore` (ring buffer), `Filter` |
| `intercept.rs` | `Interceptor`, `Action`, `Interceptors` (the chain), `Pauses`/`PauseHandle`, built-ins `HeaderRules`, `BlockHost` |
| `control.rs` | `ControlPlane`: the `--ui` listener, JSON API, SSE, embedded UI, its security checks |
| `magic.rs` | answers `http(s)://wirust.test/` and origin-form requests to the proxy port: setup page, `/ca.pem`, `/ca.crt`, `/ca.mobileconfig`, `/mobile-help`, `/pairing-status`, `/setup.js`, `/setup.css` |
| `pairing.rs` | `Pairing`: which client IPs may use a LAN proxy (loopback, `--allow-client`, approvals); `Pairing::screen` runs in `serve_client` before each request |
| `mobile.rs` | the setup page per platform, the `connect` banner, the approval console and its hints, LAN address detection |
| `sysproxy.rs`, `trust.rs`, `oscmd.rs` | `system-proxy` and `--system-proxy` with the saved-state file; `ca install`/`uninstall`/`status`; the `CommandRunner` trait both run OS tools through |
| `qr.rs`, `mobileconfig.rs`, `adb.rs` | terminal QR code; iOS profile with the CA; `adb` argument builders for `android setup`/`reset` |
| `rules.rs`, `rules_api.rs` | the rules engine (`--rules`, three chain stages) and its API routes; `docs/rules.md` |
| `script.rs`, `script_api.rs` | sandboxed Rhai scripts (`--script`, one chain stage per file, before the rule breakpoints) and `/api/v1/script`; `docs/scripting.md` |
| `replay.rs`, `replay_api.rs` | replay and compose (`Replayer`, limits, `ReplayTag` read by `forward`), the `replay` CLI, routes for replay, compose and passthrough; `docs/replay.md` |
| `passthrough.rs` | `--passthrough`/`--decrypt-only` patterns, the live `Passthrough` lists, the undecrypted relay; `docs/passthrough.md` |
| `throttle.rs` | `Throttled`, the bandwidth-capped streaming body |
| `har.rs`, `har_api.rs`, `session.rs` | HAR 1.2 export and import, the `/api/v1/har` route, session files (`--session`, `export`, `import`, `view`); `docs/interchange.md` |
| `query.rs`, `curl.rs`, `codegen.rs` | the search query language (`?q=`, `--filter`), the cURL export (`/api/v1/flows/{id}/curl`) and the code export in six languages (`/api/v1/flows/{id}/code`) |
| `ws.rs`, `ws_api.rs` | WebSocket capture: frame parser, the pump `join_upgrades` runs for `Upgrade: websocket`, `WsStore` (inside `FlowStore`), `FlowEvent::WsMessage`, `permessage-deflate` inflation of the recorded copy, `GET` and `POST /api/v1/flows/{id}/messages` (`ws::Live` holds the open connections that accept injected messages); `docs/websocket.md` |
| `grpc.rs`, `protobuf.rs`, `schema.rs`, `grpc_api.rs` | gRPC, gRPC-Web and protobuf decoding of recorded bodies: framing, inflating, status from `response_trailers`, the schema-less decoder, `.proto` schemas compiled with `protox` and decoded with `prost-reflect`, `GET /api/v1/flows/{id}/grpc` and `GET /api/v1/proto`; `docs/grpc.md` |
| `wireguard.rs`, `wireguard/` | experimental, cargo feature `wireguard` only: keys and peers (`config.rs`), the UDP listener with boringtun sessions, a smoltcp stack and the DNS relay (`server.rs`); terminated connections go to `serve_transparent` in `proxy.rs`; `docs/wireguard.md` |
| `ui/` | static files embedded with `include_bytes!` (`index.html`, `theme.js`, `panels.js`, `app.js`, `style.css`, `ws.js` and `ws.css` for the Messages tab, `grpc.js` and `grpc.css` for the gRPC tab, `replay.js` and `replay.css` for replay and compose, `script.js` for the Scripts panel, `codegen.js` and `codegen.css` for the code export) |

## One exchange

1. `serve_client` accepts the client; `proxy_request` handles `CONNECT` or an absolute-form
   `http://` request. Targets equal to the control plane's address get `403`
   (`State::refuses`); `wirust.test` goes to `magic::respond`.
2. CONNECT: `tunnel` peeks the ClientHello, fingerprints it, issues a leaf, accepts TLS and
   serves h2 or HTTP/1.1. Each request calls `forward`.
3. `forward` builds the `Exchange` record and publishes `FlowEvent::Started`.
4. With interceptors registered, `intercept_request` buffers the request body if any
   interceptor `wants_request_body` for this request (rules answer per exchange from their
   matchers; the default is the global `needs_request_body`, which scripts use) (never for
   an HTTP/1.1 `Upgrade` request, which runs the
   request half unbuffered and skips the response half once a `101` arrives; up to
   `--body-limit`; over it the body
   streams unchanged and the record gets `rewrite_skipped_body_too_large`), then runs
   `on_request` in order. `Respond` ends the chain and the exchange (`respond_locally`, no
   server contact); `Delay` sleeps; `Pause` waits on a `PauseHandle` (oneshot plus
   `--pause-timeout`, default 5 min; timeout goes on unchanged and flags `pause_timed_out`).
5. `connect` gets the tunnel's pooled server connection or opens one; `prepare` rewrites the
   request for the server's protocol; the response head arrives.
6. `intercept_response` does the same for `on_response`: `wants_response_body` sees the
   response head before anything is buffered, so unmatched responses stream with no delay.
   A buffered body keeps its `Content-Length` unless the chain changed it, and `HEAD`, `204`
   and `304` answers never get a new one.
7. The response body streams to the client through `Tee`; when it ends, `on_end` publishes
   `Completed` (or `Failed` when the exchange has an `error`). A refused handshake publishes
   `TlsFailed`; a non-TLS tunnel publishes `Completed` with a `tunnel` record.
8. Subscribers: `FlowStore::follow` (started in `Proxy::bind`), `print_flows` in `main.rs`
   (text or JSON Lines), and each `GET /api/v1/events` SSE stream.

With no interceptors the chain costs one `is_empty()` check; bodies are never buffered.

The record shows what the client sent and what it received: request headers and body before
interceptors, response status, headers and body after them. Bodies sent with a
`Content-Encoding` are stored decoded (`docs/interchange.md`, "Body records"); the bytes
forwarded either way are the wire bytes.

## The flow schema

`events::Flow` = `{ "schema_version": 1, "type": "exchange" | "tls_failure" | "tunnel", ...the
record's fields }`. The JSON Lines log (`--json`), `GET /api/v1/flows/{id}` (inside
`{"state": "done", "flow": ...}`) and the SSE stream (`{"event": "completed", "flow": ...}`)
all serialise this one type. Rules: adding an optional field keeps the version; renaming,
removing or changing the meaning of a field raises `SCHEMA_VERSION`. `flags` is omitted when
empty, so ordinary traffic logs exactly the fields it did before.

## Control plane security (`control.rs`)

| Check | Code | Test (`tests/control.rs`) |
|---|---|---|
| 128-bit token from the OS RNG, printed once as `http://ADDR/#token=...`; API needs `Authorization: Bearer` or the `token` cookie, compared in constant time; never the query string | `new_token`, `State::authorized`, `same_secret` | `the_api_needs_the_token_in_a_header_or_cookie_never_the_query` |
| `Host` must be the listener's address (or `localhost:PORT` on loopback, or any IP literal with the listener's port when bound to an unspecified address with `--allow-remote`): DNS rebinding; `Origin`, when present, must be `http://` plus that host; no `Access-Control-*` headers | `State::host_ok`, `route` | `a_wrong_host_or_origin_is_refused` |
| Loopback only unless `--allow-remote` (`wirust connect` implies it for its LAN listener only; the `--ui` address needs the flag given explicitly, see `RunArgs::ui_access` in `main.rs`) | `check_listen`, `RunArgs::ui_access` | `binding_beyond_loopback_needs_allow_remote`, `connect_keeps_the_ui_on_loopback_unless_allow_remote_was_given` |
| State changes are POST (or PUT for `/api/v1/rules` and `/api/v1/passthrough`); GET never changes state | `route`, `module_routes` | `state_changes_are_post_only_and_responses_are_hardened` |
| `no-store`, `nosniff`, `no-referrer`, `X-Frame-Options: DENY`, strict CSP (no inline script) | `handle` | same |
| The proxy refuses targets on the control plane's port at any loopback/unspecified IP or `localhost` | `Proxy::refuse_target`, `State::refuses` | `the_proxy_refuses_to_reach_the_control_plane` |

## Where features plug in

- **Web UI**: files in `crates/proxy/ui/`, listed in `control::ASSETS`. Data from
  `GET /api/v1/flows?host=&method=&status=&limit=&after=&q=`, `GET /api/v1/flows/{id}`, live
  updates from `GET /api/v1/events` (SSE; the UI must use `fetch` with the Bearer header, since
  `EventSource` cannot send headers, or set the `token` cookie). Keep the CSP: no inline
  scripts or styles.
- **New API routes**: put them in the feature's own `*_api.rs` and call it from
  `control::module_routes`, like `ws_api`, `har_api`, `grpc_api`, `rules_api`, `script_api`
  and `replay_api`. Each
  module answers only the paths it owns, after `route` has checked `Host`, `Origin` and the
  token.
- **Interceptors**: implement `intercept::Interceptor` and push it onto
  `Config::interceptors` in `main.rs::register_interceptors`, like `BlockHost`,
  `HeaderRules` and the three stages `Rules::interceptors` returns (`rules.rs`). Local answers
  return `Action::Respond`; delays return `Action::Delay`; breakpoints call
  `Pauses::pause(flow_id, Phase)` and return `Action::Pause`. Body rules return `true` from
  `needs_request_body`/`needs_response_body`.
- **Search and export**: read `FlowStore::list`/`get` (or subscribe to the bus). HAR is a
  mapping from `events::Flow`, not a new capture path; new query fields go in `query.rs`.
- **Phone setup pages**: add routes in `magic::respond` (served at `http://wirust.test/` to
  the device). The CA is `Ca::cert_pem`/`Ca::cert_der`.
- **WebSocket messages** (`docs/websocket.md`): `proxy::join_upgrades` runs `ws::pump` for
  `Upgrade: websocket` (other upgrades are still copied byte for byte); it forwards unchanged
  bytes and publishes `FlowEvent::WsMessage`, which `FlowStore` keeps in its `WsStore`.

## Known limits

- A bus subscriber more than 4096 events behind skips events (`RecvError::Lagged`); the
  printer reports it on stderr, the store just misses them.
- Pauses are resolved resume, abort or edit over HTTP (`rules_api.rs`, see `docs/rules.md`).
- Requests to the magic host are not recorded as flows.
- `State::refuses` compares addresses only; a DNS name resolving to the control plane is not
  refused by the proxy, but the control plane rejects its `Host`.
