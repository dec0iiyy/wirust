# Options and commands

`wirust --help` lists every option and command; `wirust COMMAND --help` (for example
`wirust ca --help`) shows one command's options. This page groups them.

## Running the proxy

| Option | Default | Meaning |
|---|---|---|
| `--listen ADDR` | `127.0.0.1:8080` | proxy address; for `system-proxy on`, the address of the running proxy |
| `--ui ADDR` | off | serve the web UI and API, such as `127.0.0.1:8081` |
| `--token-file FILE` | | with `--ui`: write the UI link, which holds the token, to FILE (mode 0600) |
| `--json` | | one JSON object per line instead of text |
| `--body-limit BYTES` | `1048576` | body bytes kept per request and response |
| `--max-flows N` | `5000` | flows kept in memory for the UI and API |
| `--max-memory SIZE` | `512MiB` | bytes of flow data kept in memory: bodies, headers, trailers, URLs and WebSocket messages of the held flows, plus a small fixed overhead per record; plain bytes or a `K`, `M`, `G`, `KiB`, `MiB`, `GiB` suffix (all powers of 1024). Over the budget the oldest finished flows go first; pending flows and the newest eight stay. `--max-flows` still applies; `GET /api/v1/info` reports the use |
| `--pause-timeout SECS` | `300` | how long a breakpoint waits before the exchange goes on |
| `--config-dir DIR` | platform config dir | where the CA is kept |
| `--session FILE` | | append every finished flow as JSON Lines (mode 0600; it holds tokens, cookies and passwords from the traffic) |
| `--allow-remote` | | allow a non-loopback `--listen` or `--ui` address (dangerous) |
| `--upstream-insecure` | | do not verify server certificates (dangerous) |

Fixed limits on client connections (no flags; see "Client connection limits" in
`docs/architecture.md`): a request head must arrive within 30 s, a connection with no
request in flight (or a non-TLS tunnel without traffic) closes after 5 min, an HTTP/2
preface must arrive within 10 s, and at most 10,000 client connections are served at once
(more get `503`). Requests in flight, downloads, WebSockets and TLS tunnels are not cut.

## Changing traffic

| Option | Meaning |
|---|---|
| `--rules FILE` | TOML rules (block, map local, map remote, rewrite, throttle, breakpoints), reloaded when the file changes; [rules.md](rules.md) |
| `--script FILE` | sandboxed Rhai script with `on_request` / `on_response` hooks (repeatable), reloaded when it changes; [scripting.md](scripting.md) |
| `--block-host HOST` | answer HOST and its subdomains with 403 (repeatable) |
| `--add-header 'N: V'`, `--remove-header NAME` | change every request sent to servers (repeatable) |
| `--passthrough PATTERN`, `--decrypt-only PATTERN` | relay matching hosts undecrypted, or decrypt only those (repeatable); [passthrough.md](passthrough.md) |
| `--upstream-proxy URL` | reach servers through an `http://`, `socks5://` or `socks5h://` proxy, optional `USER:PASS@`; [upstream-proxy.md](upstream-proxy.md) |
| `--upstream-bypass LIST` | hosts, `*.domains`, IPs and CIDRs that skip the upstream proxy (repeatable) |

## Protocols

| Option | Default | Meaning |
|---|---|---|
| `--proto PATH` | | `.proto` file, or a directory scanned for them, to decode gRPC messages with field names (repeatable), reloaded on change; [grpc.md](grpc.md) |
| `--proto-include DIR` | | import root for `--proto` files (repeatable) |
| `--proto-message TYPE` | | message type for bare `application/x-protobuf` bodies, such as `pkg.Msg` |
| `--ws-body-limit BYTES` | `1048576` | WebSocket bytes kept per message |
| `--ws-max-messages N` | `1000` | WebSocket messages kept per connection |
| `--ws-log` | | print one line per WebSocket message |
| `--ws-strip-compression` | | remove the client's WebSocket extension offer, for peers whose `permessage-deflate` misbehaves (by default it is decompressed for the record); [websocket.md](websocket.md) |

## Commands

| Command | What it does |
|---|---|
| `connect` | listen on this computer's LAN address, show a QR code of the setup page and ask before each phone may use the proxy; options `--port`, `--lan-ip`, `--allow-client`; [mobile.md](mobile.md) |
| `android setup`, `android reset` | over adb: reverse the port, set the device's proxy, copy the CA; or undo it; `--serial` picks a device. `--android-cleanup` on the proxy undoes it on exit |
| `ca path`, `ca show`, `ca install-help` | where the CA certificate is, the certificate in PEM, how to trust it by hand |
| `ca install`, `ca uninstall`, `ca status` | trust the CA for your user only (asks for `yes` first, `--yes` skips), remove exactly that certificate, say whether it is trusted; [desktop.md](desktop.md) |
| `system-proxy on`, `off`, `status` | point the system proxy at wirust, saving the old settings; restore them; show them. `--system-proxy` on a normal run does the same while it lives |
| `export --har OUT`, `import --har IN --session OUT` | HAR 1.2 from a session file (`--filter` narrows it), or HAR to a session file; [interchange.md](interchange.md) |
| `view --session FILE` | print a session file, `--filter` narrows it |
| `replay --session FILE --id N` | send a flow again through a running proxy (`--via`), optionally changed (`--set-header`, `--method`, `--url`); [replay.md](replay.md) |
| `mcp` | a Model Context Protocol server on stdio so AI agents can inspect a running `wirust --ui`; options `--api`, `--token`, `--token-file`, `--allow-write`, `--no-redact`, `--max-output`; [mcp.md](mcp.md) |
| `wireguard` | experimental, only in builds with the cargo feature `wireguard`: capture a phone's TCP traffic through the official WireGuard app; [wireguard.md](wireguard.md) |

## Terminal output

The proxy prints one line per exchange, with or without `--ui` (`--json` for JSON Lines):

```
13:31:06 GET    https://example.com/  200  OK  h2  289 ms  577 B  curl 8.7.1 (ja4 t13d4907h2_0d8feac7bc37_7395dae3b2f3)
13:31:07 TLS-FAIL example.com via example.com:443  received fatal alert: UnknownCA  (ja4 t13d4907h2_..., curl 8.7.1)  hint: the client does not trust the CA or pins certificates; to relay it undecrypted: --passthrough example.com
```

When a client keeps rejecting the CA, only its first `TLS-FAIL` per host and error is printed
in full; the repeats within 30 seconds become one line such as
`13:31:09 TLS-FAIL example.com (x4 more in the last 30 s)  received fatal alert: UnknownCA`.
The UI, the session file and `--json` still have every failure.

The log never slows the proxy down. A separate thread writes it, with a queue of 16,384
lines; when the terminal or the program reading a pipe falls behind, new lines are dropped
and, once the writer catches up, one line on the standard error says
`wirust: N log lines dropped (the output is too slow)`. If the standard output is closed (the
reader of a pipe exited), the proxy prints one line about it on the standard error, stops the
log and keeps running: the UI, the API and the session file still get every flow.

Requests to `http://wirust.test/` through the proxy get a page with the CA download.
