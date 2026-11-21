# Roadmap

Not built yet, in rough priority order. Everything else described in `docs/` is built.

1. Upstream proxy: reach servers through a corporate HTTP proxy with CONNECT. Direct only today.
2. System proxy auto-setup (macOS network services, Windows, GNOME) with clean undo.
3. Replay, compose and passthrough in the web UI; today they are API and CLI only.
4. WebSocket: `permessage-deflate` decoding instead of stripping, a `ws:` search field,
   messages in session files, sending and editing messages.
5. WebSocket over HTTP/2 (RFC 8441 extended CONNECT).
6. gRPC with `.proto` files or server reflection (field names), and inflating compressed
   messages; today messages are decoded schema-less and compressed ones only listed.
7. Scripting: rules are declarative TOML, with no user code.
8. HTTP/3 interception: QUIC is UDP and cannot go through an HTTP CONNECT tunnel, so clients
   fall back to h2 or HTTP/1.1. It needs a MASQUE (`CONNECT-UDP`) or transparent mode.
9. SOCKS5 listener for clients that cannot use an HTTP proxy.
10. TUI: a terminal flow list with detail panes.
11. Diff view between two flows.
12. Native desktop app; the UI is a browser page served by the binary.
13. The client's TLS audit (weak ciphers, missing extensions) next to JA4.
14. Testing on real phones: `docs/mobile.md` is written from documentation, not devices.
