# Roadmap

Not built yet, in rough priority order. Everything else described in `docs/` is built.

1. Scripting: rules are declarative TOML, with no user code.
2. HTTP/3 interception: QUIC is UDP and cannot go through an HTTP CONNECT tunnel, so clients
   fall back to h2 or HTTP/1.1. It needs a transparent mode (a WireGuard-style entry point)
   or MASQUE (`CONNECT-UDP`). The same mode would catch apps that ignore the system proxy.
3. Testing on real phones and on iOS: `docs/mobile.md` was tried only on the Android emulator.
4. Passthrough patterns in the web UI (replay and compose are there).
5. WebSocket: sending and editing messages.
6. gRPC with `.proto` files or server reflection (field names), and inflating compressed
   messages (the body decoder in `decode.rs` could be reused); today messages are decoded
   schema-less and compressed ones only listed.
7. WebSocket over HTTP/2 (RFC 8441 extended CONNECT).
8. SOCKS5 listener for clients that cannot use an HTTP proxy.
9. Replay of a body that was compressed on the wire sends it as identity; re-encoding it would
   make a replay byte-for-byte again.
10. TUI: a terminal flow list with detail panes.
11. Diff view between two flows.
12. Native desktop app; the UI is a browser page served by the binary.
13. The client's TLS audit (weak ciphers, missing extensions) next to JA4.
