# Roadmap

Not built yet, in rough priority order. Everything else described in `docs/` is built.

1. HTTP/3 interception: QUIC is UDP and cannot go through an HTTP CONNECT tunnel, so clients
   fall back to h2 or HTTP/1.1. It needs a transparent mode (a WireGuard-style entry point)
   or MASQUE (`CONNECT-UDP`). The same mode would catch apps that ignore the system proxy.
   An experimental WireGuard capture mode behind the cargo feature `wireguard` (not in release
   binaries) terminates TCP and QUIC (`docs/wireguard.md`): HTTP/3 requests from the phone
   become flows. Not built yet: HTTP/3 to the server (the server leg is HTTP/2 or HTTP/1.1),
   JA4 for QUIC clients, and a test with a real phone.
2. Testing on real phones and on iOS: `docs/mobile.md` was tried only on the Android emulator.
3. Passthrough patterns in the web UI (replay and compose are there).
4. WebSocket: editing or dropping messages in flight (breakpoints on messages).
5. gRPC schemas from server reflection and compiled descriptor sets (`.proto` files through
   `--proto` and inflating compressed messages are done, see docs/grpc.md).
6. WebSocket over HTTP/2 (RFC 8441 extended CONNECT).
7. SOCKS5 listener for clients that cannot use an HTTP proxy.
8. Replay of a body that was compressed on the wire sends it as identity; re-encoding it would
   make a replay byte-for-byte again.
9. TUI: a terminal flow list with detail panes.
10. Diff view between two flows.
11. Native desktop app; the UI is a browser page served by the binary.
12. The client's TLS audit (weak ciphers, missing extensions) next to JA4.
13. `wirust mcp` (docs/mcp.md): MCP resources and `subscriptions/listen` for live flows,
    the Streamable HTTP transport, and pause (breakpoint) tools; it has tools over stdio only.
