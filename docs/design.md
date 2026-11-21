# Design decisions

## Decision: hyper 1 + tokio-rustls + rcgen directly, not hudsucker

hudsucker is a good MITM library, but it owns the TLS accept: it hands the upgraded CONNECT
stream straight to its own `TlsAcceptor`. The first requirement of this tool is to see the
raw ClientHello bytes before the handshake (for JA4, JA3 and naming the client), and
hudsucker has no hook there. Patching or forking it would cost more than the ~600 lines the
direct design needs, and the direct design keeps full control of timing, ALPN on both legs
and body streaming.

## How a connection flows

1. `TcpListener` on 127.0.0.1 (non-loopback refused without `--allow-remote`). Each client
   connection is served by hyper's HTTP/1.1 server with upgrades on.
2. `CONNECT host:port` gets `200`, then the upgraded stream goes to `hello::peek`, which reads
   whole TLS records until the ClientHello handshake message is complete (fragmented
   hellos included, capped at 64 KiB) and keeps every byte it read.
3. The message is parsed with the `fingerprint` crate: JA4, JA3, SNI, and the known-client
   lookup. A leaf certificate for the SNI (else the CONNECT host) is issued by the local CA
   (ECDSA P-256) and cached per host as a ready `rustls::ServerConfig`.
4. `hello::Prefixed` replays the recorded bytes ahead of the stream, so `tokio-rustls`
   accepts the connection exactly as the client sent it. A failed handshake becomes a
   `tls_failure` record (SNI, reason, JA4) and the proxy carries on.
5. ALPN picks hyper's h2 or HTTP/1.1 server for the client leg. Each request is forwarded on
   one upstream connection per tunnel (opened by the first request; h2 offered upstream only
   if the client offered it), rewritten for the upstream protocol (origin-form + `Host` for
   HTTP/1.1, absolute URI for h2; hop-by-hop headers removed).
6. Bodies stream through `body::Tee`, which copies at most `--body-limit` bytes per body into
   the log and calls back when the response body ends; that callback emits the record.
7. A tunnel that does not start with a TLS handshake within 2 s (server-speaks-first
   protocols) or starts with other bytes is passed through and logged as a `tunnel` record.
8. Plain `http://` absolute-form requests are forwarded on a new connection each.
9. WebSocket (HTTP/1.1 `Upgrade`) gets its own upstream connection; after `101` the bytes
   pass through unchanged while the messages are parsed and recorded
   (`docs/websocket.md`). Other upgrades are joined byte for byte.

## What each choice costs

- **Own accept loop:** we maintain the CONNECT/upgrade/ALPN glue hudsucker would give us
  for free, and its tests.
- **One upstream connection per tunnel:** an HTTP/1.1 upstream serialises requests that an
  h2 client sends in parallel (the next request waits for the previous response body). An
  h2 upstream multiplexes them. No cross-tunnel pool, so every tunnel pays one upstream
  handshake.
- **Translating h2 and HTTP/1.1** between legs means header rewriting (`Host` vs
  `:authority`, cookie joining); unusual requests may change shape on the way.
- **Header case** is preserved on the HTTP/1.1 legs when forwarding (hyper's
  `preserve_header_case`), but the log shows lowercase names: hyper does not expose the
  original case. Order is preserved except that repeated names are grouped.
- **Leaf issued per host on first use:** one P-256 signature (well under a millisecond) per
  new host; the cache holds up to 4096 hosts and is then cleared.
- **The CA certificate is not re-parsed on start:** its fixed subject is rebuilt and paired
  with the stored key, which avoids an X.509 parser dependency. If someone edits the
  certificate file, leaves will not chain to it.
- **Upstream trust is the Mozilla root set (`webpki-roots`),** not the OS store, so a
  corporate root installed in the OS is not trusted upstream; `--upstream-insecure` is the
  explicit escape hatch.
- **aws-lc-rs** (rustls' default provider) needs a C toolchain (and CMake on some
  platforms) to build.
