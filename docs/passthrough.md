# TLS passthrough

By default every CONNECT tunnel that carries TLS is intercepted: the proxy answers with a
leaf certificate from its CA and decrypts the traffic. Passthrough hosts are relayed
undecrypted instead.

## Flags

- `--passthrough PATTERN` (repeatable): never intercept matching hosts.
- `--decrypt-only PATTERN` (repeatable): when given, intercept only matching hosts and relay
  everything else. `--passthrough` wins over `--decrypt-only`.

A pattern is a host name or IP literal, optionally with `:PORT`:

| Pattern | Matches | Does not match |
|---|---|---|
| `api.example.com` | `api.example.com` on any port, any case, with or without a trailing dot | `x.api.example.com` |
| `api.example.com:443` | the same, port 443 only | `api.example.com:8443` |
| `*.bank.example` | `www.bank.example`, `a.b.bank.example` | `bank.example`, `evilbank.example` |
| `[::1]:8443` | `::1` on port 8443 | |

`*.` is allowed only as the whole left-most label; `a.*.b`, `*bank.example` and `*` are
refused. At most 1000 patterns per list.

The CONNECT host and, when it differs, the ClientHello's SNI are both tried; a match on
either counts. So `--passthrough '*.bank.example'` also covers `CONNECT 203.0.113.5:443`
when the client sends SNI `www.bank.example`.

## When to use it

- An app pins certificates and fails the handshake with the proxy (the log line says
  `TLS-FAIL ... hint: ... to relay it undecrypted: --passthrough HOST`). Relaying keeps the app
  working while you debug the rest of its traffic.
- Hosts you must not decrypt: banking, health, corporate single sign-on.
- Noise you do not care about (telemetry, update checks), to keep the log and the CPU free.

## What is still recorded

Each passthrough tunnel ends with a `tunnel` record:

```json
{"schema_version":1,"type":"tunnel","id":7,"time":"...","client":"127.0.0.1:53211",
 "target":"www.bank.example:443","bytes_up":1834,"bytes_down":5120,"error":null,
 "reason":"passthrough","duration_ms":812.4,
 "tls":{"sni":"www.bank.example","alpn_offered":["h2","http/1.1"],
        "ja4":"t13d1516h2_8daaf6152771_02713d6af862","ja3_hash":"...","known_client":"Chrome 131"}}
```

The ClientHello is read before the decision, so the client's SNI, offered ALPN, JA4, JA3 and
the matching known client are recorded exactly as for intercepted tunnels. Bytes in both
directions, the duration and a connection error are recorded too. `reason`, `tls` and
`duration_ms` are optional fields, so `schema_version` stays 1; non-TLS tunnels omit them.
The web UI reads the same `tls` object: the row's Client column shows `known_client`, or the
JA4 when none matches, and the Client TLS tab shows the SNI, the offered ALPN and both
fingerprints (`GET /api/v1/flows/{id}` returns it).

## What is not

Nothing inside the TLS session: no URLs, methods, headers, bodies, status codes or server
certificate details. Rules, breakpoints, replay and HAR export do not apply to passthrough
tunnels. Server certificates are not checked by the proxy: the client verifies them itself,
as it would without a proxy.

## Live API (control plane, `--ui`)

- `GET /api/v1/passthrough`: `{"passthrough": [...], "decrypt_only": [...]}`.
- `PUT /api/v1/passthrough` with the same shape: validates both lists and swaps them at once;
  `400` with the first bad pattern leaves the old lists in place. Token-protected like every
  API route. Tunnels already open keep the decision they made when their ClientHello arrived.
