# Upstream proxy

`--upstream-proxy` makes wirust reach servers through another proxy instead of connecting
directly, so it can sit in front of a corporate proxy or any HTTP or SOCKS5 proxy.

```
client -> wirust (decrypts, records) -> upstream proxy -> server
```

## Options

| Option | Meaning |
|---|---|
| `--upstream-proxy URL` | send every outbound connection through this proxy: `http://`, `socks5://` or `socks5h://`, with optional `USER:PASS@` |
| `--upstream-bypass LIST` | comma-separated destinations that connect directly (repeatable): host names, `*.domain`, IP addresses, CIDR ranges |

The URL is `scheme://[user[:password]@]host[:port]`. Without a port, `http://` uses 8080 and
SOCKS uses 1080. Characters such as `@` or `:` in the user name or password are written as
`%40` and `%3A`. An IPv6 host goes in brackets: `socks5://[fd00::1]:1080`.

| Scheme | Tunnels (`https://`, passthrough, other CONNECT traffic, WebSocket upgrades) | Plain `http://` requests | Host names resolved by |
|---|---|---|---|
| `http://` | `CONNECT host:port` | absolute-form `GET http://host/path`, the proxy's credentials added as `Proxy-Authorization` | the upstream proxy |
| `socks5://` | SOCKS5 `CONNECT` to an IP address | the same SOCKS5 tunnel | wirust |
| `socks5h://` | SOCKS5 `CONNECT` to the host name | the same SOCKS5 tunnel | the upstream proxy |

Credentials go to an HTTP proxy as `Basic` `Proxy-Authorization` and to a SOCKS5 server as
user name and password authentication (RFC 1929). An IP address target is always sent as an
address.

What goes through the upstream proxy: decrypted HTTP/1.1 and HTTP/2 exchanges, WebSocket
upgrades, TLS passthrough tunnels, non-TLS CONNECT tunnels, and replays sent from the API or
the UI. `wirust replay --via` goes through the running wirust, so it follows the same route.

## What goes direct

- Loopback addresses (`127.0.0.0/8`, `::1`), `0.0.0.0`, `localhost` and `*.localhost`, and
  wirust's own setup host `wirust.test`, whatever the bypass list says.
- Destinations on `--upstream-bypass`. Matching ignores case. `*.corp.example` (or
  `.corp.example`) matches `corp.example` and every subdomain; `intranet` matches only that
  name; `10.0.0.0/8` and `fd00::/8` match IP address targets in the range; a single IP matches
  only itself. A host name is not resolved to check it against a CIDR range.

```sh
wirust --upstream-proxy http://proxy.corp.example:3128 \
       --upstream-bypass '*.corp.example,10.0.0.0/8'
```

## Seeing it in the flows

An exchange whose server connection went through the upstream proxy carries the flag
`upstream_proxy`: a badge in the UI's Flags row, and in the API, session files and the HAR
`_flags` field, like every other flag.
Tunnel records (passthrough and non-TLS tunnels) have no flags and do not show it.

## Errors

When the upstream proxy cannot be reached, refuses the tunnel, rejects the credentials
(`407`, a failed SOCKS5 login) or answers with a SOCKS5 error code, the client gets a `502`
page and the flow's error names the upstream proxy, for example:

```
upstream proxy socks5://alice:***@10.1.2.3:1080: tunnel to example.com:443: SOCKS5 reply 5: connection refused
```

Connecting to the upstream proxy and setting up the tunnel share the 10 second connect
timeout of direct connections.

## Credentials

The password is never printed. wirust shows the upstream proxy as
`scheme://user:***@host:port` in its start-up line, in errors and in flows, and a malformed
URL is reported without repeating it. The `Proxy-Authorization` header wirust adds is not
part of the recorded request.

wirust warns once at start-up when credentials go to an `http://` proxy that is not on
loopback, because they then cross the network in clear text. A password on the command line
can be read by other local users through the process list; prefer a local proxy without
credentials when that matters.

## Loops

wirust refuses to start when the upstream proxy is its own listener (a loopback address or
`localhost` with the same port), and answers `508 Loop Detected` to a `CONNECT` aimed at its
own listener.

## Behind a corporate proxy

1. Find the proxy your system uses (the PAC file or the network settings name it, often
   `http://proxy.example:3128` or `:8080`).
2. Start wirust with it, and list internal hosts the proxy does not serve:

   ```sh
   wirust --ui 127.0.0.1:8081 \
          --upstream-proxy http://proxy.example:3128 \
          --upstream-bypass '*.internal.example,10.0.0.0/8'
   ```

3. Point the browser or app at wirust (`127.0.0.1:8080`) as usual.

If the corporate proxy itself decrypts TLS with its own root, servers will present
certificates wirust does not trust, because wirust checks servers against the Mozilla roots
only, not the OS store. The exchanges then fail with a certificate error;
`--upstream-insecure` turns that check off (and warns on every start).
