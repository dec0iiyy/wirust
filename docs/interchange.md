# Interchange: HAR, sessions, search, cURL

## Privacy first

Session files, HAR files and cURL commands hold the traffic as it was: `Authorization`
headers and bearer tokens, cookies, API keys in URLs, passwords in form bodies, personal data
in responses. Treat them like passwords:

- session files and HAR files written by `wirust` are created with mode 0600 (owner only) on
  unix; the start-up banner says `saving sessions to FILE (contains request data)`;
- before attaching a HAR to a bug report, remove what the recipient must not see (headers,
  cookies, bodies), or record a fresh session with a throwaway account;
- the HAR route and the cURL route need the control plane's token like the rest of the API.

## Session files

```sh
wirust --session today.jsonl                    # append every finished flow
wirust view --session today.jsonl               # print it as the live log does
wirust view --session today.jsonl --filter 'host:api.example.com status:5xx'
```

A session file is JSON Lines: one finished flow per line, exactly the `--json` output (each
record carries `schema_version`, see `docs/architecture.md`). `--session` appends, so one file
can span several runs. Each line is flushed when written; after a crash the last line may be
cut, and readers skip it with a warning. A record with a newer `schema_version` is read with a
warning and its unknown fields are ignored. Any other broken line is an error naming the line.

## HAR export and import

```sh
wirust export --har out.har --session today.jsonl [--filter QUERY]
wirust --json | wirust export --har - --filter 'type:json'   # no --session: JSON Lines on stdin
wirust import --har devtools.har --session imported.jsonl  # the output must not exist yet
```

With `--ui`, `GET /api/v1/har?q=QUERY&limit=N` downloads the flows held in memory as
`wirust-YYYYMMDD-HHMMSS.har` (`Content-Disposition: attachment`).

Export writes HAR 1.2. Only HTTP exchanges become entries; raw tunnels and failed handshakes
have no HAR form. The mapping:

| HAR | From the flow |
|---|---|
| `log.version`, `log.creator` | `1.2`; `wirust` and the crate version. `pages` is omitted |
| `startedDateTime`, `time` | `time` (RFC 3339 UTC); `timing.total_ms` |
| `request.method`, `url`, `httpVersion` | as recorded; `h2` becomes `HTTP/2` |
| `request.headers`, `cookies`, `queryString` | headers in the original order; `Cookie` pairs; the URL query, percent-decoded |
| `request.postData` | `mimeType` from `Content-Type`, `text`, `encoding: "base64"` for binary bodies |
| `request.headersSize`, `bodySize` | -1 (unknown); the full body size |
| `response.status`, `statusText`, `httpVersion` | 0 and `""` when no response arrived |
| `response.headers`, `cookies`, `redirectURL` | original order; `Set-Cookie` with path, domain, expires, httpOnly, secure; `Location` |
| `response.content` | `size`, `mimeType` (`x-unknown` when absent), `text`, `encoding` |
| `timings` | `blocked` and `dns` -1; `connect` = TCP + TLS and `ssl` = TLS when this exchange opened the connection, else -1; `send` 0; `wait` until the response head; `receive` the rest. They add up to `time` |
| `serverIPAddress`, `connection` | not recorded yet, so omitted |
| `comment` on `postData` / `content` | set when the body was cut by `--body-limit`: the text holds only the start |
| `_tls` | client-leg TLS: `version`, `sni`, `alpn`, `ja4`, `ja3`, `client` (known client name) |
| `_flags` | interceptor flags, such as `pause_timed_out` |
| `_error` | why the exchange failed |

Import is best effort: unknown fields are ignored, missing ones get neutral values, `_tls`,
`_flags` and `_error` are read back, and every flow gets the flag `imported`. Imported flows
have no client address (`0.0.0.0:0`). The file may be at most 512 MiB and 1,000,000 entries;
anything that is not JSON shaped like a HAR document is an error naming line and column.

## The query language

One language for `GET /api/v1/flows?q=`, `GET /api/v1/har?q=`, `--filter`, and the UI.

```text
query   := or
or      := and ( "OR" and )*
and     := unary ( ["AND"] unary )*        terms side by side are ANDed
unary   := "-" unary | primary              "-" negates
primary := "(" or ")" | field ":" value | word | "\"" text "\""
```

`AND` binds tighter than `OR`: `a b OR c` is `(a b) OR c`. Text comparisons ignore ASCII case.
Quote values with spaces: `body:"free text"` (`\"` and `\\` escape inside quotes).

| Term | Matches |
|---|---|
| `host:example.com` | host contains the text (tunnels: the target; failed handshakes: the SNI) |
| `path:/api/*` | path (no query string) matches the glob; without `*`, path starts with it |
| `method:POST` | exact method |
| `status:404`, `status:5xx`, `status:>=400` | exact code, class, or comparison (`>`, `>=`, `<`, `<=`, `=`) |
| `type:json` | response `Content-Type` contains it (`js` = javascript, `image`/`img` = `image/`) |
| `header:content-type=json` | a request or response header with that name whose value contains the text |
| `header:authorization` | the header is present |
| `body:"free text"` | request or response body contains it (first 1 MiB of each stored body; base64 bodies are decoded) |
| `size:>10k` | response body size; `b`, `k`, `m`, `g` (powers of 1024) |
| `time:>500ms` | total time; `ms` (default) or `s` |
| `client:curl` | the known TLS client or the `User-Agent` contains it |
| `tls:failed`, `tls:yes`, `tls:none`, `tls:1.3` | failed handshake, intercepted TLS, plain HTTP, negotiated version |
| `flag:pause_timed_out` | the flow carries this flag (`responded`, `aborted`, `imported`, ...) |
| `word`, `"two words"` | the URL contains it (tunnels and failed handshakes: target or SNI) |

Examples:

```text
host:api.example.com status:5xx
method:POST -header:authorization (path:/login OR path:/token)
type:json time:>500ms OR size:>1m
```

Limits: a query is at most 4096 bytes and nests parentheses and negations at most 32 deep;
beyond that, and on any syntax error, the API answers 400 with
`{"error": "query error at position N: expected ..."}`.

## cURL export

`GET /api/v1/flows/{id}/curl` answers `text/plain` with a command that repeats the request:

- method (`-X` only when cURL would not pick it; `--head` for HEAD), URL (`--globoff` when it
  holds `[]{}`), `--http2` or `--http1.1` after the client's protocol;
- headers in the original order, without HTTP/2 pseudo headers, hop-by-hop headers and
  `Content-Length`; `Accept-Encoding` becomes `--compressed`; an empty header is sent as
  `-H 'Name;'`;
- the body as `--data-binary`; binary bodies and text starting with `@` (which cURL would read
  as a file name) are piped in: `printf '%s' '...' | base64 -d | curl ... --data-binary @-`;
- every argument that is not plain is single-quoted, so `$`, backticks, quotes, newlines and
  non-ASCII text arrive unchanged; a cut body adds a `#` comment line saying so.
