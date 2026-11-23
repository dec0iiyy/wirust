# Interchange: HAR, sessions, search, cURL, code

## Privacy first

Session files, HAR files and cURL commands hold the traffic as it was: `Authorization`
headers and bearer tokens, cookies, API keys in URLs, passwords in form bodies, personal data
in responses. Treat them like passwords:

- session files and HAR files written by `wirust` are created with mode 0600 (owner only) on
  unix; an existing `--session` file open to other users is narrowed to 0600 with a warning,
  and a symbolic link given as `--session` is refused; the start-up banner says
  `saving sessions to FILE (contains request data)`;
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

WebSocket messages are lines of their own, written after their flow's record as they
arrive: `{"schema_version": 1, "type": "ws_message", "flow_id": 12, "seq": 0, ...}` with the
fields of a message in `docs/websocket.md`. This is an additive record type, so
`schema_version` stays 1 and files without such lines load as before; `view`, `export` and
`--filter` read them. wirust 0.2 and older stop at the first message line.

## Body records

`request_body` and `response_body` are `{ "size", "truncated", "encoding": "utf8" | "base64",
"data" }`: the first `--body-limit` bytes of the body. A body sent with a `Content-Encoding`
other than `identity` is decoded before it is stored, and the record gains
`content_encoding` (omitted otherwise, so `schema_version` stays 1 and older files load as they
are):

```json
"response_body": {
  "size": 1256, "truncated": false, "encoding": "utf8", "data": "<!doctype html>...",
  "content_encoding": { "codings": ["br"], "wire_size": 334, "decoded": true }
}
```

| Field | Meaning |
|---|---|
| `codings` | the codings in the order the sender applied them, lowercase, `identity` left out (`gzip, br` = gzip first) |
| `wire_size` | bytes on the wire, all of them, also past the limit |
| `decoded` | `true`: `data` and `size` are the decoded body; `false`: they are the wire bytes |
| `reason` | why the body is not decoded (unknown coding, invalid data), or why the decoded body is cut short; omitted when there is nothing to say |

- Codings: `gzip` and `x-gzip` (several members allowed), `deflate` (zlib-wrapped, or raw
  deflate as some servers send), `br`, `zstd`. Lists are undone last first. An unknown coding
  or invalid data keeps the wire bytes with `decoded: false` and a `reason`.
- Limits: the decoded output stops at `--body-limit` per body (and per layer of a list) and at
  1000 output bytes per input byte (at least 64 KiB), whichever comes first; the record is then
  `truncated` and `size` counts the decoded bytes kept. A body whose wire bytes were cut by the
  limit decodes as far as the kept bytes go and is `truncated` too.
- Only the stored copy is decoded: what goes to the client and to the server is unchanged.

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
| `request.headersSize`, `bodySize` | -1 (unknown); the full body size on the wire (`wire_size` for a decoded body) |
| `response.status`, `statusText`, `httpVersion` | 0 and `""` when no response arrived |
| `response.headers`, `cookies`, `redirectURL` | original order; `Set-Cookie` with path, domain, expires, httpOnly, secure; `Location` |
| `response.content` | `size`, `mimeType` (`x-unknown` when absent), `text`, `encoding`; a decoded body writes the decoded `text` and `size`, and `compression` = decoded minus wire bytes (when decoded whole) |
| `response.bodySize` | the body size on the wire (`wire_size` for a decoded body); `Content-Encoding` stays in `headers` |
| `timings` | `blocked` and `dns` -1; `connect` = TCP + TLS and `ssl` = TLS when this exchange opened the connection, else -1; `send` 0; `wait` until the response head; `receive` the rest. They add up to `time` |
| `serverIPAddress`, `connection` | not recorded yet, so omitted |
| `comment` on `postData` / `content` | set when the body was cut by `--body-limit`: the text holds only the start |
| `_tls` | client-leg TLS: `version`, `sni`, `alpn`, `ja4`, `ja3`, `client` (known client name) |
| `_flags` | interceptor flags, such as `pause_timed_out` |
| `_error` | why the exchange failed |
| `_webSocketMessages` | the messages of a WebSocket upgrade, Chrome's format: `type` (`send`/`receive`), `time` (seconds since the epoch), `opcode`, `data` (text, or base64 for other payloads); from memory with `--ui`, from the session's message lines with `export` |

Import is best effort: unknown fields are ignored, missing ones get neutral values, `_tls`,
`_flags` and `_error` are read back, and every flow gets the flag `imported`. HAR text is the
decoded body (HAR 1.2), so a body whose headers name a `Content-Encoding` is imported with
`content_encoding.decoded: true` and `bodySize` as its `wire_size`. Imported flows
have no client address (`0.0.0.0:0`). The file may be at most 512 MiB and 1,000,000 entries;
anything that is not JSON shaped like a HAR document is an error naming line and column.

## The query language

One language for `GET /api/v1/flows?q=`, `GET /api/v1/har?q=`, `--filter`, and the UI.
A search always runs over whole flows; `GET /api/v1/flows?q=...&view=summary` only answers
the matches in summary form (no headers or bodies, `docs/ui.md`, "Summary view").

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
| `body:"free text"` | request or response body contains it (first 1 MiB of each stored body, which is the decoded body for `Content-Encoding`; base64 bodies are decoded) |
| `size:>10k` | response body size; `b`, `k`, `m`, `g` (powers of 1024) |
| `time:>500ms` | total time; `ms` (default) or `s` |
| `client:curl` | the known TLS client or the `User-Agent` contains it |
| `tls:failed`, `tls:yes`, `tls:none`, `tls:1.3` | failed handshake, intercepted TLS, plain HTTP, negotiated version |
| `flag:pause_timed_out` | the flow carries this flag (`responded`, `aborted`, `imported`, ...) |
| `ws:subscribe`, `ws:` | a WebSocket message of the flow contains the text (kept payload, decompressed for `permessage-deflate`; base64 payloads decoded); `ws:` alone: the flow has messages |
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

## Code export

`GET /api/v1/flows/{id}/code?lang=LANG` answers `text/plain; charset=utf-8` with a complete
snippet, imports included, that sends the request again. `LANG` is `python` (requests),
`fetch` (JavaScript, browser or Node 18+), `okhttp` (Kotlin), `urlsession` (Swift), `httpie`
or `powershell` (`Invoke-WebRequest`). An unknown or missing `lang` is a 400 that lists the
names; an unknown flow, or one that is not an HTTP exchange, is a 404; a flow still running
is a 409. The route needs the control plane's token like the rest of the API, and the snippet
holds only what the flow recorded, never the token.

- method, URL, headers in the original order and body of the captured request. Left out are
  the HTTP/2 pseudo headers, hop-by-hop headers, `Content-Length`, `Accept-Encoding` (each
  library asks for the encodings it can decode), a `Host` equal to the URL's host, and
  `Content-Encoding` when the stored body is decoded, so the snippet sends the decoded body.
  A header that was sent twice is joined into one (`; ` for `Cookie`, `, ` otherwise);
- text bodies are string literals escaped for the language (quotes, backslashes, newlines,
  tabs, control and invisible characters, `$` in Kotlin, backticks and `$` in PowerShell).
  A raw or multi-line literal is used instead where the language has one and the text is safe
  in it (Python `r'...'` and triple quotes, JavaScript template literals, Kotlin raw strings,
  Swift `#"..."#`, PowerShell single-quoted and here-strings), so JSON stays readable;
- binary bodies are Base64 text decoded in the code (`base64.b64decode`, `atob`,
  `Base64.getDecoder()`, `Data(base64Encoded:)`, `FromBase64String`, `base64 -d` for HTTPie);
- text with characters outside ASCII is sent as UTF-8: Python and PowerShell encode the string
  explicitly, OkHttp takes the bytes. A header value outside ASCII is sent as its UTF-8 bytes
  too (bytes in Python, `addUnsafeNonAscii` in OkHttp, byte-valued characters with a comment in
  JavaScript and Swift);
- OkHttp puts `Content-Type` in the request body's media type, because OkHttp overrides the
  header with it; the body is a byte array so OkHttp adds no charset;
- the snippets leave every other setting at the library's default, redirects included;
- a cut body adds a comment line saying so.

The tests run the Python (with `requests`), JavaScript and Swift snippets against a local
server and compare the method, target, headers and body the server read (Swift for four of
the eight cases, since each one is compiled; a language whose tool is missing is skipped).
The other three languages are covered by golden files only and were not run.

## cURL export

`GET /api/v1/flows/{id}/curl` answers `text/plain` with a command that repeats the request:

- method (`-X` only when cURL would not pick it; `--head` for HEAD), URL (`--globoff` when it
  holds `[]{}`), `--http2` or `--http1.1` after the client's protocol;
- headers in the original order, without HTTP/2 pseudo headers, hop-by-hop headers and
  `Content-Length`; `Accept-Encoding` becomes `--compressed`; an empty header is sent as
  `-H 'Name;'`; `Content-Encoding` is left out when the stored body is decoded, so the
  command sends it as identity;
- the body as `--data-binary`; binary bodies and text starting with `@` (which cURL would read
  as a file name) are piped in: `printf '%s' '...' | base64 -d | curl ... --data-binary @-`;
- every argument that is not plain is single-quoted, so `$`, backticks, quotes, newlines and
  non-ASCII text arrive unchanged; a cut body adds a `#` comment line saying so.
