# Scripting

`--script FILE` loads a script written in [Rhai](https://rhai.rs), a small embedded language
with a JavaScript/Rust-like syntax. The flag is repeatable; each file is one stage of the
interceptor chain, in the order given. A script defines either or both of two hooks:

```rhai
fn on_request(req) { }        // before the request goes to the server
fn on_response(req, resp) { } // before the response goes to the client
```

Files are polled every second and reloaded when they change. A file with a syntax error at
start stops wirust with the error and the file name; a syntax error in a reload keeps the
previous working version, says so on stderr and in the script log, and shows the error in
`GET /api/v1/script`.

## Order with rules

The chain runs in this order, for requests and for responses alike:

1. the built-in flags (`--block-host`, `--add-header`, `--remove-header`);
2. the rules: delays, then the rule actions (rewrites, map-remote, block, map-local, status,
   throttle) — see [rules.md](rules.md);
3. the scripts, in `--script` order;
4. the rule breakpoints, which therefore see what the scripts changed.

When a stage answers the request (a rule's `block`, a script's `respond`), later stages do not
run and the server is not contacted. A script's `on_response` does not run for a request a
script or a rule answered.

## Examples

Each example below is run by a test (`crates/proxy/tests/script.rs` reads this file).

<!-- example: add-header -->
```rhai
// Add a header to every request.
fn on_request(req) {
    req.headers.set("X-Added", "by-script");
}
```

<!-- example: mock-json -->
```rhai
// Answer one endpoint with JSON; the server is never contacted.
fn on_request(req) {
    if req.method == "GET" && req.path == "/api/user" {
        respond(200, #{ "content-type": "application/json" }, json_stringify(#{ name: "mock", id: 7 }));
    }
}
```

<!-- example: rewrite-json -->
```rhai
// Set a field of a JSON response. Scripts see decoded bodies (gzip, br, zstd, deflate); a
// changed body goes on as identity.
const WANTS_BODY = #{ response: true };

fn on_response(req, resp) {
    let kind = resp.headers.get("content-type");
    if kind != () && kind.starts_with("application/json") {
        let data = json_parse(resp.body);
        data.price = 0;
        resp.body = json_stringify(data);
    }
}
```

<!-- example: block-host -->
```rhai
// Block hosts and their subdomains with 403.
fn on_request(req) {
    for host in ["ads.example", "tracker.example"] {
        if req.host == host || req.host.ends_with("." + host) {
            block(403);
            return;
        }
    }
}
```

<!-- example: delay -->
```rhai
// Slow down one path by 300 ms.
fn on_request(req) {
    if req.path.starts_with("/slow") {
        delay(300);
    }
}
```

<!-- example: tag -->
```rhai
// Tag flows (shown as `script:<name>`) and log to the script log.
fn on_request(req) {
    if req.method == "POST" {
        flag("post");
    }
    if regex_match(req.query, "(^|&)debug=1") {
        flag("debug");
        log(`debug request to ${req.url}`);
    }
}

fn on_response(req, resp) {
    if resp.status >= 500 {
        flag("server-error");
    }
}
```

## The API

### `req`

| Member | Type | Notes |
|---|---|---|
| `req.method` | string | settable |
| `req.url` | string | absolute URL, read-only |
| `req.scheme`, `req.host`, `req.port` | string, string, int | read-only |
| `req.path` | string | path without the query; settable |
| `req.query` | string | the query without `?` (`""` when none); settable |
| `req.headers` | headers | see below |
| `req.body` | string | the decoded body as text (lossy UTF-8); settable with a string, a blob, or any value (sent as its JSON) |
| `req.body_bytes` | blob | the decoded body as bytes; settable |
| `req.has_body` | bool | whether the body was buffered and decoded |
| `req.client` | map | `address` (`"ip:port"`), `ja4` (HTTPS only, else `()`), `name` (the known client the JA4 matches, else `()`) |

In `on_response`, `req` is read-only: changes to it are ignored.

### `resp`

| Member | Type | Notes |
|---|---|---|
| `resp.status` | int | settable (100 to 999) |
| `resp.headers` | headers | see below |
| `resp.body`, `resp.body_bytes`, `resp.has_body` | | as for `req` |

### Headers

Names are case-insensitive. `headers.get(name)` returns the first value or `()`;
`headers.has(name)`, `headers.set(name, value)` (replaces every value),
`headers.remove(name)`, `headers.names()` (an array of lower-case names).

### Bodies and `WANTS_BODY`

Bodies are buffered only when a script asks for them, with a top-level constant:

```rhai
const WANTS_BODY = #{ request: true, response: true };
```

Without it the body is not buffered for the script (it still is when a body rule needs it),
so `req.body` and `resp.body` are usually `""` with `has_body` false, and traffic streams as
usual. A body larger than `--body-limit` is not buffered either: it streams on unchanged and
the flow gets the `rewrite_skipped_body_too_large` flag, as with body rewrite rules. A body
whose `Content-Encoding` cannot be decoded is shown as `""` with `has_body` false. Setting a
body always replaces it, even when it was not buffered, and removes `Content-Encoding`; the
proxy sets `Content-Length`.

The top level of a file runs once at load (and at each reload), only to read `WANTS_BODY`.
Hooks cannot see top-level variables or constants: keep data each hook needs inside it.

### Helpers

| Function | What it does |
|---|---|
| `respond(status, headers_map, body)` | answer without contacting the server (from `on_request`), or replace the response (from `on_response`); `body` is a string, a blob or any value (sent as JSON) |
| `block(status)` | answer with `status` and a short text body |
| `delay(ms)` | wait before going on (summed within a call, at most 60 s); ignored when the same call responds |
| `log(value)` | add a line to the script log; `print` and `debug` do the same |
| `flag(name)` | add `script:<name>` to the flow (1 to 64 letters, digits, `-`, `_`, `.`) |
| `json_parse(text)`, `json_stringify(value)` | JSON to Rhai values and back |
| `regex_match(text, pattern)` | whether `pattern` matches |
| `regex_replace(text, pattern, with)` | replace every match; `$1` and `${name}` refer to groups |
| `regex_captures(text, pattern)` | the groups of the first match (`[]` when none) |
| `base64_encode(text_or_blob)`, `base64_decode(text)`, `base64_decode_bytes(text)` | standard base64 |
| `now()` | milliseconds since the Unix epoch |

Rhai's own string, array, map, math and blob functions are available too.

## Sandbox and limits

Scripts have no file, network or process access, no `eval`, and no `import` or modules (the
engine is built without them). Each hook call runs under these limits:

| Limit | Value |
|---|---|
| operations per call | 1,000,000 |
| wall-clock time per call | 250 ms |
| function call depth | 32 |
| string size | 4 MiB, or twice `--body-limit` when larger |
| array and blob size | 1,048,576 elements, or `--body-limit` when larger |
| map size | 100,000 entries |
| `log()` lines kept per call | 100 (each cut to 4096 bytes) |

A script that fails (a runtime error, an exceeded limit, an invalid header or status) fails
open: its changes for that call are dropped, the exchange goes on as if the script were not
there, its `on_response` is skipped for that exchange, and the flow gets the `script_error`
flag. The error is written to stderr and the script log once per distinct message, with the
file name (never the directory), and shown as the last error in `GET /api/v1/script`.

## Observability

- `GET /api/v1/script` returns `{"scripts": [{file, loaded, request, response, error}]}`,
  where `request` and `response` are `{defined, body}`: whether the file defines that hook
  and whether `WANTS_BODY` asks for that body. `error` is the last load or run error, or
  `null` after a successful reload. Without `--script` the list is empty.
- `GET /api/v1/script/log?after=SEQ` returns `{"entries": [{seq, time, file, level, text}]}`,
  the `log()` lines and errors after `SEQ` (the last 500 are kept); `level` is `log` or
  `error`.
- In the web UI, the Scripts button in the toolbar (shown only with `--script`) opens a panel
  with each file, its hooks, its status and last error, and the script log, refreshed every
  two seconds while it is open. Scripts are edited in their files, not in the browser.
