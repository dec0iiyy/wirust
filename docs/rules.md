# Rules

`--rules FILE` loads an ordered list of rules from a TOML file. Each rule has a `name`, an
`enabled` switch, a matcher and exactly one action. The file is polled every second; a file
that fails to parse or compile keeps the previous rules in force and reports the error on
stderr and in `GET /api/v1/rules`. With `--ui` the rules engine is always on (empty without
`--rules`) so rules can be managed over the API.

The built-in flags (`--block-host`, `--add-header`, `--remove-header`) run before the rules.

## Example

```toml
# Rules run top to bottom. Every rule a request matches fires, except that `block` and
# `map_local` answer the request and stop the rest of the request phase.

# Answer ads with 403 and a body; the server is never contacted.
[[rules]]
name = "no-ads"
match = { host = "*.ads.example" }
action = { type = "block", status = 403, body = "blocked" }

# Serve a local build of the web app (index.html for directories).
[[rules]]
name = "local-app"
match = { host = "app.example.com", path = "/static/*" }
action = { type = "map_local", path = "./dist", strip_prefix = "/static" }

# Mock one endpoint from a single file.
[[rules]]
name = "mock-user"
match = { path = "/api/user", method = ["GET"] }
action = { type = "map_local", path = "./mocks/user.json" }

# Send API traffic to a local server; the client still sees the original URL.
[[rules]]
name = "to-staging"
match = { host = "api.example.com", path = "/v1/*" }
action = { type = "map_remote", scheme = "http", host = "127.0.0.1", port = 3000, path_from = "/v1", path_to = "/v2" }

# Request headers: set, add, remove, regex replace.
[[rules]]
name = "debug-headers"
match = { host = "*.example.com" }
action = { type = "rewrite_headers", phase = "request", set = { "x-debug" = "1" }, add = { "x-trace" = "proxy" }, remove = ["cookie"], replace = [{ name = "user-agent", regex = "Chrome/\\d+", with = "Chrome/999" }] }

# Response body: regex replace and a JSON key path.
[[rules]]
name = "feature-flag"
match = { path = "/api/flags", status = 200 }
action = { type = "rewrite_body", phase = "response", replace = [{ regex = "\"beta\":false", with = "\"beta\":true" }], json_set = [{ path = "limits.0.max", value = 100 }] }

# Override the status of a response.
[[rules]]
name = "fake-outage"
enabled = false
match = { path = "/api/*", method = ["POST"] }
action = { type = "status", status = 503 }

# Add latency before the request goes out.
[[rules]]
name = "slow-login"
match = { path = "/login" }
action = { type = "delay", ms = 1500 }

# A slow network for images: 20 KB/s after 300 ms.
[[rules]]
name = "3g-images"
match = { path_regex = "\\.(png|jpe?g|webp)$" }
action = { type = "throttle", bytes_per_second = 20000, latency_ms = 300 }

# Stop checkout requests (and their responses) for inspection and editing in the UI.
[[rules]]
name = "inspect-checkout"
match = { path = "/checkout*", header = { name = "content-type", value = "json" } }
action = { type = "breakpoint", request = true, response = true }
```

## Matcher

Every field given must match; an empty or missing `match` matches everything. Rules match
the request as the client sent it, before any rule changed it.

| Field | Matches | Example |
|---|---|---|
| `scheme` | `http` or `https` | `"https"` |
| `host` | glob over the host, case-insensitive, anchored; `*` any run, `?` one character | `"*.example.com"` |
| `port` | server port | `8443` |
| `path` | glob over the path without the query, anchored | `"/api/*/items"` |
| `path_regex` | regex searched in path and query | `"page=\\d+$"` |
| `method` | any of the methods | `["GET", "POST"]` |
| `header` | header present, optional regex on a value; request headers for request-phase actions, response headers for response-phase ones | `{ name = "x-debug", value = "^on$" }` |
| `status` | response status; response-phase actions only | `404` |

## Actions

| `type` | Phase | Fields |
|---|---|---|
| `block` | request, answers | `status` (default 403), `body` |
| `status` | response | `status` |
| `map_local` | request, answers | `path` (file or directory; relative to the rules file), `strip_prefix` |
| `map_remote` | request | `scheme`, `host`, `port`, `path_from` + `path_to` (prefix rewrite) |
| `rewrite_headers` | `phase` (default `request`) | `set`, `add`, `remove`, `replace = [{ name, regex, with }]` |
| `rewrite_body` | `phase` (default `request`) | `replace = [{ regex, with }]`, `json_set = [{ path, value }]` |
| `delay` | request | `ms` |
| `throttle` | response body | `bytes_per_second` (at least 1), `latency_ms` |
| `breakpoint` | `request` (default true), `response` | |

Order inside one exchange: all matching `delay`s (summed), then rewrites, `map_remote`,
`block` and `map_local` in rule order, then one breakpoint pause. In the response phase:
`status`, rewrites and `throttle` in rule order, then one breakpoint pause.

- `with` in replacements may use `$1` or `${name}` for capture groups.
- `json_set` paths are dot-separated; numeric parts index arrays; missing objects are made.
  A body that is not JSON is left as it is.
- Body rules buffer the body up to `--body-limit`. A larger body streams through unchanged
  and the flow gets the `rewrite_skipped_body_too_large` flag. While any enabled body rule
  exists, every intercepted exchange of that phase is buffered (up to the limit).
- `throttle` never buffers: it releases about a tenth of a second's worth of bytes at a time.
- `map_remote` without `port` but with `scheme` uses that scheme's default port.

## Flow record

Each rule that fired adds `rule:<name>` to the flow's `flags`; `map_remote` adds
`map_remote` and the field `upstream_url` (where the request really went; `url` keeps what
the client asked for). These are additions to existing JSON, so `schema_version` stays 1.

## API

All routes sit behind the control plane's token, `Host` and `Origin` checks; bodies are
limited to 1 MiB.

| Route | Does |
|---|---|
| `GET /api/v1/rules` | `{"rules": [...], "file": file name or null, "error": last load error or null}`; `file` is the name only (`rules.toml`), not the path given to `--rules` |
| `PUT /api/v1/rules` | replaces the whole set from `{"rules": [...]}` (the TOML shape in JSON); `400 {"error"}` leaves the set unchanged. Exchanges in flight keep the set they started with. The file, when watched, wins again on its next change. |
| `POST /api/v1/rules/{name}/toggle` | flips `enabled`; `{"name", "enabled"}`, `404` for no such rule |
| `GET /api/v1/pauses` | pending pauses: `[{"id", "flow_id", "phase"}]` |
| `POST /api/v1/pauses/{id}/resume`, `/abort` | go on unchanged, or answer `502` |
| `POST /api/v1/pauses/{id}/edit` | apply an edit, then go on (below) |

The edit body:

```json
{
  "method": "PUT",
  "url": "/path?q=1",
  "set_headers": { "x-debug": "1" },
  "remove_headers": ["cookie"],
  "body": "text body",
  "status": 201
}
```

`url` may also be absolute (`https://host:port/path`), which sends the request to that
server like `map_remote`. `body_base64` replaces `body` for binary data (not both).
`method` and `url` are request-phase only, `status` response-phase only. Header names must
be tokens and values visible ASCII (no CR, LF or other control characters), at most 100
headers per edit. An invalid edit answers `400` and the pause stays pending.

### Events

Pauses appear on `GET /api/v1/events` (SSE, one `data:` line of JSON each) inside the usual
envelope:

```json
{"event": "paused",  "flow": {"type": "paused",  "pause_id": 3, "flow_id": 17, "phase": "request"}}
{"event": "resumed", "flow": {"type": "resumed", "pause_id": 3, "flow_id": 17, "phase": "request", "resolution": "edit"}}
```

`resolution` is `resume`, `edit`, `abort` or `timed_out` (`--pause-timeout`, default 5 min).

## Security

- Rules are local configuration: whoever can write the rules file or call the API can
  redirect, rewrite and read traffic. The API needs the start-up token like every other
  route, and changes are `PUT`/`POST` only.
- `map_local` jail: the configured directory is canonicalised once. A request path is
  percent-decoded once, then split on `/`; any segment that is `.`, `..`, or contains a
  backslash, a colon or NUL is refused with `400`. The joined path is canonicalised again
  (resolving symlinks) and must still start with the root, else `404`; symlinks that point
  outside the root are therefore not followed. Files over 64 MiB answer `413`.
- Regexes use the `regex` crate (linear time, no backtracking, no look-around or
  back-references). Each pattern is limited to 4096 bytes and 1 MiB of compiled program; an
  invalid or too large pattern is a rule error, never a crash.
- `map_remote` and edits cannot reach the control plane's own address.
- Rule names are limited to `A-Z a-z 0-9 . _ -` and 64 characters (they appear in URLs
  and flags).

## Not supported

- HTTP/3 (QUIC) traffic is not intercepted at all.
- WebSocket messages: they are recorded (`docs/websocket.md`), but rules and breakpoints
  apply only to the upgrade request, never to messages.
- gRPC and other streaming bodies: body rules see them only when they fit the limit as one
  buffered body; there is no message-level rewriting.
- `map_local` reads files synchronously on the proxy's runtime; keep mocks small.
