# Replay and compose

Send a captured request again, changed or not, or write one from scratch. The request goes
through the proxy's own forwarding path (the same upstream connections, TLS settings and
record building as client traffic) and is recorded as a new flow.

## API (control plane, `--ui`)

Both routes need the token like every `/api/v1/` route, and both are `POST`.

### `POST /api/v1/flows/{id}/replay`

Replays finished exchange `id` from the flow store. The body is optional; when given it is
the breakpoint edit of `POST /api/v1/pauses/{id}/edit` (see `docs/rules.md`) plus
`apply_rules`:

```json
{
  "method": "PUT",
  "url": "/v2/users?id=1",
  "set_headers": { "authorization": "Bearer other" },
  "remove_headers": ["cookie"],
  "body": "{\"name\":\"x\"}",
  "apply_rules": false
}
```

`url` is a path (same server) or an absolute `http(s)://` URL (another server). `body` and
`body_base64` are exclusive. The validation is the one breakpoint edits use: header names,
CR/LF and other control characters in values, URL syntax, no `user:pass@` in the URL, at most
100 headers, request bodies up to 1 MiB.

### `POST /api/v1/compose`

```json
{
  "method": "POST",
  "url": "https://api.example.com/v1/items",
  "headers": [["content-type", "application/json"], ["x-trace", "1"]],
  "body": "{}",
  "apply_rules": false
}
```

`url` must be absolute. `headers` is a list of pairs and is sent in that order.

### Answer

`201 {"flow_id": N}` as soon as the request is handed to the forwarding path, before the
response arrives. Flow `N` then appears on the event bus like any other: `started` first,
`completed` (or `failed`) when the response body ends. Its record has the flag `replay` and,
for a replay, `replay_of` with the original flow id (`schema_version` stays 1: both are
optional additions). Its `client` is the proxy's own listen address.

| Code | When |
|---|---|
| `400` | invalid edit or compose body, or a flow that is not an HTTP exchange |
| `403` | the target is the control plane or the proxy's own listen address |
| `404` | no such flow |
| `409` | the flow has not finished, or its stored request body is incomplete (see below) |
| `429` | 8 replays in flight, or 20 started in the last second |

## What is sent

- Headers: the stored request headers in their original order, minus hop-by-hop headers
  (`connection` and what it names, `keep-alive`, `proxy-*`, `te` other than `trailers`,
  `transfer-encoding`, `upgrade`). `host` and `content-length` are recomputed for the target
  and its protocol, as forwarding does. Header case is not kept: HTTP/2 is lowercase by
  definition, and the HTTP/1.1 leg writes the names as stored, which are lowercase.
- Body: the stored request body. When `--body-limit` cut it (`truncated: true`), or it was
  never kept, the replay is refused with `409` unless the edit supplies `body` or
  `body_base64`; the proxy never sends a silently shortened body. A body stored decoded
  (`content_encoding.decoded`, `docs/interchange.md`) is sent as identity: `content-encoding`
  is dropped unless the edit sets it again.
- HTTPS targets offer h2 and HTTP/1.1 to the server.

## `apply_rules`

Default `false`: the request bypasses the interceptor chain (rules engine, `--add-header`,
`--block-host`, breakpoints), so what you send is exactly what the server gets. `true` runs
the chain as for client traffic: a block rule answers, a breakpoint pauses, map-remote
redirects, and the record shows the rule flags after `replay`.

## CLI

```
wirust replay --session flows.jsonl --id 42 --set-header 'x-debug: 1' --method PUT \
    --url /v2/items --via http://127.0.0.1:8080
```

Reads flow 42 from the session file and sends it through a running proxy as an ordinary
client (absolute-form for `http://`; CONNECT and TLS for `https://`), so it shows up in that
proxy's log and UI like any client request. HTTPS needs the proxy's CA: it is read from
`--config-dir` (default: the platform config dir), which must be the running proxy's. Prints
the status line, such as `HTTP/1.1 200 OK`. An incomplete stored body is refused; edit the
session file or use the API with a new body.

## Safety

- Replay is a state-changing `POST` behind the control plane's token, Host and Origin
  checks. The control plane is the security boundary: anyone holding the token can make the
  proxy send arbitrary requests.
- Private and loopback addresses are allowed on purpose: debugging a service on localhost is
  the point. Only the control plane's address and the proxy's own listen address are refused
  (any loopback or unspecified IP or `localhost` on those ports), which prevents loops and
  replays into the API.
- The rate and concurrency limits stop a script bug from turning the proxy into a request
  cannon. They are per process and not configurable.
- A replay sends the stored cookies and tokens again. Remove them with `remove_headers` when
  that is not intended.
