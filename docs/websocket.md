# WebSocket messages

After a `101 Switching Protocols` answer to an HTTP/1.1 request with `Upgrade: websocket`,
the proxy no longer copies bytes blindly: `ws::pump` (in `crates/proxy/src/ws.rs`) forwards
each chunk to the other side first and then parses a copy, so the traffic is never delayed
by parsing and never changed. Other upgrades (h2c, custom protocols) are still copied byte
for byte. This works over `ws://` (absolute-form request to the proxy) and `wss://`
(CONNECT, TLS interception, then the upgrade inside the tunnel).

## What is captured

Per direction (`client_to_server`, `server_to_client`) the parser reads RFC 6455 frames:
FIN, RSV1-3, opcode, the mask bit and key, 7/16/64-bit lengths. For the record it:

- unmasks a copy of client payloads; the masked bytes go to the server untouched;
- reassembles fragmented text and binary messages (continuation frames), with control
  frames allowed between fragments;
- records `text`, `binary`, `close` (with `close_code` and `close_reason`), `ping` and
  `pong` messages; text that is valid UTF-8 is kept as text, anything else as base64.

Each message is a `WsMessage`:

```json
{"flow_id": 12, "seq": 0, "time": "2026-11-21T12:00:00.123Z", "timestamp": 1795262400.123,
 "direction": "client_to_server", "kind": "text", "size": 5, "truncated": false,
 "encoding": "utf8", "data": "hello"}
```

`seq` counts both directions of one connection from 0, in the order the messages completed.
`close_code`/`close_reason` appear on close frames that carry them; `compressed: true`
appears when the server negotiated an extension (see below).

The upgrade's flow record gets `ws_messages` (omitted for other flows). The record is
published at the `101`, so the event and the JSON log show `ws_messages: 0`; the in-memory
store raises it with each message, so `GET /api/v1/flows/{id}` shows the current count.

## Limits and flags

The parser reads hostile input for as long as a connection lives, so everything is bounded:

| Limit | Default | Flag | What happens |
|---|---|---|---|
| Bytes kept per message | 1 MiB | `--ws-body-limit BYTES` | the rest is counted in `size`, `truncated: true`; forwarding is unaffected |
| Messages kept per flow | 1000 | `--ws-max-messages N` | the oldest message is dropped; the API reports `dropped` |
| Frames per message | 65 536 | (constant `ws::MAX_FRAGMENTS`) | protocol violation |
| Frame header | 14 bytes | - | the parser buffers at most one header |
| Control frame payload | 125 bytes, FIN set | - | protocol violation otherwise |
| 64-bit length | top bit clear | - | protocol violation otherwise |

Protocol violations (reserved bits without a negotiated extension, unknown opcodes, a
fragmented or oversized control frame, a length with the top bit set, a client frame
without a mask or a server frame with one, a continuation without a message, a new data
frame inside a fragmented message, too many fragments) stop parsing for that direction
only. Raw bytes keep flowing both ways; the proxy never breaks a connection it does not
understand. The other direction keeps being recorded.

A flow's messages are dropped together with the flow when the flow store evicts it
(`--max-flows`). `--ws-log` prints one short line per message on the console, such as
`ws #12 -> text 5 B`; without it the console prints nothing for messages.

## Extensions: stripped from the offer

`permessage-deflate` compresses payloads (RSV1 set), which a recorder would have to inflate
with the connection's shared window. The proxy instead removes `Sec-WebSocket-Extensions`
from the client's upgrade request, so the server never negotiates compression or any other
extension, and marks the flow `ws_extensions_stripped`. The record still shows the client's
original headers.

Trade-off: the client sees no difference (extensions are optional; it gets plain frames it
already understands), the server sends uncompressed frames, so traffic is somewhat larger. A
server that requires an extension may refuse the upgrade. If a server answers with
`Sec-WebSocket-Extensions` anyway, the flow is marked `ws_compressed`, RSV bits are allowed,
and messages are recorded as raw base64 payloads with `compressed: true`.

## API and events

- `GET /api/v1/flows/{id}/messages?after=SEQ&limit=N` (token required, like every API
  route): `{"flow_id", "total", "dropped", "messages": [WsMessage...]}`, messages with
  `seq > after` (all when absent), oldest first, `limit` default 200, at most 1000. `404`
  for an unknown flow or one that is not a WebSocket; `405` for other methods.
- The SSE stream `GET /api/v1/events` carries `{"event": "ws", "flow": {...WsMessage...}}`.
  Consumers that only want flows ignore it: `FlowEvent::flow()` returns `None` for it, so
  the log printer and the session writer skip it.
- The search language (`q=`) has no `ws` field yet.

## HAR

`GET /api/v1/har` adds `_webSocketMessages` to each WebSocket upgrade entry, in the format
Chrome DevTools writes: `{"type": "send" | "receive", "time": <seconds since the epoch,
float>, "opcode": 1 | 2 | 8 | 9 | 10, "data": "..."}`. Text is written as is, everything else
as base64. Import reads the list back best effort: the imported record gets `ws_messages`
set to its length (`har::HarWsMessage::to_message` converts entries). Session files
(`--session`) hold flow records only, not messages; `export --har` from a session therefore
has no `_webSocketMessages`.

## UI

`ui/ws.js` adds a "Messages" tab for flows with `ws_messages` or one of the WebSocket flags:
history from the API, live rows from its own SSE stream, direction arrows with a text label,
time offset from the first message, size and kind, JSON pretty-printed, binary as a hex dump,
close frames with code and reason, a text filter, a direction toggle and truncation notices.
It registers through `window.registerTab({id, title, visible, render(flow, container)})` when
app.js provides it, and otherwise adds its own tab button.

## Not covered

- WebSocket over HTTP/2 (RFC 8441 extended CONNECT) and HTTP/3 WebTransport.
- gRPC streams, Socket.IO or other application framing beyond raw messages.
- Decompressing `permessage-deflate` (it is stripped instead, see above).
- Sending, replaying or editing messages, and breakpoints on messages.
- A bus subscriber that falls more than 4096 events behind skips events: during a flood the
  store or the UI may miss messages (the SSE stream says `: lagged`).
- Memory: the worst case is `--max-flows` x `--ws-max-messages` x `--ws-body-limit`; lower
  the limits for long sessions with large messages.
