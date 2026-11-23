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
`close_code`/`close_reason` appear on close frames that carry them. A message that was
compressed on the wire adds `compressed: true` and `wire_size` (its payload bytes on the
wire); `data` and `size` are then the decompressed payload, or, with `decode_failed: true`,
the raw wire payload in base64 (see below).

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
| Decompressed bytes per message | the body limit, and 1000 per wire byte (at least 64 KiB) | `--ws-body-limit` | over the ratio: `decode_failed`, raw bytes kept |

Protocol violations (reserved bits without a negotiated extension, RSV2 or RSV3 with
`permessage-deflate`, unknown opcodes, a
fragmented or oversized control frame, a length with the top bit set, a client frame
without a mask or a server frame with one, a continuation without a message, a new data
frame inside a fragmented message, too many fragments) stop parsing for that direction
only. Raw bytes keep flowing both ways; the proxy never breaks a connection it does not
understand. The other direction keeps being recorded.

A flow's messages are dropped together with the flow when the flow store evicts it
(`--max-flows`). `--ws-log` prints one short line per message on the console, such as
`ws #12 -> text 5 B`; without it the console prints nothing for messages.

## Compression: `permessage-deflate` (RFC 7692)

The client's `Sec-WebSocket-Extensions` offer goes to the server unchanged, and every byte
of the connection is forwarded unchanged; only the recorded copy is decompressed. When the
server's `101` answers with `permessage-deflate` (alone), the flow is marked `ws_compressed`
and the parser reads the parameters of that answer: `client_no_context_takeover`,
`server_no_context_takeover`, `client_max_window_bits`, `server_max_window_bits`.

- Each direction keeps one raw-deflate state. With context takeover (the default) the window
  carries over from one message to the next; with `*_no_context_takeover` for that sender it
  is reset after each message. A 32 KiB window reads streams made with any smaller
  `*_max_window_bits`.
- RSV1 on a text or binary message's first frame marks it compressed; RSV1 on continuation
  frames is ignored, control frames are never decompressed. Fragments are inflated as they
  arrive, and the `00 00 ff ff` tail is appended at the end of the message as section 7.2.2
  says. Messages without RSV1 are recorded as they are.
- Decompressed output is kept up to `--ws-body-limit` per message (the rest is counted in
  `size`, `truncated: true`) and stops at 1000 bytes per wire byte (at least 64 KiB): a
  bomb, like invalid data, marks the message `decode_failed` and keeps the wire bytes.
  With context takeover, the window is then lost, so later messages of that direction are
  `decode_failed` too; without it the next message decodes again. Nothing panics on
  malformed data, and forwarding is never affected.
- Any other answer (another extension, several extensions, or `permessage-deflate` with an
  unknown or invalid parameter) also marks the flow `ws_compressed`; RSV bits are then
  allowed and messages with an RSV bit are recorded raw with `decode_failed: true`.

`--ws-strip-compression` restores the old behaviour for peers whose compression misbehaves:
the proxy removes `Sec-WebSocket-Extensions` from the client's upgrade request, so the server
never negotiates an extension, and marks the flow `ws_extensions_stripped`. The record still
shows the client's original headers. A server that requires an extension may then refuse the
upgrade.

## API and events

- `GET /api/v1/flows/{id}/messages?after=SEQ&limit=N` (token required, like every API
  route): `{"flow_id", "total", "dropped", "messages": [WsMessage...]}`, messages with
  `seq > after` (all when absent), oldest first, `limit` default 200, at most 1000. `404`
  for an unknown flow or one that is not a WebSocket; `405` for methods other than GET and
  POST.
- `POST /api/v1/flows/{id}/messages` with `{"direction": "client_to_server" |
  "server_to_client", "type": "text" | "binary", "data": "..."}` sends a message into the
  live connection: `client_to_server` goes to the server (masked with a random key, as a
  client must), `server_to_client` to the client (unmasked). Binary `data` is hex, two digits
  per byte, spaces allowed. The frame is a single unfragmented, uncompressed frame (RSV1
  clear, which `permessage-deflate` allows); it is written between messages, never inside a
  fragmented message of the same direction, so it may wait for that message's last frame.
  When it is written, it is recorded like any other message with `injected: true`.
  Answers: `202 {"queued": true}`; `404` unknown flow or not a WebSocket; `409` the
  connection is closed, or a Close frame already went that way (queued messages for that
  direction are dropped then); `400` a bad body or a type other than text and binary; `413` more
  than 64 KiB (`ws::MAX_INJECT`); `429` more than 20 messages per second per connection
  (`ws::INJECT_PER_SECOND`) or 16 waiting in one direction. After a protocol violation in a
  direction (see above) its framing is unknown, so waiting messages for it are dropped.
- The SSE stream `GET /api/v1/events` carries `{"event": "ws", "flow": {...WsMessage...}}`.
  Consumers that only want flows ignore it: `FlowEvent::flow()` returns `None` for it, so
  the log printer and the session writer skip it.
- The search language (`q=`, `--filter`, the UI search) has a `ws:` field: `ws:text`
  matches flows with a held message whose kept payload contains the text (base64 payloads
  are decoded first, ASCII case is ignored); `ws:` alone matches flows that have messages.

## HAR

`GET /api/v1/har` adds `_webSocketMessages` to each WebSocket upgrade entry, in the format
Chrome DevTools writes: `{"type": "send" | "receive", "time": <seconds since the epoch,
float>, "opcode": 1 | 2 | 8 | 9 | 10, "data": "..."}`. Text is written as is, everything else
as base64. Import reads the list back best effort: the imported record gets `ws_messages`
set to its length, and `import --har` writes the messages to the session file
(`har::HarWsMessage::to_message` converts entries).

## Session files

`--session FILE` appends each message as a line of its own after its flow's record:
`{"schema_version": 1, "type": "ws_message", ...WsMessage fields}` (`session::WsRecord`).
`view` prints each WebSocket flow followed by its messages as `--ws-log` prints them,
`export --har` writes them as `_webSocketMessages`, and `--filter 'ws:...'` searches them.
Files without message lines load as before. wirust 0.2 and older stop at a message line
("not a flow record").

## UI

`ui/ws.js` adds a "Messages" tab for flows with `ws_messages` or one of the WebSocket flags:
history from the API, live rows from its own SSE stream, direction arrows with a text label,
time offset from the first message, size and kind, JSON pretty-printed, binary as a hex dump,
close frames with code and reason, a text filter, a direction toggle, truncation notices and
a note on decompressed (or undecodable) compressed messages. A composer under the list sends a
message (to the client or to the server, text or hex bytes) through the POST route above and
says in plain words why it was not sent (closed connection, too large, too many); injected
messages are marked "(sent by you)".
It registers through `window.registerTab({id, title, visible, render(flow, container)})` when
app.js provides it, and otherwise adds its own tab button.

## Not covered

- WebSocket over HTTP/2 (RFC 8441 extended CONNECT) and HTTP/3 WebTransport.
- gRPC streams, Socket.IO or other application framing beyond raw messages.
- Other compression extensions (`x-webkit-deflate-frame` and the like): recorded raw.
- Editing or dropping messages in flight, breakpoints on messages, and replaying a recorded
  conversation; injected frames are always unfragmented and uncompressed.
- A bus subscriber that falls more than 4096 events behind skips events: during a flood the
  store or the UI may miss messages (the SSE stream says `: lagged`).
- Memory: held messages count toward `--max-memory` (default 512 MiB) with their flow, so
  the oldest finished flows are evicted when messages fill the budget; without that cap the
  worst case would be `--max-flows` x `--ws-max-messages` x `--ws-body-limit`.
