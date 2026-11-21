# gRPC and protobuf

wirust decodes gRPC, gRPC-Web and bare protobuf bodies without a `.proto` file, the way
`protoc --decode_raw` does. The bodies are captured as for any other exchange (up to
`--body-limit`); decoding happens when you ask for it, in the API or the UI's gRPC tab, and
never changes the traffic. Code: `crates/proxy/src/grpc.rs` (framing, status, trailers),
`protobuf.rs` (the decoder), `grpc_api.rs` (the route), `ui/grpc.js` and `ui/grpc.css`.

## What is recognised

The request `Content-Type`, else the response's, picks the kind (parameters after `;` and
letter case are ignored):

| Content-Type | Kind | Body |
|---|---|---|
| `application/grpc`, `application/grpc+proto` | `grpc` | length-prefixed messages; status in HTTP/2 trailers |
| `application/grpc-web`, `application/grpc-web+proto` | `grpc-web` | as gRPC; trailers in a final frame with flag `0x80` |
| `application/grpc-web-text`, `application/grpc-web-text+proto` | `grpc-web-text` | gRPC-Web in base64 (several padded chunks allowed) |
| `application/x-protobuf`, `application/protobuf`, `application/x-google-protobuf` | `protobuf` | one message, no framing |

Each gRPC frame is a flag byte (bit 0: compressed), a 4-byte big-endian length and the
payload. Compressed payloads are listed with `"note": "compressed, not decoded"`: wirust links
no decompressor. `grpc-encoding` is reported when present.

The service and method come from a `/pkg.Service/Method` path. `grpc-status` and
`grpc-message` (percent-decoded) come from the response trailers, from the response head for
a trailers-only answer, or from the gRPC-Web trailer frame; the status also gets its canonical
name (`NOT_FOUND`, ...).

## Trailers in the flow record

Response trailers (HTTP/2, or chunked HTTP/1.1) are now kept in the flow record as
`response_trailers`, a list of `[name, value]` pairs like the headers, omitted when empty.
At most 64 fields and 16 KiB of names and values are kept; the trailers are still forwarded
to the client in full. The field is additive, so `schema_version` is unchanged and older
records read back without it.

## The decoder

Each field is reported with its number, its wire type (`varint`, `i64`, `len`, `i32`, as the
protobuf encoding guide names them) and an interpretation:

- `varint`: the value as `uint64` and as zigzag `sint64`, both decimal strings (JSON readers
  often hold numbers as doubles);
- `fixed64` / `fixed32`: the integer and the same bits as `double` / `float` (`null` when not
  finite);
- length-delimited fields, in this order of preference: `string` when the bytes are UTF-8 with
  no control characters but tab, CR and LF; `message` when all of the bytes parse as fields;
  `packed_varints` (marked `"guess": true`) when they are a run of at most 256 varints; else
  `bytes` with the size and the first 256 bytes in base64.

Repeated fields appear once per occurrence, in wire order. Groups (wire types 3 and 4) are
not decoded and stop the message with an error.

The input is untrusted, so decoding never panics and is bounded:

| Limit | Value |
|---|---|
| Nesting of messages | under 16 levels; deeper fields are shown as text, packed varints or bytes |
| Fields visited per body, failed guesses included | 20 000 (`"truncated": true` when hit) |
| Messages per body | 64 (the stream gets `"truncated": true`) |
| Bytes shown of an opaque field | 256 |

Malformed input keeps the fields read before the fault and adds an `error` such as
`"length past the end at byte 2"`. A body cut by `--body-limit` decodes what was kept: the
last message gets `"note": "cut by the body limit"` and the stream is `truncated`.

## API

`GET /api/v1/flows/{id}/grpc` (same token and Host checks as the rest of the API) answers
`404` for flows that are not gRPC or protobuf and `409` while the exchange is in progress:

```json
{"flow_id": 7, "kind": "grpc", "service": "helloworld.Greeter", "method": "SayHello",
 "status": 7, "status_name": "PERMISSION_DENIED", "message": "not allowed",
 "trailers": [["grpc-status", "7"], ["grpc-message", "not%20allowed"]],
 "request": {"messages": [{"index": 0, "compressed": false, "size": 7, "decoded": {"fields": [
   {"field": 1, "wire": "len", "type": "string", "value": "world"}]}}], "truncated": false},
 "response": {"messages": [], "truncated": false},
 "truncated": false}
```

`truncated` at the top is true when either side is incomplete.

## UI and search

The gRPC tab appears for flows with one of the content types above. It shows the method,
the kind, `grpc-status` (green for 0) and `grpc-message`, then each request and response
message as an expandable tree (field number, wire type, value), then the trailers.

The search has no separate gRPC field; `type:grpc` or `type:protobuf` match the response
`Content-Type` like any other type.

## Not done

- Decoding with `.proto` files or server reflection: field names and enum values.
- Inflating compressed messages (`grpc-encoding: gzip`).
- Request trailers (rare in gRPC) are not kept.
