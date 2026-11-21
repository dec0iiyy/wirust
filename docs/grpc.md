# gRPC and protobuf

wirust decodes gRPC, gRPC-Web and bare protobuf bodies without a `.proto` file, the way
`protoc --decode_raw` does, and with field names, types and enum names when you give it the
`.proto` files (`--proto`). The bodies are captured as for any other exchange (up to
`--body-limit`); decoding happens when you ask for it, in the API or the UI's gRPC tab, and
never changes the traffic. Code: `crates/proxy/src/grpc.rs` (framing, inflating, status,
trailers), `protobuf.rs` (the schema-less decoder), `schema.rs` (`.proto` schemas),
`grpc_api.rs` (the routes), `ui/grpc.js` and `ui/grpc.css`.

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
payload. A compressed payload is inflated with the coding its direction's `grpc-encoding`
header names (the request header for request messages, the response header for responses;
gRPC-Web uses the same header): `gzip` and `deflate`, and also `br` and `zstd`, through the
same bounded decoders as `Content-Encoding` (at most 4 MiB and 1000 times the input per
message). The message then carries `"inflated"` (the size after inflating). Otherwise it stays
undecoded with a note: `"compressed, not decoded"` when no `grpc-encoding` is given,
`"compressed with snappy, not decoded"` for a coding wirust does not know, or the inflate
error. `grpc-encoding` is reported at the top when present.

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

## Schemas (`.proto` files)

```sh
wirust --ui 127.0.0.1:8081 --proto api/ --proto-include third_party/
wirust --ui 127.0.0.1:8081 --proto shop.proto --proto-message shop.Order
```

- `--proto PATH` (repeatable): a `.proto` file, or a directory scanned recursively for
  `*.proto` files (at most 16 levels deep; symbolic links are not followed).
- `--proto-include DIR` (repeatable): import roots. An `import "a/b.proto"` is looked up in
  the include roots first, then in the `--proto` directories (and the directory of each
  `--proto` file). A file under an include root gets its import name from that root, so it is
  not compiled twice. The well-known types (`google/protobuf/*.proto`) are built in.
- `--proto-message TYPE`: the message type for bare `application/x-protobuf` bodies (both the
  request and the response body are decoded with it). Without it such bodies stay schema-less:
  there is no method path to look the type up by. A type that is not in the schemas refuses
  to start. `--proto-include` and `--proto-message` need `--proto`.

The files are compiled at start with `protox`, a pure-Rust replacement for `protoc` (no
`protoc` binary or C toolchain is needed), and recompiled when a file is added, removed or
changed (polled every 2 seconds, by modification time and size). A bad schema at start
refuses to start with the error; a bad schema on reload keeps the previous schemas, prints
the error and shows it in `GET /api/v1/proto` and the UI. Errors name files by their import
name (`api/shop.proto`), never by an absolute path. Reading is bounded: at most 8 MiB of
`.proto` source and 1000 files per compile, imports included; import names with `..` or an
absolute path are refused. Nothing is fetched from the network.

For a gRPC call, `/pkg.Service/Method` is looked up in the compiled schemas to find the
request and response types, and each message is decoded with its type. The tree then has
the field name (`name`), the declared type (`proto`, such as `int64`, `repeated shop.Item`
or `map<string, int32>`) and the oneof (`oneof`) next to the number, and these value types
besides the schema-less ones:

- `number` (all integer and floating types, as a decimal string), `bool`;
- `enum`: the number and its `symbol` (`null` for a number the enum does not list);
- `string`, `bytes` (first 256 bytes, base64) and `message` as above; repeated fields
  appear once per element; a map entry is a message with `key` and `value` fields;
- well-known types by meaning: `Timestamp` as RFC 3339 text
  (`2023-11-14T22:13:20.000000005Z`), `Duration` as `90.5s`, the wrappers (`StringValue`,
  ...) as their value, `Struct`, `Value` and `ListValue` as `json`, and `Any` with its packed
  message decoded when the type is in the schemas;
- fields the schema does not know stay visible, schema-less, with their numbers.

Decoding with a schema keeps the caps of the schema-less decoder (16 levels, the shared
20 000-field budget, 256 bytes per opaque field) and never panics on malformed bytes. The
fallbacks, each said in the answer:

| Case | Shown |
|---|---|
| no `--proto` | the schema-less tree, `schema: null`, no note |
| method not in the schemas | schema-less; the stream's `schema_note` is `schema-less: method not found` |
| bare protobuf without `--proto-message` | schema-less; `schema-less: no --proto-message given` |
| bytes that are not a valid message of the type (a cut body, a wrong type) | schema-less; the message's note is `schema-less: not a valid pkg.Msg: ...` |

## API

`GET /api/v1/flows/{id}/grpc` (same token and Host checks as the rest of the API) answers
`404` for flows that are not gRPC or protobuf and `409` while the exchange is in progress:

```json
{"flow_id": 7, "kind": "grpc", "service": "helloworld.Greeter", "method": "SayHello",
 "status": 7, "status_name": "PERMISSION_DENIED", "message": "not allowed",
 "trailers": [["grpc-status", "7"], ["grpc-message", "not%20allowed"]],
 "request": {"messages": [{"index": 0, "compressed": false, "size": 7, "schema": null,
   "decoded": {"fields": [{"field": 1, "wire": "len", "type": "string", "value": "world"}]}}],
   "truncated": false, "schema": null},
 "response": {"messages": [], "truncated": false, "schema": null},
 "truncated": false}
```

`truncated` at the top is true when either side is incomplete. With schemas, each stream's
`schema` names the type for that direction (or a `schema_note` says why there is none), each
message's `schema` names the type it was decoded with (`null` for the schema-less tree), and
fields carry `name`, `proto` and `oneof`:

```json
{"field": 4, "wire": "varint", "name": "color", "proto": "shop.Color", "type": "enum",
 "value": 2, "symbol": "GREEN"}
```

`GET /api/v1/proto` lists the loaded schemas: file names (import names, no absolute paths),
services with their methods, the `--proto-message` type and the last reload error:

```json
{"files": ["shop.proto"], "message": null, "error": null,
 "services": [{"name": "shop.Orders", "methods": [{"name": "Place", "input": "shop.Order",
   "output": "shop.Reply", "client_streaming": false, "server_streaming": false}]}]}
```

Without `--proto` the lists are empty.

## UI and search

The gRPC tab appears for flows with one of the content types above. It shows the method,
the kind, `grpc-status` (green for 0) and `grpc-message`, then each request and response
message as an expandable tree (field number, wire type, value; with a schema, the field
name and declared type, and a `decoded with pkg.Msg` line or the fallback note), then the
trailers. With `--proto`, a collapsed "Schemas" panel at the bottom lists the services and
methods, the file names and a failed reload.

The search has no separate gRPC field; `type:grpc` or `type:protobuf` match the response
`Content-Type` like any other type.

## Not done

- Server reflection: schemas come only from local `.proto` files.
- Compiled descriptor sets (`.pb`/`.desc` files from `protoc -o`) are not read.
- Request trailers (rare in gRPC) are not kept.
