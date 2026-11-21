//! gRPC, gRPC-Web and bare protobuf bodies of a recorded exchange, decoded for viewing.
//!
//! [`decode_exchange`] finds the call kind from the `Content-Type`, splits each body into
//! the length-prefixed gRPC messages (compressed flag, 4-byte big-endian length), decodes
//! each with the schema-less [`protobuf`](crate::protobuf) decoder, and reads `grpc-status`
//! and `grpc-message` from the HTTP/2 trailers, a trailers-only response head, or the
//! trailer frame of a gRPC-Web body. Compressed messages are inflated when the direction's
//! `grpc-encoding` names a coding [`decode`](crate::decode) undoes (gzip, deflate, also br
//! and zstd), within [`MAX_INFLATED`] bytes. With `.proto` schemas loaded
//! ([`Schemas`]), messages of a known `/pkg.Service/Method` are decoded with its request
//! and response types, falling back to the schema-less tree when that fails. Works on the
//! kept part of the bodies (`--body-limit`).

use std::borrow::Cow;

use base64::Engine as _;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use serde::Serialize;

use prost_reflect::MessageDescriptor;

use crate::flow::{BodyRecord, Exchange};
use crate::protobuf::{self, Decoded};
use crate::schema::Schemas;

/// Bytes one compressed message may inflate to; the rest is cut and reported.
pub const MAX_INFLATED: usize = 4 << 20;

/// Messages listed per direction; more set [`Stream::truncated`].
pub const MAX_MESSAGES: usize = 64;

/// Trailer lines read from a gRPC-Web trailer frame.
const MAX_WEB_TRAILERS: usize = 64;

/// What carries the protobuf messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Kind {
    /// `application/grpc`, `application/grpc+proto`: length-prefixed messages, status in
    /// HTTP/2 trailers.
    #[serde(rename = "grpc")]
    Grpc,
    /// `application/grpc-web`, `+proto`: as gRPC, trailers in a final body frame.
    #[serde(rename = "grpc-web")]
    GrpcWeb,
    /// `application/grpc-web-text`: gRPC-Web, base64-encoded.
    #[serde(rename = "grpc-web-text")]
    GrpcWebText,
    /// `application/x-protobuf`, `application/protobuf`: one message, no framing.
    #[serde(rename = "protobuf")]
    Protobuf,
}

impl Kind {
    /// The kind a `Content-Type` value names, if it is one of these.
    #[must_use]
    pub fn from_content_type(value: &str) -> Option<Self> {
        let essence = value.split(';').next().unwrap_or_default().trim();
        let essence = essence.to_ascii_lowercase();
        match essence.as_str() {
            "application/grpc" | "application/grpc+proto" => Some(Self::Grpc),
            "application/grpc-web" | "application/grpc-web+proto" => Some(Self::GrpcWeb),
            "application/grpc-web-text" | "application/grpc-web-text+proto" => {
                Some(Self::GrpcWebText)
            }
            "application/x-protobuf" | "application/protobuf" | "application/x-google-protobuf" => {
                Some(Self::Protobuf)
            }
            _ => None,
        }
    }

    /// The kind of `exchange`, from its request `Content-Type`, else its response's.
    #[must_use]
    pub fn of(exchange: &Exchange) -> Option<Self> {
        let find = |headers: &[(String, String)]| {
            header(headers, "content-type").and_then(Self::from_content_type)
        };
        find(&exchange.request_headers).or_else(|| find(&exchange.response_headers))
    }
}

/// One message of a body.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Message {
    /// Position in the body, from 0.
    pub index: usize,
    /// Whether the compressed flag was set (the payload is then not decoded).
    pub compressed: bool,
    /// The length the frame declared, or the body size for bare protobuf.
    pub size: u64,
    /// The size after inflating a compressed payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inflated: Option<usize>,
    /// The message type the payload was decoded with; `null` for the schema-less tree.
    pub schema: Option<String>,
    /// Why the payload is not (fully) decoded, when it is not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The decoded fields; `None` for a compressed payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded: Option<Decoded>,
}

/// The messages of one body.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Stream {
    /// The messages, at most [`MAX_MESSAGES`].
    pub messages: Vec<Message>,
    /// What was wrong with the framing, if anything.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Whether messages are missing: the body was cut by the limit, or a cap was hit.
    pub truncated: bool,
    /// The message type the schemas give this direction; `null` when none applies.
    pub schema: Option<String>,
    /// Why the schema-less tree is shown although schemas are loaded, such as
    /// `schema-less: method not found`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_note: Option<String>,
}

/// A decoded gRPC or protobuf exchange.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Call {
    /// What carried the messages.
    pub kind: Kind,
    /// `pkg.Service` from a `/pkg.Service/Method` path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// `Method` from a `/pkg.Service/Method` path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// The `grpc-encoding` the messages declare, such as `gzip`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    /// The `grpc-status` code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u32>,
    /// Its canonical name, such as `NOT_FOUND`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_name: Option<&'static str>,
    /// The `grpc-message`, percent-decoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// The trailers the status came from: HTTP/2 trailers or the gRPC-Web trailer frame.
    pub trailers: Vec<(String, String)>,
    /// The request messages.
    pub request: Stream,
    /// The response messages, when a response arrived.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<Stream>,
    /// Whether either side is incomplete.
    pub truncated: bool,
}

/// How to read the messages of one direction.
#[derive(Debug, Clone, Default)]
struct Plan {
    /// The direction's `grpc-encoding`, lowercase, when not `identity`.
    coding: Option<String>,
    /// The type to decode with, when the schemas give one.
    schema: Option<MessageDescriptor>,
    /// Why there is no type although schemas are loaded.
    note: Option<String>,
}

/// Decodes the bodies of `exchange` schema-less, or `None` when it is not gRPC or protobuf.
#[must_use]
pub fn decode_exchange(exchange: &Exchange) -> Option<Call> {
    decode_exchange_with(exchange, None)
}

/// The request and response plans: codings from each side's `grpc-encoding`, types from
/// the method (gRPC) or the `--proto-message` hint (bare protobuf).
fn plans(
    exchange: &Exchange,
    kind: Kind,
    path: Option<(&str, &str)>,
    schemas: Option<&Schemas>,
) -> (Plan, Plan) {
    let coding = |headers: &[(String, String)]| {
        header(headers, "grpc-encoding")
            .map(|c| c.trim().to_ascii_lowercase())
            .filter(|c| !c.is_empty() && c != "identity")
    };
    let mut request = Plan {
        coding: coding(&exchange.request_headers),
        ..Plan::default()
    };
    let mut response = Plan {
        coding: coding(&exchange.response_headers),
        ..Plan::default()
    };
    let Some((schemas, compiled)) = schemas.and_then(|s| Some((s, s.current()?))) else {
        return (request, response);
    };
    let found = if kind == Kind::Protobuf {
        match schemas.message_hint() {
            Some(hint) => compiled
                .message(hint)
                .map(|m| (m.clone(), m))
                .ok_or_else(|| format!("schema-less: message {hint} not found")),
            None => Err("schema-less: no --proto-message given".to_owned()),
        }
    } else {
        path.and_then(|(service, method)| compiled.method(service, method))
            .ok_or_else(|| "schema-less: method not found".to_owned())
    };
    match found {
        Ok((input, output)) => {
            request.schema = Some(input);
            response.schema = Some(output);
        }
        Err(note) => {
            request.note = Some(note.clone());
            response.note = Some(note);
        }
    }
    (request, response)
}

/// Decodes the bodies of `exchange`, with `schemas` when given, or `None` when it is not
/// gRPC or protobuf.
#[must_use]
pub fn decode_exchange_with(exchange: &Exchange, schemas: Option<&Schemas>) -> Option<Call> {
    let kind = Kind::of(exchange)?;
    let path = exchange
        .url
        .split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|i| &rest[i..]))
        .unwrap_or_default();
    let path = path.split(['?', '#']).next().unwrap_or_default();
    let (service, method) = match path.strip_prefix('/').and_then(|p| p.split_once('/')) {
        Some((service, method)) if !service.is_empty() && !method.is_empty() => {
            (Some(service.to_owned()), Some(method.to_owned()))
        }
        _ => (None, None),
    };
    let encoding = header(&exchange.request_headers, "grpc-encoding")
        .or_else(|| header(&exchange.response_headers, "grpc-encoding"))
        .map(str::to_owned);
    let path = service.as_deref().zip(method.as_deref());
    let (request_plan, response_plan) = plans(exchange, kind, path, schemas);
    let (request, _) = body_stream(kind, &exchange.request_body, &request_plan);
    let (response, web_trailers) = exchange
        .response_body
        .as_ref()
        .map(|body| body_stream(kind, body, &response_plan))
        .unzip();
    let web_trailers = web_trailers.unwrap_or_default();
    let trailers = if exchange.response_trailers.is_empty() {
        web_trailers
    } else {
        exchange.response_trailers.clone()
    };
    // A trailers-only response puts the status in the head.
    let status_text = header(&trailers, "grpc-status")
        .or_else(|| header(&exchange.response_headers, "grpc-status"));
    let status = status_text.and_then(|s| s.trim().parse::<u32>().ok());
    let message = header(&trailers, "grpc-message")
        .or_else(|| header(&exchange.response_headers, "grpc-message"))
        .map(percent_decode);
    let truncated = request.truncated || response.as_ref().is_some_and(|r| r.truncated);
    Some(Call {
        kind,
        service,
        method,
        encoding,
        status,
        status_name: status.and_then(status_name),
        message,
        trailers,
        request,
        response,
        truncated,
    })
}

/// The first value of the header `name` (case-insensitive).
fn header<'h>(headers: &'h [(String, String)], name: &str) -> Option<&'h str> {
    headers
        .iter()
        .find_map(|(k, v)| k.eq_ignore_ascii_case(name).then_some(v.as_str()))
}

/// The kept bytes of a body record.
fn body_bytes(body: &BodyRecord) -> Result<Vec<u8>, String> {
    if body.encoding == "base64" {
        base64::engine::general_purpose::STANDARD
            .decode(&body.data)
            .map_err(|e| format!("stored body is not base64: {e}"))
    } else {
        Ok(body.data.as_bytes().to_vec())
    }
}

/// The messages of one body, and the trailers of a gRPC-Web trailer frame.
fn body_stream(kind: Kind, body: &BodyRecord, plan: &Plan) -> (Stream, Vec<(String, String)>) {
    let (mut stream, trailers) = raw_body_stream(kind, body, plan);
    stream.schema = plan.schema.as_ref().map(|m| m.full_name().to_owned());
    stream.schema_note.clone_from(&plan.note);
    (stream, trailers)
}

fn raw_body_stream(kind: Kind, body: &BodyRecord, plan: &Plan) -> (Stream, Vec<(String, String)>) {
    let failed = |error| {
        let stream = Stream {
            error: Some(error),
            truncated: body.truncated,
            ..Stream::default()
        };
        (stream, Vec::new())
    };
    let mut data = match body_bytes(body) {
        Ok(data) => data,
        Err(e) => return failed(e),
    };
    if kind == Kind::GrpcWebText {
        data = match web_text(&data, body.truncated) {
            Ok(data) => data,
            Err(e) => return failed(format!("grpc-web-text body is not base64: {e}")),
        };
    }
    if kind == Kind::Protobuf {
        let mut stream = Stream {
            truncated: body.truncated,
            ..Stream::default()
        };
        if !data.is_empty() {
            let mut budget = protobuf::MAX_STEPS;
            let (schema, failure, decoded) = payload(&data, plan, &mut budget);
            let cut = body.truncated.then(|| "cut by the body limit".to_owned());
            stream.messages.push(Message {
                index: 0,
                compressed: false,
                size: body.size,
                inflated: None,
                schema,
                note: join_notes(cut, failure),
                decoded: Some(decoded),
            });
        }
        return (stream, Vec::new());
    }
    frames(&data, body.truncated, plan)
}

/// Decodes one payload with the plan's type, else schema-less. Returns the type used, why
/// the schema failed (when it did) and the tree.
fn payload(
    data: &[u8],
    plan: &Plan,
    budget: &mut usize,
) -> (Option<String>, Option<String>, Decoded) {
    if let Some(desc) = &plan.schema {
        match crate::schema::decode(desc, data, budget) {
            Ok(decoded) => return (Some(desc.full_name().to_owned()), None, decoded),
            Err(e) => {
                let note = format!("schema-less: not a valid {}: {e}", desc.full_name());
                return (None, Some(note), protobuf::decode_within(data, budget));
            }
        }
    }
    (None, None, protobuf::decode_within(data, budget))
}

fn join_notes(a: Option<String>, b: Option<String>) -> Option<String> {
    match (a, b) {
        (Some(a), Some(b)) => Some(format!("{a}; {b}")),
        (a, b) => a.or(b),
    }
}

/// Inflates a compressed payload with the plan's coding: the bytes and a note, or why not.
fn inflate(data: &[u8], plan: &Plan, cut: bool) -> Result<(Vec<u8>, Option<String>), String> {
    let Some(coding) = &plan.coding else {
        return Err("compressed, not decoded".to_owned());
    };
    if crate::decode::Coding::from_token(coding).is_none() {
        return Err(format!("compressed with {coding}, not decoded"));
    }
    let inflated = crate::decode::decode(data, std::slice::from_ref(coding), MAX_INFLATED, cut)
        .map_err(|e| format!("{e}, not decoded"))?;
    let note = match inflated.cut {
        None => None,
        Some(crate::decode::Cut::Input) => Some("cut by the body limit".to_owned()),
        Some(_) => Some(format!(
            "inflated output cut at {} bytes",
            inflated.data.len()
        )),
    };
    Ok((inflated.data, note))
}

/// Decodes gRPC-Web text: base64, possibly several padded chunks back to back. A body cut
/// by the limit drops its last partial quantum.
fn web_text(text: &[u8], cut: bool) -> Result<Vec<u8>, base64::DecodeError> {
    let engine = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    let clean: Vec<u8> = text
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let mut out = Vec::new();
    let mut start = 0;
    for i in 1..=clean.len() {
        let boundary = i == clean.len() || (clean[i - 1] == b'=' && clean[i] != b'=');
        if boundary {
            let mut chunk = &clean[start..i];
            if cut && i == clean.len() {
                chunk = &chunk[..chunk.len() - chunk.len() % 4];
            }
            out.extend(engine.decode(chunk)?);
            start = i;
        }
    }
    Ok(out)
}

/// Splits length-prefixed frames. `cut` says the bytes end where the body limit cut them,
/// so a short last frame is truncation rather than an error.
fn frames(data: &[u8], cut: bool, plan: &Plan) -> (Stream, Vec<(String, String)>) {
    let mut stream = Stream {
        truncated: cut,
        ..Stream::default()
    };
    let mut trailers = Vec::new();
    let mut budget = protobuf::MAX_STEPS;
    let mut pos = 0;
    while pos < data.len() {
        let Some(&[flag, a, b, c, d]) = data.get(pos..pos + 5) else {
            if !cut {
                stream.error = Some(format!("incomplete frame header at byte {pos}"));
            }
            break;
        };
        if stream.messages.len() == MAX_MESSAGES {
            stream.truncated = true;
            break;
        }
        let declared = u32::from_be_bytes([a, b, c, d]);
        let start = pos + 5;
        let end = start.saturating_add(usize::try_from(declared).unwrap_or(usize::MAX));
        let (payload, short) = match data.get(start..end) {
            Some(payload) => (payload, false),
            None if cut => (&data[start..], true),
            None => {
                stream.error = Some(format!(
                    "frame at byte {pos} declares {declared} bytes, {} left",
                    data.len() - start
                ));
                break;
            }
        };
        pos = end;
        if flag & 0x80 != 0 {
            trailers = web_trailers(payload);
            continue;
        }
        let compressed = flag & 0x01 != 0;
        let mut message = Message {
            index: stream.messages.len(),
            compressed,
            size: u64::from(declared),
            inflated: None,
            schema: None,
            note: None,
            decoded: None,
        };
        let clear = if compressed {
            inflate(payload, plan, short).map(|(bytes, note)| {
                message.inflated = Some(bytes.len());
                (Cow::Owned(bytes), note)
            })
        } else {
            let note = short.then(|| "cut by the body limit".to_owned());
            Ok((Cow::Borrowed(payload), note))
        };
        match clear {
            Ok((bytes, note)) => {
                let (schema, failure, decoded) = self::payload(&bytes, plan, &mut budget);
                message.schema = schema;
                message.note = join_notes(note, failure);
                message.decoded = Some(decoded);
            }
            Err(note) => message.note = Some(note),
        }
        if budget == 0 {
            stream.truncated = true;
        }
        stream.messages.push(message);
        if short {
            break;
        }
    }
    (stream, trailers)
}

/// The `name: value` lines of a gRPC-Web trailer frame, names lower-cased.
fn web_trailers(payload: &[u8]) -> Vec<(String, String)> {
    String::from_utf8_lossy(payload)
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .take(MAX_WEB_TRAILERS)
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect()
}

/// Undoes the percent-encoding of `grpc-message`; bad escapes stay as written.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match (bytes[i], hex) {
            (b'%', Some(byte)) => {
                out.push(byte);
                i += 3;
            }
            (byte, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The canonical name of a gRPC status code.
#[must_use]
pub fn status_name(code: u32) -> Option<&'static str> {
    const NAMES: [&str; 17] = [
        "OK",
        "CANCELLED",
        "UNKNOWN",
        "INVALID_ARGUMENT",
        "DEADLINE_EXCEEDED",
        "NOT_FOUND",
        "ALREADY_EXISTS",
        "PERMISSION_DENIED",
        "RESOURCE_EXHAUSTED",
        "FAILED_PRECONDITION",
        "ABORTED",
        "OUT_OF_RANGE",
        "UNIMPLEMENTED",
        "INTERNAL",
        "UNAVAILABLE",
        "DATA_LOSS",
        "UNAUTHENTICATED",
    ];
    NAMES.get(usize::try_from(code).ok()?).copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::Capture;
    use crate::protobuf::Value;
    use crate::query::tests::exchange;

    fn frame(flag: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![flag];
        out.extend_from_slice(&u32::try_from(payload.len()).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn record(bytes: &[u8], limit: usize) -> BodyRecord {
        let mut capture = Capture::new(limit);
        capture.push(bytes);
        BodyRecord::from(&capture)
    }

    fn grpc_exchange(content_type: &str, request: &[u8], response: &[u8]) -> Exchange {
        let mut x = exchange(
            1,
            "POST",
            "https://api.test/helloworld.Greeter/SayHello",
            200,
        );
        x.request_headers = vec![("content-type".to_owned(), content_type.to_owned())];
        x.response_headers = vec![("content-type".to_owned(), content_type.to_owned())];
        x.request_body = record(request, 1 << 20);
        x.response_body = Some(record(response, 1 << 20));
        x
    }

    /// `HelloRequest { name: "world" }`.
    const HELLO: &[u8] = &[0x0a, 0x05, b'w', b'o', b'r', b'l', b'd'];

    #[test]
    fn content_types_map_to_kinds() {
        assert_eq!(
            Kind::from_content_type("application/grpc"),
            Some(Kind::Grpc)
        );
        assert_eq!(
            Kind::from_content_type("Application/GRPC+proto; charset=x"),
            Some(Kind::Grpc)
        );
        assert_eq!(
            Kind::from_content_type("application/grpc-web-text"),
            Some(Kind::GrpcWebText)
        );
        assert_eq!(
            Kind::from_content_type("application/x-protobuf"),
            Some(Kind::Protobuf)
        );
        assert_eq!(Kind::from_content_type("application/json"), None);
    }

    #[test]
    fn decodes_grpc_frames_method_and_trailers() {
        let mut body = frame(0, HELLO);
        body.extend(frame(0, &[0x08, 0x01]));
        let mut x = grpc_exchange("application/grpc", &frame(0, HELLO), &body);
        x.response_trailers = vec![
            ("grpc-status".to_owned(), "5".to_owned()),
            ("grpc-message".to_owned(), "no%20such%20user".to_owned()),
        ];
        let call = decode_exchange(&x).expect("a gRPC call");
        assert_eq!(call.service.as_deref(), Some("helloworld.Greeter"));
        assert_eq!(call.method.as_deref(), Some("SayHello"));
        assert_eq!(
            (call.status, call.status_name, call.message.as_deref()),
            (Some(5), Some("NOT_FOUND"), Some("no such user"))
        );
        let response = call.response.expect("response");
        assert_eq!(response.messages.len(), 2);
        let decoded = call.request.messages[0].decoded.as_ref().expect("decoded");
        assert_eq!(
            decoded.fields[0].value,
            Value::String {
                value: "world".to_owned()
            }
        );
        assert!(!call.truncated);
    }

    #[test]
    fn grpc_web_text_carries_trailers_in_the_body() {
        let mut raw = frame(0, HELLO);
        raw.extend(frame(0x80, b"grpc-status: 0\r\ngrpc-message: ok\r\n"));
        // Two separately padded chunks, as streaming servers send them.
        let engine = base64::engine::general_purpose::STANDARD;
        let text = format!("{}{}", engine.encode(&raw[..8]), engine.encode(&raw[8..]));
        let x = grpc_exchange("application/grpc-web-text", b"", text.as_bytes());
        let call = decode_exchange(&x).expect("a gRPC-Web call");
        assert_eq!(call.kind, Kind::GrpcWebText);
        assert_eq!(
            (call.status, call.message.as_deref()),
            (Some(0), Some("ok"))
        );
        assert_eq!(call.response.expect("response").messages.len(), 1);
        assert_eq!(call.request.messages.len(), 0);
    }

    #[test]
    fn compressed_cut_and_broken_frames_are_reported() {
        let mut body = frame(1, &[0x1f, 0x8b, 0x08]);
        body.extend(frame(0, &[0x0a, 0x10, b'a', b'b']));
        // The limit keeps the first frame and part of the second.
        let mut x = grpc_exchange("application/grpc", &[0, 0, 0, 0, 9, 1], &[]);
        x.response_body = Some(record(&body, body.len() - 1));
        let call = decode_exchange(&x).expect("a gRPC call");
        assert!(
            call.request.error.is_some(),
            "short request frame is an error"
        );
        let response = call.response.expect("response");
        assert!(response.truncated && call.truncated);
        assert_eq!(
            response.messages[0].note.as_deref(),
            Some("compressed, not decoded")
        );
        assert!(response.messages[0].decoded.is_none());
        assert_eq!(
            response.messages[1].note.as_deref(),
            Some("cut by the body limit")
        );
        assert!(
            response.messages[1]
                .decoded
                .as_ref()
                .is_some_and(|d| d.error.is_some())
        );
    }

    #[test]
    fn bare_protobuf_is_one_message_and_trailers_only_status_is_read() {
        let mut x = grpc_exchange("application/x-protobuf", HELLO, b"");
        x.response_headers
            .push(("grpc-status".to_owned(), "12".to_owned()));
        let call = decode_exchange(&x).expect("protobuf");
        assert_eq!(call.request.messages.len(), 1);
        assert_eq!(call.status_name, Some("UNIMPLEMENTED"));
        let plain = exchange(2, "GET", "https://a.test/", 200);
        assert!(decode_exchange(&plain).is_none());
    }

    #[test]
    fn many_frames_are_capped() {
        let body: Vec<u8> = (0..MAX_MESSAGES + 5)
            .flat_map(|_| frame(0, HELLO))
            .collect();
        let x = grpc_exchange("application/grpc", &body, b"");
        let call = decode_exchange(&x).expect("a gRPC call");
        assert_eq!(call.request.messages.len(), MAX_MESSAGES);
        assert!(call.request.truncated);
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(data).expect("compress");
        encoder.finish().expect("finish")
    }

    #[test]
    fn gzip_messages_are_inflated_and_unknown_codings_named() {
        let mut x = grpc_exchange(
            "application/grpc",
            &frame(1, &gzip(HELLO)),
            &frame(1, b"zz"),
        );
        x.request_headers
            .push(("grpc-encoding".to_owned(), "gzip".to_owned()));
        x.response_headers
            .push(("grpc-encoding".to_owned(), "snappy".to_owned()));
        let call = decode_exchange(&x).expect("a gRPC call");
        let request = &call.request.messages[0];
        assert_eq!(
            (request.inflated, request.note.as_deref()),
            (Some(HELLO.len()), None)
        );
        let decoded = request.decoded.as_ref().expect("inflated and decoded");
        assert_eq!(
            decoded.fields[0].value,
            Value::String {
                value: "world".to_owned()
            }
        );
        let response = &call.response.expect("response").messages[0];
        assert_eq!(
            response.note.as_deref(),
            Some("compressed with snappy, not decoded")
        );
        assert!(response.decoded.is_none());

        let mut bad = grpc_exchange("application/grpc", &frame(1, b"not gzip"), b"");
        bad.request_headers
            .push(("grpc-encoding".to_owned(), "gzip".to_owned()));
        let call = decode_exchange(&bad).expect("a gRPC call");
        let note = call.request.messages[0].note.clone().unwrap_or_default();
        assert!(note.starts_with("invalid gzip data"), "{note}");
    }

    #[test]
    fn schemas_name_fields_and_fall_back_when_they_do_not_apply() {
        use crate::schema::tests::{order_bytes, temp_dir, write_shop};
        use crate::schema::{Schemas, Sources};
        let dir = temp_dir("grpc");
        let schemas = Schemas::load(Sources {
            protos: vec![write_shop(&dir)],
            ..Sources::default()
        })
        .expect("compiles");
        let order = order_bytes(&schemas);
        let mut x = grpc_exchange(
            "application/grpc",
            &frame(1, &gzip(&order)),
            &frame(0, &[0x08, 0x01]),
        );
        x.url = "https://api.test/shop.Orders/Place".to_owned();
        x.request_headers
            .push(("grpc-encoding".to_owned(), "gzip".to_owned()));
        let call = decode_exchange_with(&x, Some(&schemas)).expect("a gRPC call");
        assert_eq!(call.request.schema.as_deref(), Some("shop.Order"));
        let message = &call.request.messages[0];
        assert_eq!(message.schema.as_deref(), Some("shop.Order"));
        let first = &message.decoded.as_ref().expect("decoded").fields[0];
        assert_eq!(
            (first.name.as_deref(), first.proto.as_deref()),
            (Some("id"), Some("int64"))
        );
        let response = call.response.expect("response");
        assert_eq!(response.schema.as_deref(), Some("shop.Reply"));
        let ok = &response.messages[0]
            .decoded
            .as_ref()
            .expect("decoded")
            .fields[0];
        assert_eq!(ok.value, Value::Bool { value: true });

        // Bytes that are not an Order: the schema-less tree, and why.
        let mut broken = x.clone();
        broken.request_headers.clear();
        broken
            .request_headers
            .push(("content-type".to_owned(), "application/grpc".to_owned()));
        broken.request_body = record(&frame(0, &[0x0a, 0x02, 0xff, 0xfe]), 1 << 20);
        let call = decode_exchange_with(&broken, Some(&schemas)).expect("a gRPC call");
        let message = &call.request.messages[0];
        assert!(message.schema.is_none());
        let note = message.note.clone().unwrap_or_default();
        assert!(
            note.starts_with("schema-less: not a valid shop.Order"),
            "{note}"
        );
        assert!(message.decoded.is_some());

        let unknown = grpc_exchange("application/grpc", &frame(0, HELLO), b"");
        let call = decode_exchange_with(&unknown, Some(&schemas)).expect("a gRPC call");
        assert_eq!(call.request.schema, None);
        assert_eq!(
            call.request.schema_note.as_deref(),
            Some("schema-less: method not found")
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn random_framed_bytes_never_panic() {
        let mut state: u64 = 7;
        for _ in 0..5_000 {
            let mut data = Vec::new();
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len = usize::try_from(state % 64).unwrap_or(0);
            for i in 0..len {
                data.push(
                    state
                        .rotate_left(u32::try_from(i).unwrap_or(0))
                        .to_le_bytes()[0]
                        % 12,
                );
            }
            for cut in [false, true] {
                let _ = frames(&data, cut, &Plan::default());
                let _ = web_text(&data, cut);
            }
        }
    }
}
