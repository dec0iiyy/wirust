//! The flow log: one [`Event`] per finished exchange, failed client handshake or raw tunnel.

use std::fmt;
use std::net::SocketAddr;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::body::Capture;

/// One log record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// A request and its response, or the error that ended it.
    Exchange(Box<Exchange>),
    /// The client refused our certificate or otherwise failed the TLS handshake.
    TlsFailure(TlsFailure),
    /// A CONNECT tunnel that did not carry TLS, passed through without inspection.
    Tunnel(Tunnel),
}

/// A request and its response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exchange {
    /// Sequence number, unique per process.
    pub id: u64,
    /// When the request arrived, RFC 3339 UTC.
    pub time: String,
    /// The client's address.
    pub client: SocketAddr,
    /// Request method.
    pub method: String,
    /// The full URL, scheme and authority included.
    pub url: String,
    /// HTTP version between the client and the proxy.
    pub client_version: String,
    /// HTTP version between the proxy and the server, when a response arrived.
    pub upstream_version: Option<String>,
    /// Response status code.
    pub status: Option<u16>,
    /// Canonical reason phrase of the status.
    pub reason: Option<String>,
    /// Request headers in the order received.
    pub request_headers: Vec<(String, String)>,
    /// Response headers in the order received.
    pub response_headers: Vec<(String, String)>,
    /// Start of the request body.
    pub request_body: BodyRecord,
    /// Start of the response body.
    pub response_body: Option<BodyRecord>,
    /// Durations of the exchange.
    pub timing: Timing,
    /// The client's TLS session; `None` for plain `http://`.
    pub tls: Option<ClientTls>,
    /// Why the exchange failed, if it did.
    pub error: Option<String>,
    /// What the interceptor chain did; omitted from JSON when empty.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub flags: Vec<Flag>,
    /// Where the request really went when a rule or an edit changed the server
    /// ([`Flag::MapRemote`]); `url` stays what the client asked for. Omitted when `None`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub upstream_url: Option<String>,
    /// The flow this one replays ([`Flag::Replay`]); omitted when `None`, and for a request
    /// composed from scratch.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub replay_of: Option<u64>,
    /// WebSocket messages seen so far, both directions; only on a WebSocket upgrade
    /// (`docs/websocket.md`). Omitted when `None`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ws_messages: Option<u64>,
    /// Response trailers (HTTP/2, or chunked HTTP/1.1), at most 64 fields and 16 KiB; gRPC
    /// puts `grpc-status` here. Omitted when empty.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub response_trailers: Vec<(String, String)>,
}

impl Exchange {
    /// The HTTP version the log and the web UI show for this exchange: the client leg, and
    /// the server leg after an arrow when it differs, such as `h2→http/1.1` for an HTTP/2
    /// client whose server only speaks HTTP/1.1. The web UI builds the same text from
    /// `client_version` and `upstream_version`.
    #[must_use]
    pub fn protocol(&self) -> String {
        match self.upstream_version.as_deref() {
            Some(server) if server != self.client_version => {
                format!("{}→{server}", self.client_version)
            }
            _ => self.client_version.clone(),
        }
    }
}

/// Something the interceptor chain did to an exchange. Serialised as its [`Display`] text,
/// such as `"responded"` or `"rule:mock-users"`, and read back from the same text.
///
/// [`Display`]: fmt::Display
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Flag {
    /// An interceptor answered the request itself; the server may not have been contacted.
    Responded,
    /// A body was over the buffering limit, so body rules did not see it and it passed
    /// through unchanged.
    RewriteSkippedBodyTooLarge,
    /// A breakpoint ran out of time and the exchange went on unchanged.
    PauseTimedOut,
    /// A breakpoint aborted the exchange.
    Aborted,
    /// The record was converted from a HAR file, not captured by this proxy.
    Imported,
    /// The request went to another server than the client named (see
    /// [`Exchange::upstream_url`]).
    MapRemote,
    /// The control plane sent this request (replay or compose), not a client.
    Replay,
    /// `--ws-strip-compression`: the proxy removed the client's `Sec-WebSocket-Extensions`
    /// offer so the server could not negotiate compression.
    WsExtensionsStripped,
    /// The server answered the WebSocket upgrade with an extension: `permessage-deflate`
    /// messages are inflated for the record, other extensions are recorded raw.
    WsCompressed,
    /// The server connection went through the upstream proxy (`--upstream-proxy`).
    UpstreamProxy,
    /// The rule with this name fired (`rule:<name>`).
    Rule(String),
}

impl fmt::Display for Flag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Responded => "responded",
            Self::RewriteSkippedBodyTooLarge => "rewrite_skipped_body_too_large",
            Self::PauseTimedOut => "pause_timed_out",
            Self::Aborted => "aborted",
            Self::Imported => "imported",
            Self::MapRemote => "map_remote",
            Self::Replay => "replay",
            Self::WsExtensionsStripped => "ws_extensions_stripped",
            Self::WsCompressed => "ws_compressed",
            Self::UpstreamProxy => "upstream_proxy",
            Self::Rule(name) => return write!(f, "rule:{name}"),
        })
    }
}

impl Serialize for Flag {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Flag {
    /// Reads the text [`Serialize`] writes. An unknown word is an error, as it was with the
    /// derived implementation.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Ok(match text.as_str() {
            "responded" => Self::Responded,
            "rewrite_skipped_body_too_large" => Self::RewriteSkippedBodyTooLarge,
            "pause_timed_out" => Self::PauseTimedOut,
            "aborted" => Self::Aborted,
            "imported" => Self::Imported,
            "map_remote" => Self::MapRemote,
            "replay" => Self::Replay,
            "ws_extensions_stripped" => Self::WsExtensionsStripped,
            "ws_compressed" => Self::WsCompressed,
            "upstream_proxy" => Self::UpstreamProxy,
            other => match other.strip_prefix("rule:") {
                Some(name) => Self::Rule(name.to_owned()),
                None => {
                    return Err(serde::de::Error::unknown_variant(
                        other,
                        &[
                            "responded",
                            "rewrite_skipped_body_too_large",
                            "pause_timed_out",
                            "aborted",
                            "imported",
                            "map_remote",
                            "replay",
                            "ws_extensions_stripped",
                            "ws_compressed",
                            "upstream_proxy",
                            "rule:<name>",
                        ],
                    ));
                }
            },
        })
    }
}

/// The kept part of a body.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BodyRecord {
    /// Total size in bytes.
    pub size: u64,
    /// Whether `data` holds less than `size`.
    pub truncated: bool,
    /// `utf8` or `base64`.
    pub encoding: &'static str,
    /// The kept bytes in that encoding.
    pub data: String,
    /// What the body's `Content-Encoding` was and whether `data` is decoded; omitted for a
    /// body sent without one (`docs/interchange.md`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub content_encoding: Option<ContentDecoding>,
}

/// How a body sent with a `Content-Encoding` was recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentDecoding {
    /// The codings in the order the sender applied them, lowercase, without `identity`.
    pub codings: Vec<String>,
    /// Bytes on the wire, all of them, also past the body limit.
    pub wire_size: u64,
    /// Whether the record holds the decoded body; `false` means the wire bytes.
    pub decoded: bool,
    /// Why the body is not decoded, or why the decoded body is cut short.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
}

/// The serialised form of a [`BodyRecord`]; any encoding but `base64` reads as `utf8`.
#[derive(Deserialize)]
struct BodyRecordWire {
    size: u64,
    truncated: bool,
    encoding: String,
    data: String,
    #[serde(default)]
    content_encoding: Option<ContentDecoding>,
}

impl<'de> Deserialize<'de> for BodyRecord {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = BodyRecordWire::deserialize(deserializer)?;
        Ok(Self {
            size: wire.size,
            truncated: wire.truncated,
            encoding: if wire.encoding == "base64" {
                "base64"
            } else {
                "utf8"
            },
            data: wire.data,
            content_encoding: wire.content_encoding,
        })
    }
}

impl From<&Capture> for BodyRecord {
    /// The captured bytes as they are, without decoding.
    fn from(capture: &Capture) -> Self {
        Self::from_bytes(capture.data(), capture.size(), capture.truncated())
    }
}

impl BodyRecord {
    /// The record of `data`, the first bytes of a `size`-byte body; text stays text.
    #[must_use]
    pub fn from_bytes(data: &[u8], size: u64, truncated: bool) -> Self {
        // A UTF-8 sequence cut by the limit is still text: keep the valid prefix.
        let text = match std::str::from_utf8(data) {
            Ok(text) => Some(text),
            Err(e) if e.error_len().is_none() && truncated => {
                std::str::from_utf8(&data[..e.valid_up_to()]).ok()
            }
            Err(_) => None,
        };
        let (encoding, data) = match text {
            Some(text) => ("utf8", text.to_owned()),
            None => (
                "base64",
                base64::engine::general_purpose::STANDARD.encode(data),
            ),
        };
        Self {
            size,
            truncated,
            encoding,
            data,
            content_encoding: None,
        }
    }
}

/// Durations in milliseconds from the arrival of the request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Timing {
    /// TCP connect to the server, when this exchange opened the connection.
    pub connect_ms: Option<f64>,
    /// TLS handshake with the server, when this exchange opened the connection.
    pub tls_ms: Option<f64>,
    /// Until the response head arrived.
    pub first_byte_ms: Option<f64>,
    /// Until the response body ended.
    pub total_ms: f64,
}

/// The TLS session between the client and the proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientTls {
    /// Negotiated version, such as `TLSv1_3`.
    pub version: Option<String>,
    /// Negotiated ALPN protocol.
    pub alpn: Option<String>,
    /// Server name the client asked for.
    pub sni: Option<String>,
    /// JA4 of the ClientHello.
    pub ja4: String,
    /// JA3 hash of the ClientHello.
    pub ja3_hash: String,
    /// The known client this JA4 matches, if any.
    pub client: Option<String>,
}

/// A client that did not complete the TLS handshake with the proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsFailure {
    /// Sequence number, unique per process.
    pub id: u64,
    /// When the handshake failed, RFC 3339 UTC.
    pub time: String,
    /// The client's address.
    pub client: SocketAddr,
    /// The CONNECT target.
    pub target: String,
    /// Server name the client asked for.
    pub sni: Option<String>,
    /// JA4 of the ClientHello.
    pub ja4: String,
    /// The known client this JA4 matches, if any.
    pub known_client: Option<String>,
    /// The TLS error.
    pub reason: String,
}

/// A CONNECT tunnel passed through without TLS interception.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tunnel {
    /// Sequence number, unique per process.
    pub id: u64,
    /// When the tunnel closed, RFC 3339 UTC.
    pub time: String,
    /// The client's address.
    pub client: SocketAddr,
    /// The CONNECT target.
    pub target: String,
    /// Bytes from the client to the server.
    pub bytes_up: u64,
    /// Bytes from the server to the client.
    pub bytes_down: u64,
    /// Why the tunnel failed, if it did.
    pub error: Option<String>,
    /// Why the bytes were not decrypted; omitted when `None` (a non-TLS tunnel).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<TunnelReason>,
    /// The client's ClientHello facts, for TLS tunnels relayed undecrypted.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tls: Option<TunnelTls>,
    /// How long the tunnel was open, in milliseconds; omitted when not measured.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub duration_ms: Option<f64>,
}

/// Why a tunnel's bytes were relayed without decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelReason {
    /// The host matched `--passthrough` or missed `--decrypt-only`.
    Passthrough,
}

/// What the ClientHello of a passthrough tunnel said.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelTls {
    /// Server name the client asked for.
    pub sni: Option<String>,
    /// ALPN protocols the client offered, in its order.
    pub alpn_offered: Vec<String>,
    /// JA4 of the ClientHello.
    pub ja4: String,
    /// JA3 hash of the ClientHello.
    pub ja3_hash: String,
    /// The known client this JA4 matches, if any.
    pub known_client: Option<String>,
}

/// `HH:MM:SS` of an RFC 3339 time.
fn clock(time: &str) -> &str {
    time.get(11..19).unwrap_or(time)
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exchange(x) => {
                write!(f, "{} {:<6} {}", clock(&x.time), x.method, x.url)?;
                match (x.status, &x.error) {
                    (Some(status), _) => {
                        write!(f, "  {status}  {}", x.reason.as_deref().unwrap_or_default())?;
                    }
                    (None, Some(error)) => write!(f, "  ERROR {error}")?,
                    (None, None) => {}
                }
                write!(f, "  {}  {:.0} ms", x.protocol(), x.timing.total_ms)?;
                if let Some(body) = &x.response_body {
                    write!(f, "  {} B", body.size)?;
                }
                if let Some(tls) = &x.tls {
                    let ja4 = &tls.ja4;
                    match &tls.client {
                        Some(client) => write!(f, "  {client} (ja4 {ja4})")?,
                        None => write!(f, "  (ja4 {ja4})")?,
                    }
                }
                if let (Some(_), Some(error)) = (x.status, &x.error) {
                    write!(f, "  error: {error}")?;
                }
                for flag in &x.flags {
                    write!(f, "  [{flag}]")?;
                }
                Ok(())
            }
            Self::TlsFailure(t) => {
                let sni = t.sni.as_deref().unwrap_or("(no SNI)");
                write!(
                    f,
                    "{} TLS-FAIL {sni} via {}  {}  (ja4 {}",
                    clock(&t.time),
                    t.target,
                    t.reason,
                    t.ja4
                )?;
                if let Some(client) = &t.known_client {
                    write!(f, ", {client}")?;
                }
                let host = t.sni.as_deref().unwrap_or_else(|| {
                    t.target
                        .rsplit_once(':')
                        .map_or(t.target.as_str(), |(h, _)| h)
                });
                write!(
                    f,
                    ")  hint: the client does not trust the CA or pins certificates; \
                     to relay it undecrypted: --passthrough {host}"
                )
            }
            Self::Tunnel(t) => {
                write!(f, "{} TUNNEL {} ", clock(&t.time), t.target)?;
                match &t.tls {
                    Some(tls) => write!(
                        f,
                        "(TLS passthrough, sni {}, ja4 {})",
                        tls.sni.as_deref().unwrap_or("-"),
                        tls.ja4
                    )?,
                    None => f.write_str("(not TLS, passed through)")?,
                }
                write!(f, "  up {} B  down {} B", t.bytes_up, t.bytes_down)?;
                if let Some(error) = &t.error {
                    write!(f, "  error: {error}")?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_bodies_stay_text_even_when_cut_mid_character() {
        let mut capture = Capture::new(3);
        capture.push("aé!".as_bytes()); // 'é' is two bytes; the limit cuts after its first
        let record = BodyRecord::from(&capture);
        assert_eq!((record.encoding, record.data.as_str()), ("utf8", "aé"));
        let mut capture = Capture::new(2);
        capture.push("aé".as_bytes());
        assert_eq!(BodyRecord::from(&capture).data, "a");
    }

    fn exchange(client: &str, server: Option<&str>) -> Exchange {
        serde_json::from_value(serde_json::json!({
            "id": 1, "time": "2026-01-02T03:04:05Z", "client": "127.0.0.1:1", "method": "GET",
            "url": "https://example.test/", "client_version": client, "upstream_version": server,
            "status": null, "reason": null, "request_headers": [], "response_headers": [],
            "request_body": {"size": 0, "truncated": false, "encoding": "utf8", "data": ""},
            "response_body": null, "timing": {"total_ms": 1.0}, "tls": null, "error": null,
        }))
        .unwrap_or_else(|e| panic!("fixture: {e}"))
    }

    #[test]
    fn the_protocol_names_the_client_leg_and_a_different_server_leg() {
        let table = [
            ("http/1.1", Some("http/1.1"), "http/1.1"),
            ("h2", Some("h2"), "h2"),
            ("h2", Some("http/1.1"), "h2→http/1.1"),
            ("http/1.1", Some("h2"), "http/1.1→h2"),
            ("h2", None, "h2"),
        ];
        for (client, server, want) in table {
            let x = exchange(client, server);
            assert_eq!(x.protocol(), want, "client {client}, server {server:?}");
            let line = Event::Exchange(Box::new(x)).to_string();
            assert!(line.contains(&format!("  {want}  ")), "{line}");
        }
    }

    #[test]
    fn binary_bodies_are_base64() {
        let mut capture = Capture::new(16);
        capture.push(&[0xff, 0x00]);
        let record = BodyRecord::from(&capture);
        assert_eq!((record.encoding, record.data.as_str()), ("base64", "/wA="));
        assert!(!record.truncated);
    }
}
