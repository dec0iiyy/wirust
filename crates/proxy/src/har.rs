//! HAR 1.2 (HTTP Archive) export and import.
//!
//! [`to_har`] maps finished exchanges to a HAR document that browser devtools and other
//! debugging proxies read; tunnels and failed handshakes have no HAR form and are left out.
//! What HAR has no field for travels in `_`-prefixed extensions: `_tls` (client-leg TLS and
//! fingerprints), `_flags` (what the interceptor chain did), `_error` and, on WebSocket upgrades,
//! `_webSocketMessages` in the Chrome `DevTools` format.
//! [`from_har`] reads a HAR file back into flow records, best effort, marking each with
//! [`Flag::Imported`].

use std::fmt;
use std::net::SocketAddr;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::NAME;
use crate::clock::Utc;
use crate::events::Flow;
use crate::flow::{BodyRecord, ClientTls, Event, Exchange, Flag, Timing};
use crate::ws::{Direction, Kind, WsMessage, WsStore};

/// Largest HAR document [`from_har`] accepts, in bytes.
pub const MAX_HAR_BYTES: usize = 512 * 1024 * 1024;

/// Most entries [`from_har`] converts.
pub const MAX_HAR_ENTRIES: usize = 1_000_000;

/// The HAR value for an unknown optional timing.
const UNKNOWN: f64 = -1.0;

fn unknown() -> f64 {
    UNKNOWN
}

fn minus_one() -> i64 {
    -1
}

/// A HAR document: `{"log": ...}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Har {
    /// The archive.
    pub log: Log,
}

/// The `log` object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    /// Format version, `1.2`.
    #[serde(default)]
    pub version: String,
    /// The program that wrote the file.
    #[serde(default)]
    pub creator: Creator,
    /// One entry per exchange, oldest first.
    #[serde(default)]
    pub entries: Vec<Entry>,
}

/// The `creator` object.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Creator {
    /// Program name.
    #[serde(default)]
    pub name: String,
    /// Program version.
    #[serde(default)]
    pub version: String,
}

/// One request and its response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    /// When the request started, RFC 3339.
    #[serde(default)]
    pub started_date_time: String,
    /// Total milliseconds: the sum of the non-negative timings except `ssl`.
    #[serde(default)]
    pub time: f64,
    /// The request.
    #[serde(default)]
    pub request: Request,
    /// The response; status 0 when none arrived.
    #[serde(default)]
    pub response: Response,
    /// Cache state; always empty.
    #[serde(default)]
    pub cache: Cache,
    /// Phase durations.
    #[serde(default)]
    pub timings: Timings,
    /// Server IP address, when known.
    #[serde(
        rename = "serverIPAddress",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub server_ip_address: Option<String>,
    /// Connection id, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<String>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Extension: the client's TLS session with the proxy.
    #[serde(rename = "_tls", default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsExtension>,
    /// Extension: interceptor flags, such as `pause_timed_out`.
    #[serde(rename = "_flags", default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
    /// Extension: why the exchange failed.
    #[serde(rename = "_error", default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Extension (Chrome `DevTools`): the messages of a WebSocket upgrade.
    #[serde(
        rename = "_webSocketMessages",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub web_socket_messages: Vec<HarWsMessage>,
}

/// One entry of `_webSocketMessages`, as Chrome `DevTools` writes it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HarWsMessage {
    /// `send` (client to server) or `receive`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Seconds since the Unix epoch.
    pub time: f64,
    /// The RFC 6455 opcode: 1 text, 2 binary, 8 close, 9 ping, 10 pong.
    pub opcode: u8,
    /// Text as is; other payloads in base64.
    pub data: String,
}

impl HarWsMessage {
    /// The HAR form of `message`.
    #[must_use]
    pub fn from_message(message: &WsMessage) -> Self {
        Self {
            kind: match message.direction {
                Direction::ClientToServer => "send",
                Direction::ServerToClient => "receive",
            }
            .to_owned(),
            time: message.timestamp,
            opcode: message.kind.opcode(),
            data: message.data.clone(),
        }
    }

    /// Best-effort reverse of [`from_message`](Self::from_message); `None` for an unknown
    /// opcode. Text frames read as text, everything else as base64 when it decodes.
    #[must_use]
    pub fn to_message(&self, flow_id: u64, seq: u64) -> Option<WsMessage> {
        let kind = Kind::from_opcode(self.opcode)?;
        let base64 = kind != Kind::Text
            && base64::engine::general_purpose::STANDARD
                .decode(&self.data)
                .is_ok();
        let parsed = crate::ws::Parsed {
            kind,
            kept: if base64 {
                base64::engine::general_purpose::STANDARD
                    .decode(&self.data)
                    .unwrap_or_default()
            } else {
                self.data.clone().into_bytes()
            },
            size: 0,
            compressed: false,
        };
        let direction = if self.kind == "send" {
            Direction::ClientToServer
        } else {
            Direction::ServerToClient
        };
        let size = parsed.kept.len() as u64;
        let mut message = crate::ws::message(
            flow_id,
            seq,
            direction,
            &crate::ws::Parsed { size, ..parsed },
        );
        message.timestamp = self.time;
        Some(message)
    }
}

/// The `_tls` extension: the TLS session between the client and the proxy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsExtension {
    /// Negotiated version, such as `TLSv1_3`.
    #[serde(default)]
    pub version: Option<String>,
    /// Server name the client asked for.
    #[serde(default)]
    pub sni: Option<String>,
    /// Negotiated ALPN protocol.
    #[serde(default)]
    pub alpn: Option<String>,
    /// JA4 of the ClientHello.
    #[serde(default)]
    pub ja4: String,
    /// JA3 hash of the ClientHello.
    #[serde(default)]
    pub ja3: String,
    /// The known client the JA4 matches.
    #[serde(default)]
    pub client: Option<String>,
}

/// A header, query parameter or similar pair.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NameValue {
    /// Name.
    #[serde(default)]
    pub name: String,
    /// Value.
    #[serde(default)]
    pub value: String,
}

/// A cookie.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cookie {
    /// Name.
    #[serde(default)]
    pub name: String,
    /// Value.
    #[serde(default)]
    pub value: String,
    /// `Path` attribute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// `Domain` attribute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// `Expires` attribute, as sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    /// `HttpOnly` attribute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_only: Option<bool>,
    /// `Secure` attribute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure: Option<bool>,
}

/// The `request` object.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    /// Method.
    #[serde(default)]
    pub method: String,
    /// Absolute URL.
    #[serde(default)]
    pub url: String,
    /// Protocol, such as `HTTP/1.1` or `HTTP/2`.
    #[serde(default)]
    pub http_version: String,
    /// Cookies from the `Cookie` headers.
    #[serde(default)]
    pub cookies: Vec<Cookie>,
    /// Headers in the order sent.
    #[serde(default)]
    pub headers: Vec<NameValue>,
    /// Query parameters, percent-decoded.
    #[serde(default)]
    pub query_string: Vec<NameValue>,
    /// The body, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_data: Option<PostData>,
    /// Header bytes; -1 (unknown).
    #[serde(default = "minus_one")]
    pub headers_size: i64,
    /// Body bytes; -1 when unknown.
    #[serde(default = "minus_one")]
    pub body_size: i64,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl Default for Request {
    fn default() -> Self {
        Self {
            method: String::new(),
            url: String::new(),
            http_version: String::new(),
            cookies: Vec::new(),
            headers: Vec::new(),
            query_string: Vec::new(),
            post_data: None,
            headers_size: -1,
            body_size: -1,
            comment: None,
        }
    }
}

/// The `postData` object.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostData {
    /// The request's content type.
    #[serde(default)]
    pub mime_type: String,
    /// The body as text, or base64 with `encoding`.
    #[serde(default)]
    pub text: String,
    /// `base64` for binary bodies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    /// Says when the body was cut by the body limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// The `response` object.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    /// Status code; 0 when no response arrived.
    #[serde(default)]
    pub status: i64,
    /// Reason phrase.
    #[serde(default)]
    pub status_text: String,
    /// Protocol.
    #[serde(default)]
    pub http_version: String,
    /// Cookies from the `Set-Cookie` headers.
    #[serde(default)]
    pub cookies: Vec<Cookie>,
    /// Headers in the order received.
    #[serde(default)]
    pub headers: Vec<NameValue>,
    /// The body.
    #[serde(default)]
    pub content: Content,
    /// The `Location` header, or empty.
    #[serde(rename = "redirectURL", default)]
    pub redirect_url: String,
    /// Header bytes; -1 (unknown).
    #[serde(default = "minus_one")]
    pub headers_size: i64,
    /// Body bytes as transferred; -1 when unknown.
    #[serde(default = "minus_one")]
    pub body_size: i64,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl Default for Response {
    fn default() -> Self {
        Self {
            status: 0,
            status_text: String::new(),
            http_version: String::new(),
            cookies: Vec::new(),
            headers: Vec::new(),
            content: Content::default(),
            redirect_url: String::new(),
            headers_size: -1,
            body_size: -1,
            comment: None,
        }
    }
}

/// The `content` object.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Content {
    /// Body length in bytes.
    #[serde(default)]
    pub size: i64,
    /// The response's content type.
    #[serde(default)]
    pub mime_type: String,
    /// The body as text, or base64 with `encoding`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// `base64` for binary bodies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    /// Says when the body was cut by the body limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// The `cache` object; this proxy has nothing to say about caches.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Cache {}

/// The `timings` object, milliseconds; -1 marks an unknown optional phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timings {
    /// Queueing; unknown.
    #[serde(default = "unknown")]
    pub blocked: f64,
    /// DNS; unknown.
    #[serde(default = "unknown")]
    pub dns: f64,
    /// TCP connect plus TLS, when this exchange opened the connection.
    #[serde(default = "unknown")]
    pub connect: f64,
    /// Sending the request.
    #[serde(default)]
    pub send: f64,
    /// Waiting for the response head.
    #[serde(default)]
    pub wait: f64,
    /// Reading the response body.
    #[serde(default)]
    pub receive: f64,
    /// TLS handshake with the server (also counted in `connect`).
    #[serde(default = "unknown")]
    pub ssl: f64,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            blocked: UNKNOWN,
            dns: UNKNOWN,
            connect: UNKNOWN,
            send: 0.0,
            wait: 0.0,
            receive: 0.0,
            ssl: UNKNOWN,
        }
    }
}

/// Builds a HAR document from `flows`; only exchanges become entries.
#[must_use]
pub fn to_har<'f>(flows: impl IntoIterator<Item = &'f Flow>) -> Har {
    to_har_with_ws(flows, None)
}

/// [`to_har`] plus `_webSocketMessages` on WebSocket upgrades, from the messages `ws` holds.
#[must_use]
pub fn to_har_with_ws<'f>(flows: impl IntoIterator<Item = &'f Flow>, ws: Option<&WsStore>) -> Har {
    let entries = flows
        .into_iter()
        .filter_map(|flow| match &flow.record {
            Event::Exchange(x) => {
                let mut entry = entry(x);
                if let Some(ws) = ws.filter(|_| x.ws_messages.is_some()) {
                    entry.web_socket_messages = ws
                        .list(x.id, None, usize::MAX)
                        .iter()
                        .map(|m| HarWsMessage::from_message(m))
                        .collect();
                }
                Some(entry)
            }
            Event::TlsFailure(_) | Event::Tunnel(_) => None,
        })
        .collect();
    Har {
        log: Log {
            version: "1.2".to_owned(),
            creator: Creator {
                name: NAME.to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            entries,
        },
    }
}

/// `NAME-YYYYMMDD-HHMMSS.har` for the current UTC time.
#[must_use]
pub fn download_name() -> String {
    let now = Utc::now();
    format!(
        "{NAME}-{:04}{:02}{:02}-{:02}{:02}{:02}.har",
        now.year, now.month, now.day, now.hour, now.minute, now.second
    )
}

fn pairs(headers: &[(String, String)]) -> Vec<NameValue> {
    headers
        .iter()
        .map(|(name, value)| NameValue {
            name: name.clone(),
            value: value.clone(),
        })
        .collect()
}

fn header<'h>(headers: &'h [(String, String)], name: &str) -> Option<&'h str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn har_version(ours: &str) -> String {
    match ours {
        "h2" => "HTTP/2".to_owned(),
        "h3" => "HTTP/3".to_owned(),
        other => other.to_ascii_uppercase(),
    }
}

fn our_version(theirs: &str) -> String {
    match theirs.to_ascii_lowercase().as_str() {
        "h2" | "http/2" | "http/2.0" => "h2".to_owned(),
        "h3" | "http/3" | "http/3.0" => "h3".to_owned(),
        "" => "http/1.1".to_owned(),
        other => other.to_owned(),
    }
}

fn truncation_note(body: &BodyRecord) -> Option<String> {
    body.truncated.then(|| {
        format!(
            "truncated: the text holds only the start of the {} byte body (body limit)",
            body.size
        )
    })
}

fn encoding(body: &BodyRecord) -> Option<String> {
    (body.encoding == "base64").then(|| "base64".to_owned())
}

fn size(bytes: u64) -> i64 {
    i64::try_from(bytes).unwrap_or(i64::MAX)
}

fn entry(x: &Exchange) -> Entry {
    let post_data =
        (x.request_body.size > 0 || !x.request_body.data.is_empty()).then(|| PostData {
            mime_type: header(&x.request_headers, "content-type")
                .unwrap_or_default()
                .to_owned(),
            text: x.request_body.data.clone(),
            encoding: encoding(&x.request_body),
            comment: truncation_note(&x.request_body),
        });
    let request = Request {
        method: x.method.clone(),
        url: x.url.clone(),
        http_version: har_version(&x.client_version),
        cookies: request_cookies(&x.request_headers),
        headers: pairs(&x.request_headers),
        query_string: query_string(&x.url),
        post_data,
        headers_size: -1,
        body_size: size(x.request_body.size),
        comment: None,
    };
    let content = match &x.response_body {
        Some(body) => Content {
            size: size(body.size),
            mime_type: header(&x.response_headers, "content-type")
                .unwrap_or("x-unknown")
                .to_owned(),
            text: Some(body.data.clone()),
            encoding: encoding(body),
            comment: truncation_note(body),
        },
        None => Content {
            mime_type: "x-unknown".to_owned(),
            ..Content::default()
        },
    };
    let response = Response {
        status: x.status.map_or(0, i64::from),
        status_text: x.reason.clone().unwrap_or_default(),
        http_version: har_version(x.upstream_version.as_deref().unwrap_or(&x.client_version)),
        cookies: response_cookies(&x.response_headers),
        headers: pairs(&x.response_headers),
        content,
        redirect_url: header(&x.response_headers, "location")
            .unwrap_or_default()
            .to_owned(),
        headers_size: -1,
        body_size: x.response_body.as_ref().map_or(-1, |b| size(b.size)),
        comment: None,
    };
    let timings = timings(&x.timing);
    Entry {
        started_date_time: x.time.clone(),
        time: x.timing.total_ms,
        request,
        response,
        cache: Cache {},
        timings,
        server_ip_address: None,
        connection: None,
        comment: None,
        tls: x.tls.as_ref().map(|tls| TlsExtension {
            version: tls.version.clone(),
            sni: tls.sni.clone(),
            alpn: tls.alpn.clone(),
            ja4: tls.ja4.clone(),
            ja3: tls.ja3_hash.clone(),
            client: tls.client.clone(),
        }),
        flags: x.flags.iter().map(ToString::to_string).collect(),
        error: x.error.clone(),
        web_socket_messages: Vec::new(),
    }
}

/// HAR timings whose sum (without `ssl`) is the exchange's total time.
fn timings(t: &Timing) -> Timings {
    let connect = t.connect_ms.unwrap_or(0.0) + t.tls_ms.unwrap_or(0.0);
    let first_byte = t.first_byte_ms.unwrap_or(t.total_ms);
    Timings {
        blocked: UNKNOWN,
        dns: UNKNOWN,
        connect: if t.connect_ms.is_some() || t.tls_ms.is_some() {
            connect
        } else {
            UNKNOWN
        },
        send: 0.0,
        wait: (first_byte - connect).max(0.0),
        receive: (t.total_ms - first_byte).max(0.0),
        ssl: t.tls_ms.unwrap_or(UNKNOWN),
    }
}

fn query_string(url: &str) -> Vec<NameValue> {
    let Some((_, query)) = url.split_once('?') else {
        return Vec::new();
    };
    let query = query.split('#').next().unwrap_or_default();
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            NameValue {
                name: percent_decode(name, Plus::Keep),
                value: percent_decode(value, Plus::Keep),
            }
        })
        .collect()
}

/// How [`percent_decode`] treats `+`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plus {
    /// Leave `+` alone (URLs).
    Keep,
    /// `+` means a space (form encoding, API query parameters).
    Space,
}

/// Decodes `%XX` escapes; invalid escapes stay as written, invalid UTF-8 becomes U+FFFD.
pub(crate) fn percent_decode(text: &str, plus: Plus) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |at: usize| bytes.get(at).and_then(|b| char::from(*b).to_digit(16));
        match bytes[i] {
            b'%' => {
                if let (Some(hi), Some(lo)) = (hex(i + 1), hex(i + 2)) {
                    out.push(u8::try_from(hi * 16 + lo).unwrap_or(b'?'));
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            b'+' if plus == Plus::Space => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn request_cookies(headers: &[(String, String)]) -> Vec<Cookie> {
    headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("cookie"))
        .flat_map(|(_, v)| v.split(';'))
        .filter_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            Some(Cookie {
                name: name.to_owned(),
                value: value.to_owned(),
                ..Cookie::default()
            })
        })
        .collect()
}

fn response_cookies(headers: &[(String, String)]) -> Vec<Cookie> {
    headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(_, v)| {
            let mut parts = v.split(';');
            let (name, value) = parts.next()?.trim().split_once('=')?;
            let mut cookie = Cookie {
                name: name.to_owned(),
                value: value.to_owned(),
                ..Cookie::default()
            };
            for attribute in parts {
                let (key, value) = attribute
                    .trim()
                    .split_once('=')
                    .unwrap_or((attribute.trim(), ""));
                match key.to_ascii_lowercase().as_str() {
                    "path" => cookie.path = Some(value.to_owned()),
                    "domain" => cookie.domain = Some(value.to_owned()),
                    "expires" => cookie.expires = Some(value.to_owned()),
                    "httponly" => cookie.http_only = Some(true),
                    "secure" => cookie.secure = Some(true),
                    _ => {}
                }
            }
            Some(cookie)
        })
        .collect()
}

/// Why a HAR document could not be imported.
#[derive(Debug)]
#[non_exhaustive]
pub enum ImportHarError {
    /// The document is over [`MAX_HAR_BYTES`].
    TooLarge {
        /// Its size in bytes.
        size: usize,
    },
    /// The document has more than [`MAX_HAR_ENTRIES`] entries.
    TooManyEntries {
        /// How many it has.
        entries: usize,
    },
    /// Not JSON, or not shaped like a HAR document.
    Malformed(serde_json::Error),
}

impl fmt::Display for ImportHarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { size } => write!(
                f,
                "the HAR file is {size} bytes; the limit is {MAX_HAR_BYTES}"
            ),
            Self::TooManyEntries { entries } => write!(
                f,
                "the HAR file has {entries} entries; the limit is {MAX_HAR_ENTRIES}"
            ),
            Self::Malformed(e) => write!(f, "not a valid HAR document: {e}"),
        }
    }
}

impl std::error::Error for ImportHarError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Malformed(e) => Some(e),
            Self::TooLarge { .. } | Self::TooManyEntries { .. } => None,
        }
    }
}

/// Converts a HAR document to flow records numbered from 1, each flagged
/// [`Flag::Imported`]. Unknown fields are ignored; missing ones get neutral values.
///
/// # Errors
///
/// Fails on input over [`MAX_HAR_BYTES`] or [`MAX_HAR_ENTRIES`], and on input that is not
/// JSON shaped like a HAR document (the error names the line and column).
pub fn from_har(document: &[u8]) -> Result<Vec<Flow>, ImportHarError> {
    if document.len() > MAX_HAR_BYTES {
        return Err(ImportHarError::TooLarge {
            size: document.len(),
        });
    }
    let har: Har = serde_json::from_slice(document).map_err(ImportHarError::Malformed)?;
    if har.log.entries.len() > MAX_HAR_ENTRIES {
        return Err(ImportHarError::TooManyEntries {
            entries: har.log.entries.len(),
        });
    }
    Ok((1..)
        .zip(har.log.entries)
        .map(|(id, entry)| Flow::new(Event::Exchange(Box::new(exchange(id, entry)))))
        .collect())
}

fn body(text: String, encoding: Option<&str>, declared: i64) -> BodyRecord {
    let base64 = encoding == Some("base64")
        && base64::engine::general_purpose::STANDARD
            .decode(&text)
            .is_ok();
    let kept = if base64 {
        // Valid base64 decodes to three bytes per four characters, minus padding.
        let padding = text.bytes().rev().take_while(|b| *b == b'=').count();
        (text.len() / 4 * 3).saturating_sub(padding)
    } else {
        text.len()
    };
    let kept = u64::try_from(kept).unwrap_or(u64::MAX);
    let size = u64::try_from(declared).unwrap_or(kept).max(kept);
    BodyRecord {
        size,
        truncated: size > kept,
        encoding: if base64 { "base64" } else { "utf8" },
        data: text,
    }
}

fn known(ms: f64) -> Option<f64> {
    (ms.is_finite() && ms >= 0.0).then_some(ms)
}

fn exchange(id: u64, entry: Entry) -> Exchange {
    let Entry {
        started_date_time,
        time,
        request,
        response,
        timings: t,
        tls,
        flags,
        error,
        web_socket_messages,
        ..
    } = entry;
    let headers = |list: Vec<NameValue>| -> Vec<(String, String)> {
        list.into_iter().map(|h| (h.name, h.value)).collect()
    };
    let status = u16::try_from(response.status)
        .ok()
        .filter(|s| (100..=999).contains(s));
    let request_body = match request.post_data {
        Some(post) => body(post.text, post.encoding.as_deref(), request.body_size),
        None => body(String::new(), None, request.body_size),
    };
    let content = response.content;
    let response_body = (status.is_some() || content.text.is_some()).then(|| {
        body(
            content.text.unwrap_or_default(),
            content.encoding.as_deref(),
            content.size,
        )
    });
    let ssl = known(t.ssl);
    let connect = known(t.connect).map(|c| (c - ssl.unwrap_or(0.0)).max(0.0));
    let head: f64 = [t.blocked, t.dns, t.connect, t.send, t.wait]
        .into_iter()
        .filter_map(known)
        .sum();
    let total = known(time).unwrap_or(head + known(t.receive).unwrap_or(0.0));
    let mut flags: Vec<Flag> = flags
        .into_iter()
        .filter_map(|name| serde_json::from_value(serde_json::Value::String(name)).ok())
        .collect();
    if !flags.contains(&Flag::Imported) {
        flags.push(Flag::Imported);
    }
    Exchange {
        id,
        time: if started_date_time.is_empty() {
            "1970-01-01T00:00:00.000Z".to_owned()
        } else {
            started_date_time
        },
        client: SocketAddr::from(([0, 0, 0, 0], 0)),
        method: request.method,
        url: request.url,
        client_version: our_version(&request.http_version),
        upstream_version: status.map(|_| our_version(&response.http_version)),
        status,
        reason: status.map(|_| response.status_text),
        request_headers: headers(request.headers),
        response_headers: headers(response.headers),
        request_body,
        response_body,
        timing: Timing {
            connect_ms: connect,
            tls_ms: ssl,
            first_byte_ms: status.map(|_| head),
            total_ms: total,
        },
        tls: tls.map(|tls| ClientTls {
            version: tls.version,
            alpn: tls.alpn,
            sni: tls.sni,
            ja4: tls.ja4,
            ja3_hash: tls.ja3,
            client: tls.client,
        }),
        error,
        flags,
        // A HAR file does not say where a request really went when a rule changed the server.
        upstream_url: None,
        replay_of: None,
        ws_messages: (!web_socket_messages.is_empty()).then_some(web_socket_messages.len() as u64),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::query::tests::exchange as sample_exchange;

    fn sample() -> Vec<Flow> {
        let mut a = sample_exchange(
            1,
            "POST",
            "https://api.example.com/a?x=1&y=%20z&flag#frag",
            201,
        );
        a.request_headers
            .push(("cookie".to_owned(), "sid=abc; theme=dark".to_owned()));
        a.request_headers.push((
            "content-type".to_owned(),
            "application/octet-stream".to_owned(),
        ));
        a.request_body = BodyRecord {
            size: 4000,
            truncated: true,
            encoding: "base64",
            data: "/wA=".to_owned(),
        };
        a.response_headers.push((
            "set-cookie".to_owned(),
            "sid=new; Path=/; HttpOnly; Secure".to_owned(),
        ));
        a.response_headers
            .push(("location".to_owned(), "/next".to_owned()));
        if let Some(body) = &mut a.response_body {
            body.size = u64::try_from(body.data.len()).unwrap_or_default();
        }
        let mut b = sample_exchange(2, "GET", "http://plain.test/", 0);
        b.status = None;
        b.reason = None;
        b.upstream_version = None;
        b.response_body = None;
        b.tls = None;
        b.error = Some("connection refused".to_owned());
        b.timing = Timing {
            total_ms: 3.0,
            ..Timing::default()
        };
        vec![
            Flow::new(Event::Exchange(Box::new(a))),
            Flow::new(Event::Exchange(Box::new(b))),
        ]
    }

    fn is_iso_date(text: &str) -> bool {
        let b = text.as_bytes();
        let digits = |range: std::ops::Range<usize>| {
            b.get(range)
                .is_some_and(|s| s.iter().all(u8::is_ascii_digit))
        };
        let date = digits(0..4)
            && b.get(4) == Some(&b'-')
            && digits(5..7)
            && b.get(7) == Some(&b'-')
            && digits(8..10)
            && b.get(10) == Some(&b'T')
            && digits(11..13)
            && b.get(13) == Some(&b':')
            && digits(14..16)
            && b.get(16) == Some(&b':')
            && digits(17..19);
        let mut rest = text.get(19..).unwrap_or_default();
        if let Some(fraction) = rest.strip_prefix('.') {
            let n = fraction.bytes().take_while(u8::is_ascii_digit).count();
            if n == 0 {
                return false;
            }
            rest = &fraction[n..];
        }
        let zone = rest == "Z"
            || (rest.len() == 6
                && matches!(rest.as_bytes()[0], b'+' | b'-')
                && rest.as_bytes()[3] == b':');
        date && zone
    }

    /// Checks the required structure of HAR 1.2 (`http://www.softwareishard.com/blog/har-12-spec/`).
    fn validate(har: &Value) -> Result<(), String> {
        fn string(v: &Value, path: &str) -> Result<(), String> {
            v.as_str()
                .map(|_| ())
                .ok_or(format!("{path} must be a string"))
        }
        fn number(v: &Value, path: &str, min: f64) -> Result<(), String> {
            match v.as_f64() {
                Some(n) if n >= min => Ok(()),
                _ => Err(format!("{path} must be a number >= {min}, got {v}")),
            }
        }
        fn pairs(v: &Value, path: &str) -> Result<(), String> {
            let list = v.as_array().ok_or(format!("{path} must be an array"))?;
            for (i, item) in list.iter().enumerate() {
                string(&item["name"], &format!("{path}[{i}].name"))?;
                string(&item["value"], &format!("{path}[{i}].value"))?;
            }
            Ok(())
        }
        let log = &har["log"];
        if log["version"] != "1.2" {
            return Err("log.version must be 1.2".to_owned());
        }
        string(&log["creator"]["name"], "log.creator.name")?;
        string(&log["creator"]["version"], "log.creator.version")?;
        let entries = log["entries"]
            .as_array()
            .ok_or("log.entries must be an array")?;
        for (i, e) in entries.iter().enumerate() {
            let p = format!("entries[{i}]");
            let date = e["startedDateTime"].as_str().unwrap_or_default();
            if !is_iso_date(date) {
                return Err(format!("{p}.startedDateTime is not ISO 8601: {date:?}"));
            }
            number(&e["time"], &format!("{p}.time"), 0.0)?;
            let rq = &e["request"];
            for key in ["method", "url", "httpVersion"] {
                string(&rq[key], &format!("{p}.request.{key}"))?;
            }
            pairs(&rq["headers"], &format!("{p}.request.headers"))?;
            pairs(&rq["queryString"], &format!("{p}.request.queryString"))?;
            pairs(&rq["cookies"], &format!("{p}.request.cookies"))?;
            number(
                &rq["headersSize"],
                &format!("{p}.request.headersSize"),
                -1.0,
            )?;
            number(&rq["bodySize"], &format!("{p}.request.bodySize"), -1.0)?;
            if let Some(post) = rq.get("postData") {
                string(&post["mimeType"], &format!("{p}.request.postData.mimeType"))?;
            }
            let rs = &e["response"];
            number(&rs["status"], &format!("{p}.response.status"), 0.0)?;
            for key in ["statusText", "httpVersion", "redirectURL"] {
                string(&rs[key], &format!("{p}.response.{key}"))?;
            }
            pairs(&rs["headers"], &format!("{p}.response.headers"))?;
            pairs(&rs["cookies"], &format!("{p}.response.cookies"))?;
            number(
                &rs["content"]["size"],
                &format!("{p}.response.content.size"),
                0.0,
            )?;
            string(
                &rs["content"]["mimeType"],
                &format!("{p}.response.content.mimeType"),
            )?;
            number(
                &rs["headersSize"],
                &format!("{p}.response.headersSize"),
                -1.0,
            )?;
            number(&rs["bodySize"], &format!("{p}.response.bodySize"), -1.0)?;
            if !e["cache"].is_object() {
                return Err(format!("{p}.cache must be an object"));
            }
            let t = &e["timings"];
            for key in ["send", "wait", "receive"] {
                number(&t[key], &format!("{p}.timings.{key}"), 0.0)?;
            }
            for key in ["blocked", "dns", "connect", "ssl"] {
                if let Some(v) = t.get(key) {
                    number(v, &format!("{p}.timings.{key}"), -1.0)?;
                }
            }
            let sum: f64 = ["blocked", "dns", "connect", "send", "wait", "receive"]
                .iter()
                .filter_map(|k| t[*k].as_f64())
                .filter(|v| *v >= 0.0)
                .sum();
            let time = e["time"].as_f64().unwrap_or_default();
            if (sum - time).abs() > 0.001 {
                return Err(format!("{p}.time {time} is not the sum of timings {sum}"));
            }
        }
        Ok(())
    }

    #[test]
    fn export_follows_the_har_1_2_structure() -> serde_json::Result<()> {
        let har = serde_json::to_value(to_har(&sample()))?;
        validate(&har).map_err(serde::ser::Error::custom)?;
        let e = &har["log"]["entries"][0];
        assert_eq!(har["log"]["creator"]["name"], NAME);
        assert!(har["log"].get("pages").is_none());
        assert_eq!(e["request"]["httpVersion"], "HTTP/2");
        assert_eq!(e["request"]["headers"][0]["name"], "user-agent");
        assert_eq!(
            e["request"]["queryString"],
            serde_json::json!([
                {"name": "x", "value": "1"},
                {"name": "y", "value": " z"},
                {"name": "flag", "value": ""}
            ])
        );
        assert_eq!(e["request"]["cookies"][1]["name"], "theme");
        assert_eq!(e["request"]["postData"]["encoding"], "base64");
        assert!(
            e["request"]["postData"]["comment"]
                .as_str()
                .is_some_and(|c| c.contains("truncated"))
        );
        assert_eq!(e["request"]["bodySize"], 4000);
        assert_eq!(e["response"]["status"], 201);
        assert_eq!(e["response"]["redirectURL"], "/next");
        assert_eq!(e["response"]["cookies"][0]["httpOnly"], true);
        assert_eq!(
            e["response"]["content"]["mimeType"],
            "application/json; charset=utf-8"
        );
        assert_eq!(e["timings"]["connect"], 30.0);
        assert_eq!(e["timings"]["ssl"], 20.0);
        assert_eq!(e["timings"]["wait"], 370.0);
        assert_eq!(e["timings"]["receive"], 250.0);
        assert_eq!(e["_tls"]["ja4"], "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(e["_tls"]["client"], "curl");
        assert_eq!(e["_flags"], serde_json::json!(["pause_timed_out"]));
        let failed = &har["log"]["entries"][1];
        assert_eq!(failed["response"]["status"], 0);
        assert_eq!(failed["_error"], "connection refused");
        assert_eq!(failed["timings"]["connect"], -1.0);
        Ok(())
    }

    #[test]
    fn import_round_trips_an_export() -> Result<(), Box<dyn std::error::Error>> {
        let original = to_har(&sample());
        let bytes = serde_json::to_vec(&original)?;
        let flows = from_har(&bytes)?;
        assert_eq!(flows.len(), 2);
        let Event::Exchange(x) = &flows[0].record else {
            panic!("an exchange");
        };
        assert!(x.flags.contains(&Flag::Imported));
        assert!(x.flags.contains(&Flag::PauseTimedOut));
        assert_eq!(x.request_body.encoding, "base64");
        assert!(x.request_body.truncated);
        assert_eq!(x.client_version, "h2");
        assert_eq!(x.tls.as_ref().map(|t| t.ja3_hash.as_str()), Some("0123"));
        let mut again = serde_json::to_value(to_har(&flows))?;
        let mut first = serde_json::to_value(&original)?;
        for har in [&mut again, &mut first] {
            for entry in har["log"]["entries"].as_array_mut().into_iter().flatten() {
                entry["_flags"] = Value::Null;
            }
        }
        assert_eq!(again, first);
        Ok(())
    }

    #[test]
    fn imports_a_minimal_browser_export() -> Result<(), ImportHarError> {
        let doc = br#"{"log":{"version":"1.2","creator":{"name":"Browser","version":"1"},
            "pages":[{"id":"p"}],"entries":[{"startedDateTime":"2026-01-02T03:04:05.678+01:00",
            "time":12.5,"request":{"method":"GET","url":"https://e.test/","httpVersion":"http/2.0",
            "headers":[{"name":":authority","value":"e.test"}],"_priority":"High"},
            "response":{"status":200,"statusText":"","httpVersion":"http/2.0","headers":[],
            "content":{"size":5,"mimeType":"text/plain","text":"hello"}},
            "timings":{"blocked":1,"dns":-1,"connect":-1,"send":0.5,"wait":10,"receive":1}}]}}"#;
        let flows = from_har(doc)?;
        let Event::Exchange(x) = &flows[0].record else {
            panic!("an exchange");
        };
        assert_eq!((x.status, x.client_version.as_str()), (Some(200), "h2"));
        assert_eq!(
            x.response_body.as_ref().map(|b| b.data.as_str()),
            Some("hello")
        );
        assert!((x.timing.total_ms - 12.5).abs() < f64::EPSILON);
        assert_eq!(x.flags, [Flag::Imported]);
        Ok(())
    }

    #[test]
    fn hostile_input_is_an_error_never_a_panic() {
        let valid = serde_json::to_vec(&to_har(&sample())).unwrap_or_default();
        let mut inputs: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"null".to_vec(),
            b"[]".to_vec(),
            b"{\"log\":null}".to_vec(),
            b"{\"log\":{\"entries\":{}}}".to_vec(),
            b"{\"log\":{\"entries\":[{\"response\":{\"status\":1e300}}]}}".to_vec(),
            b"{\"log\":{\"entries\":[{\"time\":\"soon\"}]}}".to_vec(),
            "[".repeat(100_000).into_bytes(),
            vec![0xff; 64],
        ];
        // Every prefix of a valid document, and a few byte flips.
        inputs.extend((0..valid.len()).step_by(7).map(|n| valid[..n].to_vec()));
        let mut seed = 0x2545_f491_u32;
        for _ in 0..200 {
            let mut doc = valid.clone();
            for _ in 0..4 {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                let at = usize::try_from(seed).unwrap_or(0) % doc.len().max(1);
                if let Some(byte) = doc.get_mut(at) {
                    *byte = byte.wrapping_add(u8::try_from(seed % 251).unwrap_or(1));
                }
            }
            inputs.push(doc);
        }
        for input in inputs {
            if let Ok(flows) = from_har(&input) {
                // Whatever parsed must still export.
                let _ = serde_json::to_vec(&to_har(&flows));
            }
        }
        assert!(matches!(
            from_har(b"{\"log\":"),
            Err(ImportHarError::Malformed(_))
        ));
    }

    #[test]
    fn percent_decoding_is_lenient() {
        assert_eq!(percent_decode("a%20b%zz%", Plus::Keep), "a b%zz%");
        assert_eq!(percent_decode("a+b%2B", Plus::Space), "a b+");
        assert_eq!(percent_decode("%ff", Plus::Keep), "\u{fffd}");
    }
}
