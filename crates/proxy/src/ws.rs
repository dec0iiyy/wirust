//! WebSocket capture (RFC 6455): a frame-aware pump that forwards the bytes of an upgraded
//! connection unchanged while it records the messages in each direction.
//!
//! The pump writes every chunk it reads to the other side first and parses a copy after, so
//! parsing never delays or changes the traffic. The parser is incremental and bounded: a
//! message keeps at most [`WsLimits::body_limit`] bytes (the rest is only counted), a message
//! may have at most [`MAX_FRAGMENTS`] frames, a frame header is at most 14 bytes, and any
//! protocol violation stops parsing for that direction while the raw bytes keep flowing.
//! See `docs/websocket.md`.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use http::HeaderMap;
use http::header;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::clock::Utc;
use crate::events::{Bus, FlowEvent};

/// Default bytes kept per message (`--ws-body-limit`); the rest is counted.
pub const DEFAULT_WS_BODY_LIMIT: usize = 1024 * 1024;

/// Default messages kept per flow (`--ws-max-messages`); older ones are dropped.
pub const DEFAULT_WS_MAX_MESSAGES: usize = 1000;

/// Frames one message may span before the parser gives up on that direction. Real clients
/// fragment into a handful of frames; this only stops a peer that streams empty fragments.
pub const MAX_FRAGMENTS: usize = 65_536;

/// Largest frame header: 2 bytes, an 8-byte length and a 4-byte mask.
const MAX_HEADER: usize = 14;

/// Largest control frame payload (RFC 6455 section 5.5).
const MAX_CONTROL: u64 = 125;

/// Bytes the pump reads at a time per direction.
const CHUNK: usize = 16 * 1024;

/// Most messages one `GET /api/v1/flows/{id}/messages` returns.
pub const MAX_PAGE: usize = 1000;

/// Decoded bytes a compressed message may produce per wire byte before it counts as a
/// decompression bomb (with a floor of [`MIN_INFLATE_BUDGET`]).
const MAX_INFLATE_RATIO: u64 = 1000;

/// Decoded bytes every compressed message may produce, whatever its wire size.
const MIN_INFLATE_BUDGET: u64 = 64 * 1024;

/// The tail RFC 7692 section 7.2.2 removes from each compressed message; the reader appends
/// it again before inflating.
const DEFLATE_TAIL: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

/// Capture limits, set from `--ws-body-limit`, `--ws-max-messages` and
/// `--ws-strip-compression`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WsLimits {
    /// Bytes kept per message.
    pub body_limit: usize,
    /// Messages kept per flow.
    pub max_messages: usize,
    /// Remove `Sec-WebSocket-Extensions` from the client's offer, for peers whose
    /// compression misbehaves (`--ws-strip-compression`).
    pub strip_compression: bool,
}

impl Default for WsLimits {
    fn default() -> Self {
        Self {
            body_limit: DEFAULT_WS_BODY_LIMIT,
            max_messages: DEFAULT_WS_MAX_MESSAGES,
            strip_compression: false,
        }
    }
}

/// Which way a message went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// From the client to the server; these frames are masked.
    ClientToServer,
    /// From the server to the client; these frames are not masked.
    ServerToClient,
}

/// What a message is, from its first frame's opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Opcode 1.
    Text,
    /// Opcode 2.
    Binary,
    /// Opcode 8.
    Close,
    /// Opcode 9.
    Ping,
    /// Opcode 10.
    Pong,
}

impl Kind {
    /// The RFC 6455 opcode.
    #[must_use]
    pub fn opcode(self) -> u8 {
        match self {
            Self::Text => 1,
            Self::Binary => 2,
            Self::Close => 8,
            Self::Ping => 9,
            Self::Pong => 10,
        }
    }

    /// The kind for a non-continuation opcode.
    #[must_use]
    pub fn from_opcode(opcode: u8) -> Option<Self> {
        Some(match opcode {
            1 => Self::Text,
            2 => Self::Binary,
            8 => Self::Close,
            9 => Self::Ping,
            10 => Self::Pong,
            _ => return None,
        })
    }

    fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

/// How [`WsMessage::data`] is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    /// The bytes are valid UTF-8 and `data` is that text.
    Utf8,
    /// `data` is standard base64 of the bytes.
    Base64,
}

/// One recorded WebSocket message, as the API, the event stream and HAR carry it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent JSON flags of the interchange format"
)]
pub struct WsMessage {
    /// The upgrade exchange this message belongs to.
    pub flow_id: u64,
    /// Position in the connection, both directions counted, from 0.
    pub seq: u64,
    /// When the message's last frame arrived, RFC 3339 UTC.
    pub time: String,
    /// The same instant in seconds since the Unix epoch.
    pub timestamp: f64,
    /// Which way it went.
    pub direction: Direction,
    /// Text, binary or a control frame.
    pub kind: Kind,
    /// Payload bytes of the whole message (all fragments).
    pub size: u64,
    /// Whether `data` holds less than `size` (the per-message limit).
    pub truncated: bool,
    /// How `data` is written.
    pub encoding: Encoding,
    /// The kept payload, unmasked.
    pub data: String,
    /// Close frames: the status code, when the payload has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_code: Option<u16>,
    /// Close frames: the reason text after the code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_reason: Option<String>,
    /// The message was compressed on the wire (RSV1 with `permessage-deflate`, or an RSV
    /// bit with another extension).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub compressed: bool,
    /// Compressed messages: the payload bytes on the wire, all fragments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_size: Option<u64>,
    /// Compressed messages that could not be inflated (invalid data, a bomb, an unknown
    /// extension): `data` and `size` are the raw wire payload, in base64.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub decode_failed: bool,
    /// The control plane sent this message into the connection (`POST .../messages`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub injected: bool,
}

impl WsMessage {
    /// The kept payload bytes, decoded from `data`.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        match self.encoding {
            Encoding::Utf8 => self.data.as_bytes().to_vec(),
            Encoding::Base64 => base64::engine::general_purpose::STANDARD
                .decode(&self.data)
                .unwrap_or_default(),
        }
    }
}

/// One short console line for `--ws-log`.
#[must_use]
pub fn log_line(message: &WsMessage) -> String {
    use std::fmt::Write as _;
    let arrow = match message.direction {
        Direction::ClientToServer => "->",
        Direction::ServerToClient => "<-",
    };
    let kind = serde_json::to_value(message.kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    let mut line = format!("ws #{} {arrow} {kind} {} B", message.flow_id, message.size);
    if let Some(code) = message.close_code {
        let _ = write!(line, " code {code}");
    }
    if message.truncated {
        line.push_str(" (truncated)");
    }
    line
}

/// Why the parser stopped reading a direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    /// RSV bits set although no extension was negotiated.
    ReservedBits,
    /// Opcode 3-7 or 11-15.
    UnknownOpcode(u8),
    /// A control frame without FIN.
    FragmentedControl,
    /// A control frame longer than 125 bytes.
    ControlTooLong,
    /// A 64-bit length with the most significant bit set.
    LengthTopBit,
    /// A client frame without a mask or a server frame with one.
    MaskMismatch,
    /// A continuation frame with no message in progress.
    UnexpectedContinuation,
    /// A new text or binary frame while a fragmented message is in progress.
    InterleavedDataFrame,
    /// More than [`MAX_FRAGMENTS`] frames in one message.
    TooManyFragments,
}

/// What the server's `101` agreed to, which decides how RSV bits and payloads are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Extensions {
    /// None negotiated: RSV bits are a protocol violation.
    None,
    /// `permessage-deflate` (RFC 7692): RSV1 on a message's first frame marks it
    /// compressed, and the record holds the inflated payload. RSV2 and RSV3 are violations.
    Deflate(DeflateParams),
    /// Another extension, or a `permessage-deflate` answer this parser does not understand:
    /// RSV bits are allowed and such messages are recorded raw with `decode_failed`.
    Other,
}

/// The `permessage-deflate` parameters of the server's answer (RFC 7692 section 7.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeflateParams {
    /// The client resets its compression window after each message.
    pub client_no_context_takeover: bool,
    /// The server resets its compression window after each message.
    pub server_no_context_takeover: bool,
    /// The client's LZ77 window, 8 to 15 bits, when limited.
    pub client_max_window_bits: Option<u8>,
    /// The server's LZ77 window, 8 to 15 bits, when limited.
    pub server_max_window_bits: Option<u8>,
}

impl DeflateParams {
    /// Whether the sender of `direction` keeps its window from one message to the next.
    #[must_use]
    pub fn context_takeover(&self, direction: Direction) -> bool {
        match direction {
            Direction::ClientToServer => !self.client_no_context_takeover,
            Direction::ServerToClient => !self.server_no_context_takeover,
        }
    }

    /// Parses one `permessage-deflate` element of a `Sec-WebSocket-Extensions` answer
    /// (`permessage-deflate; server_no_context_takeover; client_max_window_bits=10`).
    /// `None` for another extension, an unknown or repeated parameter, or a bad value.
    #[must_use]
    pub fn parse(element: &str) -> Option<Self> {
        let mut parts = element.split(';').map(str::trim);
        if !parts.next()?.eq_ignore_ascii_case("permessage-deflate") {
            return None;
        }
        let mut params = Self::default();
        let mut seen = Vec::new();
        for part in parts.filter(|p| !p.is_empty()) {
            let (name, value) = match part.split_once('=') {
                Some((name, value)) => (name.trim(), Some(value.trim().trim_matches('"'))),
                None => (part, None),
            };
            let name = name.to_ascii_lowercase();
            if seen.contains(&name) {
                return None;
            }
            match (name.as_str(), value) {
                ("client_no_context_takeover", None) => params.client_no_context_takeover = true,
                ("server_no_context_takeover", None) => params.server_no_context_takeover = true,
                ("client_max_window_bits", None) => {}
                ("client_max_window_bits", Some(v)) => {
                    params.client_max_window_bits = Some(window_bits(v)?);
                }
                ("server_max_window_bits", Some(v)) => {
                    params.server_max_window_bits = Some(window_bits(v)?);
                }
                _ => return None,
            }
            seen.push(name);
        }
        Some(params)
    }
}

/// A window size parameter: 8 to 15, digits only.
fn window_bits(value: &str) -> Option<u8> {
    let bits: u8 = value
        .bytes()
        .all(|b| b.is_ascii_digit())
        .then(|| value.parse().ok())??;
    (8..=15).contains(&bits).then_some(bits)
}

/// A parsed frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Last frame of its message.
    pub fin: bool,
    /// RSV1-3 as the low three bits.
    pub rsv: u8,
    /// The opcode, 0 for continuation.
    pub opcode: u8,
    /// The masking key, when the mask bit is set.
    pub mask: Option<[u8; 4]>,
    /// Payload length.
    pub len: u64,
    /// Header bytes: 2 to 14.
    pub header_len: usize,
}

/// Parses the frame header at the start of `buf`.
///
/// Returns `Ok(None)` when `buf` is too short to hold the whole header.
///
/// # Errors
///
/// A [`Violation`] for reserved bits, unknown opcodes, bad control frames, a length with
/// its top bit set, or a mask bit that does not match `direction`.
pub fn parse_header(
    buf: &[u8],
    direction: Direction,
    extensions: Extensions,
) -> Result<Option<FrameHeader>, Violation> {
    let [b0, b1, rest @ ..] = buf else {
        return Ok(None);
    };
    let fin = b0 & 0x80 != 0;
    let rsv = (b0 >> 4) & 0x07;
    let opcode = b0 & 0x0F;
    let allowed = match extensions {
        Extensions::None => 0,
        Extensions::Deflate(_) => 0b100,
        Extensions::Other => 0b111,
    };
    if rsv & !allowed != 0 {
        return Err(Violation::ReservedBits);
    }
    if opcode != 0 && Kind::from_opcode(opcode).is_none() {
        return Err(Violation::UnknownOpcode(opcode));
    }
    let control = opcode >= 8;
    let len7 = u64::from(b1 & 0x7F);
    if control && !fin {
        return Err(Violation::FragmentedControl);
    }
    if control && len7 > MAX_CONTROL {
        return Err(Violation::ControlTooLong);
    }
    let masked = b1 & 0x80 != 0;
    if masked != (direction == Direction::ClientToServer) {
        return Err(Violation::MaskMismatch);
    }
    let ext = match len7 {
        126 => 2,
        127 => 8,
        _ => 0,
    };
    let mask_len = if masked { 4 } else { 0 };
    if rest.len() < ext + mask_len {
        return Ok(None);
    }
    let len = match ext {
        2 => u64::from(u16::from_be_bytes([rest[0], rest[1]])),
        8 => {
            let mut be = [0_u8; 8];
            be.copy_from_slice(&rest[..8]);
            let len = u64::from_be_bytes(be);
            if len >> 63 != 0 {
                return Err(Violation::LengthTopBit);
            }
            len
        }
        _ => len7,
    };
    let mask = masked.then(|| {
        let mut key = [0_u8; 4];
        key.copy_from_slice(&rest[ext..ext + 4]);
        key
    });
    Ok(Some(FrameHeader {
        fin,
        rsv,
        opcode,
        mask,
        len,
        header_len: 2 + ext + mask_len,
    }))
}

/// A complete message the parser produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// What it is.
    pub kind: Kind,
    /// The kept, unmasked payload (at most the body limit).
    pub kept: Vec<u8>,
    /// Payload bytes of the whole message (decoded bytes when it was inflated).
    pub size: u64,
    /// Set when the message was compressed on the wire.
    pub compression: Option<Compression>,
}

/// How a compressed message was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Compression {
    /// Payload bytes on the wire, all fragments.
    pub wire_size: u64,
    /// `true`: `kept` and `size` are the inflated payload; `false`: they are the wire bytes.
    pub decoded: bool,
}

#[derive(Debug)]
struct Frame {
    header: FrameHeader,
    remaining: u64,
    /// Payload bytes of this frame seen so far, for the mask position.
    offset: u64,
}

#[derive(Debug)]
struct Partial {
    kind: Kind,
    kept: Vec<u8>,
    size: u64,
    fragments: usize,
    /// RSV bits of the first frame.
    rsv: u8,
    /// The inflated payload, for a `permessage-deflate` message with RSV1.
    inflated: Option<Inflated>,
}

impl Partial {
    fn new(kind: Kind, rsv: u8, inflated: Option<Inflated>) -> Self {
        Self {
            kind,
            kept: Vec::new(),
            size: 0,
            fragments: 1,
            rsv,
            inflated,
        }
    }
}

/// The inflated side of one compressed message.
#[derive(Debug, Default)]
struct Inflated {
    kept: Vec<u8>,
    size: u64,
    failed: bool,
}

/// Raw-deflate state of one direction (RFC 7692 section 7.2.2). With context takeover the
/// window carries over between messages; without it the state resets after each message.
struct Inflater {
    state: flate2::Decompress,
    takeover: bool,
    /// Data was lost with context takeover: later messages cannot be inflated either.
    broken: bool,
}

impl std::fmt::Debug for Inflater {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inflater")
            .field("takeover", &self.takeover)
            .field("broken", &self.broken)
            .finish_non_exhaustive()
    }
}

impl Inflater {
    fn new(takeover: bool) -> Self {
        Self {
            // Raw deflate; a 32 KiB window also reads streams made with a smaller one.
            state: flate2::Decompress::new(false),
            takeover,
            broken: false,
        }
    }

    /// Inflates the next `input` of a message whose wire payload is `wire` bytes so far.
    fn feed(&mut self, input: &[u8], wire: u64, limit: usize, out: &mut Inflated) {
        self.run(input, wire, limit, out, flate2::FlushDecompress::None);
    }

    /// Ends a message: appends the RFC 7692 tail and resets without context takeover.
    fn finish(&mut self, wire: u64, limit: usize, out: &mut Inflated) {
        self.run(
            &DEFLATE_TAIL,
            wire,
            limit,
            out,
            flate2::FlushDecompress::Sync,
        );
        if !self.takeover {
            self.state.reset(false);
        }
    }

    fn run(
        &mut self,
        mut input: &[u8],
        wire: u64,
        limit: usize,
        out: &mut Inflated,
        flush: flate2::FlushDecompress,
    ) {
        if out.failed {
            return;
        }
        if self.broken {
            out.failed = true;
            return;
        }
        let budget = wire
            .saturating_mul(MAX_INFLATE_RATIO)
            .max(MIN_INFLATE_BUDGET);
        let mut scratch = [0_u8; 8192];
        loop {
            let (in_before, out_before) = (self.state.total_in(), self.state.total_out());
            let status = self.state.decompress(input, &mut scratch, flush);
            let consumed = usize::try_from(self.state.total_in() - in_before).unwrap_or(0);
            let produced = usize::try_from(self.state.total_out() - out_before).unwrap_or(0);
            input = input.get(consumed..).unwrap_or_default();
            let room = limit.saturating_sub(out.kept.len()).min(produced);
            out.kept.extend_from_slice(&scratch[..room]);
            out.size = out.size.saturating_add(produced as u64);
            match status {
                Err(_) => return self.fail(out),
                _ if out.size > budget => return self.fail(out),
                // A final block ends the stream; the next message starts a new one.
                Ok(flate2::Status::StreamEnd) => self.state.reset(false),
                Ok(_) => {}
            }
            let drained = produced < scratch.len();
            if (input.is_empty() && drained) || (consumed == 0 && produced == 0) {
                return;
            }
        }
    }

    fn fail(&mut self, out: &mut Inflated) {
        out.failed = true;
        self.state.reset(false);
        self.broken = self.takeover;
    }
}

/// Incremental frame parser for one direction of a connection. Bounded: it holds at most
/// one partial header, one message's kept bytes (wire and inflated) and one control payload.
#[derive(Debug)]
pub struct FrameParser {
    direction: Direction,
    extensions: Extensions,
    body_limit: usize,
    header: [u8; MAX_HEADER],
    have: usize,
    frame: Option<Frame>,
    message: Option<Partial>,
    control: Option<Partial>,
    inflater: Option<Inflater>,
    failed: Option<Violation>,
}

impl FrameParser {
    /// A parser for `direction` that keeps at most `body_limit` bytes per message.
    #[must_use]
    pub fn new(direction: Direction, extensions: Extensions, body_limit: usize) -> Self {
        let inflater = match extensions {
            Extensions::Deflate(params) => Some(Inflater::new(params.context_takeover(direction))),
            Extensions::None | Extensions::Other => None,
        };
        Self {
            direction,
            extensions,
            body_limit,
            header: [0; MAX_HEADER],
            have: 0,
            frame: None,
            message: None,
            control: None,
            inflater,
            failed: None,
        }
    }

    /// The violation that stopped parsing, if one did.
    #[must_use]
    pub fn failed(&self) -> Option<Violation> {
        self.failed
    }

    /// Bytes held in buffers right now.
    #[must_use]
    pub fn buffered(&self) -> usize {
        let inflated = |m: &Partial| m.inflated.as_ref().map_or(0, |i| i.kept.capacity());
        self.have
            + self
                .message
                .as_ref()
                .map_or(0, |m| m.kept.capacity() + inflated(m))
            + self.control.as_ref().map_or(0, |m| m.kept.capacity())
    }

    /// Whether the stream is between messages: no partial header, frame or fragmented
    /// message, and no violation. Only then can a frame be inserted.
    #[must_use]
    pub fn between_messages(&self) -> bool {
        self.failed.is_none() && self.have == 0 && self.frame.is_none() && self.message.is_none()
    }

    /// Feeds the next bytes of the stream; complete messages go to `out`. After a
    /// violation it ignores everything.
    pub fn feed(&mut self, mut bytes: &[u8], out: &mut Vec<Parsed>) {
        while self.failed.is_none() {
            if self.frame.is_none() {
                if bytes.is_empty() {
                    return;
                }
                let take = (MAX_HEADER - self.have).min(bytes.len());
                self.header[self.have..self.have + take].copy_from_slice(&bytes[..take]);
                match parse_header(
                    &self.header[..self.have + take],
                    self.direction,
                    self.extensions,
                ) {
                    Err(violation) => self.fail(violation),
                    Ok(None) => {
                        self.have += take;
                        return;
                    }
                    Ok(Some(header)) => {
                        bytes = &bytes[header.header_len - self.have..];
                        self.have = 0;
                        if let Err(violation) = self.start(header) {
                            self.fail(violation);
                        }
                    }
                }
                continue;
            }
            self.payload(&mut bytes);
            if self.frame.as_ref().is_some_and(|f| f.remaining == 0) {
                self.end_frame(out);
            } else {
                return;
            }
        }
    }

    fn fail(&mut self, violation: Violation) {
        self.failed = Some(violation);
        self.frame = None;
        self.message = None;
        self.control = None;
    }

    fn start(&mut self, header: FrameHeader) -> Result<(), Violation> {
        match Kind::from_opcode(header.opcode) {
            None => {
                let message = self
                    .message
                    .as_mut()
                    .ok_or(Violation::UnexpectedContinuation)?;
                message.fragments += 1;
                if message.fragments > MAX_FRAGMENTS {
                    return Err(Violation::TooManyFragments);
                }
            }
            Some(kind) if kind.is_control() => {
                self.control = Some(Partial::new(kind, 0, None));
            }
            Some(kind) => {
                if self.message.is_some() {
                    return Err(Violation::InterleavedDataFrame);
                }
                // RSV1 counts on the first frame only (RFC 7692 section 6.1).
                let inflated =
                    (self.inflater.is_some() && header.rsv & 0b100 != 0).then(Inflated::default);
                self.message = Some(Partial::new(kind, header.rsv, inflated));
            }
        }
        self.frame = Some(Frame {
            header,
            remaining: header.len,
            offset: 0,
        });
        Ok(())
    }

    fn payload(&mut self, bytes: &mut &[u8]) {
        let Some(frame) = self.frame.as_mut() else {
            return;
        };
        let n = usize::try_from(frame.remaining)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        let (chunk, rest) = bytes.split_at(n);
        *bytes = rest;
        let control = frame.header.opcode >= 8;
        let partial = if control {
            self.control.as_mut()
        } else {
            self.message.as_mut()
        };
        if let Some(partial) = partial {
            let limit = if control { usize::MAX } else { self.body_limit };
            let room = limit.saturating_sub(partial.kept.len()).min(chunk.len());
            // An inflated message needs every byte; otherwise only the kept ones.
            let need = if partial.inflated.is_some() { n } else { room };
            let plain = unmask(&chunk[..need], frame.header.mask, frame.offset);
            partial.kept.extend_from_slice(&plain[..room]);
            partial.size = partial.size.saturating_add(n as u64);
            if let (Some(inflated), Some(inflater)) =
                (partial.inflated.as_mut(), self.inflater.as_mut())
            {
                inflater.feed(&plain, partial.size, self.body_limit, inflated);
            }
        }
        frame.remaining -= n as u64;
        frame.offset = frame.offset.wrapping_add(n as u64);
    }

    fn end_frame(&mut self, out: &mut Vec<Parsed>) {
        let Some(frame) = self.frame.take() else {
            return;
        };
        let done = if frame.header.opcode >= 8 {
            self.control.take()
        } else if frame.header.fin {
            self.message.take()
        } else {
            None
        };
        if let Some(partial) = done {
            out.push(self.complete(partial));
        }
    }

    /// The record of a finished message: inflated when it was compressed and inflates.
    fn complete(&mut self, partial: Partial) -> Parsed {
        let Partial {
            kind,
            kept,
            size,
            rsv,
            inflated,
            ..
        } = partial;
        if rsv == 0 || kind.is_control() {
            return Parsed {
                kind,
                kept,
                size,
                compression: None,
            };
        }
        if let (Some(mut inflated), Some(inflater)) = (inflated, self.inflater.as_mut()) {
            inflater.finish(size, self.body_limit, &mut inflated);
            if !inflated.failed {
                return Parsed {
                    kind,
                    kept: inflated.kept,
                    size: inflated.size,
                    compression: Some(Compression {
                        wire_size: size,
                        decoded: true,
                    }),
                };
            }
        }
        Parsed {
            kind,
            kept,
            size,
            compression: Some(Compression {
                wire_size: size,
                decoded: false,
            }),
        }
    }
}

/// `chunk` unmasked with `mask`, whose position starts at `offset` into the frame payload.
fn unmask(chunk: &[u8], mask: Option<[u8; 4]>, offset: u64) -> std::borrow::Cow<'_, [u8]> {
    match mask {
        None => std::borrow::Cow::Borrowed(chunk),
        Some(key) => chunk
            .iter()
            .enumerate()
            .map(|(i, byte)| {
                let pos = offset.wrapping_add(i as u64);
                byte ^ key[usize::try_from(pos % 4).unwrap_or(0)]
            })
            .collect(),
    }
}

/// The close code and reason in a close frame's payload.
#[must_use]
pub fn close_payload(payload: &[u8]) -> (Option<u16>, Option<String>) {
    match payload {
        [hi, lo, reason @ ..] => (
            Some(u16::from_be_bytes([*hi, *lo])),
            (!reason.is_empty()).then(|| String::from_utf8_lossy(reason).into_owned()),
        ),
        _ => (None, None),
    }
}

/// Builds the record of `parsed`.
#[must_use]
pub fn message(flow_id: u64, seq: u64, direction: Direction, parsed: &Parsed) -> WsMessage {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let truncated = parsed.size > parsed.kept.len() as u64;
    let (close_code, close_reason) = if parsed.kind == Kind::Close {
        close_payload(&parsed.kept)
    } else {
        (None, None)
    };
    let decode_failed = parsed.compression.is_some_and(|c| !c.decoded);
    let text = (parsed.kind != Kind::Binary && !decode_failed)
        .then(|| match std::str::from_utf8(&parsed.kept) {
            Ok(text) => Some(text),
            // A UTF-8 sequence cut by the limit is still text: keep the valid prefix.
            Err(e) if e.error_len().is_none() && truncated => {
                std::str::from_utf8(&parsed.kept[..e.valid_up_to()]).ok()
            }
            Err(_) => None,
        })
        .flatten();
    let (encoding, data) = match text {
        Some(text) => (Encoding::Utf8, text.to_owned()),
        None => (
            Encoding::Base64,
            base64::engine::general_purpose::STANDARD.encode(&parsed.kept),
        ),
    };
    WsMessage {
        flow_id,
        seq,
        time: Utc::now().rfc3339(),
        timestamp: since.as_secs_f64(),
        direction,
        kind: parsed.kind,
        size: parsed.size,
        truncated,
        encoding,
        data,
        close_code,
        close_reason,
        compressed: parsed.compression.is_some(),
        wire_size: parsed.compression.map(|c| c.wire_size),
        decode_failed,
        injected: false,
    }
}

/// Whether `headers` ask for a WebSocket upgrade (`Upgrade: websocket`).
#[must_use]
pub fn is_websocket(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::UPGRADE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("websocket"))
}

/// Removes `Sec-WebSocket-Extensions` from a client's upgrade request, so the server cannot
/// negotiate `permessage-deflate` or any other extension (`--ws-strip-compression`).
/// Returns whether an offer was removed.
pub fn strip_extensions(headers: &mut HeaderMap) -> bool {
    let offered = headers
        .get_all(header::SEC_WEBSOCKET_EXTENSIONS)
        .iter()
        .any(|v| !v.as_bytes().trim_ascii().is_empty());
    headers.remove(header::SEC_WEBSOCKET_EXTENSIONS);
    offered
}

/// What the server's `101` answer agreed to: nothing, `permessage-deflate` alone (with its
/// parameters), or anything else.
#[must_use]
pub fn negotiated(headers: &HeaderMap) -> Extensions {
    let values: Vec<&str> = headers
        .get_all(header::SEC_WEBSOCKET_EXTENSIONS)
        .iter()
        .map(|v| v.to_str().unwrap_or("?"))
        .collect();
    let elements: Vec<&str> = values
        .iter()
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .collect();
    match elements.as_slice() {
        [] if values.is_empty() => Extensions::None,
        [one] => DeflateParams::parse(one).map_or(Extensions::Other, Extensions::Deflate),
        _ => Extensions::Other,
    }
}

/// Most payload bytes one injected message may carry.
pub const MAX_INJECT: usize = 64 * 1024;

/// Injected messages one connection accepts per second.
pub const INJECT_PER_SECOND: u32 = 20;

/// Injected messages one direction queues while a fragmented message is in flight.
const INJECT_QUEUE: usize = 16;

/// A message the control plane sends into a live connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Injection {
    /// Text or binary.
    pub kind: Kind,
    /// The payload, unmasked.
    pub payload: Vec<u8>,
}

/// Why [`Live::inject`] refused a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectError {
    /// The connection is closed (or never was a captured WebSocket).
    Closed,
    /// More than [`MAX_INJECT`] bytes, or not text or binary.
    Invalid,
    /// More than [`INJECT_PER_SECOND`] messages this second, or the queue is full.
    RateLimited,
}

impl std::fmt::Display for InjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Closed => "the connection is closed",
            Self::Invalid => "only text or binary messages up to 64 KiB can be sent",
            Self::RateLimited => "too many messages: wait a moment and send again",
        })
    }
}

impl std::error::Error for InjectError {}

#[derive(Debug)]
struct LiveConn {
    up: tokio::sync::mpsc::Sender<Injection>,
    down: tokio::sync::mpsc::Sender<Injection>,
    window: (std::time::Instant, u32),
}

/// The open WebSocket connections that accept injected messages, by flow id.
#[derive(Debug, Clone, Default)]
pub struct Live {
    inner: Arc<Mutex<HashMap<u64, LiveConn>>>,
}

/// Unregisters a connection from [`Live`] when the pump ends.
#[derive(Debug)]
struct LiveGuard {
    live: Live,
    flow_id: u64,
}

impl Drop for LiveGuard {
    fn drop(&mut self) {
        self.live.lock().remove(&self.flow_id);
    }
}

type Inbox = tokio::sync::mpsc::Receiver<Injection>;

impl Live {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, LiveConn>> {
        self.inner.lock().expect("ws live lock poisoned")
    }

    fn register(&self, flow_id: u64) -> (LiveGuard, Inbox, Inbox) {
        let (up, up_inbox) = tokio::sync::mpsc::channel(INJECT_QUEUE);
        let (down, down_inbox) = tokio::sync::mpsc::channel(INJECT_QUEUE);
        let conn = LiveConn {
            up,
            down,
            window: (std::time::Instant::now(), 0),
        };
        self.lock().insert(flow_id, conn);
        let guard = LiveGuard {
            live: self.clone(),
            flow_id,
        };
        (guard, up_inbox, down_inbox)
    }

    /// Whether flow `flow_id` is an open, captured WebSocket connection.
    #[must_use]
    pub fn is_open(&self, flow_id: u64) -> bool {
        self.lock().contains_key(&flow_id)
    }

    /// Queues `injection` toward `direction`'s receiver: [`Direction::ClientToServer`] sends
    /// it to the server (masked, as a client would), [`Direction::ServerToClient`] to the
    /// client. It is written between messages, never inside a fragmented one, and recorded
    /// with `injected: true` when written.
    ///
    /// # Errors
    ///
    /// [`InjectError`] when the connection is closed, the message too large or not text or
    /// binary, or the rate limit is reached.
    pub fn inject(
        &self,
        flow_id: u64,
        direction: Direction,
        injection: Injection,
    ) -> Result<(), InjectError> {
        if injection.payload.len() > MAX_INJECT || injection.kind.is_control() {
            return Err(InjectError::Invalid);
        }
        let mut live = self.lock();
        let conn = live.get_mut(&flow_id).ok_or(InjectError::Closed)?;
        let now = std::time::Instant::now();
        if now.duration_since(conn.window.0) >= std::time::Duration::from_secs(1) {
            conn.window = (now, 0);
        }
        if conn.window.1 >= INJECT_PER_SECOND {
            return Err(InjectError::RateLimited);
        }
        let sender = match direction {
            Direction::ClientToServer => &conn.up,
            Direction::ServerToClient => &conn.down,
        };
        sender.try_send(injection).map_err(|e| match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) => InjectError::RateLimited,
            tokio::sync::mpsc::error::TrySendError::Closed(_) => InjectError::Closed,
        })?;
        conn.window.1 += 1;
        Ok(())
    }
}

/// One unfragmented frame of `kind` with `payload`, masked with a random key when it goes
/// to the server (RFC 6455 section 5.3).
#[must_use]
pub fn encode_frame(direction: Direction, kind: Kind, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + MAX_HEADER);
    out.push(0x80 | kind.opcode());
    let mask_bit = if direction == Direction::ClientToServer {
        0x80
    } else {
        0
    };
    // 7-bit length, or 0x7E with 16 bits, or 0x7F with 64 bits (RFC 6455 section 5.2).
    let len = payload.len();
    if let Ok(short) = u8::try_from(len)
        && short < 0x7E
    {
        out.push(mask_bit | short);
    } else if let Ok(len16) = u16::try_from(len) {
        out.push(mask_bit | 0x7E);
        out.extend_from_slice(&len16.to_be_bytes());
    } else {
        out.push(mask_bit | 0x7F);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    if direction == Direction::ClientToServer {
        let key = mask_key();
        out.extend_from_slice(&key);
        out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
    } else {
        out.extend_from_slice(payload);
    }
    out
}

fn mask_key() -> [u8; 4] {
    let mut key = [0_u8; 4];
    if rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(&mut key)
        .is_err()
    {
        // Masking only stops cache poisoning by in-page scripts; any key is valid framing.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        key = nanos.to_le_bytes();
    }
    key
}

/// Numbers and publishes the messages of one connection, both directions in one order.
#[derive(Debug)]
struct Recorder {
    flow_id: u64,
    bus: Bus,
    next: Mutex<u64>,
}

impl Recorder {
    fn record(&self, direction: Direction, parsed: &Parsed, injected: bool) {
        // Numbering and publishing under one lock keeps the bus in `seq` order.
        let mut next = self.next.lock().expect("ws recorder lock poisoned");
        let mut message = message(self.flow_id, *next, direction, parsed);
        message.injected = injected;
        *next += 1;
        self.bus.publish(FlowEvent::WsMessage(Arc::new(message)));
    }
}

/// Joins the upgraded `client` and `server` streams of WebSocket flow `flow_id`, forwarding
/// bytes unchanged both ways and publishing each message as [`FlowEvent::WsMessage`].
/// While it runs, `live` accepts messages to inject into the connection. Returns when
/// either side closes or fails.
pub async fn pump<C, S>(
    (client, server): (C, S),
    flow_id: u64,
    bus: Bus,
    limits: WsLimits,
    extensions: Extensions,
    live: &Live,
) where
    C: AsyncRead + AsyncWrite,
    S: AsyncRead + AsyncWrite,
{
    let recorder = Recorder {
        flow_id,
        bus,
        next: Mutex::new(0),
    };
    let (_guard, up_inbox, down_inbox) = live.register(flow_id);
    let (client_read, client_write) = tokio::io::split(client);
    let (server_read, server_write) = tokio::io::split(server);
    let up = FrameParser::new(Direction::ClientToServer, extensions, limits.body_limit);
    let down = FrameParser::new(Direction::ServerToClient, extensions, limits.body_limit);
    let _ = tokio::try_join!(
        one_way(client_read, server_write, up, up_inbox, &recorder),
        one_way(server_read, client_write, down, down_inbox, &recorder),
    );
}

async fn one_way<R, W>(
    mut from: R,
    mut to: W,
    mut parser: FrameParser,
    mut inbox: Inbox,
    recorder: &Recorder,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0_u8; CHUNK];
    let mut out = Vec::new();
    let mut queued: VecDeque<Injection> = VecDeque::new();
    loop {
        tokio::select! {
            read = from.read(&mut buf) => {
                let n = read?;
                if n == 0 {
                    return to.shutdown().await;
                }
                // Forward first: parsing never delays the traffic.
                to.write_all(&buf[..n]).await?;
                parser.feed(&buf[..n], &mut out);
                for parsed in out.drain(..) {
                    recorder.record(parser.direction, &parsed, false);
                }
            }
            Some(injection) = inbox.recv(), if queued.len() < INJECT_QUEUE => {
                queued.push_back(injection);
            }
        }
        if parser.failed().is_some() {
            // The stream's framing is unknown: inserting a frame could corrupt it.
            queued.clear();
        } else if parser.between_messages() {
            while let Some(injection) = queued.pop_front() {
                write_injection(&mut to, parser.direction, injection, recorder).await?;
            }
        }
    }
}

async fn write_injection<W: AsyncWrite + Unpin>(
    to: &mut W,
    direction: Direction,
    injection: Injection,
    recorder: &Recorder,
) -> std::io::Result<()> {
    to.write_all(&encode_frame(direction, injection.kind, &injection.payload))
        .await?;
    to.flush().await?;
    let parsed = Parsed {
        kind: injection.kind,
        size: injection.payload.len() as u64,
        kept: injection.payload,
        compression: None,
    };
    recorder.record(direction, &parsed, true);
    Ok(())
}

/// The recorded messages of each WebSocket flow, at most [`WsLimits::max_messages`] per
/// flow. [`crate::events::FlowStore`] owns one and drops a flow's messages with the flow.
#[derive(Debug, Clone)]
pub struct WsStore {
    inner: Arc<Mutex<HashMap<u64, VecDeque<Arc<WsMessage>>>>>,
    max_messages: usize,
    live: Live,
}

impl WsStore {
    /// An empty store keeping `max_messages` per flow (at least one).
    #[must_use]
    pub fn new(max_messages: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max_messages: max_messages.max(1),
            live: Live::default(),
        }
    }

    /// The open connections of these flows, for injecting messages.
    #[must_use]
    pub fn live(&self) -> &Live {
        &self.live
    }

    /// Adds `message`, dropping its flow's oldest message when full.
    pub fn push(&self, message: Arc<WsMessage>) {
        let mut flows = self.lock();
        let ring = flows.entry(message.flow_id).or_default();
        if ring.len() >= self.max_messages {
            ring.pop_front();
        }
        ring.push_back(message);
    }

    /// Up to `limit` messages of `flow_id` with `seq` above `after`, oldest first.
    #[must_use]
    pub fn list(&self, flow_id: u64, after: Option<u64>, limit: usize) -> Vec<Arc<WsMessage>> {
        self.lock().get(&flow_id).map_or_else(Vec::new, |ring| {
            ring.iter()
                .filter(|m| after.is_none_or(|after| m.seq > after))
                .take(limit)
                .cloned()
                .collect()
        })
    }

    /// Whether any held message of `flow_id` satisfies `predicate`.
    #[must_use]
    pub fn any(&self, flow_id: u64, predicate: impl FnMut(&WsMessage) -> bool) -> bool {
        let mut predicate = predicate;
        self.lock()
            .get(&flow_id)
            .is_some_and(|ring| ring.iter().any(|m| predicate(m)))
    }

    /// Messages held for `flow_id`.
    #[must_use]
    pub fn len(&self, flow_id: u64) -> usize {
        self.lock().get(&flow_id).map_or(0, VecDeque::len)
    }

    /// Whether no message is held for any flow.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Forgets the messages of `flow_id`.
    pub fn remove(&self, flow_id: u64) {
        self.lock().remove(&flow_id);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, VecDeque<Arc<WsMessage>>>> {
        self.inner.lock().expect("ws store lock poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const C2S: Direction = Direction::ClientToServer;
    const S2C: Direction = Direction::ServerToClient;

    /// Builds one frame; `mask` masks the payload.
    fn frame(fin: bool, opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut out = vec![if fin { 0x80 } else { 0 } | opcode];
        let bit = if mask.is_some() { 0x80 } else { 0 };
        match payload.len() {
            n if n < 126 => out.push(bit | u8::try_from(n).expect("short")),
            n if n <= 0xFFFF => {
                out.push(bit | 0x7E);
                out.extend_from_slice(&u16::try_from(n).expect("16-bit").to_be_bytes());
            }
            n => {
                out.push(bit | 0x7F);
                out.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        match mask {
            Some(key) => {
                out.extend_from_slice(&key);
                out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
            }
            None => out.extend_from_slice(payload),
        }
        out
    }

    fn parse_all(direction: Direction, bytes: &[u8], limit: usize) -> (Vec<Parsed>, FrameParser) {
        let mut parser = FrameParser::new(direction, Extensions::None, limit);
        let mut out = Vec::new();
        // One byte at a time exercises every split point.
        for byte in bytes {
            parser.feed(std::slice::from_ref(byte), &mut out);
        }
        (out, parser)
    }

    #[test]
    fn header_table() {
        type Case<'a> = (
            &'a [u8],
            Direction,
            Result<Option<(u8, u64, usize)>, Violation>,
        );
        let key = [1, 2, 3, 4];
        let cases: &[Case<'_>] = &[
            (&[0x81, 0x05], S2C, Ok(Some((1, 5, 2)))),
            (&[0x82, 0x7E, 0x01, 0x00], S2C, Ok(Some((2, 256, 4)))),
            (
                &[0x82, 0x7F, 0, 0, 0, 0, 0, 1, 0, 0],
                S2C,
                Ok(Some((2, 65_536, 10))),
            ),
            (&[0x81, 0x85, 1, 2, 3, 4], C2S, Ok(Some((1, 5, 6)))),
            (&[0x81], S2C, Ok(None)),
            (&[0x82, 0x7E, 0x01], S2C, Ok(None)),
            (&[0x81, 0x85, 1, 2], C2S, Ok(None)),
            (&[0xC1, 0x00], S2C, Err(Violation::ReservedBits)),
            (&[0x91, 0x00], S2C, Err(Violation::ReservedBits)),
            (&[0x83, 0x00], S2C, Err(Violation::UnknownOpcode(3))),
            (&[0x8F, 0x00], S2C, Err(Violation::UnknownOpcode(15))),
            (&[0x09, 0x00], S2C, Err(Violation::FragmentedControl)),
            (&[0x89, 0x7E, 0, 200], S2C, Err(Violation::ControlTooLong)),
            (
                &[0x82, 0x7F, 0x80, 0, 0, 0, 0, 0, 0, 0],
                S2C,
                Err(Violation::LengthTopBit),
            ),
            (
                &[0x82, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                S2C,
                Err(Violation::LengthTopBit),
            ),
            (&[0x81, 0x05], C2S, Err(Violation::MaskMismatch)),
            (&[0x81, 0x85, 1, 2, 3, 4], S2C, Err(Violation::MaskMismatch)),
        ];
        for (bytes, direction, want) in cases {
            let got = parse_header(bytes, *direction, Extensions::None)
                .map(|h| h.map(|h| (h.opcode, h.len, h.header_len)));
            assert_eq!(&got, want, "header {bytes:02x?}");
        }
        let h = parse_header(&[0x81, 0x85, 1, 2, 3, 4], C2S, Extensions::None);
        assert_eq!(h.ok().flatten().and_then(|h| h.mask), Some(key));
        let rsv1 = parse_header(&[0xC1, 0x00], S2C, Extensions::Other);
        assert!(rsv1.is_ok_and(|h| h.is_some_and(|h| h.rsv == 4)));
    }

    #[test]
    fn unmasks_reassembles_and_reads_control_frames() {
        let key = [0x37, 0xfa, 0x21, 0x3d];
        let mut wire = frame(false, 1, b"Hel", Some(key));
        wire.extend(frame(true, 9, b"p", Some(key)));
        wire.extend(frame(false, 0, b"lo ", Some(key)));
        wire.extend(frame(true, 0, b"world", Some(key)));
        wire.extend(frame(true, 8, b"\x03\xe8bye", Some(key)));
        let (out, parser) = parse_all(C2S, &wire, 1024);
        assert_eq!(parser.failed(), None);
        let kinds: Vec<Kind> = out.iter().map(|p| p.kind).collect();
        assert_eq!(kinds, [Kind::Ping, Kind::Text, Kind::Close]);
        assert_eq!(out[1].kept, b"Hello world");
        assert_eq!(
            close_payload(&out[2].kept),
            (Some(1000), Some("bye".into()))
        );
    }

    #[test]
    fn keeps_only_the_limit_and_counts_the_rest() {
        let payload = vec![b'a'; 70_000];
        let (out, _) = parse_all(S2C, &frame(true, 2, &payload, None), 1000);
        assert_eq!((out[0].kept.len(), out[0].size), (1000, 70_000));
        let record = message(1, 0, S2C, &out[0]);
        assert!(record.truncated);
    }

    #[test]
    fn violations_stop_parsing() {
        let mut wire = frame(true, 1, b"ok", None);
        wire.extend(frame(true, 0, b"orphan", None));
        wire.extend(frame(true, 1, b"after", None));
        let (out, parser) = parse_all(S2C, &wire, 1024);
        assert_eq!(out.len(), 1);
        assert_eq!(parser.failed(), Some(Violation::UnexpectedContinuation));

        let mut wire = frame(false, 1, b"a", None);
        wire.extend(frame(true, 2, b"b", None));
        let (_, parser) = parse_all(S2C, &wire, 1024);
        assert_eq!(parser.failed(), Some(Violation::InterleavedDataFrame));
    }

    #[test]
    fn too_many_fragments_stop_parsing() {
        let mut parser = FrameParser::new(S2C, Extensions::None, 16);
        let mut out = Vec::new();
        parser.feed(&frame(false, 1, b"", None), &mut out);
        let empty = frame(false, 0, b"", None);
        for _ in 0..MAX_FRAGMENTS {
            parser.feed(&empty, &mut out);
        }
        assert_eq!(parser.failed(), Some(Violation::TooManyFragments));
        assert_eq!(out, Vec::<Parsed>::new());
    }

    #[test]
    fn random_bytes_never_panic_and_stay_bounded() {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..2000 {
            let direction = if round % 2 == 0 { C2S } else { S2C };
            let extensions = match round % 4 {
                0 => Extensions::Other,
                1 => Extensions::Deflate(DeflateParams::default()),
                _ => Extensions::None,
            };
            let mut parser = FrameParser::new(direction, extensions, 256);
            let mut out = Vec::new();
            let len = usize::try_from(next() % 4096).unwrap_or(0);
            let mut bytes: Vec<u8> = (0..len).map(|_| next().to_le_bytes()[0]).collect();
            if round % 8 == 1 {
                // A well-formed compressed frame header with a random payload.
                let mut frame = vec![0xC2, if direction == C2S { 0xFE } else { 0x7E }, 1, 0];
                if direction == C2S {
                    frame.extend_from_slice(&[0; 4]);
                }
                bytes.splice(0..0, frame);
            }
            for chunk in bytes.chunks(usize::try_from(next() % 64 + 1).unwrap_or(1)) {
                parser.feed(chunk, &mut out);
                // Wire and inflated copies, each at most twice the limit in capacity.
                assert!(
                    parser.buffered() <= 4 * 256 + 128 + MAX_HEADER,
                    "round {round}"
                );
            }
            for parsed in out {
                assert!(parsed.kept.len() <= 256, "round {round}");
                let _ = message(1, 0, direction, &parsed);
            }
        }
    }

    #[test]
    fn strips_extension_offers() {
        let mut headers = HeaderMap::new();
        headers.insert(header::UPGRADE, "WebSocket".parse().expect("value"));
        assert!(is_websocket(&headers));
        assert!(!strip_extensions(&mut headers));
        headers.insert(
            header::SEC_WEBSOCKET_EXTENSIONS,
            "permessage-deflate; client_max_window_bits"
                .parse()
                .expect("value"),
        );
        assert!(strip_extensions(&mut headers));
        assert!(!headers.contains_key(header::SEC_WEBSOCKET_EXTENSIONS));
    }

    /// Compresses `messages` as one `permessage-deflate` sender would, each with the tail
    /// removed; `takeover` keeps the window between messages.
    pub(crate) fn deflate_messages(messages: &[&[u8]], takeover: bool) -> Vec<Vec<u8>> {
        let mut state = flate2::Compress::new(flate2::Compression::default(), false);
        messages
            .iter()
            .map(|message| {
                if !takeover {
                    state.reset();
                }
                let mut out = Vec::with_capacity(message.len() + 64);
                state
                    .compress_vec(message, &mut out, flate2::FlushCompress::Sync)
                    .expect("compress");
                while out.len() == out.capacity() {
                    out.reserve(64);
                    state
                        .compress_vec(&[], &mut out, flate2::FlushCompress::Sync)
                        .expect("compress");
                }
                assert!(out.ends_with(&DEFLATE_TAIL), "sync flush tail");
                out.truncate(out.len() - DEFLATE_TAIL.len());
                out
            })
            .collect()
    }

    /// One compressed message split into `parts` frames, RSV1 on the first only.
    fn compressed_frames(payload: &[u8], parts: usize, mask: Option<[u8; 4]>) -> Vec<u8> {
        let size = payload.len().div_ceil(parts.max(1)).max(1);
        let chunks: Vec<&[u8]> = payload.chunks(size).collect();
        let mut wire = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            // Text on the first frame, continuation after.
            let opcode = u8::from(i == 0);
            let mut f = frame(i + 1 == chunks.len(), opcode, chunk, mask);
            if i == 0 {
                f[0] |= 0x40;
            }
            wire.extend(f);
        }
        wire
    }

    fn deflate(
        params: DeflateParams,
        direction: Direction,
        wire: &[u8],
        limit: usize,
    ) -> Vec<Parsed> {
        let mut parser = FrameParser::new(direction, Extensions::Deflate(params), limit);
        let mut out = Vec::new();
        for chunk in wire.chunks(7) {
            parser.feed(chunk, &mut out);
        }
        assert_eq!(parser.failed(), None);
        out
    }

    #[test]
    fn parses_deflate_answers() {
        let header = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::SEC_WEBSOCKET_EXTENSIONS,
                value.parse().expect("value"),
            );
            negotiated(&headers)
        };
        assert_eq!(negotiated(&HeaderMap::new()), Extensions::None);
        assert_eq!(
            header("permessage-deflate"),
            Extensions::Deflate(DeflateParams::default())
        );
        assert_eq!(
            header("permessage-deflate; server_no_context_takeover; client_max_window_bits=10"),
            Extensions::Deflate(DeflateParams {
                server_no_context_takeover: true,
                client_max_window_bits: Some(10),
                ..DeflateParams::default()
            })
        );
        assert_eq!(
            header("Permessage-Deflate; client_no_context_takeover; server_max_window_bits=\"15\""),
            Extensions::Deflate(DeflateParams {
                client_no_context_takeover: true,
                server_max_window_bits: Some(15),
                ..DeflateParams::default()
            })
        );
        for other in [
            "x-webkit-deflate-frame",
            "permessage-deflate; server_max_window_bits=7",
            "permessage-deflate; server_max_window_bits",
            "permessage-deflate; foo",
            "permessage-deflate; server_no_context_takeover; server_no_context_takeover",
            "permessage-deflate, x-other",
        ] {
            assert_eq!(header(other), Extensions::Other, "{other}");
        }
    }

    #[test]
    fn inflates_with_and_without_context_takeover() {
        let texts: [&[u8]; 3] = [
            b"hello hello hello",
            b"hello hello hello again",
            b"{\"a\":1}",
        ];
        for takeover in [true, false] {
            let params = DeflateParams {
                server_no_context_takeover: !takeover,
                client_no_context_takeover: !takeover,
                ..DeflateParams::default()
            };
            for (direction, mask) in [(S2C, None), (C2S, Some([9, 8, 7, 6]))] {
                let mut wire = Vec::new();
                for (i, payload) in deflate_messages(&texts, takeover).iter().enumerate() {
                    wire.extend(compressed_frames(payload, i + 1, mask));
                    // A control frame and an uncompressed message in between.
                    wire.extend(frame(true, 9, b"p", mask));
                    wire.extend(frame(true, 1, b"plain", mask));
                }
                let out = deflate(params, direction, &wire, 1024);
                let got: Vec<&[u8]> = out.iter().map(|p| p.kept.as_slice()).collect();
                let want: Vec<&[u8]> = texts
                    .iter()
                    .flat_map(|t| [*t, b"p".as_slice(), b"plain".as_slice()])
                    .collect();
                assert_eq!(got, want, "takeover {takeover} {direction:?}");
                let record = message(1, 0, direction, &out[3]);
                assert!(record.compressed && !record.decode_failed);
                assert_eq!(record.data, "hello hello hello again");
                assert!(record.wire_size.is_some_and(|w| w > 0));
                assert!(!message(1, 0, direction, &out[4]).compressed);
            }
        }
    }

    #[test]
    fn caps_decoded_output_and_survives_bad_data() {
        let big = vec![b'z'; 200_000];
        let payloads = deflate_messages(&[&big, b"after"], true);
        let mut wire = compressed_frames(&payloads[0], 3, None);
        wire.extend(compressed_frames(&payloads[1], 1, None));
        let out = deflate(DeflateParams::default(), S2C, &wire, 1000);
        assert_eq!((out[0].kept.len(), out[0].size), (1000, 200_000));
        assert!(message(1, 0, S2C, &out[0]).truncated);
        assert_eq!(out[1].kept, b"after");

        // Garbage: kept raw, flagged, and with takeover the next message fails too.
        let mut wire = compressed_frames(&[0xff; 40], 1, None);
        wire.extend(compressed_frames(
            &deflate_messages(&[b"x"], true)[0],
            1,
            None,
        ));
        let out = deflate(DeflateParams::default(), S2C, &wire, 1000);
        let record = message(1, 0, S2C, &out[0]);
        assert!(record.decode_failed && record.encoding == Encoding::Base64);
        assert_eq!(record.bytes(), [0xff; 40]);
        assert!(message(1, 1, S2C, &out[1]).decode_failed);

        // Without takeover the next message decodes again.
        let params = DeflateParams {
            server_no_context_takeover: true,
            ..DeflateParams::default()
        };
        let mut wire = compressed_frames(&[0xff; 40], 1, None);
        wire.extend(compressed_frames(
            &deflate_messages(&[b"x"], false)[0],
            1,
            None,
        ));
        let out = deflate(params, S2C, &wire, 1000);
        assert_eq!(out[1].kept, b"x");
    }

    #[test]
    fn stops_a_decompression_bomb() {
        // 32 MiB of zeros compresses to about 32 KiB, past the 1000:1 ratio.
        let zeros = vec![0_u8; 32 * 1024 * 1024];
        let payload = &deflate_messages(&[&zeros], true)[0];
        assert!((payload.len() as u64) * MAX_INFLATE_RATIO < zeros.len() as u64);
        let mut wire = frame(true, 2, payload, None);
        wire[0] |= 0x40;
        let out = deflate(DeflateParams::default(), S2C, &wire, 1 << 20);
        let record = message(1, 0, S2C, &out[0]);
        assert!(record.decode_failed);
        assert_eq!(record.size, payload.len() as u64);
    }

    #[tokio::test]
    async fn injected_frames_are_framed_per_direction_and_wait_for_fragments() {
        let (client_side, mut client) = tokio::io::duplex(1 << 16);
        let (server_side, mut server) = tokio::io::duplex(1 << 16);
        let bus = Bus::new();
        let mut events = bus.subscribe();
        let live = Live::default();
        let pump_live = live.clone();
        let pump = tokio::spawn(async move {
            let limits = WsLimits::default();
            pump(
                (client_side, server_side),
                7,
                bus,
                limits,
                Extensions::None,
                &pump_live,
            )
            .await;
        });
        while !live.is_open(7) {
            tokio::task::yield_now().await;
        }
        let key = [1, 2, 3, 4];
        let first = frame(false, 1, b"ab", Some(key));
        client.write_all(&first).await.expect("write");
        let mut got = vec![0; first.len()];
        server.read_exact(&mut got).await.expect("read");
        // A fragmented message is in flight: the injection waits for its end.
        let text = Injection {
            kind: Kind::Text,
            payload: b"INJ".to_vec(),
        };
        live.inject(7, C2S, text).expect("queued");
        let last = frame(true, 0, b"cd", Some(key));
        client.write_all(&last).await.expect("write");
        let mut got = vec![0; last.len()];
        server.read_exact(&mut got).await.expect("read");
        assert_eq!(got, last, "the fragment comes before the injected frame");
        let mut head = [0; 6];
        server.read_exact(&mut head).await.expect("read");
        let header = parse_header(&head, C2S, Extensions::None)
            .expect("valid")
            .expect("whole");
        assert_eq!((header.fin, header.opcode, header.len), (true, 1, 3));
        let mask = header.mask.expect("client frames are masked");
        let mut payload = [0; 3];
        server.read_exact(&mut payload).await.expect("read");
        let plain: Vec<u8> = payload
            .iter()
            .zip(mask.iter().cycle())
            .map(|(b, k)| b ^ k)
            .collect();
        assert_eq!(plain, b"INJ");

        let binary = Injection {
            kind: Kind::Binary,
            payload: vec![1, 2, 3],
        };
        live.inject(7, S2C, binary).expect("queued");
        let mut down = [0; 5];
        client.read_exact(&mut down).await.expect("read");
        assert_eq!(down, [0x82, 3, 1, 2, 3], "server frames are not masked");

        let mut injected = Vec::new();
        while injected.len() < 3 {
            if let Ok(FlowEvent::WsMessage(m)) = events.recv().await {
                injected.push((m.data.clone(), m.injected));
            }
        }
        assert_eq!(
            injected,
            [
                ("abcd".to_owned(), false),
                ("INJ".to_owned(), true),
                ("AQID".to_owned(), true)
            ]
        );
        assert_eq!(
            live.inject(
                7,
                S2C,
                Injection {
                    kind: Kind::Ping,
                    payload: Vec::new()
                }
            ),
            Err(InjectError::Invalid)
        );
        drop((client, server));
        pump.await.expect("pump ends");
        assert!(!live.is_open(7));
        let late = Injection {
            kind: Kind::Text,
            payload: b"x".to_vec(),
        };
        assert_eq!(live.inject(7, S2C, late), Err(InjectError::Closed));
    }

    #[test]
    fn encoded_frames_parse_back_at_every_length_form() {
        for (len, direction) in [
            (0, S2C),
            (125, C2S),
            (126, S2C),
            (65_535, C2S),
            (65_536, S2C),
        ] {
            let payload: Vec<u8> = (0..len).map(|i: usize| i.to_le_bytes()[0]).collect();
            let wire = encode_frame(direction, Kind::Binary, &payload);
            let (out, parser) = parse_all(direction, &wire, len + 1);
            assert_eq!(parser.failed(), None, "len {len}");
            assert_eq!(out[0].kept, payload, "len {len}");
        }
    }

    #[test]
    fn rsv2_is_a_violation_with_deflate() {
        let params = Extensions::Deflate(DeflateParams::default());
        assert_eq!(
            parse_header(&[0xA1, 0x00], S2C, params),
            Err(Violation::ReservedBits)
        );
        assert!(parse_header(&[0xC1, 0x00], S2C, params).is_ok());
    }

    #[test]
    fn the_store_keeps_the_newest_messages() {
        let store = WsStore::new(3);
        for seq in 0..5 {
            let parsed = Parsed {
                kind: Kind::Text,
                kept: b"x".to_vec(),
                size: 1,
                compression: None,
            };
            store.push(Arc::new(message(7, seq, S2C, &parsed)));
        }
        let seqs: Vec<u64> = store.list(7, None, 10).iter().map(|m| m.seq).collect();
        assert_eq!(seqs, [2, 3, 4]);
        let after: Vec<u64> = store.list(7, Some(2), 1).iter().map(|m| m.seq).collect();
        assert_eq!(after, [3]);
        store.remove(7);
        assert!(store.is_empty());
    }
}
