//! The search language shared by the API (`?q=`), the CLI (`--filter`) and the UI.
//!
//! ```text
//! query   := or
//! or      := and ( "OR" and )*
//! and     := unary ( ["AND"] unary )*          implicit AND between terms
//! unary   := "-" unary | primary
//! primary := "(" or ")" | field ":" value | word | "\"" text "\""
//! ```
//!
//! Fields: `host`, `path`, `method`, `status`, `type`, `header`, `body`, `size`, `time`,
//! `client`, `tls`, `flag`. A bare word or quoted text matches the URL (or the target and
//! SNI of tunnels and failed handshakes). Text comparisons are ASCII case-insensitive.
//! `docs/interchange.md` lists every field with examples.

use std::fmt;
use std::str::FromStr;

use base64::Engine as _;

use crate::events::{Flow, StoredFlow};
use crate::flow::{BodyRecord, ClientTls, Event, Flag};

/// Longest accepted query in bytes; longer ones are refused before parsing.
pub const MAX_QUERY_LEN: usize = 4096;

/// Deepest accepted nesting of parentheses and negations.
pub const MAX_DEPTH: usize = 32;

/// Bytes of each stored body that `body:` searches.
const BODY_SEARCH_LIMIT: usize = 1024 * 1024;

/// Field names, for error messages.
const FIELDS: &str =
    "host, path, method, status, type, header, body, size, time, client, tls, flag";

/// A parsed query, compiled to a predicate over stored flows. The empty query matches all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    root: Node,
}

/// Why a query did not parse: where, and what was expected there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseQueryError {
    /// Byte offset into the query, starting at 0.
    pub position: usize,
    /// What went wrong, naming the expected token.
    pub message: String,
}

impl fmt::Display for ParseQueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "query error at position {}: {}",
            self.position, self.message
        )
    }
}

impl std::error::Error for ParseQueryError {}

fn fail<T>(position: usize, message: impl Into<String>) -> Result<T, ParseQueryError> {
    Err(ParseQueryError {
        position,
        message: message.into(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    And(Vec<Node>),
    Or(Vec<Node>),
    Not(Box<Node>),
    Term(Term),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cmp {
    Eq,
    Lt,
    Le,
    Gt,
    Ge,
}

impl Cmp {
    fn holds<T: PartialOrd + Copy>(self, got: T, want: T) -> bool {
        match self {
            Self::Eq => got == want,
            Self::Lt => got < want,
            Self::Le => got <= want,
            Self::Gt => got > want,
            Self::Ge => got >= want,
        }
    }

    /// Splits a leading comparison operator off `text`; none means equality.
    fn split(text: &str) -> (Self, &str) {
        [
            (">=", Self::Ge),
            ("<=", Self::Le),
            (">", Self::Gt),
            ("<", Self::Lt),
            ("=", Self::Eq),
        ]
        .into_iter()
        .find_map(|(op, cmp)| text.strip_prefix(op).map(|rest| (cmp, rest)))
        .unwrap_or((Self::Eq, text))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TlsState {
    Failed,
    Intercepted,
    Plain,
    Version(String),
}

/// One condition; text values are stored ASCII-lowercased.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Term {
    Host(String),
    Path(String),
    Method(String),
    Status(Cmp, u16),
    StatusClass(u16),
    Type(String),
    Header(String, Option<String>),
    Body(String),
    Size(Cmp, u64),
    /// Total time in microseconds.
    Time(Cmp, u32),
    Client(String),
    Tls(TlsState),
    Flag(String),
    Text(String),
}

impl FromStr for Query {
    type Err = ParseQueryError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        Self::parse(src)
    }
}

impl Query {
    /// Parses `src`.
    ///
    /// # Errors
    ///
    /// Fails on a query longer than [`MAX_QUERY_LEN`], nested deeper than [`MAX_DEPTH`], or
    /// with a syntax error; the error names the byte position and the expected token.
    pub fn parse(src: &str) -> Result<Self, ParseQueryError> {
        if src.len() > MAX_QUERY_LEN {
            return fail(
                MAX_QUERY_LEN,
                format!(
                    "the query is {} bytes; the limit is {MAX_QUERY_LEN}",
                    src.len()
                ),
            );
        }
        let tokens = lex(src)?;
        let mut parser = Parser {
            tokens,
            at: 0,
            end: src.len(),
        };
        if parser.tokens.is_empty() {
            return Ok(Self {
                root: Node::And(Vec::new()),
            });
        }
        let root = parser.or(0)?;
        if let Some(token) = parser.peek() {
            return fail(
                token.pos,
                format!("expected a term or the end, found {}", token.kind),
            );
        }
        Ok(Self { root })
    }

    /// Whether a stored flow (pending or finished) matches.
    #[must_use]
    pub fn matches(&self, flow: &StoredFlow) -> bool {
        let facts = match flow {
            StoredFlow::Pending(s) => Facts {
                url: &s.url,
                method: &s.method,
                request_headers: &s.request_headers,
                tls: s.tls.as_ref(),
                ..Facts::default()
            },
            StoredFlow::Done(flow) => Facts::of(flow),
        };
        self.root.eval(&facts)
    }

    /// Whether a finished flow matches.
    #[must_use]
    pub fn matches_flow(&self, flow: &Flow) -> bool {
        self.root.eval(&Facts::of(flow))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    Open,
    Close,
    Not,
    Or,
    Term { key: Option<String>, value: String },
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => f.write_str("`(`"),
            Self::Close => f.write_str("`)`"),
            Self::Not => f.write_str("`-`"),
            Self::Or => f.write_str("`OR`"),
            Self::Term { key: Some(key), .. } => write!(f, "`{key}:`"),
            Self::Term { value, .. } => write!(f, "`{value}`"),
        }
    }
}

#[derive(Debug)]
struct Token {
    kind: Kind,
    pos: usize,
}

fn lex(src: &str) -> Result<Vec<Token>, ParseQueryError> {
    let bytes = src.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let pos = i;
        let kind = match bytes[i] {
            c if c.is_ascii_whitespace() => {
                i += 1;
                continue;
            }
            b'(' => {
                i += 1;
                Kind::Open
            }
            b')' => {
                i += 1;
                Kind::Close
            }
            b'-' => {
                if bytes
                    .get(i + 1)
                    .is_none_or(|c| c.is_ascii_whitespace() || *c == b')')
                {
                    return fail(i, "expected a term right after `-`");
                }
                i += 1;
                Kind::Not
            }
            b'"' => {
                let (value, end) = quoted(src, i)?;
                i = end;
                Kind::Term { key: None, value }
            }
            _ => {
                while i < bytes.len()
                    && !bytes[i].is_ascii_whitespace()
                    && !matches!(bytes[i], b'(' | b')' | b'"')
                {
                    i += 1;
                }
                let word = &src[pos..i];
                match word {
                    "OR" => Kind::Or,
                    "AND" => continue,
                    _ => match word.split_once(':') {
                        Some((key, rest)) if !key.is_empty() && !rest.starts_with("//") => {
                            let value = if rest.is_empty() && bytes.get(i) == Some(&b'"') {
                                let (value, end) = quoted(src, i)?;
                                i = end;
                                value
                            } else if rest.is_empty() {
                                return fail(i, format!("expected a value after `{key}:`"));
                            } else {
                                rest.to_owned()
                            };
                            Kind::Term {
                                key: Some(key.to_ascii_lowercase()),
                                value,
                            }
                        }
                        _ => Kind::Term {
                            key: None,
                            value: word.to_owned(),
                        },
                    },
                }
            }
        };
        tokens.push(Token { kind, pos });
    }
    Ok(tokens)
}

/// Reads a `"..."` string starting at `start`; `\"` and `\\` escape. Returns the text and
/// the offset after the closing quote.
fn quoted(src: &str, start: usize) -> Result<(String, usize), ParseQueryError> {
    let mut text = String::new();
    let mut chars = src[start + 1..].char_indices();
    while let Some((offset, c)) = chars.next() {
        match c {
            '"' => return Ok((text, start + 1 + offset + 1)),
            '\\' => match chars.next() {
                Some((_, escaped)) => text.push(escaped),
                None => break,
            },
            c => text.push(c),
        }
    }
    fail(start, "unterminated quote: expected a closing `\"`")
}

struct Parser {
    tokens: Vec<Token>,
    at: usize,
    end: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn here(&self) -> usize {
        self.peek().map_or(self.end, |t| t.pos)
    }

    fn found(&self) -> String {
        self.peek()
            .map_or_else(|| "the end".to_owned(), |t| t.kind.to_string())
    }

    fn or(&mut self, depth: usize) -> Result<Node, ParseQueryError> {
        let mut items = vec![self.and(depth)?];
        while self.peek().is_some_and(|t| t.kind == Kind::Or) {
            self.at += 1;
            items.push(self.and(depth)?);
        }
        Ok(if items.len() == 1 {
            items.remove(0)
        } else {
            Node::Or(items)
        })
    }

    fn and(&mut self, depth: usize) -> Result<Node, ParseQueryError> {
        let mut items = Vec::new();
        while self
            .peek()
            .is_some_and(|t| !matches!(t.kind, Kind::Close | Kind::Or))
        {
            items.push(self.unary(depth)?);
        }
        match items.len() {
            0 => fail(
                self.here(),
                format!("expected a term, found {}", self.found()),
            ),
            1 => Ok(items.remove(0)),
            _ => Ok(Node::And(items)),
        }
    }

    fn unary(&mut self, depth: usize) -> Result<Node, ParseQueryError> {
        let Some(token) = self.peek() else {
            return fail(self.end, "expected a term, found the end");
        };
        let pos = token.pos;
        if depth >= MAX_DEPTH {
            return fail(pos, format!("nested deeper than {MAX_DEPTH} levels"));
        }
        match &token.kind {
            Kind::Not => {
                self.at += 1;
                Ok(Node::Not(Box::new(self.unary(depth + 1)?)))
            }
            Kind::Open => {
                self.at += 1;
                let inner = self.or(depth + 1)?;
                if self.peek().is_some_and(|t| t.kind == Kind::Close) {
                    self.at += 1;
                    Ok(inner)
                } else {
                    fail(self.here(), format!("expected `)`, found {}", self.found()))
                }
            }
            Kind::Term { key, value } => {
                let term = term(key.as_deref(), value, pos)?;
                self.at += 1;
                Ok(Node::Term(term))
            }
            Kind::Close | Kind::Or => fail(pos, format!("expected a term, found {}", token.kind)),
        }
    }
}

fn term(key: Option<&str>, value: &str, pos: usize) -> Result<Term, ParseQueryError> {
    let lower = value.to_ascii_lowercase();
    let Some(key) = key else {
        return Ok(Term::Text(lower));
    };
    if value.is_empty() {
        return fail(pos, format!("expected a value after `{key}:`"));
    }
    Ok(match key {
        "host" => Term::Host(lower),
        "path" => Term::Path(value.to_owned()),
        "method" => Term::Method(value.to_ascii_uppercase()),
        "status" => status(&lower, pos)?,
        "type" => Term::Type(match lower.as_str() {
            "js" => "javascript".to_owned(),
            "img" | "image" => "image/".to_owned(),
            _ => lower,
        }),
        "header" => match lower.split_once('=') {
            Some(("", _)) => {
                return fail(pos, "expected a header name before `=`");
            }
            Some((name, value)) => Term::Header(name.to_owned(), Some(value.to_owned())),
            None => Term::Header(lower, None),
        },
        "body" => Term::Body(lower),
        "size" => {
            let (cmp, rest) = Cmp::split(&lower);
            let Some(bytes) = size(rest) else {
                return fail(pos, "expected a size such as >10k, <=2m or 512");
            };
            Term::Size(cmp, bytes)
        }
        "time" => {
            let (cmp, rest) = Cmp::split(&lower);
            let Some(micros) = duration(rest) else {
                return fail(pos, "expected a duration such as >500ms or <2s");
            };
            Term::Time(cmp, micros)
        }
        "client" => Term::Client(lower),
        "tls" => Term::Tls(match lower.as_str() {
            "failed" | "fail" => TlsState::Failed,
            "yes" | "ok" | "on" => TlsState::Intercepted,
            "no" | "none" | "plain" | "off" => TlsState::Plain,
            _ => TlsState::Version(lower.replace('.', "_")),
        }),
        "flag" => Term::Flag(lower),
        other => {
            return fail(
                pos,
                format!("unknown field `{other}`; expected one of {FIELDS}"),
            );
        }
    })
}

fn status(text: &str, pos: usize) -> Result<Term, ParseQueryError> {
    if let [digit @ b'1'..=b'5', b'x', b'x'] = text.as_bytes() {
        return Ok(Term::StatusClass(u16::from(digit - b'0')));
    }
    let (cmp, rest) = Cmp::split(text);
    match rest.parse::<u16>() {
        Ok(code) if (100..=999).contains(&code) => Ok(Term::Status(cmp, code)),
        _ => fail(pos, "expected a status such as 404, 5xx or >=400"),
    }
}

fn size(text: &str) -> Option<u64> {
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let multiplier = match unit {
        "" | "b" => 1,
        "k" | "kb" => 1024,
        "m" | "mb" => 1024 * 1024,
        "g" | "gb" => 1024 * 1024 * 1024,
        _ => return None,
    };
    number.parse::<u64>().ok()?.checked_mul(multiplier)
}

fn duration(text: &str) -> Option<u32> {
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let multiplier = match unit {
        "" | "ms" => 1000,
        "s" => 1_000_000,
        _ => return None,
    };
    number.parse::<u32>().ok()?.checked_mul(multiplier)
}

/// What a query can look at in one flow.
#[derive(Default)]
struct Facts<'f> {
    url: &'f str,
    method: &'f str,
    status: Option<u16>,
    request_headers: &'f [(String, String)],
    response_headers: &'f [(String, String)],
    request_body: Option<&'f BodyRecord>,
    response_body: Option<&'f BodyRecord>,
    total_ms: Option<f64>,
    tls: Option<&'f ClientTls>,
    tls_failed: bool,
    known_client: Option<&'f str>,
    flags: &'f [Flag],
    /// Tunnel target, or the target and SNI of a failed handshake.
    targets: [Option<&'f str>; 2],
}

impl<'f> Facts<'f> {
    fn of(flow: &'f Flow) -> Self {
        match &flow.record {
            Event::Exchange(x) => Facts {
                url: &x.url,
                method: &x.method,
                status: x.status,
                request_headers: &x.request_headers,
                response_headers: &x.response_headers,
                request_body: Some(&x.request_body),
                response_body: x.response_body.as_ref(),
                total_ms: Some(x.timing.total_ms),
                tls: x.tls.as_ref(),
                known_client: x.tls.as_ref().and_then(|t| t.client.as_deref()),
                flags: &x.flags,
                ..Facts::default()
            },
            Event::TlsFailure(t) => Facts {
                tls_failed: true,
                known_client: t.known_client.as_deref(),
                targets: [Some(&t.target), t.sni.as_deref()],
                ..Facts::default()
            },
            Event::Tunnel(t) => Facts {
                targets: [Some(&t.target), None],
                ..Facts::default()
            },
        }
    }

    fn host(&self) -> &'f str {
        if self.url.is_empty() {
            let target = self.targets[1].or(self.targets[0]).unwrap_or_default();
            return target.rsplit_once(':').map_or(target, |(host, _)| host);
        }
        let rest = self
            .url
            .split_once("://")
            .map_or(self.url, |(_, rest)| rest);
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let authority = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        match authority.strip_prefix('[') {
            Some(v6) => v6.split(']').next().unwrap_or_default(),
            None => authority.split(':').next().unwrap_or_default(),
        }
    }

    fn path(&self) -> &'f str {
        let rest = self
            .url
            .split_once("://")
            .map_or(self.url, |(_, rest)| rest);
        let path = rest.find('/').map_or("", |at| &rest[at..]);
        path.split(['?', '#']).next().unwrap_or_default()
    }

    fn headers(&self) -> impl Iterator<Item = &'f (String, String)> {
        self.request_headers.iter().chain(self.response_headers)
    }

    fn header<'n>(
        headers: &'f [(String, String)],
        name: &'n str,
    ) -> impl Iterator<Item = &'f str> + use<'f, 'n> {
        headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

impl Node {
    fn eval(&self, facts: &Facts<'_>) -> bool {
        match self {
            Self::And(items) => items.iter().all(|n| n.eval(facts)),
            Self::Or(items) => items.iter().any(|n| n.eval(facts)),
            Self::Not(inner) => !inner.eval(facts),
            Self::Term(term) => term.eval(facts),
        }
    }
}

impl Term {
    fn eval(&self, facts: &Facts<'_>) -> bool {
        match self {
            Self::Host(want) => contains(facts.host(), want),
            Self::Path(pattern) => {
                let path = facts.path();
                if pattern.contains('*') {
                    glob(pattern.as_bytes(), path.as_bytes())
                } else {
                    path.starts_with(pattern.as_str())
                }
            }
            Self::Method(want) => facts.method.eq_ignore_ascii_case(want),
            Self::Status(cmp, want) => facts.status.is_some_and(|got| cmp.holds(got, *want)),
            Self::StatusClass(class) => facts.status.is_some_and(|got| got / 100 == *class),
            Self::Type(want) => {
                Facts::header(facts.response_headers, "content-type").any(|v| contains(v, want))
            }
            Self::Header(name, value) => facts.headers().any(|(n, v)| {
                n.eq_ignore_ascii_case(name) && value.as_ref().is_none_or(|want| contains(v, want))
            }),
            Self::Body(want) => [facts.request_body, facts.response_body]
                .into_iter()
                .flatten()
                .any(|body| body_contains(body, want)),
            Self::Size(cmp, want) => facts
                .response_body
                .is_some_and(|body| cmp.holds(body.size, *want)),
            Self::Time(cmp, micros) => facts
                .total_ms
                .is_some_and(|ms| cmp.holds(ms * 1000.0, f64::from(*micros))),
            Self::Client(want) => {
                facts.known_client.is_some_and(|c| contains(c, want))
                    || Facts::header(facts.request_headers, "user-agent").any(|v| contains(v, want))
            }
            Self::Tls(state) => match state {
                TlsState::Failed => facts.tls_failed,
                TlsState::Intercepted => facts.tls.is_some(),
                TlsState::Plain => !facts.url.is_empty() && facts.tls.is_none(),
                TlsState::Version(want) => facts
                    .tls
                    .and_then(|t| t.version.as_deref())
                    .is_some_and(|v| contains(v, want)),
            },
            Self::Flag(want) => facts.flags.iter().any(|f| f.to_string() == *want),
            Self::Text(want) => {
                contains(facts.url, want)
                    || facts.targets.iter().flatten().any(|t| contains(t, want))
            }
        }
    }
}

/// Whether `hay` contains `needle` (already ASCII-lowercased), ignoring ASCII case.
fn contains(hay: &str, needle: &str) -> bool {
    contains_bytes(hay.as_bytes(), needle.as_bytes())
}

fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || hay
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

fn body_contains(body: &BodyRecord, needle: &str) -> bool {
    if body.encoding == "base64" {
        // Four base64 characters hold three bytes.
        let end = body.data.len().min(BODY_SEARCH_LIMIT / 3 * 4);
        let Some(chunk) = body.data.get(..end) else {
            return false;
        };
        base64::engine::general_purpose::STANDARD
            .decode(chunk)
            .is_ok_and(|bytes| contains_bytes(&bytes, needle.as_bytes()))
    } else {
        let data = body.data.as_bytes();
        contains_bytes(
            &data[..data.len().min(BODY_SEARCH_LIMIT)],
            needle.as_bytes(),
        )
    }
}

/// Whole-string glob where `*` matches any run of bytes.
fn glob(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p, t));
            p += 1;
        } else if p < pattern.len() && pattern[p] == text[t] {
            p += 1;
            t += 1;
        } else if let Some((sp, st)) = star {
            p = sp + 1;
            t = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Instant;

    use super::*;
    use crate::flow::{Exchange, Timing, TlsFailure};

    /// A finished exchange for tests.
    pub(crate) fn exchange(id: u64, method: &str, url: &str, status: u16) -> Exchange {
        Exchange {
            id,
            time: "2026-11-21T10:00:00.000Z".to_owned(),
            client: SocketAddr::from(([127, 0, 0, 1], 5000)),
            method: method.to_owned(),
            url: url.to_owned(),
            client_version: "h2".to_owned(),
            upstream_version: Some("h2".to_owned()),
            status: Some(status),
            reason: Some("OK".to_owned()),
            request_headers: vec![
                ("user-agent".to_owned(), "curl/8.9.1".to_owned()),
                ("authorization".to_owned(), "Bearer abc".to_owned()),
            ],
            response_headers: vec![(
                "content-type".to_owned(),
                "application/json; charset=utf-8".to_owned(),
            )],
            request_body: BodyRecord {
                size: 0,
                truncated: false,
                encoding: "utf8",
                data: String::new(),
                content_encoding: None,
            },
            response_body: Some(BodyRecord {
                size: 20_000,
                truncated: false,
                encoding: "utf8",
                data: "{\"greeting\": \"Hello World\"}".to_owned(),
                content_encoding: None,
            }),
            timing: Timing {
                connect_ms: Some(10.0),
                tls_ms: Some(20.0),
                first_byte_ms: Some(400.0),
                total_ms: 650.0,
            },
            tls: Some(ClientTls {
                version: Some("TLSv1_3".to_owned()),
                alpn: Some("h2".to_owned()),
                sni: Some("api.example.com".to_owned()),
                ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1".to_owned(),
                ja3_hash: "0123".to_owned(),
                client: Some("curl".to_owned()),
            }),
            error: None,
            flags: vec![Flag::PauseTimedOut],
            upstream_url: None,
            replay_of: None,
            ws_messages: None,
            response_trailers: Vec::new(),
        }
    }

    fn stored(x: Exchange) -> StoredFlow {
        StoredFlow::Done(Arc::new(Flow::new(Event::Exchange(Box::new(x)))))
    }

    fn sample() -> Vec<StoredFlow> {
        let a = exchange(1, "GET", "https://api.example.com/api/users?id=1", 200);
        let mut b = exchange(2, "POST", "http://other.test/login", 503);
        b.tls = None;
        b.flags.clear();
        b.request_headers = vec![("user-agent".to_owned(), "Mozilla/5.0".to_owned())];
        b.response_headers = vec![("content-type".to_owned(), "text/html".to_owned())];
        b.request_body.data = "user=bob&password=hunter2".to_owned();
        b.response_body = Some(BodyRecord {
            size: 100,
            truncated: false,
            encoding: "base64",
            data: base64::engine::general_purpose::STANDARD.encode(b"\xffbinary SECRET"),
            content_encoding: None,
        });
        b.timing.total_ms = 30.0;
        let c = StoredFlow::Done(Arc::new(Flow::new(Event::TlsFailure(TlsFailure {
            id: 3,
            time: String::new(),
            client: SocketAddr::from(([127, 0, 0, 1], 1)),
            target: "pinned.test:443".to_owned(),
            sni: Some("pinned.test".to_owned()),
            ja4: String::new(),
            known_client: None,
            reason: "bad certificate".to_owned(),
        }))));
        let mut d = exchange(4, "GET", "https://api.example.com/v2/items", 404);
        d.flags.clear();
        vec![stored(a), stored(b), c, stored(d)]
    }

    fn ids(query: &str) -> Vec<u64> {
        let query = Query::parse(query).unwrap_or_else(|e| panic!("{query:?}: {e}"));
        sample()
            .iter()
            .filter(|f| query.matches(f))
            .map(StoredFlow::id)
            .collect()
    }

    #[test]
    fn grammar_table() {
        let table: &[(&str, &[u64])] = &[
            ("", &[1, 2, 3, 4]),
            ("host:example.com", &[1, 4]),
            ("host:PINNED", &[3]),
            ("path:/api/*", &[1]),
            ("path:/api", &[1]),
            ("path:/*/items", &[4]),
            ("method:post", &[2]),
            ("status:404", &[4]),
            ("status:5xx", &[2]),
            ("status:>=400", &[2, 4]),
            ("status:<300", &[1]),
            ("type:json", &[1, 4]),
            ("type:html", &[2]),
            ("header:content-type=JSON", &[1, 4]),
            ("header:authorization", &[1, 4]),
            ("body:\"hello world\"", &[1, 4]),
            ("body:hunter2", &[2]),
            ("body:secret", &[2]),
            ("size:>10k", &[1, 4]),
            ("size:<=100", &[2]),
            ("time:>500ms", &[1, 4]),
            ("time:<1s", &[1, 2, 4]),
            ("client:curl", &[1, 4]),
            ("client:mozilla", &[2]),
            ("tls:failed", &[3]),
            ("tls:none", &[2]),
            ("tls:1.3", &[1, 4]),
            ("flag:pause_timed_out", &[1]),
            ("users", &[1]),
            ("\"other.test/login\"", &[2]),
            ("https://api", &[1, 4]),
            ("-host:example.com", &[2, 3]),
            ("method:GET status:404", &[4]),
            ("method:GET AND status:404", &[4]),
            ("status:404 OR status:503", &[2, 4]),
            ("method:GET status:404 OR method:POST", &[2, 4]),
            ("method:GET (status:404 OR status:200)", &[1, 4]),
            ("-(status:404 OR status:200)", &[2, 3]),
            ("--method:POST", &[2]),
            ("-tls:failed -method:get", &[2]),
        ];
        for (query, want) in table {
            assert_eq!(ids(query), *want, "query {query:?}");
        }
    }

    #[test]
    fn errors_name_the_position_and_the_expected_token() {
        let table: &[(&str, usize, &str)] = &[
            ("status:abc", 0, "expected a status"),
            ("method:GET (status:404", 22, "expected `)`, found the end"),
            ("method:GET )", 11, "expected a term or the end, found `)`"),
            ("a OR", 4, "expected a term, found the end"),
            ("OR a", 0, "expected a term, found `OR`"),
            ("()", 1, "expected a term, found `)`"),
            ("bogus:1", 0, "unknown field `bogus`"),
            ("body:\"open", 5, "unterminated quote"),
            ("host:", 5, "expected a value after `host:`"),
            ("size:>10q", 0, "expected a size"),
            ("time:>5h", 0, "expected a duration"),
            ("x -", 2, "expected a term right after `-`"),
            ("-(", 2, "expected a term, found the end"),
        ];
        for (query, position, message) in table {
            let error = Query::parse(query).expect_err(query);
            assert_eq!(error.position, *position, "{query:?}: {error}");
            assert!(error.message.contains(message), "{query:?}: {error}");
        }
    }

    #[test]
    fn big_and_deep_queries_are_refused_cheaply() {
        let huge = "a".repeat(1024 * 1024);
        let started = Instant::now();
        let error = Query::parse(&huge).expect_err("1 MB query");
        assert!(error.message.contains("limit"), "{error}");
        assert!(started.elapsed().as_millis() < 50);
        let deep = format!("{}a{}", "(".repeat(100), ")".repeat(100));
        assert!(
            Query::parse(&deep)
                .expect_err("deep")
                .message
                .contains("nested")
        );
        let negations = "-".repeat(100) + "a";
        assert!(Query::parse(&negations).is_err());
        let ok = format!("{}a{}", "(".repeat(20), ")".repeat(20));
        assert!(Query::parse(&ok).is_ok());
    }

    #[test]
    fn quoted_values_keep_spaces_and_escapes() -> Result<(), ParseQueryError> {
        let query = Query::parse(r#"body:"say \"hi\"""#)?;
        assert_eq!(query.root, Node::Term(Term::Body("say \"hi\"".to_owned())));
        Ok(())
    }

    #[test]
    fn five_thousand_flows_filter_quickly() -> Result<(), ParseQueryError> {
        let flows: Vec<StoredFlow> = (0..5000)
            .map(|id| {
                let status = if id % 10 == 0 { 500 } else { 200 };
                stored(exchange(
                    id,
                    "GET",
                    &format!("https://h{id}.test/p/{id}"),
                    status,
                ))
            })
            .collect();
        let query = Query::parse(
            "(host:h1 OR status:5xx) -body:\"not there\" type:json time:>100ms path:/p/*",
        )?;
        let started = Instant::now();
        let hits = flows.iter().filter(|f| query.matches(f)).count();
        assert!(hits > 0);
        let elapsed = started.elapsed();
        assert!(elapsed.as_secs() < 2, "took {elapsed:?}");
        Ok(())
    }
}
