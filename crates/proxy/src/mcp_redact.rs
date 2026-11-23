//! Redaction of secrets in captured traffic before `wirust mcp` hands it to an agent.
//!
//! One pass runs over a flow (or a HAR document, a page of WebSocket messages, a gRPC call)
//! before any tool output is built from it, so `get_curl` and `generate_code` work from the
//! already redacted flow. Secret values become `[redacted: REASON]`; see `docs/mcp.md` for the
//! rules. Every pass is idempotent, bounded in size and nesting, and fails closed: what it
//! cannot read (binary bodies, text nested too deep, text past the size cap) is hidden.

use std::sync::LazyLock;

use regex::{Captures, Regex};
use serde_json::{Map, Value};

/// Strings that make a name secret wherever they appear in its normalised form.
const SECRET_PARTS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "passphrase",
    "passcode",
    "pwd",
    "credential",
    "authorization",
    "authentication",
    "apikey",
    "privatekey",
    "secretkey",
    "accesskey",
    "signingkey",
    "clientkey",
    "masterkey",
    "sessionkey",
    "encryptionkey",
    "subscriptionkey",
    "licensekey",
    "sessionid",
    "sessid",
    "signature",
    "cookie",
    "jwt",
    "bearer",
    "csrf",
    "xsrf",
];

/// Short words that make a name secret only as a whole word of it (`X-Sig`, `key`, `auth`).
const SECRET_WORDS: &[&str] = &["key", "auth", "session", "sid", "sig", "otp", "pass"];

/// Endings that make a name secret (`oauth`, `totp`, `hmacsig`).
const SECRET_ENDINGS: &[&str] = &["auth", "otp", "sig"];

/// The start of every replacement text; a value that starts with it is already redacted.
const MARK: &str = "[redacted";
/// What replaces a secret header value.
pub(crate) const HEADER: &str = "[redacted: secret header]";
/// What replaces a secret query or form parameter value.
pub(crate) const QUERY: &str = "[redacted: secret query parameter]";
/// What replaces a secret JSON field, multipart part or `name: value` text pair.
pub(crate) const FIELD: &str = "[redacted: secret field]";
/// What replaces a cookie value.
pub(crate) const COOKIE: &str = "[redacted: cookie]";
/// What replaces a JWT.
pub(crate) const JWT_TEXT: &str = "[redacted: jwt]";
/// What replaces a credential after `Bearer`, `Basic` and the like in free text.
const CREDENTIAL: &str = "[redacted: credential]";
/// What replaces text nested deeper than [`MAX_DEPTH`].
const NESTED: &str = "[redacted: nested too deep]";

/// Levels of text inside text (JSON in a JSON string, a URL in a query value) that are
/// read; anything deeper is hidden.
const MAX_DEPTH: usize = 6;
/// Bytes of one text that are read; the rest is hidden. Bodies shown over MCP are at most
/// 64 KiB, so this only cuts HAR exports of huge bodies.
const MAX_TEXT: usize = 1024 * 1024;

/// A JWT, also unsigned (empty third segment) or encrypted (five segments).
static JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"eyJ[A-Za-z0-9_-]{2,}(?:\.[A-Za-z0-9_-]*){2,4}").expect("the JWT pattern is valid")
});

/// `name=value` anywhere: query strings, fragments, form text, cookies.
static PAIR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?P<pre>^|[^A-Za-z0-9_.%\[\]-])(?P<name>[A-Za-z0-9_.%\[\]-]{1,128})=(?P<value>\[redacted[^\]]*\]|"[^"]*"|'[^']*'|[^\s&;,"'<>#]*)"#,
    )
    .expect("the pair pattern is valid")
});

/// `"name": value` in JSON-like text that did not parse (cut, or not quite JSON).
static JSON_PAIR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""(?P<name>[^"\\]{1,128})"\s*:\s*(?P<value>"(?:[^"\\]|\\.)*(?:"|$)|[^,}\]\s]+)"#)
        .expect("the JSON pair pattern is valid")
});

/// `Name: value` lines (raw headers, YAML, multipart part headers).
static LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^(?P<name>[A-Za-z0-9_.-]{1,64})[ \t]*:[ \t]*(?P<value>[^\r\n]*)")
        .expect("the line pattern is valid")
});

/// A credential after an authentication scheme in free text.
static SCHEME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?P<scheme>bearer|basic|digest|token)\s+(?P<value>[A-Za-z0-9._~+/=-]{8,})")
        .expect("the scheme pattern is valid")
});

/// A long opaque value right after a name, separated by spaces or quotes only.
static OPAQUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?P<name>[A-Za-z][A-Za-z0-9_.-]{1,63})["']?\s{1,3}["']?(?P<value>[A-Za-z0-9._~+/-]{16,}={0,2})"#,
    )
    .expect("the opaque pattern is valid")
});

/// A whole `application/x-www-form-urlencoded` text without spaces.
static FORM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9_.%\[\]*+-]+=[^&\s]*(?:&[A-Za-z0-9_.%\[\]*+-]*(?:=[^&\s]*)?)*$")
        .expect("the form pattern is valid")
});

/// `name` lowercased without `-`, `_`, `.`, `[`, `]` and spaces: `X-CSRF_Token` gives
/// `xcsrftoken`.
fn normalised(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, '-' | '_' | '.' | '[' | ']' | ' '))
        .flat_map(char::to_lowercase)
        .collect()
}

/// `name` in lower-case words, split at non-alphanumerics and lower-to-upper case changes.
fn words(name: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut previous_lower = false;
    for c in name.chars() {
        if !c.is_ascii_alphanumeric() {
            words.push(std::mem::take(&mut current));
            previous_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && previous_lower {
            words.push(std::mem::take(&mut current));
        }
        previous_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        current.push(c.to_ascii_lowercase());
    }
    words.push(current);
    words.retain(|w| !w.is_empty());
    words
}

/// Whether a header, parameter or field called `name` holds a secret. The rule, with
/// examples, is in `docs/mcp.md`.
pub(crate) fn is_secret_name(name: &str) -> bool {
    let joined = normalised(name);
    if SECRET_PARTS.iter().any(|part| joined.contains(part)) {
        return true;
    }
    words(name).iter().any(|word| {
        SECRET_WORDS.contains(&word.as_str())
            || SECRET_ENDINGS.iter().any(|end| word.ends_with(end))
            || (word.starts_with("auth") && !word.starts_with("author"))
    })
}

/// Whether JSON field `name` with `value` is secret: a secret name, except usage counts
/// such as `"max_tokens": 100`.
fn is_secret_field(name: &str, value: &Value) -> bool {
    if value.is_null() || !is_secret_name(name) {
        return false;
    }
    !(value.is_number() && normalised(name).ends_with("tokens"))
}

/// `%XX` escapes and `+` decoded, for matching names and reading nested values.
fn percent_decoded(text: &str) -> String {
    let bytes = text.as_bytes();
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
            (b'+', _) => {
                out.push(b' ');
                i += 1;
            }
            (byte, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// What replaces a body that is not text.
pub(crate) fn binary_note(size: u64) -> String {
    format!("[redacted: binary body, {size} bytes, not shown while redaction is on]")
}

/// `text` cut to [`MAX_TEXT`] at a character boundary, and the note for what was cut.
fn capped(text: &str) -> (&str, String) {
    if text.len() <= MAX_TEXT {
        return (text, String::new());
    }
    let mut end = MAX_TEXT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let rest = text.len() - end;
    let note = format!("[redacted: {rest} more bytes not shown while redaction is on]");
    (&text[..end], note)
}

/// Whether `value` (a decoded query value, say) holds a secret one level down.
fn holds_secret(value: &str, depth: usize) -> bool {
    !value.contains(MARK) && text_at(value, depth + 1).contains(MARK)
}

/// Redacts free text, a URL or a header value.
#[cfg(test)]
fn text(text: &str) -> String {
    text_at(text, 0)
}

/// Redacts the secret query parameters and JWTs of a URL.
#[cfg(test)]
fn url(url: &str) -> String {
    text_at(url, 0)
}

fn text_at(text: &str, depth: usize) -> String {
    if depth > MAX_DEPTH {
        return NESTED.to_owned();
    }
    let (head, note) = capped(text);
    let trimmed = head.trim();
    if trimmed.starts_with(['{', '['])
        && let Ok(mut parsed) = serde_json::from_str::<Value>(trimmed)
    {
        value_at(&mut parsed, depth + 1);
        // A `Value` always serialises; fail closed all the same.
        let out = serde_json::to_string(&parsed).unwrap_or_else(|_| FIELD.to_owned());
        return out + note.as_str();
    }
    if FORM.is_match(trimmed) {
        let start = head.len() - head.trim_start().len();
        let end = start + trimmed.len();
        return format!(
            "{}{}{}{note}",
            &head[..start],
            form(trimmed, depth),
            &head[end..]
        );
    }
    patterns(head, depth) + note.as_str()
}

/// The pattern passes over text that is neither JSON nor a form.
fn patterns(text: &str, depth: usize) -> String {
    let lines = LINE.replace_all(text, |c: &Captures| {
        let value = &c["value"];
        if is_secret_name(&c["name"]) && !value.trim().is_empty() && !value.starts_with(MARK) {
            format!("{}: {FIELD}", &c["name"])
        } else {
            c[0].to_owned()
        }
    });
    let json = JSON_PAIR.replace_all(&lines, |c: &Captures| {
        if is_secret_name(&c["name"]) && !c["value"].trim_start_matches('"').starts_with(MARK) {
            format!("\"{}\":\"{FIELD}\"", &c["name"])
        } else {
            c[0].to_owned()
        }
    });
    let pairs = PAIR.replace_all(&json, |c: &Captures| pair(c, depth));
    let schemes = SCHEME.replace_all(&pairs, |c: &Captures| {
        let value = &c["value"];
        // `basic authentication` is prose; `Basic dXNlcjpwYXNz` is a credential.
        let plain_word = value.chars().all(|ch| ch.is_ascii_alphabetic())
            && value.chars().skip(1).all(|ch| ch.is_ascii_lowercase());
        if c["scheme"].eq_ignore_ascii_case("bearer") || !plain_word {
            format!("{} {CREDENTIAL}", &c["scheme"])
        } else {
            c[0].to_owned()
        }
    });
    let opaque = OPAQUE.replace_all(&schemes, |c: &Captures| {
        if is_secret_name(&c["name"]) {
            c[0].replace(&c["value"], CREDENTIAL)
        } else {
            c[0].to_owned()
        }
    });
    JWT.replace_all(&opaque, JWT_TEXT).into_owned()
}

/// One `name=value` match: the value hidden when the name is secret, or when the value,
/// decoded, holds a secret itself (`next=https%3A%2F%2Fh%2F%3Ftoken%3Dx`).
fn pair(c: &Captures, depth: usize) -> String {
    let (pre, name, value) = (&c["pre"], &c["name"], &c["value"]);
    let hidden = !value.starts_with(MARK)
        && !value.is_empty()
        && (is_secret_name(&percent_decoded(name))
            || (value.contains(['%', '=', '+']) && holds_secret(&percent_decoded(value), depth)));
    if hidden {
        format!("{pre}{name}={QUERY}")
    } else {
        c[0].to_owned()
    }
}

/// Redacts a form body or query string (`a=1&token=2`), pair by pair.
fn form(text: &str, depth: usize) -> String {
    let pairs: Vec<String> = text
        .split('&')
        .map(|piece| match piece.split_once('=') {
            Some((name, value))
                if !value.starts_with(MARK)
                    && (is_secret_name(&percent_decoded(name))
                        || holds_secret(&percent_decoded(value), depth)) =>
            {
                format!("{name}={QUERY}")
            }
            _ => piece.to_owned(),
        })
        .collect();
    pairs.join("&")
}

/// The value shown for header `name`: cookies keep their names, other secret headers their
/// authentication scheme; any other header goes through the text pass.
pub(crate) fn header_value(name: &str, value: &str) -> String {
    let joined = normalised(name);
    if joined == "cookie" {
        let cookies: Vec<String> = value
            .split(';')
            .map(|cookie| match cookie.split_once('=') {
                Some((name, _)) => format!("{}={COOKIE}", name.trim()),
                None => COOKIE.to_owned(),
            })
            .collect();
        return cookies.join("; ");
    }
    if joined == "setcookie" {
        let (first, attributes) = value.split_once(';').unwrap_or((value, ""));
        let name = first.split_once('=').map_or("", |(name, _)| name.trim());
        let tail = if attributes.is_empty() {
            String::new()
        } else {
            format!(";{attributes}")
        };
        return format!("{name}={COOKIE}{tail}");
    }
    if is_secret_name(name) {
        if value.starts_with(MARK) {
            return value.to_owned();
        }
        return match value.split_once(' ') {
            Some((scheme, rest))
                if !rest.trim().is_empty()
                    && scheme.len() <= 32
                    && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
                    && scheme
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
                    && !rest.starts_with(MARK) =>
            {
                format!("{scheme} {HEADER}")
            }
            Some((_, rest)) if rest.starts_with(MARK) => value.to_owned(),
            _ => HEADER.to_owned(),
        };
    }
    text_at(value, 0)
}

/// Redacts a body text by its content type: multipart parts by name, forms pair by pair,
/// then JSON by parsing, forms by shape and the pattern passes for anything else.
pub(crate) fn body_text(text: &str, content_type: Option<&str>) -> String {
    let content_type = content_type.unwrap_or_default();
    let lower = content_type.to_ascii_lowercase();
    if lower.contains("multipart/")
        && let Some(boundary) = boundary(content_type)
    {
        let (head, note) = capped(text);
        return multipart(head, &boundary) + note.as_str();
    }
    if lower.contains("x-www-form-urlencoded") && !text.trim().starts_with(['{', '[']) {
        let (head, note) = capped(text);
        let trimmed = head.trim_end();
        let pairs = form(trimmed, 0);
        return JWT.replace_all(&pairs, JWT_TEXT).into_owned()
            + &head[trimmed.len()..]
            + note.as_str();
    }
    text_at(text, 0)
}

/// The `boundary` parameter of a multipart content type.
fn boundary(content_type: &str) -> Option<String> {
    content_type.split(';').find_map(|param| {
        let (name, value) = param.split_once('=')?;
        let value = value.trim().trim_matches('"');
        (name.trim().eq_ignore_ascii_case("boundary") && !value.is_empty())
            .then(|| value.to_owned())
    })
}

/// Redacts each part of a multipart body: a part with a secret `name` loses its content,
/// any other part goes through the text pass.
fn multipart(text: &str, boundary: &str) -> String {
    let delimiter = format!("--{boundary}");
    let mut parts = text.split(delimiter.as_str());
    let mut out = parts.next().unwrap_or_default().to_owned();
    for part in parts {
        out.push_str(&delimiter);
        let split = part
            .find("\r\n\r\n")
            .map(|at| at + 4)
            .or_else(|| part.find("\n\n").map(|at| at + 2));
        let Some(at) = split else {
            out.push_str(&text_at(part, 1));
            continue;
        };
        let (head, content) = part.split_at(at);
        let secret = head
            .split(';')
            .filter_map(|param| param.trim().strip_prefix("name="))
            .any(|name| is_secret_name(name.trim_matches(|c| c == '"' || c == '\r' || c == '\n')));
        out.push_str(&text_at(head, 1));
        if secret {
            let ending = content.len() - content.trim_end_matches(['\r', '\n']).len();
            out.push_str(FIELD);
            out.push_str(&content[content.len() - ending..]);
        } else {
            out.push_str(&text_at(content, 1));
        }
    }
    out
}

/// Redacts a JSON value in place: fields with secret names, `[name, value]` pairs and
/// `{"name", "value"}` objects with a secret name, and every string through the text pass.
pub(crate) fn value(value: &mut Value) {
    value_at(value, 0);
}

fn value_at(value: &mut Value, depth: usize) {
    match value {
        Value::String(text) => *text = text_at(text, depth),
        Value::Array(items) => {
            if let [Value::String(name), second] = items.as_mut_slice()
                && is_secret_field(name, second)
            {
                *second = Value::String(FIELD.to_owned());
                return;
            }
            for item in items {
                value_at(item, depth);
            }
        }
        Value::Object(map) => object(map, depth),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn object(map: &mut Map<String, Value>, depth: usize) {
    let named_secret = map
        .get("name")
        .and_then(Value::as_str)
        .is_some_and(is_secret_name);
    for (key, field) in map.iter_mut() {
        let secret_pair = named_secret && key == "value" && !field.is_null();
        if secret_pair || is_secret_field(key, field) {
            *field = Value::String(FIELD.to_owned());
        } else {
            value_at(field, depth);
        }
    }
}

/// The `Content-Type` of a `[[name, value]]` header list.
fn content_type(headers: Option<&Value>) -> Option<String> {
    headers?.as_array()?.iter().find_map(|pair| {
        let [name, value] = pair.as_array()?.as_slice() else {
            return None;
        };
        name.as_str()?
            .eq_ignore_ascii_case("content-type")
            .then(|| value.as_str().map(str::to_owned))?
    })
}

/// Redacts a `[[name, value]]` header list in place; any other shape goes through the
/// generic JSON pass.
fn headers(list: &mut Value) {
    let Some(items) = list.as_array_mut() else {
        value_at(list, 0);
        return;
    };
    for item in items {
        match item.as_array_mut().map(Vec::as_mut_slice) {
            Some([Value::String(name), Value::String(header)]) => {
                *header = header_value(name, header);
            }
            _ => value_at(item, 0),
        }
    }
}

/// Redacts a body record (`{"size", "encoding", "data", ...}`): text by its content type;
/// a base64 (binary) record is replaced by a note.
fn body_record(record: &mut Value, content_type: Option<&str>) {
    let Some(map) = record.as_object_mut() else {
        value_at(record, 0);
        return;
    };
    let size = map.get("size").and_then(Value::as_u64).unwrap_or_default();
    let binary = map.get("encoding").and_then(Value::as_str) != Some("utf8");
    let data = match map.get("data") {
        Some(Value::String(data)) if !binary => body_text(data, content_type),
        Some(Value::String(data)) if data.is_empty() => String::new(),
        _ => binary_note(size),
    };
    map.insert("encoding".to_owned(), Value::String("utf8".to_owned()));
    map.insert("data".to_owned(), Value::String(data));
    if binary {
        map.insert("redacted_binary".to_owned(), Value::Bool(true));
    }
}

/// Redacts a flow record (an exchange, a tunnel or a TLS failure) in place: headers by
/// name, bodies by content type, every other field through the generic JSON pass.
pub(crate) fn flow(flow: &mut Value) {
    let Some(map) = flow.as_object_mut() else {
        value_at(flow, 0);
        return;
    };
    let request_type = content_type(map.get("request_headers"));
    let response_type = content_type(map.get("response_headers"));
    for (key, field) in map.iter_mut() {
        match key.as_str() {
            "request_headers" | "response_headers" | "response_trailers" => headers(field),
            "request_body" => body_record(field, request_type.as_deref()),
            "response_body" => body_record(field, response_type.as_deref()),
            _ => value_at(field, 0),
        }
    }
}

/// Redacts a page of WebSocket messages (`{"messages": [...]}`): text messages through the
/// text pass (JSON inside included), binary ones replaced by a note.
pub(crate) fn ws_messages(page: &mut Value) {
    let Some(map) = page.as_object_mut() else {
        value_at(page, 0);
        return;
    };
    for (key, field) in map.iter_mut() {
        match (key.as_str(), field.as_array_mut()) {
            ("messages", Some(messages)) => messages.iter_mut().for_each(ws_message),
            _ => value_at(field, 0),
        }
    }
}

fn ws_message(message: &mut Value) {
    let Some(map) = message.as_object_mut() else {
        value_at(message, 0);
        return;
    };
    let binary = map.get("encoding").and_then(Value::as_str) != Some("utf8");
    let size = map.get("size").and_then(Value::as_u64).unwrap_or_default();
    for (key, field) in map.iter_mut() {
        if key == "data" && binary {
            *field = Value::String(binary_note(size));
        } else {
            value_at(field, 0);
        }
    }
}

/// Redacts a HAR document in place, entry by entry, with the same rules as [`flow`].
pub(crate) fn har(document: &mut Value) {
    let Some(log) = document.get_mut("log").and_then(Value::as_object_mut) else {
        value_at(document, 0);
        return;
    };
    for (key, field) in log.iter_mut() {
        match (key.as_str(), field.as_array_mut()) {
            ("entries", Some(entries)) => entries.iter_mut().for_each(har_entry),
            _ => value_at(field, 0),
        }
    }
}

fn har_entry(entry: &mut Value) {
    let Some(map) = entry.as_object_mut() else {
        value_at(entry, 0);
        return;
    };
    for (key, field) in map.iter_mut() {
        match key.as_str() {
            "request" => har_message(field, "postData"),
            "response" => har_message(field, "content"),
            "_webSocketMessages" => har_ws(field),
            _ => value_at(field, 0),
        }
    }
}

/// A HAR request or response: `body_key` names its body (`postData` or `content`).
fn har_message(message: &mut Value, body_key: &str) {
    let Some(map) = message.as_object_mut() else {
        value_at(message, 0);
        return;
    };
    for (key, field) in map.iter_mut() {
        match key.as_str() {
            "headers" => har_pairs(field, header_value),
            "queryString" => har_pairs(field, query_value),
            "cookies" => har_pairs(field, |_, _| COOKIE.to_owned()),
            key if key == body_key => har_body(field),
            _ => value_at(field, 0),
        }
    }
}

fn query_value(name: &str, value: &str) -> String {
    if is_secret_name(name) || holds_secret(value, 0) {
        QUERY.to_owned()
    } else {
        value.to_owned()
    }
}

/// A HAR `[{"name", "value"}]` list, each value through `redact`.
fn har_pairs(list: &mut Value, redact: impl Fn(&str, &str) -> String) {
    let Some(items) = list.as_array_mut() else {
        value_at(list, 0);
        return;
    };
    for item in items {
        let name = item["name"].as_str().unwrap_or_default().to_owned();
        let Some(map) = item.as_object_mut() else {
            continue;
        };
        for (key, field) in map.iter_mut() {
            match (key.as_str(), &*field) {
                ("value", Value::String(text)) => *field = Value::String(redact(&name, text)),
                ("name", _) => {}
                _ => value_at(field, 0),
            }
        }
    }
}

/// A HAR `postData` or `content`: text by `mimeType`, base64 replaced by a note, `params`
/// as form pairs.
fn har_body(body: &mut Value) {
    let Some(map) = body.as_object_mut() else {
        value_at(body, 0);
        return;
    };
    let mime = map
        .get("mimeType")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let binary = map.get("encoding").and_then(Value::as_str) == Some("base64");
    let size = map.get("size").and_then(Value::as_u64).unwrap_or_default();
    if binary {
        map.remove("encoding");
    }
    for (key, field) in map.iter_mut() {
        match (key.as_str(), &*field) {
            ("text", _) if binary => *field = Value::String(binary_note(size)),
            ("text", Value::String(text)) => {
                *field = Value::String(body_text(text, mime.as_deref()));
            }
            ("params", _) => har_pairs(field, query_value),
            ("mimeType", _) => {}
            _ => value_at(field, 0),
        }
    }
}

/// HAR `_webSocketMessages`: text frames (opcode 1) through the text pass, others hidden.
fn har_ws(list: &mut Value) {
    let Some(items) = list.as_array_mut() else {
        value_at(list, 0);
        return;
    };
    for item in items {
        let text_frame = item["opcode"].as_u64() == Some(1);
        let Some(map) = item.as_object_mut() else {
            continue;
        };
        for (key, field) in map.iter_mut() {
            match (key.as_str(), &*field) {
                ("data", Value::String(data)) if !text_frame => {
                    let size = u64::try_from(data.len()).unwrap_or(u64::MAX);
                    *field = Value::String(binary_note(size));
                }
                ("type", _) => {}
                _ => value_at(field, 0),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn secret_names_match_on_the_normalised_name() {
        for secret in [
            "Authorization",
            "Proxy-Authorization",
            "X-Api-Key",
            "apiKey",
            "access_token",
            "accesstoken",
            "ACCESSTOKEN",
            "refreshtoken",
            "X-CSRFToken",
            "privatekey",
            "apikey",
            "clientsecret",
            "client_secret",
            "Set-Cookie",
            "X-Amz-Signature",
            "sessionid",
            "PHPSESSID",
            "key",
            "passcode",
            "totp",
            "oauth",
            "user[password]",
            "authCode",
            "X-Sig",
            "Ocp-Apim-Subscription-Key",
            "x-goog-api-key",
        ] {
            assert!(is_secret_name(secret), "{secret}");
        }
        for plain in [
            "author",
            "authority",
            "monkey",
            "keyboard",
            "keyword",
            "hotkey",
            "content-type",
            "page",
            "accept",
            "design",
            "signal",
            "inside",
            "footprint",
            "sidebar",
            "passenger",
        ] {
            assert!(!is_secret_name(plain), "{plain}");
        }
        assert!(!is_secret_field("max_tokens", &json!(100)));
        assert!(is_secret_field("tokens", &json!(["abc"])));
    }

    #[test]
    fn urls_lose_secret_parameters_and_jwts() {
        assert_eq!(
            url("https://a.test/p?page=2&API_KEY=abc&Token=x#frag"),
            format!("https://a.test/p?page=2&API_KEY={QUERY}&Token={QUERY}#frag")
        );
        let jwt = "eyJhbGciOi.eyJzdWIiOiIx.c2lnbmF0dXJl";
        assert_eq!(
            url(&format!("https://a.test/{jwt}")),
            format!("https://a.test/{JWT_TEXT}")
        );
        let unsigned = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.";
        assert_eq!(text(unsigned), JWT_TEXT);
        let nested = url("https://a.test/?next=https%3A%2F%2Fb%2F%3Ftoken%3Dzz&page=1");
        assert_eq!(nested, format!("https://a.test/?next={QUERY}&page=1"));
        assert!(!url("https://a.test/#access_token=zz&x=1").contains("zz"));
    }

    #[test]
    fn json_bodies_lose_secret_fields_at_any_depth() {
        let body = r#"{"user":"ann","password":"hunter2","list":[[{"refreshtoken":"r1"}]],
            "payload":"{\"password\":\"inner\",\"deeper\":\"{\\\"apikey\\\":\\\"k2\\\"}\"}","n":null}"#;
        let out = body_text(body, Some("application/json"));
        for secret in ["hunter2", "r1", "inner", "k2"] {
            assert!(!out.contains(secret), "{secret}: {out}");
        }
        let parsed: Value = serde_json::from_str(&out).expect("json");
        assert_eq!(parsed["user"], "ann");
        assert_eq!(parsed["password"], FIELD);
        assert!(parsed["n"].is_null());
        // Cut JSON still loses its secret pairs.
        let cut = body_text(r#"{"a":1,"password":"hun"#, Some("application/json"));
        assert!(!cut.contains("hun"), "{cut}");
    }

    #[test]
    fn forms_by_content_type_or_shape() {
        assert_eq!(
            body_text("a=1&password=x\n", None),
            format!("a=1&password={QUERY}\n")
        );
        let typed = body_text(
            "user=a b&pwd=x y",
            Some("application/x-www-form-urlencoded"),
        );
        assert_eq!(typed, format!("user=a b&pwd={QUERY}"));
        let multipart = "--XX\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--XX\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nann\r\n--XX--\r\n";
        let out = body_text(multipart, Some("multipart/form-data; boundary=XX"));
        assert!(!out.contains("hunter2") && out.contains("ann"), "{out}");
    }

    #[test]
    fn free_text_loses_pairs_schemes_and_lines() {
        let out = text(
            "log: sending Authorization: Basic dXNlcjpwYXNz\nretry with token=abc123 and \
             api_key AIzaSyA1234567890abcdefghij\nX-CSRFToken: zzz",
        );
        for secret in [
            "dXNlcjpwYXNz",
            "abc123",
            "AIzaSyA1234567890abcdefghij",
            "zzz",
        ] {
            assert!(!out.contains(secret), "{secret}: {out}");
        }
        assert_eq!(text("plain words only"), "plain words only");
    }

    #[test]
    fn headers_keep_schemes_and_cookie_names() {
        assert_eq!(
            header_value("Authorization", "Bearer x"),
            format!("Bearer {HEADER}")
        );
        assert_eq!(
            header_value("Proxy-Authorization", "Digest a=\"1\", b=2"),
            format!("Digest {HEADER}")
        );
        assert_eq!(header_value("X-Api-Key", "k"), HEADER);
        assert_eq!(
            header_value("Cookie", "a=1; b=2"),
            format!("a={COOKIE}; b={COOKIE}")
        );
        assert_eq!(
            header_value("Set-Cookie", "sid=1; Path=/; HttpOnly"),
            format!("sid={COOKIE}; Path=/; HttpOnly")
        );
        assert!(!header_value("Referer", "https://a/?access_token=zz").contains("zz"));
    }

    #[test]
    fn flows_lose_binary_bodies_and_secrets() {
        let mut record = json!({
            "id": 1,
            "url": "https://a/?token=zz",
            "request_headers": [["Content-Type", "application/x-www-form-urlencoded"], ["Cookie", "s=1"]],
            "request_body": { "size": 13, "truncated": false, "encoding": "utf8", "data": "password=zz\n" },
            "response_headers": [],
            "response_body": { "size": 3, "truncated": false, "encoding": "base64", "data": "AAEC" },
        });
        flow(&mut record);
        let shown = record.to_string();
        assert!(!shown.contains("zz") && !shown.contains("AAEC"), "{shown}");
        assert!(shown.contains("binary body, 3 bytes"), "{shown}");
    }

    #[test]
    fn websocket_text_holding_json_is_redacted() {
        let mut page = json!({ "messages": [
            { "encoding": "utf8", "size": 20, "data": "{\"password\":\"zz\"}" },
            { "encoding": "base64", "size": 3, "data": "AAEC" },
        ]});
        ws_messages(&mut page);
        let shown = page.to_string();
        assert!(!shown.contains("zz") && !shown.contains("AAEC"), "{shown}");
    }

    #[test]
    fn har_bodies_cookies_and_queries_are_redacted() {
        let mut document = json!({ "log": { "entries": [{
            "request": {
                "url": "https://a/?sig=zz1",
                "headers": [{ "name": "Authorization", "value": "Basic zz2" }],
                "queryString": [{ "name": "sig", "value": "zz1" }],
                "cookies": [{ "name": "theme", "value": "zz3" }],
                "postData": { "mimeType": "application/x-www-form-urlencoded", "text": "pwd=zz4" },
            },
            "response": { "content": { "size": 2, "mimeType": "image/png", "encoding": "base64", "text": "zz5" } },
            "_webSocketMessages": [{ "type": "send", "opcode": 1, "data": "{\"otp\":\"zz6\"}" }],
        }]}});
        har(&mut document);
        let shown = document.to_string();
        for secret in ["zz1", "zz2", "zz3", "zz4", "zz5", "zz6"] {
            assert!(!shown.contains(secret), "{secret}: {shown}");
        }
    }

    #[test]
    fn redaction_is_idempotent() {
        let samples = [
            "a=1&password=x",
            r#"{"token":"x","list":["a",{"apikey":"b"}]}"#,
            "https://a/?next=https%3A%2F%2Fb%2F%3Ftoken%3Dz&x=1",
            "Authorization: Bearer abcdefghijkl\nok: 1",
            "see eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0. here",
            "\"password\":\"cut",
        ];
        for sample in samples {
            let once = text(sample);
            assert_eq!(text(&once), once, "{sample}");
            let body = body_text(sample, Some("application/x-www-form-urlencoded"));
            assert_eq!(
                body_text(&body, Some("application/x-www-form-urlencoded")),
                body
            );
        }
        for (name, value) in [
            ("Cookie", "a=1"),
            ("Authorization", "Bearer x"),
            ("Set-Cookie", "a=1; Path=/"),
        ] {
            let once = header_value(name, value);
            assert_eq!(header_value(name, &once), once, "{name}");
        }
    }

    #[test]
    fn adversarial_input_is_bounded_and_fails_closed() {
        // JSON in a string in a string ... deeper than MAX_DEPTH: the innermost is hidden.
        let mut nested = json!({ "password": "zz" }).to_string();
        for _ in 0..(MAX_DEPTH + 2) {
            nested = json!({ "wrap": nested }).to_string();
        }
        let out = text(&nested);
        assert!(!out.contains("zz"), "{out}");
        // Huge input is cut, not scanned without end.
        let huge = "a=1&".repeat(MAX_TEXT / 2);
        let out = text(&huge);
        assert!(out.len() < huge.len() && out.contains("not shown while redaction is on"));
        // Deep arrays that serde refuses fall back to the pattern pass.
        let deep = format!("{}\"password\":\"zz\"{}", "[".repeat(300), "]".repeat(300));
        assert!(!text(&deep).contains("zz"));
    }
}
