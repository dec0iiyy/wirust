//! Rebuilds a recorded request as code for an HTTP client: Python `requests`, JavaScript
//! `fetch`, Kotlin `OkHttp`, Swift `URLSession`, `HTTPie` and PowerShell `Invoke-WebRequest`.
//!
//! Each snippet is complete (imports included) and sends the method, URL, headers and body of
//! the captured request. Left out are what the client library sets itself: pseudo-headers,
//! hop-by-hop headers, `Content-Length`, `Accept-Encoding`, a `Host` that names the URL's
//! own host, and `Content-Encoding` when the stored body is the decoded one. Text bodies
//! become string literals escaped for the language, readable raw or multi-line literals where
//! that is safe; binary bodies are Base64 text decoded in the code. Only the exchange is read,
//! so nothing of the proxy's own state, such as the control-plane token, can reach a snippet.

use std::fmt::Write as _;

use crate::curl::{SKIPPED, quote};
use crate::flow::Exchange;

/// A language `generate` writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    /// Python with `requests`.
    Python,
    /// JavaScript `fetch`, in a browser or Node.
    Fetch,
    /// Kotlin with `OkHttp`.
    OkHttp,
    /// Swift with `URLSession`.
    UrlSession,
    /// The `HTTPie` command line.
    Httpie,
    /// PowerShell `Invoke-WebRequest`.
    PowerShell,
}

impl Lang {
    /// Every language, in the order the UI lists them.
    pub const ALL: [Self; 6] = [
        Self::Python,
        Self::Fetch,
        Self::OkHttp,
        Self::UrlSession,
        Self::Httpie,
        Self::PowerShell,
    ];

    /// The `lang` value of the API: `python`, `fetch`, `okhttp`, `urlsession`, `httpie` or
    /// `powershell`.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Fetch => "fetch",
            Self::OkHttp => "okhttp",
            Self::UrlSession => "urlsession",
            Self::Httpie => "httpie",
            Self::PowerShell => "powershell",
        }
    }

    /// The language with this API name, `None` for an unknown one.
    #[must_use]
    pub fn parse(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|lang| lang.id() == id)
    }
}

/// The code that sends `exchange`'s request again, in `lang`.
#[must_use]
pub fn generate(lang: Lang, exchange: &Exchange) -> String {
    let request = Request::new(exchange);
    match lang {
        Lang::Python => python(&request),
        Lang::Fetch => fetch(&request),
        Lang::OkHttp => okhttp(&request),
        Lang::UrlSession => urlsession(&request),
        Lang::Httpie => httpie(&request),
        Lang::PowerShell => powershell(&request),
    }
}

/// The request body as the code has to carry it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Body {
    Empty,
    Text(String),
    /// Base64 text of bytes that are not UTF-8.
    Binary(String),
}

/// What the snippets are written from.
#[derive(Debug, Clone)]
struct Request {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Body,
    /// Set when the stored body is shorter than the real one: its full size in bytes.
    cut_from: Option<u64>,
}

impl Request {
    fn new(x: &Exchange) -> Self {
        let record = &x.request_body;
        let authority = x.url.split_once("://").map_or("", |(_, rest)| {
            rest.split(['/', '?', '#']).next().unwrap_or_default()
        });
        let mut headers: Vec<(String, String)> = Vec::new();
        for (name, value) in &x.request_headers {
            let lower = name.to_ascii_lowercase();
            let library_sets_it = lower.starts_with(':')
                || SKIPPED.contains(&lower.as_str())
                || lower == "accept-encoding"
                || (lower == "content-encoding" && record.is_decoded())
                || (lower == "host" && value.eq_ignore_ascii_case(authority));
            if library_sets_it {
                continue;
            }
            // A repeated header is joined, as HTTP allows; most libraries take one value.
            match headers
                .iter_mut()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
            {
                Some((_, joined)) => {
                    joined.push_str(if lower == "cookie" { "; " } else { ", " });
                    joined.push_str(value);
                }
                None => headers.push((name.clone(), value.clone())),
            }
        }
        let body = match (record.data.is_empty(), record.encoding) {
            (true, _) => Body::Empty,
            (false, "base64") => Body::Binary(record.data.clone()),
            (false, _) => Body::Text(record.data.clone()),
        };
        Self {
            method: x.method.clone(),
            url: x.url.clone(),
            headers,
            body,
            cut_from: record.truncated.then_some(record.size),
        }
    }

    /// Removes the header and returns its value.
    fn take_header(&mut self, name: &str) -> Option<String> {
        let at = self
            .headers
            .iter()
            .position(|(n, _)| n.eq_ignore_ascii_case(name))?;
        Some(self.headers.remove(at).1)
    }

    /// The comment line about a cut body, with the language's comment marker.
    fn cut_note(&self, marker: &str) -> String {
        self.cut_from.map_or_else(String::new, |size| {
            format!(
                "{marker} the captured body was cut to its first part by the body limit; the \
                 request had {size} bytes\n"
            )
        })
    }
}

// ---------------------------------------------------------------------------
// String literals

/// Characters that are better written as escapes than pasted into source: controls, line
/// separators, zero-width and direction marks.
fn invisible(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{ad}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        )
}

/// No character that needs an escape except the newline and tab of a multi-line literal.
fn multi_line_ok(s: &str) -> bool {
    s.chars().all(|c| c == '\n' || c == '\t' || !invisible(c))
}

/// A single line with nothing to escape but quotes and backslashes.
fn one_line_ok(s: &str) -> bool {
    !s.chars().any(invisible)
}

/// `s` in double quotes, with the escapes the C-like languages share and `other` for the
/// control and invisible characters. `dollar` also escapes `$` (Kotlin templates).
fn escaped(s: &str, dollar: bool, other: fn(char) -> String) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '$' if dollar => out.push_str("\\$"),
            c if invisible(c) => out.push_str(&other(c)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `\xNN` below 0x100, else `\uXXXX`: Python and JavaScript.
fn hex_escape(c: char) -> String {
    let n = u32::from(c);
    if n < 0x100 {
        format!("\\x{n:02x}")
    } else {
        format!("\\u{n:04x}")
    }
}

/// `\uXXXX`: Kotlin.
fn kotlin_escape(c: char) -> String {
    format!("\\u{:04x}", u32::from(c))
}

/// `\u{X}`: Swift.
fn swift_escape(c: char) -> String {
    format!("\\u{{{:x}}}", u32::from(c))
}

/// Quotes for a line without backslashes: double quotes, or single ones when the text holds
/// double quotes and no single one (JSON stays readable).
fn simple_quotes(s: &str) -> Option<char> {
    if s.contains(['\\', '\'']) && s.contains('"') {
        None
    } else if s.contains('"') {
        Some('\'')
    } else {
        Some('"')
    }
}

fn python_str(s: &str) -> String {
    let raw = if s.contains('\\') { "r" } else { "" };
    if s.contains('\n') && multi_line_ok(s) && !s.contains("\"\"\"") && !s.ends_with(['"', '\\']) {
        return format!("{raw}\"\"\"{s}\"\"\"");
    }
    if one_line_ok(s) && !s.contains(['\n', '\r']) {
        if !s.contains('\\') {
            if let Some(q) = simple_quotes(s) {
                return format!("{q}{s}{q}");
            }
        } else if !s.contains('\'') && !s.ends_with('\\') {
            return format!("r'{s}'");
        }
    }
    escaped(s, false, hex_escape)
}

fn js_str(s: &str) -> String {
    if s.contains('\n') && multi_line_ok(s) && !s.contains(['\\', '`']) && !s.contains("${") {
        return format!("`{s}`");
    }
    if one_line_ok(s)
        && !s.contains(['\n', '\r', '\\'])
        && let Some(q) = simple_quotes(s)
    {
        return format!("{q}{s}{q}");
    }
    escaped(s, false, hex_escape)
}

fn kotlin_str(s: &str) -> String {
    let raw_ok =
        multi_line_ok(s) && !s.contains(['$', '\r']) && !s.contains("\"\"\"") && !s.ends_with('"');
    if (s.contains('\n') || s.contains('"')) && raw_ok {
        return format!("\"\"\"{s}\"\"\"");
    }
    escaped(s, true, kotlin_escape)
}

fn swift_str(s: &str) -> String {
    let raw_ok = !s.contains("\\#") && !s.contains('\r');
    if s.contains('\n') && multi_line_ok(s) && raw_ok && !s.contains("\"\"\"#") {
        return format!("#\"\"\"\n{s}\n\"\"\"#");
    }
    if (s.contains('"') || s.contains('\\'))
        && one_line_ok(s)
        && !s.contains('\n')
        && raw_ok
        && !s.contains("\"#")
    {
        return format!("#\"{s}\"#");
    }
    escaped(s, false, swift_escape)
}

/// `s` as a Swift literal of the characters whose Latin-1 bytes are the UTF-8 bytes of `s`.
fn swift_latin1(s: &str) -> String {
    let mut out = String::from("\"");
    for b in s.bytes() {
        match b {
            b'\\' | b'"' => {
                out.push('\\');
                out.push(char::from(b));
            }
            0x20..=0x7e => out.push(char::from(b)),
            _ => {
                let _ = write!(out, "\\u{{{b:x}}}");
            }
        }
    }
    out.push('"');
    out
}

/// A PowerShell string expression for `s`.
fn powershell_str(s: &str) -> String {
    // The typographic quotes are quote characters to PowerShell, in both kinds of string.
    let single = |c: char| matches!(c, '\'' | '\u{2018}'..='\u{201b}');
    let double = |c: char| matches!(c, '"' | '\u{201c}'..='\u{201e}');
    if one_line_ok(s) {
        let mut out = String::from("'");
        for c in s.chars() {
            if single(c) {
                out.push(c);
            }
            out.push(c);
        }
        out.push('\'');
        return out;
    }
    if s.contains('\n')
        && multi_line_ok(s)
        && !s.contains('\r')
        && !s.lines().any(|line| line.starts_with("'@"))
    {
        return format!("@'\n{s}\n'@");
    }
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '`' | '$' => {
                out.push('`');
                out.push(c);
            }
            '\n' => out.push_str("`n"),
            '\r' => out.push_str("`r"),
            '\t' => out.push_str("`t"),
            '\0' => out.push_str("`0"),
            c if double(c) => {
                out.push('`');
                out.push(c);
            }
            c if invisible(c) => {
                let _ = write!(out, "$([char]0x{:x})", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// ---------------------------------------------------------------------------
// Languages

fn python(r: &Request) -> String {
    let mut out = String::new();
    if matches!(r.body, Body::Binary(_)) {
        out.push_str("import base64\n");
    }
    out.push_str("import requests\n\n");
    out.push_str(&r.cut_note("#"));
    let verb = r.method.to_ascii_lowercase();
    let url = python_str(&r.url);
    if matches!(
        verb.as_str(),
        "get" | "post" | "put" | "patch" | "delete" | "head" | "options"
    ) {
        let _ = writeln!(out, "response = requests.{verb}(\n    {url},");
    } else {
        let _ = writeln!(
            out,
            "response = requests.request(\n    {},\n    {url},",
            python_str(&r.method)
        );
    }
    if !r.headers.is_empty() {
        out.push_str("    headers={\n");
        for (name, value) in &r.headers {
            // `requests` encodes a str header value as Latin-1; bytes keep the UTF-8 sent.
            let value = if value.is_ascii() {
                python_str(value)
            } else {
                format!("{}.encode(\"utf-8\")", python_str(value))
            };
            let _ = writeln!(out, "        {}: {value},", python_str(name));
        }
        out.push_str("    },\n");
    }
    match &r.body {
        Body::Empty => {}
        // `requests` would send a str body as Latin-1.
        Body::Text(text) if text.is_ascii() => {
            let _ = writeln!(out, "    data={},", python_str(text));
        }
        Body::Text(text) => {
            let _ = writeln!(out, "    data={}.encode(\"utf-8\"),", python_str(text));
        }
        Body::Binary(b64) => {
            let _ = writeln!(out, "    data=base64.b64decode(\"{b64}\"),");
        }
    }
    out.push_str(")\nprint(response.status_code)\nprint(response.text)\n");
    out
}

fn fetch(r: &Request) -> String {
    let mut out = r.cut_note("//");
    let browser_refuses: Vec<String> = r
        .headers
        .iter()
        .map(|(n, _)| n.to_ascii_lowercase())
        .filter(|n| {
            matches!(
                n.as_str(),
                "cookie" | "host" | "origin" | "referer" | "user-agent"
            )
        })
        .collect();
    if !browser_refuses.is_empty() {
        let _ = writeln!(
            out,
            "// Browsers ignore these headers (Node sends them): {}",
            browser_refuses.join(", ")
        );
    }
    let _ = writeln!(out, "fetch({}, {{", js_str(&r.url));
    let _ = writeln!(out, "  method: {},", js_str(&r.method));
    if !r.headers.is_empty() {
        out.push_str("  headers: {\n");
        for (name, value) in &r.headers {
            // A header value is a ByteString: spell the UTF-8 bytes out as characters.
            let value = if value.is_ascii() {
                js_str(value)
            } else {
                let bytes: String = value.bytes().map(char::from).collect();
                format!("{} /* sent as UTF-8 bytes */", js_str(&bytes))
            };
            let _ = writeln!(out, "    {}: {value},", js_str(name));
        }
        out.push_str("  },\n");
    }
    match &r.body {
        Body::Empty => {}
        Body::Text(text) => {
            let _ = writeln!(out, "  body: {},", js_str(text));
        }
        Body::Binary(b64) => {
            let _ = writeln!(
                out,
                "  body: Uint8Array.from(atob(\"{b64}\"), (c) => c.charCodeAt(0)),"
            );
        }
    }
    out.push_str(
        "}).then(async (response) => {\n  console.log(response.status);\n  console.log(await \
         response.text());\n});\n",
    );
    out
}

fn okhttp(r: &Request) -> String {
    let mut r = r.clone();
    let content_type = (r.body != Body::Empty)
        .then(|| r.take_header("content-type"))
        .flatten();
    let mut imports = vec!["okhttp3.OkHttpClient", "okhttp3.Request"];
    if content_type.is_some() {
        imports.push("okhttp3.MediaType.Companion.toMediaType");
    }
    let needs_body = matches!(
        r.method.as_str(),
        "POST" | "PUT" | "PATCH" | "PROPPATCH" | "REPORT"
    );
    if r.body != Body::Empty || needs_body {
        imports.push("okhttp3.RequestBody.Companion.toRequestBody");
    }
    if matches!(r.body, Body::Binary(_)) {
        imports.push("java.util.Base64");
    }
    imports.sort_unstable();
    let mut out = String::new();
    for import in imports {
        let _ = writeln!(out, "import {import}");
    }
    out.push('\n');
    out.push_str(&r.cut_note("//"));
    out.push_str("fun main() {\n    val client = OkHttpClient()\n");
    let media =
        content_type.map_or_else(String::new, |t| format!("{}.toMediaType()", kotlin_str(&t)));
    // The byte-array overload leaves the Content-Type as it is; a String body would add a charset.
    let bytes = match &r.body {
        Body::Empty => None,
        Body::Text(text) => Some(format!("{}.toByteArray()", kotlin_str(text))),
        Body::Binary(b64) => Some(format!("Base64.getDecoder().decode(\"{b64}\")")),
    };
    let method = match (r.method.as_str(), &bytes) {
        ("GET", None) => ".get()".to_owned(),
        ("HEAD", None) => ".head()".to_owned(),
        (m, Some(_)) => format!(".method({}, body)", kotlin_str(m)),
        (m, None) if matches!(m, "POST" | "PUT" | "PATCH" | "PROPPATCH" | "REPORT") => {
            format!(".method({}, ByteArray(0).toRequestBody())", kotlin_str(m))
        }
        (m, None) => format!(".method({}, null)", kotlin_str(m)),
    };
    if let Some(bytes) = bytes {
        if matches!(r.method.as_str(), "GET" | "HEAD") {
            out.push_str(
                "    // OkHttp refuses a body on GET and HEAD; use another method to send it.\n",
            );
        }
        let _ = writeln!(out, "    val body = {bytes}.toRequestBody({media})");
    }
    let _ = writeln!(
        out,
        "    val request = Request.Builder()\n        .url({})\n        {method}",
        kotlin_str(&r.url)
    );
    for (name, value) in &r.headers {
        // `addHeader` refuses characters outside ASCII; this one sends them as UTF-8.
        let add = if value.is_ascii() {
            "addHeader"
        } else {
            "addUnsafeNonAscii"
        };
        let _ = writeln!(
            out,
            "        .{add}({}, {})",
            kotlin_str(name),
            kotlin_str(value)
        );
    }
    out.push_str(
        "        .build()\n    client.newCall(request).execute().use { response ->\n        \
         println(response.code)\n        println(response.body?.string())\n    }\n}\n",
    );
    out
}

fn urlsession(r: &Request) -> String {
    let mut out = String::from(
        "import Foundation\n#if canImport(FoundationNetworking)\nimport FoundationNetworking\n#endif\n\n",
    );
    out.push_str(&r.cut_note("//"));
    let _ = writeln!(
        out,
        "var request = URLRequest(url: URL(string: {})!)\nrequest.httpMethod = {}",
        swift_str(&r.url),
        swift_str(&r.method)
    );
    for (name, value) in &r.headers {
        // `URLSession` writes a header value as Latin-1: spell the UTF-8 bytes out as characters.
        let (value, note) = if value.is_ascii() {
            (swift_str(value), "")
        } else {
            (swift_latin1(value), " // sent as UTF-8 bytes")
        };
        let _ = writeln!(
            out,
            "request.setValue({value}, forHTTPHeaderField: {}){note}",
            swift_str(name)
        );
    }
    match &r.body {
        Body::Empty => {}
        Body::Text(text) => {
            let _ = writeln!(out, "request.httpBody = Data({}.utf8)", swift_str(text));
        }
        Body::Binary(b64) => {
            let _ = writeln!(out, "request.httpBody = Data(base64Encoded: \"{b64}\")!");
        }
    }
    out.push_str(
        "\nlet done = DispatchSemaphore(value: 0)\nURLSession.shared.dataTask(with: request) { data, \
         response, error in\n    if let http = response as? HTTPURLResponse { print(http.statusCode) }\n    \
         if let data = data { print(String(decoding: data, as: UTF8.self)) }\n    \
         if let error = error { print(error) }\n    done.signal()\n}.resume()\ndone.wait()\n",
    );
    out
}

/// `HTTPie` header argument `Name:value`, with `Name;` for an empty value.
fn httpie_header(name: &str, value: &str) -> String {
    if value.is_empty() {
        return format!("{name};");
    }
    // A backslash that precedes a separator would escape it; `@` after `:` reads a file.
    let mut escaped = String::new();
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\'
            && chars
                .peek()
                .is_some_and(|n| matches!(n, ':' | '=' | '@' | ';' | '\\'))
        {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    let escaped = escaped
        .strip_prefix('@')
        .map_or(escaped.clone(), |rest| format!("\\@{rest}"));
    format!("{name}:{escaped}")
}

fn httpie(r: &Request) -> String {
    let mut out = r.cut_note("#");
    let mut args: Vec<String> = Vec::new();
    let mut input = String::new();
    match &r.body {
        Body::Empty => args.push("--ignore-stdin".to_owned()),
        Body::Text(text) => {
            args.push("--raw".to_owned());
            args.push(quote(text));
        }
        Body::Binary(b64) => {
            let _ = write!(input, "printf '%s' {} | base64 -d | ", quote(b64));
        }
    }
    args.push(quote(&r.method));
    args.push(quote(&r.url));
    args.extend(r.headers.iter().map(|(n, v)| quote(&httpie_header(n, v))));
    out.push_str(&input);
    out.push_str("http");
    for arg in args {
        out.push_str(" \\\n  ");
        out.push_str(&arg);
    }
    out.push('\n');
    out
}

fn powershell(r: &Request) -> String {
    let mut r = r.clone();
    let content_type = r.take_header("content-type");
    let user_agent = r.take_header("user-agent");
    let mut out = r.cut_note("#");
    if !r.headers.is_empty() {
        out.push_str("$headers = @{\n");
        for (name, value) in &r.headers {
            let _ = writeln!(
                out,
                "    {} = {}",
                powershell_str(name),
                powershell_str(value)
            );
        }
        out.push_str("}\n");
    }
    let mut call = format!(
        "Invoke-WebRequest -UseBasicParsing -Method {} -Uri {}",
        powershell_str(&r.method),
        powershell_str(&r.url)
    );
    if !r.headers.is_empty() {
        call.push_str(" -Headers $headers");
    }
    if let Some(t) = &content_type {
        let _ = write!(call, " -ContentType {}", powershell_str(t));
    }
    if let Some(ua) = &user_agent {
        let _ = write!(call, " -UserAgent {}", powershell_str(ua));
    }
    match &r.body {
        Body::Empty => {}
        Body::Text(text) => {
            let _ = writeln!(out, "$body = {}", powershell_str(text));
            // A string body is encoded by the Content-Type's charset; bytes are sent as they are.
            call.push_str(if text.is_ascii() {
                " -Body $body"
            } else {
                " -Body ([System.Text.Encoding]::UTF8.GetBytes($body))"
            });
        }
        Body::Binary(b64) => {
            let _ = writeln!(out, "$body = [System.Convert]::FromBase64String('{b64}')");
            call.push_str(" -Body $body");
        }
    }
    let _ = writeln!(out, "$response = {call}");
    out.push_str("$response.StatusCode\n$response.Content\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_literals_pick_the_readable_form_when_it_is_safe() {
        assert_eq!(python_str("plain"), "\"plain\"");
        assert_eq!(python_str(r#"{"a":1}"#), r#"'{"a":1}'"#);
        assert_eq!(python_str(r#"{"a":"x\ny"}"#), r#"r'{"a":"x\ny"}'"#);
        assert_eq!(python_str("a\nb"), "\"\"\"a\nb\"\"\"");
        assert_eq!(python_str("a\\\nb"), "r\"\"\"a\\\nb\"\"\"");
        // Unsafe for a raw or triple-quoted literal: the escaped form.
        assert_eq!(python_str("it's \"x\""), r#""it's \"x\"""#);
        assert_eq!(python_str("a\nb\""), r#""a\nb\"""#);
        assert_eq!(python_str("a\nb\\"), r#""a\nb\\""#);
        assert_eq!(python_str("a\r\nb"), r#""a\r\nb""#);
        assert_eq!(python_str("\u{1b}[0m\u{2028}"), r#""\x1b[0m\u2028""#);
    }

    #[test]
    fn javascript_literals_leave_templates_and_backslashes_alone() {
        assert_eq!(js_str("a\nb"), "`a\nb`");
        assert_eq!(js_str("a\nb${c}"), r#""a\nb${c}""#);
        assert_eq!(js_str("a\nb`c"), r#""a\nb`c""#);
        assert_eq!(js_str(r"a\b"), r#""a\\b""#);
        assert_eq!(js_str(r#"say "x""#), r#"'say "x"'"#);
    }

    #[test]
    fn kotlin_literals_escape_dollars_and_use_raw_strings_only_without_them() {
        assert_eq!(kotlin_str(r#"{"a":1}"#), r#""""{"a":1}""""#);
        assert_eq!(kotlin_str("$5"), r#""\$5""#);
        assert_eq!(kotlin_str("\"$5\""), r#""\"\$5\"""#);
        assert_eq!(kotlin_str("a\"\"\"b"), r#""a\"\"\"b""#);
        assert_eq!(kotlin_str("ends\""), r#""ends\"""#);
        assert_eq!(kotlin_str("tab\there\u{1}"), r#""tab\there\u0001""#);
    }

    #[test]
    fn swift_literals_use_extended_delimiters_for_quotes_and_backslashes() {
        assert_eq!(swift_str(r"C:\dir"), "#\"C:\\dir\"#");
        assert_eq!(swift_str("a\nb"), "#\"\"\"\na\nb\n\"\"\"#");
        assert_eq!(swift_str("plain"), "\"plain\"");
        assert_eq!(swift_str("say \"x\"#"), "\"say \\\"x\\\"#\"");
        assert_eq!(swift_str("\\#(x)"), "\"\\\\#(x)\"");
        assert_eq!(swift_latin1("Zo\u{eb}"), "\"Zo\\u{c3}\\u{ab}\"");
    }

    #[test]
    fn powershell_literals_never_expand_dollars_or_backticks() {
        assert_eq!(powershell_str("it's $x `y`"), "'it''s $x `y`'");
        assert_eq!(powershell_str("\u{2019}"), "'\u{2019}\u{2019}'");
        assert_eq!(powershell_str("a\nb"), "@'\na\nb\n'@");
        assert_eq!(powershell_str("a\n'@\nb"), "\"a`n'@`nb\"");
        assert_eq!(powershell_str("a\r\n$x`"), "\"a`r`n`$x``\"");
        assert_eq!(
            powershell_str("\u{1b}\u{201c}"),
            "\"$([char]0x1b)`\u{201c}\""
        );
    }

    #[test]
    fn httpie_headers_escape_what_the_tool_would_read_as_syntax() {
        assert_eq!(httpie_header("x", ""), "x;");
        assert_eq!(httpie_header("x", "a=1"), "x:a=1");
        assert_eq!(httpie_header("x", "@file"), r"x:\@file");
        assert_eq!(httpie_header("x", r"a\:b"), r"x:a\\:b");
        assert_eq!(httpie_header("x", r"C:\dir"), r"x:C:\dir");
    }
}
