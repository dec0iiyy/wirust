//! Redaction of secrets in captured traffic before `wirust mcp` hands it to an agent.
//!
//! Secret header values, secret query parameters, secret JSON fields and JWT-looking strings
//! are replaced by `[redacted: REASON]`. See `docs/mcp.md` for the rules.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

/// Words that make a header, query parameter or JSON field name secret, compared against
/// the name split at `-`, `_`, `.` and lower-to-upper case changes.
const SECRET_WORDS: &[&str] = &[
    "token",
    "key",
    "apikey",
    "secret",
    "password",
    "passwd",
    "pwd",
    "signature",
    "sig",
    "session",
    "sessionid",
    "sid",
    "auth",
    "authorization",
    "authentication",
    "jwt",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "csrf",
    "xsrf",
    "otp",
];

/// A JWT: a base64url JSON header (`eyJ`), a payload and a signature.
static JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}")
        .expect("the JWT pattern is valid")
});

/// What replaces a secret header value.
pub(crate) const HEADER: &str = "[redacted: secret header]";
/// What replaces a secret query parameter value.
pub(crate) const QUERY: &str = "[redacted: secret query parameter]";
/// What replaces a secret JSON field.
pub(crate) const FIELD: &str = "[redacted: secret field]";
/// What replaces a JWT.
pub(crate) const JWT_TEXT: &str = "[redacted: jwt]";

/// Whether a header, parameter or field called `name` holds a secret.
pub(crate) fn is_secret_name(name: &str) -> bool {
    words(name)
        .iter()
        .any(|word| SECRET_WORDS.contains(&word.as_str()))
}

/// `name` in lower-case words: `X-Api-Key` and `apiKey` give `x api key` and `api key`.
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

/// Replaces JWTs in `text`.
pub(crate) fn jwts(text: &str) -> String {
    JWT.replace_all(text, JWT_TEXT).into_owned()
}

/// Redacts the values of secret parameters in a query string or form body (`a=1&token=2`).
pub(crate) fn query_string(query: &str) -> String {
    let pairs: Vec<String> = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((name, _)) if is_secret_name(&percent_decoded(name)) => format!("{name}={QUERY}"),
            _ => pair.to_owned(),
        })
        .collect();
    pairs.join("&")
}

/// `%XX` escapes decoded, for matching parameter names only.
fn percent_decoded(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok());
        match (bytes[i], hex.and_then(|h| u8::from_str_radix(h, 16).ok())) {
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

/// Redacts the secret query parameters and JWTs of a URL.
pub(crate) fn url(url: &str) -> String {
    let (base, fragment) = url
        .split_once('#')
        .map_or((url, None), |(b, f)| (b, Some(f)));
    let redacted = match base.split_once('?') {
        Some((path, query)) => format!("{path}?{}", query_string(query)),
        None => base.to_owned(),
    };
    let whole = match fragment {
        Some(fragment) => format!("{redacted}#{}", query_string(fragment)),
        None => redacted,
    };
    jwts(&whole)
}

/// The value shown for header `name`: redacted when the name is secret, JWTs removed
/// otherwise.
pub(crate) fn header_value(name: &str, value: &str) -> String {
    if is_secret_name(name) {
        HEADER.to_owned()
    } else {
        jwts(value)
    }
}

/// Redacts a body text: JSON gets its secret fields replaced, a form body its secret
/// parameters; JWTs go everywhere.
pub(crate) fn body_text(text: &str) -> String {
    let trimmed = text.trim_start();
    if (trimmed.starts_with('{') || trimmed.starts_with('['))
        && let Ok(mut value) = serde_json::from_str::<Value>(text)
    {
        json(&mut value);
        return serde_json::to_string(&value).unwrap_or_else(|_| jwts(text));
    }
    let form_like = !text.contains(char::is_whitespace)
        && text.contains('=')
        && !text.contains(['{', '<', '"']);
    if form_like {
        return jwts(&query_string(text));
    }
    jwts(text)
}

/// Redacts a JSON value in place: fields with secret names, `[name, value]` header pairs,
/// `{"name", "value"}` objects (HAR headers, query strings and cookies) and JWTs in every
/// string. URLs get their secret query parameters redacted.
pub(crate) fn json(value: &mut Value) {
    match value {
        Value::String(text) => {
            *text = if text.starts_with("http://") || text.starts_with("https://") {
                url(text)
            } else {
                jwts(text)
            };
        }
        Value::Array(items) => {
            if let [Value::String(name), Value::String(header)] = items.as_mut_slice() {
                *header = header_value(name, header);
                return;
            }
            items.iter_mut().for_each(json);
        }
        Value::Object(map) => {
            let named_secret = map
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(is_secret_name);
            for (key, field) in map.iter_mut() {
                let secret_pair = named_secret && key == "value";
                if secret_pair || (is_secret_name(key) && !field.is_null()) {
                    *field = Value::String(FIELD.to_owned());
                } else {
                    json(field);
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Every literal secret of a flow that a generated text (curl, code) could repeat: secret
/// header values, secret query values and JWTs. Short values are skipped, as replacing them
/// would garble unrelated text.
pub(crate) fn literal_secrets(headers: &[(String, String)], url: &str) -> Vec<String> {
    let mut found: Vec<String> = headers
        .iter()
        .filter(|(name, _)| is_secret_name(name))
        .flat_map(|(name, value)| {
            let mut parts = vec![value.clone()];
            if name.eq_ignore_ascii_case("cookie") {
                parts.extend(
                    value
                        .split(';')
                        .filter_map(|c| c.split_once('=').map(|(_, v)| v.trim().to_owned())),
                );
            }
            if let Some((_, credential)) = value.split_once(' ') {
                parts.push(credential.trim().to_owned());
            }
            parts
        })
        .collect();
    if let Some((_, query)) = url.split_once('?') {
        found.extend(
            query
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .filter(|(name, _)| is_secret_name(&percent_decoded(name)))
                .map(|(_, value)| value.to_owned()),
        );
    }
    found.retain(|secret| secret.len() >= 4);
    // Longest first, so a whole header value goes before the credential inside it.
    found.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
    found.dedup();
    found
}

/// Replaces each of `secrets` and every JWT in `text`.
pub(crate) fn text_with(text: &str, secrets: &[String]) -> String {
    let mut out = text.to_owned();
    for secret in secrets {
        out = out.replace(secret.as_str(), "[redacted]");
    }
    jwts(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn names_split_into_words() {
        for secret in [
            "Authorization",
            "X-Api-Key",
            "apiKey",
            "access_token",
            "Set-Cookie",
            "X-Amz-Signature",
            "sessionid",
            "client_secret",
        ] {
            assert!(is_secret_name(secret), "{secret}");
        }
        for plain in [
            "author",
            "monkey",
            "content-type",
            "keyword",
            "page",
            "accept",
        ] {
            assert!(!is_secret_name(plain), "{plain}");
        }
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
    }

    #[test]
    fn json_bodies_lose_secret_fields() {
        let body = r#"{"user":"ann","password":"hunter2","nested":{"refresh_token":"r"},"n":null}"#;
        let out: Value = serde_json::from_str(&body_text(body)).expect("json");
        assert_eq!(out["user"], "ann");
        assert_eq!(out["password"], FIELD);
        assert_eq!(out["nested"]["refresh_token"], FIELD);
        assert_eq!(body_text("a=1&password=x"), format!("a=1&password={QUERY}"));
    }

    #[test]
    fn header_pairs_and_har_objects_are_redacted() {
        let mut value = json!({
            "request_headers": [["Authorization", "Bearer s3cret"], ["Accept", "*/*"]],
            "headers": [{"name": "Cookie", "value": "sid=1"}, {"name": "Host", "value": "h"}],
        });
        json(&mut value);
        assert_eq!(value["request_headers"][0][1], HEADER);
        assert_eq!(value["request_headers"][1][1], "*/*");
        assert_eq!(value["headers"][0]["value"], FIELD);
        assert_eq!(value["headers"][1]["value"], "h");
    }

    #[test]
    fn literal_secrets_come_out_of_generated_text() {
        let headers = vec![
            ("Authorization".to_owned(), "Bearer abcdef".to_owned()),
            ("Cookie".to_owned(), "a=12345; b=67890".to_owned()),
        ];
        let secrets = literal_secrets(&headers, "https://h/p?token=zzzz");
        let text = "curl -H 'Authorization: Bearer abcdef' -H 'Cookie: a=12345; b=67890' \
                    'https://h/p?token=zzzz'";
        let out = text_with(text, &secrets);
        for secret in ["abcdef", "12345", "67890", "zzzz"] {
            assert!(!out.contains(secret), "{out}");
        }
    }
}
