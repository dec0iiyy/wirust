//! The control plane routes of the rules engine and of breakpoint edits.
//!
//! `control::route` checks Host, Origin and the token first, then hands every API request
//! here; [`route`] answers the paths it owns and returns `None` for the rest.
//!
//! | Route | Answer |
//! |---|---|
//! | `GET /api/v1/rules` | [`Report`](crate::rules::Report): rules, watched file, last load error |
//! | `PUT /api/v1/rules` | replaces the whole set from `{"rules": [...]}`; `400` with the errors |
//! | `POST /api/v1/rules/{name}/toggle` | `{"name", "enabled"}`; `404` for no such rule |
//! | `POST /api/v1/pauses/{id}/edit` | resolves the pause with an [`Edit`]; `400` leaves it pending |

use std::collections::BTreeMap;

use base64::Engine as _;
use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, StatusCode, Uri};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::intercept::{Edit, Pauses, Phase, Resolution, Server};
use crate::rules::{Rules, RulesFile};

/// Largest request body the control plane reads (a rule set or an edit), in bytes.
pub(crate) const MAX_BODY: usize = 1024 * 1024;

/// Most headers one edit may set or remove.
pub(crate) const MAX_EDIT_HEADERS: usize = 100;

/// Answers the routes this module owns, `None` for any other path.
pub(crate) fn route(
    rules: Option<&Rules>,
    pauses: &Pauses,
    method: &Method,
    segments: &[&str],
    body: &Bytes,
) -> Option<(StatusCode, Value)> {
    Some(match (method, segments) {
        (_, ["rules", ..]) if rules.is_none() => error(StatusCode::NOT_FOUND, "rules are off"),
        (&Method::GET, ["rules"]) => (StatusCode::OK, json!(rules?.report())),
        (&Method::PUT, ["rules"]) => put_rules(rules?, body),
        (&Method::POST, ["rules", name, "toggle"]) => match rules?.toggle(name) {
            Some(enabled) => (StatusCode::OK, json!({"name": name, "enabled": enabled})),
            None => error(StatusCode::NOT_FOUND, "no such rule"),
        },
        (&Method::POST, ["pauses", id, "edit"]) => edit(pauses, id, body),
        (_, ["rules"] | ["rules", _, "toggle"] | ["pauses", _, "edit"]) => {
            error(StatusCode::METHOD_NOT_ALLOWED, "wrong method")
        }
        _ => return None,
    })
}

fn error(status: StatusCode, message: &str) -> (StatusCode, Value) {
    (status, json!({ "error": message }))
}

fn put_rules(rules: &Rules, body: &Bytes) -> (StatusCode, Value) {
    let file: RulesFile = match serde_json::from_slice(body) {
        Ok(file) => file,
        Err(e) => return error(StatusCode::BAD_REQUEST, &e.to_string()),
    };
    match rules.replace(&file) {
        Ok(()) => (StatusCode::OK, json!(rules.report())),
        Err(e) => error(StatusCode::BAD_REQUEST, &e),
    }
}

/// The JSON body of `POST /api/v1/pauses/{id}/edit`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct EditBody {
    /// New method (request phase).
    method: Option<String>,
    /// New path and query (`/a?b`) or absolute `http(s)://` URL (request phase).
    url: Option<String>,
    /// New status (response phase).
    status: Option<u16>,
    /// Headers to set.
    #[serde(default)]
    set_headers: BTreeMap<String, String>,
    /// Headers to remove.
    #[serde(default)]
    remove_headers: Vec<String>,
    /// New body as text.
    body: Option<String>,
    /// New body as base64.
    body_base64: Option<String>,
}

fn edit(pauses: &Pauses, id: &str, body: &Bytes) -> (StatusCode, Value) {
    let Some((id, phase)) = id
        .parse::<u64>()
        .ok()
        .and_then(|id| Some((id, pauses.phase(id)?)))
    else {
        return error(StatusCode::NOT_FOUND, "no such pending pause");
    };
    let edit = match parse_edit(body, phase) {
        Ok(edit) => edit,
        Err(e) => return error(StatusCode::BAD_REQUEST, &e),
    };
    if pauses.resolve(id, Resolution::Edit(edit)) {
        (StatusCode::OK, json!({ "resolved": id }))
    } else {
        error(StatusCode::NOT_FOUND, "no such pending pause")
    }
}

/// Validates an edit for a pause in `phase`.
///
/// # Errors
///
/// Unknown fields, fields of the other phase, invalid method, URL, status, header name or
/// value (CR, LF and other control characters included), too many headers, both body forms.
pub(crate) fn parse_edit(body: &Bytes, phase: Phase) -> Result<Edit, String> {
    let body: EditBody = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    if body.set_headers.len() + body.remove_headers.len() > MAX_EDIT_HEADERS {
        return Err(format!("at most {MAX_EDIT_HEADERS} headers per edit"));
    }
    let request_only = body.method.is_some() || body.url.is_some();
    match phase {
        Phase::Request if body.status.is_some() => {
            return Err("status is for the response phase".to_owned());
        }
        Phase::Response if request_only => {
            return Err("method and url are for the request phase".to_owned());
        }
        _ => {}
    }
    let mut edit = Edit::default();
    for (name, value) in &body.set_headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| format!("invalid header name {name:?}"))?;
        let value =
            HeaderValue::from_str(value).map_err(|_| format!("invalid value for header {name}"))?;
        edit.set_headers.push((name, value));
    }
    for name in &body.remove_headers {
        edit.remove_headers.push(
            HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| format!("invalid header name {name:?}"))?,
        );
    }
    edit.body = match (body.body, body.body_base64) {
        (Some(_), Some(_)) => return Err("give body or body_base64, not both".to_owned()),
        (Some(text), None) => Some(Bytes::from(text)),
        (None, Some(b64)) => Some(Bytes::from(
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| format!("body_base64: {e}"))?,
        )),
        (None, None) => None,
    };
    if let Some(code) = body.status {
        edit.status = Some(
            (100..=599)
                .contains(&code)
                .then(|| StatusCode::from_u16(code).ok())
                .flatten()
                .ok_or_else(|| format!("invalid status {code}"))?,
        );
    }
    if let Some(method) = body.method {
        edit.method =
            Some(Method::from_bytes(method.as_bytes()).map_err(|_| "invalid method".to_owned())?);
    }
    if let Some(url) = body.url {
        let (server, path) = parse_url(&url)?;
        edit.server = server;
        edit.path = Some(path);
    }
    Ok(edit)
}

/// Splits a path or absolute `http(s)` URL into the server (if any) and the path and query.
pub(crate) fn parse_url(url: &str) -> Result<(Option<Server>, String), String> {
    let uri: Uri = url.parse().map_err(|_| format!("invalid url {url:?}"))?;
    let path = uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    if !path.starts_with('/') {
        return Err(format!("invalid url {url:?}"));
    }
    let server = match (uri.scheme_str(), uri.authority()) {
        (None, None) => None,
        (Some(scheme @ ("http" | "https")), Some(authority)) => {
            if authority.as_str().contains('@') {
                return Err("credentials in the url are not supported".to_owned());
            }
            let scheme = if scheme == "https" { "https" } else { "http" };
            Some(Server {
                scheme,
                host: authority
                    .host()
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_owned(),
                port: authority
                    .port_u16()
                    .unwrap_or(if scheme == "https" { 443 } else { 80 }),
            })
        }
        _ => return Err(format!("url must be a path or an http(s) URL, got {url:?}")),
    };
    Ok((server, path.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str, phase: Phase) -> Result<Edit, String> {
        parse_edit(&Bytes::from(json.to_owned()), phase)
    }

    #[test]
    fn edits_parse_and_bad_ones_are_refused() -> Result<(), String> {
        let edit = parse(
            r#"{"method":"PUT","url":"https://[::1]:8443/x?y=1","set_headers":{"x-a":"1"},
                "remove_headers":["cookie"],"body_base64":"aGk="}"#,
            Phase::Request,
        )?;
        assert_eq!(edit.method, Some(Method::PUT));
        assert_eq!(edit.path.as_deref(), Some("/x?y=1"));
        let server = edit.server.ok_or("server")?;
        assert_eq!(
            (server.scheme, server.host.as_str(), server.port),
            ("https", "::1", 8443)
        );
        assert_eq!(edit.body, Some(Bytes::from_static(b"hi")));
        let edit = parse(r#"{"status":201,"body":"ok"}"#, Phase::Response)?;
        assert_eq!(edit.status, Some(StatusCode::CREATED));

        let bad = [
            (
                r#"{"set_headers":{"x-a":"v\r\nInjected: 1"}}"#,
                Phase::Request,
            ),
            (r#"{"set_headers":{"bad name":"v"}}"#, Phase::Request),
            (r#"{"set_headers":{"x-a":"v\n"}}"#, Phase::Response),
            (r#"{"url":"/a b"}"#, Phase::Request),
            (r#"{"url":"ftp://h/x"}"#, Phase::Request),
            (r#"{"url":"http://u:p@h/x"}"#, Phase::Request),
            (r#"{"method":"GE T"}"#, Phase::Request),
            (r#"{"status":99}"#, Phase::Response),
            (r#"{"status":200}"#, Phase::Request),
            (r#"{"method":"GET"}"#, Phase::Response),
            (r#"{"body":"a","body_base64":"YQ=="}"#, Phase::Request),
            (r#"{"body_base64":"!!"}"#, Phase::Request),
            (r#"{"unknown":1}"#, Phase::Request),
            ("not json", Phase::Request),
        ];
        for (json, phase) in bad {
            assert!(parse(json, phase).is_err(), "should be refused: {json}");
        }
        let many: BTreeMap<String, String> = (0..=MAX_EDIT_HEADERS)
            .map(|i| (format!("x-{i}"), "v".to_owned()))
            .collect();
        let json =
            serde_json::to_string(&json!({ "set_headers": many })).map_err(|e| e.to_string())?;
        assert!(parse(&json, Phase::Request).is_err(), "too many headers");
        Ok(())
    }
}
