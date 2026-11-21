//! The control plane routes of replay, compose and the passthrough lists.
//!
//! `control::route` checks Host, Origin and the token first, then hands API requests here;
//! [`route`] answers the paths it owns and returns `None` for the rest.
//!
//! | Route | Answer |
//! |---|---|
//! | `POST /api/v1/flows/{id}/replay` | `201 {"flow_id"}`; body: optional edit plus `apply_rules` |
//! | `POST /api/v1/compose` | `201 {"flow_id"}`; body: method, url, headers, body, `apply_rules` |
//! | `GET /api/v1/passthrough` | `{"passthrough": [...], "decrypt_only": [...]}` |
//! | `PUT /api/v1/passthrough` | replaces both lists at once; `400` with the first bad pattern |

use base64::Engine as _;
use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::events::{FlowStore, StoredFlow};
use crate::flow::Event;
use crate::intercept::Phase;
use crate::passthrough::{ListsBody, Passthrough};
use crate::proxy::Proxy;
use crate::replay::{BuildError, Outgoing, Refusal, Replayer, without_recomputed};
use crate::rules_api::{MAX_EDIT_HEADERS, parse_edit, parse_url};

/// What the routes act on: the replayer (bound to the proxy) and the live passthrough lists.
#[derive(Debug, Clone)]
pub(crate) struct Handles {
    replayer: Replayer,
    passthrough: Passthrough,
}

impl Handles {
    /// Shares `proxy`'s state; call it after the proxy's last `refuse_target`.
    pub(crate) fn new(proxy: &Proxy) -> Self {
        Self {
            replayer: Replayer::new(proxy.shared_state()),
            passthrough: proxy.passthrough().clone(),
        }
    }
}

/// Answers the routes this module owns, `None` for any other path.
pub(crate) fn route(
    handles: &Handles,
    store: &FlowStore,
    method: &Method,
    segments: &[&str],
    body: &Bytes,
) -> Option<(StatusCode, Value)> {
    Some(match (method, segments) {
        (&Method::POST, ["flows", id, "replay"]) => replay(handles, store, id, body),
        (&Method::POST, ["compose"]) => compose(handles, body),
        (&Method::GET, ["passthrough"]) => (StatusCode::OK, json!(*handles.passthrough.current())),
        (&Method::PUT, ["passthrough"]) => put_passthrough(&handles.passthrough, body),
        (_, ["flows", _, "replay"] | ["compose" | "passthrough"]) => {
            error(StatusCode::METHOD_NOT_ALLOWED, "wrong method")
        }
        _ => return None,
    })
}

fn error(status: StatusCode, message: &str) -> (StatusCode, Value) {
    (status, json!({ "error": message }))
}

fn started(handles: &Handles, out: Outgoing) -> (StatusCode, Value) {
    match handles.replayer.start(out) {
        Ok(id) => (StatusCode::CREATED, json!({ "flow_id": id })),
        Err(Refusal::SelfTarget) => error(
            StatusCode::FORBIDDEN,
            "refusing to send a replay to the control plane or the proxy itself",
        ),
        Err(Refusal::Busy(why)) => error(StatusCode::TOO_MANY_REQUESTS, &why),
        Err(Refusal::Invalid(why)) => error(StatusCode::BAD_REQUEST, &why),
    }
}

fn replay(handles: &Handles, store: &FlowStore, id: &str, body: &Bytes) -> (StatusCode, Value) {
    let flow = match id.parse().ok().and_then(|id| store.get(id)) {
        Some(StoredFlow::Done(flow)) => flow,
        Some(StoredFlow::Pending(_)) => {
            return error(StatusCode::CONFLICT, "the flow has not finished yet");
        }
        None => return error(StatusCode::NOT_FOUND, "no such flow"),
    };
    let Event::Exchange(exchange) = &flow.record else {
        return error(
            StatusCode::BAD_REQUEST,
            "only HTTP exchanges can be replayed",
        );
    };
    let (edit, apply_rules) = match split_apply_rules(body) {
        Ok((rest, apply_rules)) => match parse_edit(&rest, Phase::Request) {
            Ok(edit) => (edit, apply_rules),
            Err(e) => return error(StatusCode::BAD_REQUEST, &e),
        },
        Err(e) => return error(StatusCode::BAD_REQUEST, &e),
    };
    match Outgoing::from_flow(exchange, edit, apply_rules) {
        Ok(out) => started(handles, out),
        Err(BuildError::Conflict(e)) => error(StatusCode::CONFLICT, &e),
        Err(BuildError::Invalid(e)) => error(StatusCode::BAD_REQUEST, &e),
    }
}

/// Takes `apply_rules` out of a replay body; the rest is a breakpoint edit. An empty body
/// is no edit.
fn split_apply_rules(body: &Bytes) -> Result<(Bytes, bool), String> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok((Bytes::from_static(b"{}"), false));
    }
    let mut object: serde_json::Map<String, Value> =
        serde_json::from_slice(body).map_err(|e| e.to_string())?;
    let apply_rules = match object.remove("apply_rules") {
        None => false,
        Some(Value::Bool(b)) => b,
        Some(_) => return Err("apply_rules must be true or false".to_owned()),
    };
    let rest = serde_json::to_vec(&object).map_err(|e| e.to_string())?;
    Ok((Bytes::from(rest), apply_rules))
}

/// The JSON body of `POST /api/v1/compose`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeBody {
    method: String,
    /// Absolute `http(s)://` URL.
    url: String,
    /// `[name, value]` pairs, sent in this order.
    #[serde(default)]
    headers: Vec<(String, String)>,
    body: Option<String>,
    body_base64: Option<String>,
    #[serde(default)]
    apply_rules: bool,
}

fn compose(handles: &Handles, body: &Bytes) -> (StatusCode, Value) {
    match parse_compose(body) {
        Ok(out) => started(handles, out),
        Err(e) => error(StatusCode::BAD_REQUEST, &e),
    }
}

/// Validates a composed request with the rules of breakpoint edits.
///
/// # Errors
///
/// Unknown fields, an invalid method, a URL that is not absolute `http(s)` or carries
/// credentials, invalid header names or values, too many headers, both body forms.
fn parse_compose(body: &Bytes) -> Result<Outgoing, String> {
    let body: ComposeBody = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    let method = Method::from_bytes(body.method.as_bytes()).map_err(|_| "invalid method")?;
    let (server, path) = parse_url(&body.url)?;
    let server = server.ok_or("url must be an absolute http(s) URL")?;
    if body.headers.len() > MAX_EDIT_HEADERS {
        return Err(format!("at most {MAX_EDIT_HEADERS} headers"));
    }
    let mut headers = Vec::with_capacity(body.headers.len());
    for (name, value) in &body.headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| format!("invalid header name {name:?}"))?;
        let value =
            HeaderValue::from_str(value).map_err(|_| format!("invalid value for header {name}"))?;
        headers.push((name, value));
    }
    let bytes = match (body.body, body.body_base64) {
        (Some(_), Some(_)) => return Err("give body or body_base64, not both".to_owned()),
        (Some(text), None) => Bytes::from(text),
        (None, Some(b64)) => Bytes::from(
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| format!("body_base64: {e}"))?,
        ),
        (None, None) => Bytes::new(),
    };
    Ok(Outgoing {
        method,
        server,
        path,
        headers: without_recomputed(headers),
        body: bytes,
        replay_of: None,
        apply_rules: body.apply_rules,
    })
}

fn put_passthrough(passthrough: &Passthrough, body: &Bytes) -> (StatusCode, Value) {
    let lists = serde_json::from_slice::<ListsBody>(body)
        .map_err(|e| e.to_string())
        .and_then(ListsBody::parse);
    match lists {
        Ok(lists) => {
            passthrough.replace(lists);
            (StatusCode::OK, json!(*passthrough.current()))
        }
        Err(e) => error(StatusCode::BAD_REQUEST, &e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compose_bodies_are_validated() {
        let ok = parse_compose(&Bytes::from_static(
            br#"{"method":"POST","url":"http://h:81/p?q","headers":[["b","1"],["a","2"],["host","x"]],"body":"x"}"#,
        ))
        .expect("valid");
        assert_eq!((ok.server.port, ok.path.as_str()), (81, "/p?q"));
        let names: Vec<&str> = ok.headers.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["b", "a"], "order kept, host dropped");
        for bad in [
            r#"{"method":"GET","url":"/relative"}"#,
            r#"{"method":"GET","url":"http://u:p@h/"}"#,
            r#"{"method":"G T","url":"http://h/"}"#,
            r#"{"method":"GET","url":"http://h/","headers":[["x","a\r\nb: c"]]}"#,
            r#"{"method":"GET","url":"http://h/","body":"a","body_base64":"YQ=="}"#,
            r#"{"method":"GET","url":"http://h/","extra":1}"#,
        ] {
            assert!(
                parse_compose(&Bytes::from(bad)).is_err(),
                "should be refused: {bad}"
            );
        }
    }

    #[test]
    fn apply_rules_is_split_from_the_edit() {
        let (rest, apply) = split_apply_rules(&Bytes::from_static(
            br#"{"apply_rules":true,"method":"PUT"}"#,
        ))
        .expect("valid");
        assert!(apply);
        assert_eq!(rest, Bytes::from_static(br#"{"method":"PUT"}"#));
        assert_eq!(
            split_apply_rules(&Bytes::new()),
            Ok((Bytes::from_static(b"{}"), false))
        );
        assert!(split_apply_rules(&Bytes::from_static(br#"{"apply_rules":1}"#)).is_err());
    }
}
