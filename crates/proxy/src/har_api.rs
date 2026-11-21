//! Control-plane routes for interchange: `GET /api/v1/har` and
//! `GET /api/v1/flows/{id}/curl`. `control::route` calls [`route`] after its Host, Origin
//! and token checks.

use std::sync::Arc;

use bytes::Bytes;
use http::header::{self, HeaderValue};
use http::{Method, Response, StatusCode};
use serde::Serialize;

use crate::events::{Filter, FlowStore, StoredFlow};
use crate::flow::Event;
use crate::har::{self, Plus, percent_decode};
use crate::query::{MAX_QUERY_LEN, Query};
use crate::{codegen, curl, events::Flow};

/// Answers the interchange routes; `None` leaves the request to `control::route`.
pub(crate) fn route(
    store: &FlowStore,
    method: &Method,
    segments: &[&str],
    query: &str,
) -> Option<Response<Bytes>> {
    let get = method == Method::GET;
    Some(match segments {
        ["har"] if get => har(store, query),
        ["flows", id, "curl"] if get => curl(store, id),
        ["flows", id, "code"] if get => code(store, id, query),
        ["har"] | ["flows", _, "curl" | "code"] => {
            error(StatusCode::METHOD_NOT_ALLOWED, "wrong method")
        }
        _ => return None,
    })
}

/// The `q` parameter of an API query string, parsed; `Ok(None)` when absent or empty.
///
/// # Errors
///
/// The parse error as text, for a 400 answer.
pub(crate) fn search(query: &str) -> Result<Option<Arc<Query>>, String> {
    let Some(raw) = param(query, "q") else {
        return Ok(None);
    };
    // Escapes take three bytes per character: refuse longer input before decoding it.
    if raw.len() > MAX_QUERY_LEN * 3 {
        return Err(format!(
            "the query is {} bytes; the limit is {MAX_QUERY_LEN}",
            raw.len()
        ));
    }
    let text = percent_decode(raw, Plus::Space);
    if text.trim().is_empty() {
        return Ok(None);
    }
    Query::parse(&text)
        .map(|q| Some(Arc::new(q)))
        .map_err(|e| e.to_string())
}

fn param<'q>(query: &'q str, key: &str) -> Option<&'q str> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find_map(|(k, v)| (k == key).then_some(v))
}

fn har(store: &FlowStore, query: &str) -> Response<Bytes> {
    let search = match search(query) {
        Ok(search) => search,
        Err(e) => return error(StatusCode::BAD_REQUEST, &e),
    };
    let filter = Filter {
        limit: param(query, "limit").and_then(|v| v.parse().ok()),
        query: search,
        ..Filter::default()
    };
    let flows: Vec<Arc<Flow>> = store
        .list(.., &filter)
        .into_iter()
        .filter_map(|f| match f {
            StoredFlow::Done(flow) => Some(flow),
            StoredFlow::Pending(_) => None,
        })
        .collect();
    let document = har::to_har_with_ws(flows.iter().map(AsRef::as_ref), Some(store.ws()));
    let body = match serde_json::to_vec(&document) {
        Ok(body) => body,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    let mut response = respond(StatusCode::OK, "application/json", Bytes::from(body));
    let disposition = format!("attachment; filename=\"{}\"", har::download_name());
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, value);
    }
    response
}

fn curl(store: &FlowStore, id: &str) -> Response<Bytes> {
    let flow = id.parse().ok().and_then(|id| store.get(id));
    match flow {
        Some(StoredFlow::Done(flow)) => match &flow.record {
            Event::Exchange(x) => respond(
                StatusCode::OK,
                "text/plain; charset=utf-8",
                Bytes::from(curl::command(x) + "\n"),
            ),
            Event::TlsFailure(_) | Event::Tunnel(_) => {
                error(StatusCode::NOT_FOUND, "the flow is not an HTTP exchange")
            }
        },
        Some(StoredFlow::Pending(_)) => {
            error(StatusCode::CONFLICT, "the exchange is still running")
        }
        None => error(StatusCode::NOT_FOUND, "no such flow"),
    }
}

/// `GET /api/v1/flows/{id}/code?lang=`: the request as code in one of [`codegen::Lang`].
fn code(store: &FlowStore, id: &str, query: &str) -> Response<Bytes> {
    let Some(lang) = param(query, "lang").and_then(codegen::Lang::parse) else {
        let names: Vec<&str> = codegen::Lang::ALL.iter().map(|l| l.id()).collect();
        return error(
            StatusCode::BAD_REQUEST,
            &format!("lang must be one of {}", names.join(", ")),
        );
    };
    let flow = id.parse().ok().and_then(|id| store.get(id));
    match flow {
        Some(StoredFlow::Done(flow)) => match &flow.record {
            Event::Exchange(x) => respond(
                StatusCode::OK,
                "text/plain; charset=utf-8",
                Bytes::from(codegen::generate(lang, x)),
            ),
            Event::TlsFailure(_) | Event::Tunnel(_) => {
                error(StatusCode::NOT_FOUND, "the flow is not an HTTP exchange")
            }
        },
        Some(StoredFlow::Pending(_)) => {
            error(StatusCode::CONFLICT, "the exchange is still running")
        }
        None => error(StatusCode::NOT_FOUND, "no such flow"),
    }
}

fn respond(status: StatusCode, content_type: &'static str, body: Bytes) -> Response<Bytes> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

fn error(status: StatusCode, message: &str) -> Response<Bytes> {
    let body = serde_json::to_vec(&ErrorBody { error: message }).unwrap_or_default();
    respond(status, "application/json", Bytes::from(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::FlowEvent;
    use crate::query::tests::exchange;

    fn store() -> FlowStore {
        let store = FlowStore::new(10);
        for (id, host, status) in [(1, "a.test", 200), (2, "b.test", 404), (3, "a.test", 500)] {
            let x = exchange(id, "GET", &format!("https://{host}/x"), status);
            store.apply(&FlowEvent::finished(Event::Exchange(Box::new(x))));
        }
        store
    }

    fn har_ids(response: &Response<Bytes>) -> Vec<String> {
        let value: serde_json::Value = serde_json::from_slice(response.body()).expect("JSON body");
        value["log"]["entries"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|e| e["request"]["url"].as_str().unwrap_or_default().to_owned())
            .collect()
    }

    #[test]
    fn har_route_filters_and_names_the_download() {
        let store = store();
        let response = route(
            &store,
            &Method::GET,
            &["har"],
            "q=host%3Aa.test+status%3A5xx",
        )
        .expect("handled");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(har_ids(&response), ["https://a.test/x"]);
        let disposition = response.headers()[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap_or_default();
        assert!(disposition.starts_with(&format!("attachment; filename=\"{}-", crate::NAME)));
        assert!(disposition.ends_with(".har\""));
        let all = route(&store, &Method::GET, &["har"], "limit=2").expect("handled");
        assert_eq!(har_ids(&all).len(), 2);
    }

    #[test]
    fn bad_and_huge_queries_are_400() {
        let store = store();
        let bad = route(&store, &Method::GET, &["har"], "q=status%3Aabc").expect("handled");
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
        let huge = format!("q={}", "a".repeat(1024 * 1024));
        let huge = route(&store, &Method::GET, &["har"], &huge).expect("handled");
        assert_eq!(huge.status(), StatusCode::BAD_REQUEST);
        assert!(search("q=").is_ok_and(|q| q.is_none()));
    }

    #[test]
    fn curl_route_answers_text_and_refuses_other_methods() {
        let store = store();
        let ok = route(&store, &Method::GET, &["flows", "2", "curl"], "").expect("handled");
        assert_eq!(ok.status(), StatusCode::OK);
        assert!(ok.body().starts_with(b"curl"));
        let missing = route(&store, &Method::GET, &["flows", "9", "curl"], "").expect("handled");
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let post = route(&store, &Method::POST, &["har"], "").expect("handled");
        assert_eq!(post.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(route(&store, &Method::GET, &["flows"], "").is_none());
    }

    #[test]
    fn code_route_answers_plain_text_per_language() {
        let store = store();
        let path = ["flows", "2", "code"];
        for lang in codegen::Lang::ALL {
            let query = format!("lang={}", lang.id());
            let ok = route(&store, &Method::GET, &path, &query).expect("handled");
            assert_eq!(ok.status(), StatusCode::OK, "{}", lang.id());
            assert_eq!(
                ok.headers()[header::CONTENT_TYPE],
                "text/plain; charset=utf-8"
            );
            let text = String::from_utf8_lossy(ok.body());
            assert!(text.contains("https://b.test/x"), "{}: {text}", lang.id());
        }
    }

    #[test]
    fn code_route_refuses_unknown_languages_flows_and_methods() {
        let store = store();
        for query in ["", "lang=", "lang=cobol", "lang=Python", "other=python"] {
            let bad = route(&store, &Method::GET, &["flows", "2", "code"], query).expect("handled");
            assert_eq!(bad.status(), StatusCode::BAD_REQUEST, "{query:?}");
            let body = String::from_utf8_lossy(bad.body());
            assert!(
                body.contains("python") && body.contains("powershell"),
                "{body}"
            );
        }
        for id in ["9", "x", "-1"] {
            let missing = route(&store, &Method::GET, &["flows", id, "code"], "lang=python")
                .expect("handled");
            assert_eq!(missing.status(), StatusCode::NOT_FOUND, "{id}");
        }
        let post = route(
            &store,
            &Method::POST,
            &["flows", "2", "code"],
            "lang=python",
        )
        .expect("handled");
        assert_eq!(post.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
