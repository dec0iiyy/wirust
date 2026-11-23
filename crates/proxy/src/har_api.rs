//! Control-plane routes for interchange: `GET /api/v1/har` and
//! `GET /api/v1/flows/{id}/curl`. `control::route` calls [`route`] after its Host, Origin
//! and token checks.

use std::io::{self, Write as _};
use std::sync::Arc;

use bytes::Bytes;
use http::header::{self, HeaderValue};
use http::{Method, Response, StatusCode};
use http_body_util::{BodyExt as _, Full};
use serde::Serialize;
use tokio::sync::mpsc;

use crate::control::{ChannelBody, ControlBody};
use crate::events::{Filter, FlowStore, StoredFlow};
use crate::flow::Event;
use crate::har::{self, Plus, percent_decode};
use crate::query::{MAX_QUERY_LEN, Query};
use crate::ws::WsStore;
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

/// Bytes the HAR stream hands to the connection at a time.
const HAR_CHUNK: usize = 64 * 1024;

/// Chunks the HAR writer may run ahead of the client.
const HAR_CHUNKS_AHEAD: usize = 4;

/// `GET /api/v1/har`: the finished flows matching `q` (and `limit`) as a HAR document,
/// streamed (`docs/interchange.md`). `None` leaves other requests to [`route`].
pub(crate) fn har_route(
    store: &FlowStore,
    method: &Method,
    segments: &[&str],
    query: &str,
) -> Option<Response<ControlBody>> {
    if method != Method::GET || segments != ["har"] {
        return None;
    }
    Some(match har_flows(store, query) {
        Ok(flows) => har_stream(flows, store.ws().clone()),
        Err(e) => error(StatusCode::BAD_REQUEST, &e).map(|body| Full::new(body).boxed_unsync()),
    })
}

/// The finished flows a HAR request asks for, oldest first.
fn har_flows(store: &FlowStore, query: &str) -> Result<Vec<Arc<Flow>>, String> {
    let filter = Filter {
        limit: param(query, "limit").and_then(|v| v.parse().ok()),
        query: search(query)?,
        ..Filter::default()
    };
    let flows = store.list(.., &filter).into_iter();
    Ok(flows
        .filter_map(|f| match f {
            StoredFlow::Done(flow) => Some(flow),
            StoredFlow::Pending(_) => None,
        })
        .collect())
}

/// Serialises the HAR document of `flows` on a blocking thread, entry by entry, into a
/// chunked body: memory stays near one entry plus a few chunks, whatever the export size.
fn har_stream(flows: Vec<Arc<Flow>>, ws: WsStore) -> Response<ControlBody> {
    let (sender, receiver) = mpsc::channel::<Bytes>(HAR_CHUNKS_AHEAD);
    tokio::task::spawn_blocking(move || {
        let mut out = io::BufWriter::with_capacity(HAR_CHUNK, ChunkSender(sender));
        let document = har::StreamedHar::new(&flows, Some(&ws));
        // An error means the client went away; the body then just ends.
        if serde_json::to_writer(&mut out, &document).is_ok() {
            let _ = out.flush();
        }
    });
    let mut response = Response::new(ChannelBody { receiver }.boxed_unsync());
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let disposition = format!("attachment; filename=\"{}\"", har::download_name());
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, value);
    }
    response
}

/// A blocking [`io::Write`] into the channel of a [`ChannelBody`].
struct ChunkSender(mpsc::Sender<Bytes>);

impl io::Write for ChunkSender {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .blocking_send(Bytes::copy_from_slice(buf))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
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

    /// `GET /api/v1/har?{query}`: status, headers and the whole streamed body.
    async fn get_har(store: &FlowStore, query: &str) -> (Response<()>, Bytes) {
        let response = har_route(store, &Method::GET, &["har"], query).expect("handled");
        let (parts, body) = response.into_parts();
        let body = body.collect().await.expect("infallible").to_bytes();
        (Response::from_parts(parts, ()), body)
    }

    fn har_ids(body: &[u8]) -> Vec<String> {
        let value: serde_json::Value = serde_json::from_slice(body).expect("JSON body");
        value["log"]["entries"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|e| e["request"]["url"].as_str().unwrap_or_default().to_owned())
            .collect()
    }

    #[tokio::test]
    async fn har_route_filters_and_names_the_download() {
        let store = store();
        let (response, body) = get_har(&store, "q=host%3Aa.test+status%3A5xx").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(har_ids(&body), ["https://a.test/x"]);
        let disposition = response.headers()[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap_or_default();
        assert!(disposition.starts_with(&format!("attachment; filename=\"{}-", crate::NAME)));
        assert!(disposition.ends_with(".har\""));
        let (_, all) = get_har(&store, "limit=2").await;
        assert_eq!(har_ids(&all).len(), 2);
    }

    #[tokio::test]
    async fn the_streamed_har_is_the_bytes_the_built_document_serialises_to() {
        let store = store();
        let mut big = exchange(4, "POST", "https://c.test/up", 200);
        big.response_body = Some(crate::flow::BodyRecord::from_bytes(
            &vec![b'z'; 3 * HAR_CHUNK],
            3 * HAR_CHUNK as u64,
            false,
        ));
        store.apply(&FlowEvent::finished(Event::Exchange(Box::new(big))));
        let (response, body) = get_har(&store, "").await;
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        let flows = har_flows(&store, "").expect("no query");
        let built = har::to_har_with_ws(flows.iter().map(AsRef::as_ref), Some(store.ws()));
        let want = serde_json::to_vec(&built).expect("serialisable");
        assert_eq!(body.len(), want.len());
        assert!(body == want, "the streamed HAR differs from the built one");
        assert_eq!(har::from_har(&body).map(|f| f.len()).ok(), Some(4));
    }

    #[tokio::test]
    async fn bad_and_huge_queries_are_400() {
        let store = store();
        let (bad, _) = get_har(&store, "q=status%3Aabc").await;
        assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
        let huge = format!("q={}", "a".repeat(1024 * 1024));
        let (huge, _) = get_har(&store, &huge).await;
        assert_eq!(huge.status(), StatusCode::BAD_REQUEST);
        assert!(search("q=").is_ok_and(|q| q.is_none()));
        assert!(har_route(&store, &Method::POST, &["har"], "").is_none());
        assert!(har_route(&store, &Method::GET, &["flows"], "").is_none());
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
