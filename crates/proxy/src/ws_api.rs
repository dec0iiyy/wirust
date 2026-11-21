//! Control-plane route for WebSocket messages: `GET /api/v1/flows/{id}/messages`.
//! `control::route` calls [`route`] after its Host, Origin and token checks.

use std::sync::Arc;

use bytes::Bytes;
use http::header::{self, HeaderValue};
use http::{Method, Response, StatusCode};
use serde::Serialize;

use crate::events::{FlowStore, StoredFlow};
use crate::flow::Event;
use crate::ws::{MAX_PAGE, WsMessage};

/// Messages one page holds when `limit` is not given.
const DEFAULT_PAGE: usize = 200;

/// The answer: one page of messages and how many the connection had in all.
#[derive(Serialize)]
struct Page {
    flow_id: u64,
    /// Messages seen on the connection so far, both directions.
    total: u64,
    /// Messages the per-flow ring no longer holds.
    dropped: u64,
    messages: Vec<Arc<WsMessage>>,
}

/// Answers `GET /api/v1/flows/{id}/messages?after=SEQ&limit=N`; `None` leaves the request
/// to `control::route`.
pub(crate) fn route(
    store: &FlowStore,
    method: &Method,
    segments: &[&str],
    query: &str,
) -> Option<Response<Bytes>> {
    let ["flows", id, "messages"] = segments else {
        return None;
    };
    if method != Method::GET {
        return Some(error(StatusCode::METHOD_NOT_ALLOWED, "wrong method"));
    }
    let Some((id, flow)) = id
        .parse::<u64>()
        .ok()
        .and_then(|id| Some((id, store.get(id)?)))
    else {
        return Some(error(StatusCode::NOT_FOUND, "no such flow"));
    };
    let total = match &flow {
        StoredFlow::Done(flow) => match &flow.record {
            Event::Exchange(x) => x.ws_messages,
            Event::TlsFailure(_) | Event::Tunnel(_) => None,
        },
        StoredFlow::Pending(_) => None,
    };
    let Some(total) = total else {
        return Some(error(StatusCode::NOT_FOUND, "the flow is not a WebSocket"));
    };
    let after = param(query, "after").and_then(|v| v.parse().ok());
    let limit = param(query, "limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_PAGE)
        .clamp(1, MAX_PAGE);
    let held = store.ws().len(id) as u64;
    let page = Page {
        flow_id: id,
        total,
        dropped: total.saturating_sub(held),
        messages: store.ws().list(id, after, limit),
    };
    let body = serde_json::to_vec(&page).unwrap_or_default();
    Some(respond(StatusCode::OK, Bytes::from(body)))
}

fn param<'q>(query: &'q str, key: &str) -> Option<&'q str> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find_map(|(k, v)| (k == key).then_some(v))
}

fn respond(status: StatusCode, body: Bytes) -> Response<Bytes> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

fn error(status: StatusCode, message: &str) -> Response<Bytes> {
    let body = serde_json::to_vec(&ErrorBody { error: message }).unwrap_or_default();
    respond(status, Bytes::from(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::FlowEvent;
    use crate::query::tests::exchange;
    use crate::ws::{Direction, Kind, Parsed, message};

    fn store() -> FlowStore {
        let store = FlowStore::with_ws_messages(10, 3);
        let mut ws = exchange(1, "GET", "https://a.test/socket", 101);
        ws.ws_messages = Some(0);
        store.apply(&FlowEvent::finished(Event::Exchange(Box::new(ws))));
        let plain = exchange(2, "GET", "https://a.test/x", 200);
        store.apply(&FlowEvent::finished(Event::Exchange(Box::new(plain))));
        for seq in 0..5 {
            let parsed = Parsed {
                kind: Kind::Text,
                kept: format!("m{seq}").into_bytes(),
                size: 2,
                compressed: false,
            };
            let m = message(1, seq, Direction::ServerToClient, &parsed);
            store.apply(&FlowEvent::WsMessage(Arc::new(m)));
        }
        store
    }

    fn json(response: &Response<Bytes>) -> serde_json::Value {
        serde_json::from_slice(response.body()).expect("JSON body")
    }

    #[test]
    fn pages_messages_and_counts_dropped_ones() {
        let store = store();
        let page = route(
            &store,
            &Method::GET,
            &["flows", "1", "messages"],
            "after=2&limit=1",
        )
        .expect("handled");
        assert_eq!(page.status(), StatusCode::OK);
        let value = json(&page);
        assert_eq!(
            (value["total"].as_u64(), value["dropped"].as_u64()),
            (Some(5), Some(2))
        );
        assert_eq!(value["messages"][0]["seq"].as_u64(), Some(3));
        assert_eq!(value["messages"].as_array().map(Vec::len), Some(1));
        let flow = store.get(1).expect("held");
        let StoredFlow::Done(flow) = flow else {
            panic!("done expected")
        };
        let Event::Exchange(x) = &flow.record else {
            panic!("exchange expected")
        };
        assert_eq!(x.ws_messages, Some(5));
    }

    #[test]
    fn refuses_plain_flows_unknown_ids_and_other_methods() {
        let store = store();
        let plain = route(&store, &Method::GET, &["flows", "2", "messages"], "").expect("handled");
        assert_eq!(plain.status(), StatusCode::NOT_FOUND);
        let missing =
            route(&store, &Method::GET, &["flows", "9", "messages"], "").expect("handled");
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let post = route(&store, &Method::POST, &["flows", "1", "messages"], "").expect("handled");
        assert_eq!(post.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(route(&store, &Method::GET, &["flows", "1"], "").is_none());
    }

    #[test]
    fn har_carries_web_socket_messages_both_ways() {
        let store = store();
        let flows: Vec<Arc<crate::events::Flow>> = store
            .list(.., &crate::events::Filter::default())
            .into_iter()
            .filter_map(|f| match f {
                StoredFlow::Done(flow) => Some(flow),
                StoredFlow::Pending(_) => None,
            })
            .collect();
        let har = crate::har::to_har_with_ws(flows.iter().map(AsRef::as_ref), Some(store.ws()));
        let value = serde_json::to_value(&har).expect("serialisable");
        let first = &value["log"]["entries"][0]["_webSocketMessages"][0];
        assert_eq!(first["type"], "receive");
        assert_eq!(first["opcode"], 1);
        assert_eq!(first["data"], "m2");
        assert!(first["time"].as_f64().is_some_and(|t| t > 1.0e9));
        assert!(
            value["log"]["entries"][1]
                .get("_webSocketMessages")
                .is_none()
        );
        let back = &har.log.entries[0].web_socket_messages[0];
        let message = back.to_message(1, 0).expect("known opcode");
        assert_eq!((message.kind, message.data.as_str()), (Kind::Text, "m2"));
        let binary = crate::har::HarWsMessage {
            kind: "send".to_owned(),
            time: 1.5,
            opcode: 2,
            data: "AAEC".to_owned(),
        };
        let message = binary.to_message(1, 1).expect("known opcode");
        assert_eq!(message.bytes(), [0, 1, 2]);
        assert_eq!(message.direction, Direction::ClientToServer);
    }

    #[test]
    fn evicting_a_flow_drops_its_messages() {
        let store = store();
        assert_eq!(store.ws().len(1), 3);
        for id in 3..20 {
            let x = exchange(id, "GET", "https://b.test/", 200);
            store.apply(&FlowEvent::finished(Event::Exchange(Box::new(x))));
        }
        assert!(store.ws().is_empty());
    }
}
