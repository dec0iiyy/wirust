//! Control-plane routes for decoded gRPC and protobuf messages:
//! `GET /api/v1/flows/{id}/grpc` and the loaded `.proto` schemas, `GET /api/v1/proto`.
//! `control::route` calls [`route`] after its Host, Origin and token checks.

use bytes::Bytes;
use http::header::{self, HeaderValue};
use http::{Method, Response, StatusCode};
use serde::Serialize;

use crate::events::{FlowStore, StoredFlow};
use crate::flow::Event;
use crate::grpc::{Call, decode_exchange_with};
use crate::schema::{Report, Schemas};

/// The answer: the flow id and its decoded call.
#[derive(Serialize)]
struct Answer {
    flow_id: u64,
    #[serde(flatten)]
    call: Call,
}

/// Answers `GET /api/v1/flows/{id}/grpc` and `GET /api/v1/proto`; `None` leaves the request
/// to `control::route`.
pub(crate) fn route(
    store: &FlowStore,
    schemas: Option<&Schemas>,
    method: &Method,
    segments: &[&str],
) -> Option<Response<Bytes>> {
    if segments == ["proto"] {
        return Some(proto(schemas, method));
    }
    let ["flows", id, "grpc"] = segments else {
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
    let call = match &flow {
        StoredFlow::Done(flow) => match &flow.record {
            Event::Exchange(x) => decode_exchange_with(x, schemas),
            Event::TlsFailure(_) | Event::Tunnel(_) => None,
        },
        StoredFlow::Pending(_) => {
            return Some(error(StatusCode::CONFLICT, "the flow has not finished"));
        }
    };
    let Some(call) = call else {
        return Some(error(
            StatusCode::NOT_FOUND,
            "the flow is not gRPC or protobuf",
        ));
    };
    let body = serde_json::to_vec(&Answer { flow_id: id, call }).unwrap_or_default();
    Some(respond(StatusCode::OK, Bytes::from(body)))
}

/// `GET /api/v1/proto`: the schema files (names only), services and methods; empty lists
/// when no `--proto` was given.
fn proto(schemas: Option<&Schemas>, method: &Method) -> Response<Bytes> {
    if method != Method::GET {
        return error(StatusCode::METHOD_NOT_ALLOWED, "wrong method");
    }
    let report = schemas.map_or_else(
        || Report {
            files: Vec::new(),
            services: Vec::new(),
            message: None,
            error: None,
        },
        Schemas::report,
    );
    let body = serde_json::to_vec(&report).unwrap_or_default();
    respond(StatusCode::OK, Bytes::from(body))
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
    use crate::body::Capture;
    use crate::events::FlowEvent;
    use crate::flow::BodyRecord;
    use crate::query::tests::exchange;

    fn store() -> FlowStore {
        let store = FlowStore::new(10);
        let mut x = exchange(1, "POST", "https://a.test/pkg.Svc/Get", 200);
        x.request_headers = vec![("content-type".to_owned(), "application/grpc".to_owned())];
        let mut capture = Capture::new(1024);
        capture.push(&[0, 0, 0, 0, 2, 0x08, 0x2a]);
        x.request_body = BodyRecord::from(&capture);
        x.response_body = Some(BodyRecord::from(&Capture::new(0)));
        x.response_trailers = vec![("grpc-status".to_owned(), "0".to_owned())];
        store.apply(&FlowEvent::finished(Event::Exchange(Box::new(x))));
        let plain = exchange(2, "GET", "https://a.test/x", 200);
        store.apply(&FlowEvent::finished(Event::Exchange(Box::new(plain))));
        store
    }

    #[test]
    fn answers_decoded_messages_for_grpc_flows_only() {
        let store = store();
        let ok = route(&store, None, &Method::GET, &["flows", "1", "grpc"]).expect("handled");
        assert_eq!(ok.status(), StatusCode::OK);
        let value: serde_json::Value = serde_json::from_slice(ok.body()).expect("JSON");
        assert_eq!(value["flow_id"], 1);
        assert_eq!(value["kind"], "grpc");
        assert_eq!(value["method"], "Get");
        assert_eq!(value["status_name"], "OK");
        let field = &value["request"]["messages"][0]["decoded"]["fields"][0];
        assert_eq!(
            (&field["wire"], &field["value"]),
            (&"varint".into(), &"42".into())
        );
        assert_eq!(value["truncated"], false);
        let plain = route(&store, None, &Method::GET, &["flows", "2", "grpc"]).expect("handled");
        assert_eq!(plain.status(), StatusCode::NOT_FOUND);
        let missing = route(&store, None, &Method::GET, &["flows", "x", "grpc"]).expect("handled");
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let post = route(&store, None, &Method::POST, &["flows", "1", "grpc"]).expect("handled");
        assert_eq!(post.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(route(&store, None, &Method::GET, &["flows", "1"]).is_none());
    }
}
