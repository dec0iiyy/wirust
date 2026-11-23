//! The summary view of flows (`?view=summary` on `GET /api/v1/flows` and `/events`): what
//! the flow list shows, without header lists, bodies or trailers. Each summary object has
//! the field names and order of the full record it stands for, plus `"summary": true`; the
//! full record stays at `GET /api/v1/flows/{id}`.

use std::net::SocketAddr;

use serde::Serialize;

use crate::events::{Flow, FlowEvent, Started, StoredFlow};
use crate::flow::{BodyRecord, ClientTls, ContentDecoding, Event, Exchange, Flag, Timing};
use crate::flow::{TlsFailure, Tunnel};

/// Which form of a flow an API answer carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum View {
    /// The whole record, bodies included (the default).
    #[default]
    Full,
    /// [`StoredSummary`] and [`EventSummary`]: no headers, bodies or trailers.
    Summary,
}

impl View {
    /// The `view` query parameter: absent or `full` is [`View::Full`], `summary` is
    /// [`View::Summary`].
    ///
    /// # Errors
    ///
    /// Any other value, as a message for a 400 answer.
    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        match value {
            None | Some("" | "full") => Ok(Self::Full),
            Some("summary") => Ok(Self::Summary),
            Some(_) => Err("view must be full or summary".to_owned()),
        }
    }
}

/// A [`StoredFlow`] in summary form (`{"state", "flow"}`).
#[derive(Debug, Serialize)]
#[serde(tag = "state", content = "flow", rename_all = "snake_case")]
pub enum StoredSummary<'a> {
    /// An exchange still in progress.
    Pending(StartedSummary<'a>),
    /// A finished exchange, tunnel or failed handshake.
    Done(FlowSummary<'a>),
}

impl<'a> From<&'a StoredFlow> for StoredSummary<'a> {
    fn from(flow: &'a StoredFlow) -> Self {
        match flow {
            StoredFlow::Pending(started) => Self::Pending(StartedSummary::from(&**started)),
            StoredFlow::Done(flow) => Self::Done(FlowSummary::from(&**flow)),
        }
    }
}

/// A [`FlowEvent`] in summary form: the flow events carry summaries, pause and WebSocket
/// events are unchanged.
#[derive(Debug, Serialize)]
#[serde(tag = "event", content = "flow", rename_all = "snake_case")]
pub enum EventSummary<'a> {
    /// A request head arrived.
    Started(StartedSummary<'a>),
    /// An exchange ended normally, or a raw tunnel closed.
    Completed(FlowSummary<'a>),
    /// An exchange ended with an error.
    Failed(FlowSummary<'a>),
    /// A client failed the TLS handshake with the proxy.
    TlsFailed(FlowSummary<'a>),
    /// Any other event, as the full stream sends it.
    #[serde(untagged)]
    Other(&'a FlowEvent),
}

impl<'a> From<&'a FlowEvent> for EventSummary<'a> {
    fn from(event: &'a FlowEvent) -> Self {
        match event {
            FlowEvent::Started(started) => Self::Started(StartedSummary::from(&**started)),
            FlowEvent::Completed(flow) => Self::Completed(FlowSummary::from(&**flow)),
            FlowEvent::Failed(flow) => Self::Failed(FlowSummary::from(&**flow)),
            FlowEvent::TlsFailed(flow) => Self::TlsFailed(FlowSummary::from(&**flow)),
            FlowEvent::Paused(_) | FlowEvent::Resumed(_) | FlowEvent::WsMessage(_) => {
                Self::Other(event)
            }
        }
    }
}

/// [`Started`] without its request headers.
#[derive(Debug, Serialize)]
pub struct StartedSummary<'a> {
    schema_version: u32,
    id: u64,
    time: &'a str,
    client: SocketAddr,
    method: &'a str,
    url: &'a str,
    client_version: &'a str,
    tls: Option<&'a ClientTls>,
    summary: bool,
}

impl<'a> From<&'a Started> for StartedSummary<'a> {
    fn from(started: &'a Started) -> Self {
        Self {
            schema_version: started.schema_version,
            id: started.id,
            time: &started.time,
            client: started.client,
            method: &started.method,
            url: &started.url,
            client_version: &started.client_version,
            tls: started.tls.as_ref(),
            summary: true,
        }
    }
}

/// A finished [`Flow`] in summary form.
#[derive(Debug, Serialize)]
pub struct FlowSummary<'a> {
    schema_version: u32,
    #[serde(flatten)]
    record: RecordSummary<'a>,
    summary: bool,
}

impl<'a> From<&'a Flow> for FlowSummary<'a> {
    fn from(flow: &'a Flow) -> Self {
        let record = match &flow.record {
            Event::Exchange(x) => RecordSummary::Exchange(Box::new(ExchangeSummary::from(&**x))),
            Event::TlsFailure(t) => RecordSummary::TlsFailure(t),
            Event::Tunnel(t) => RecordSummary::Tunnel(t),
        };
        Self {
            schema_version: flow.schema_version,
            record,
            summary: true,
        }
    }
}

/// Failed handshakes and tunnels hold no headers or bodies, so they stay whole. The exchange
/// is boxed like [`Event::Exchange`], which keeps the enum small.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum RecordSummary<'a> {
    Exchange(Box<ExchangeSummary<'a>>),
    TlsFailure(&'a TlsFailure),
    Tunnel(&'a Tunnel),
}

/// [`Exchange`] without header lists, body data and trailers; `response_content_type`
/// carries the one header the list shows (its Type column).
#[derive(Debug, Serialize)]
struct ExchangeSummary<'a> {
    id: u64,
    time: &'a str,
    client: SocketAddr,
    method: &'a str,
    url: &'a str,
    client_version: &'a str,
    upstream_version: Option<&'a str>,
    status: Option<u16>,
    reason: Option<&'a str>,
    request_body: BodySummary<'a>,
    response_body: Option<BodySummary<'a>>,
    timing: &'a Timing,
    tls: Option<&'a ClientTls>,
    error: Option<&'a str>,
    #[serde(skip_serializing_if = "<[Flag]>::is_empty")]
    flags: &'a [Flag],
    #[serde(skip_serializing_if = "Option::is_none")]
    upstream_url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    replay_of: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ws_messages: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_content_type: Option<&'a str>,
}

impl<'a> From<&'a Exchange> for ExchangeSummary<'a> {
    fn from(x: &'a Exchange) -> Self {
        let content_type = x
            .response_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.as_str());
        Self {
            id: x.id,
            time: &x.time,
            client: x.client,
            method: &x.method,
            url: &x.url,
            client_version: &x.client_version,
            upstream_version: x.upstream_version.as_deref(),
            status: x.status,
            reason: x.reason.as_deref(),
            request_body: BodySummary::from(&x.request_body),
            response_body: x.response_body.as_ref().map(BodySummary::from),
            timing: &x.timing,
            tls: x.tls.as_ref(),
            error: x.error.as_deref(),
            flags: &x.flags,
            upstream_url: x.upstream_url.as_deref(),
            replay_of: x.replay_of,
            ws_messages: x.ws_messages,
            response_content_type: content_type,
        }
    }
}

/// [`BodyRecord`] without `data`.
#[derive(Debug, Serialize)]
struct BodySummary<'a> {
    size: u64,
    truncated: bool,
    encoding: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_encoding: Option<&'a ContentDecoding>,
}

impl<'a> From<&'a BodyRecord> for BodySummary<'a> {
    fn from(body: &'a BodyRecord) -> Self {
        Self {
            size: body.size,
            truncated: body.truncated,
            encoding: body.encoding,
            content_encoding: body.content_encoding.as_ref(),
        }
    }
}

/// `flows` as a JSON array in the form `view` asks for.
///
/// # Errors
///
/// A serialisation error, which only a broken record can cause.
pub fn list_json(flows: &[StoredFlow], view: View) -> serde_json::Result<Vec<u8>> {
    match view {
        View::Full => serde_json::to_vec(flows),
        View::Summary => {
            let summaries: Vec<StoredSummary<'_>> = flows.iter().map(StoredSummary::from).collect();
            serde_json::to_vec(&summaries)
        }
    }
}

/// `event` as the JSON of one SSE `data:` line, in the form `view` asks for.
///
/// # Errors
///
/// A serialisation error, which only a broken record can cause.
pub fn event_json(event: &FlowEvent, view: View) -> serde_json::Result<String> {
    match view {
        View::Full => serde_json::to_string(event),
        View::Summary => serde_json::to_string(&EventSummary::from(event)),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::Value;

    use super::*;
    use crate::events::SCHEMA_VERSION;
    use crate::query::tests::exchange;

    fn done() -> StoredFlow {
        let mut x = exchange(7, "POST", "https://a.test/x?y=1", 201);
        x.response_trailers = vec![("grpc-status".to_owned(), "0".to_owned())];
        x.ws_messages = Some(3);
        StoredFlow::Done(Arc::new(Flow::new(Event::Exchange(Box::new(x)))))
    }

    fn started() -> Started {
        Started {
            schema_version: SCHEMA_VERSION,
            id: 8,
            time: "2026-11-21T10:00:00.000Z".to_owned(),
            client: SocketAddr::from(([127, 0, 0, 1], 5000)),
            method: "GET".to_owned(),
            url: "https://a.test/".to_owned(),
            client_version: "http/1.1".to_owned(),
            request_headers: vec![("cookie".to_owned(), "a=b".to_owned())],
            tls: None,
        }
    }

    fn json(bytes: &[u8]) -> Value {
        serde_json::from_slice(bytes).expect("valid JSON")
    }

    #[test]
    fn views_parse_and_unknown_ones_are_errors() {
        assert_eq!(View::parse(None), Ok(View::Full));
        assert_eq!(View::parse(Some("full")), Ok(View::Full));
        assert_eq!(View::parse(Some("summary")), Ok(View::Summary));
        assert!(View::parse(Some("Summary")).is_err());
    }

    #[test]
    fn the_full_list_is_the_plain_serialisation() -> serde_json::Result<()> {
        let flows = [done(), StoredFlow::Pending(Arc::new(started()))];
        assert_eq!(list_json(&flows, View::Full)?, serde_json::to_vec(&flows)?);
        Ok(())
    }

    #[test]
    fn a_done_summary_keeps_the_list_columns_and_drops_headers_and_bodies() -> serde_json::Result<()>
    {
        let flows = [done()];
        let full = json(&list_json(&flows, View::Full)?);
        let summary = json(&list_json(&flows, View::Summary)?);
        let (whole, flow) = (&full[0]["flow"], &summary[0]["flow"]);
        assert_eq!(summary[0]["state"], "done");
        assert_eq!(flow["summary"], true);
        for absent in ["request_headers", "response_headers", "response_trailers"] {
            assert!(flow.get(absent).is_none(), "{absent}");
            assert!(whole.get(absent).is_some(), "{absent} in the full record");
        }
        assert!(flow["response_body"].get("data").is_none());
        assert_eq!(flow["response_body"]["size"], 20_000);
        assert_eq!(
            flow["response_content_type"],
            "application/json; charset=utf-8"
        );
        let map = whole.as_object().expect("an object");
        for (key, value) in map {
            let dropped = key.ends_with("_headers") || key == "response_trailers";
            let bodies = key.ends_with("_body");
            if !dropped && !bodies {
                assert_eq!(&flow[key], value, "{key}");
            }
        }
        Ok(())
    }

    #[test]
    fn pending_and_event_summaries_drop_request_headers() -> serde_json::Result<()> {
        let event = FlowEvent::Started(Arc::new(started()));
        let flow = json(event_json(&event, View::Summary)?.as_bytes());
        assert_eq!(flow["event"], "started");
        assert_eq!(flow["flow"]["summary"], true);
        assert_eq!(flow["flow"]["url"], "https://a.test/");
        assert!(flow["flow"].get("request_headers").is_none());
        let StoredFlow::Done(record) = done() else {
            unreachable!("done() builds a finished flow")
        };
        let finished = FlowEvent::Completed(record);
        let summary = json(event_json(&finished, View::Summary)?.as_bytes());
        assert_eq!(summary["event"], "completed");
        assert_eq!(summary["flow"]["ws_messages"], 3);
        assert!(summary["flow"]["request_body"].get("data").is_none());
        assert_eq!(
            event_json(&finished, View::Full)?,
            serde_json::to_string(&finished)?
        );
        Ok(())
    }

    #[test]
    fn pause_events_pass_through_unchanged() -> serde_json::Result<()> {
        let pause = FlowEvent::Paused(Arc::new(crate::events::PauseEvent {
            kind: "paused",
            pause_id: 1,
            flow_id: 2,
            phase: crate::intercept::Phase::Request,
            resolution: None,
        }));
        assert_eq!(
            event_json(&pause, View::Summary)?,
            serde_json::to_string(&pause)?
        );
        Ok(())
    }
}
