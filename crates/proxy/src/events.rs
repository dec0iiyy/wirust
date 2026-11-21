//! The flow event bus and the in-memory [`FlowStore`] that follows it.
//!
//! Every exchange publishes [`FlowEvent::Started`] when its request head arrives and one of
//! [`FlowEvent::Completed`], [`FlowEvent::Failed`] when it ends; a refused client handshake
//! publishes [`FlowEvent::TlsFailed`]. Consumers (the log printer, the store, the control
//! plane's event stream) subscribe with [`Bus::subscribe`].

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::ops::RangeBounds;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::flow::{ClientTls, Event};
use crate::intercept::{PauseInfo, Phase, Resolution};
use crate::ws::{WsMessage, WsStore};

/// Version of the serialised flow schema ([`Flow`], [`Started`], [`StoredFlow`]). Raise it
/// when a field changes meaning or disappears; adding an optional field does not need it.
pub const SCHEMA_VERSION: u32 = 1;

/// Default number of flows the [`FlowStore`] keeps.
pub const DEFAULT_MAX_FLOWS: usize = 5000;

/// Events a subscriber may fall behind by before it misses some.
const BUS_CAPACITY: usize = 4096;

/// A finished flow record as logged and stored: the [`Event`] plus [`SCHEMA_VERSION`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    /// The schema version of this record.
    pub schema_version: u32,
    /// The record itself; its fields are flattened into this object.
    #[serde(flatten)]
    pub record: Event,
}

impl Flow {
    /// Wraps `record` with the current schema version.
    #[must_use]
    pub fn new(record: Event) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            record,
        }
    }

    /// The flow id.
    #[must_use]
    pub fn id(&self) -> u64 {
        match &self.record {
            Event::Exchange(x) => x.id,
            Event::TlsFailure(t) => t.id,
            Event::Tunnel(t) => t.id,
        }
    }
}

/// The request head of an exchange that is still in progress.
#[derive(Debug, Clone, Serialize)]
pub struct Started {
    /// The schema version of this record.
    pub schema_version: u32,
    /// Flow id; the matching [`FlowEvent::Completed`] or [`FlowEvent::Failed`] carries it too.
    pub id: u64,
    /// When the request arrived, RFC 3339 UTC.
    pub time: String,
    /// The client's address.
    pub client: SocketAddr,
    /// Request method.
    pub method: String,
    /// The full URL.
    pub url: String,
    /// HTTP version between the client and the proxy.
    pub client_version: String,
    /// Request headers in the order received.
    pub request_headers: Vec<(String, String)>,
    /// The client's TLS session; `None` for plain `http://`.
    pub tls: Option<ClientTls>,
}

/// One message on the [`Bus`].
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", content = "flow", rename_all = "snake_case")]
pub enum FlowEvent {
    /// A request head arrived.
    Started(Arc<Started>),
    /// An exchange ended normally, or a raw tunnel closed.
    Completed(Arc<Flow>),
    /// An exchange ended with an error (its record says which).
    Failed(Arc<Flow>),
    /// A client failed the TLS handshake with the proxy.
    TlsFailed(Arc<Flow>),
    /// A breakpoint holds an exchange until `POST /api/v1/pauses/{id}/resume`, `/abort`
    /// or `/edit`, or the pause timeout.
    Paused(Arc<PauseEvent>),
    /// A held exchange goes on; [`PauseEvent::resolution`] says how.
    Resumed(Arc<PauseEvent>),
    /// A WebSocket message of an upgraded exchange (`{"event": "ws", "flow": {...}}`).
    #[serde(rename = "ws")]
    WsMessage(Arc<WsMessage>),
}

/// A breakpoint pause starting or ending, as [`FlowEvent::Paused`] and
/// [`FlowEvent::Resumed`] carry it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PauseEvent {
    /// `paused` or `resumed`.
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// The pause id, for `/api/v1/pauses/{id}/...`.
    pub pause_id: u64,
    /// The flow it holds.
    pub flow_id: u64,
    /// Which half of the exchange.
    pub phase: Phase,
    /// `resume`, `edit`, `abort` or `timed_out`; only on `resumed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution: Option<&'static str>,
}

impl PauseEvent {
    /// The event for `info`: `paused` without a resolution, else `resumed`.
    #[must_use]
    pub fn new(info: &PauseInfo, resolution: Option<&Resolution>) -> Self {
        Self {
            kind: if resolution.is_some() {
                "resumed"
            } else {
                "paused"
            },
            pause_id: info.id,
            flow_id: info.flow_id,
            phase: info.phase,
            resolution: resolution.map(|r| match r {
                Resolution::Resume => "resume",
                Resolution::Edit(_) => "edit",
                Resolution::Abort => "abort",
                Resolution::TimedOut => "timed_out",
            }),
        }
    }
}

impl FlowEvent {
    /// Classifies a finished record.
    #[must_use]
    pub fn finished(record: Event) -> Self {
        let failed = matches!(&record, Event::Exchange(x) if x.error.is_some());
        let tls_failed = matches!(record, Event::TlsFailure(_));
        let flow = Arc::new(Flow::new(record));
        if tls_failed {
            Self::TlsFailed(flow)
        } else if failed {
            Self::Failed(flow)
        } else {
            Self::Completed(flow)
        }
    }

    /// The flow id this event belongs to.
    #[must_use]
    pub fn id(&self) -> u64 {
        match self {
            Self::Started(s) => s.id,
            Self::Completed(f) | Self::Failed(f) | Self::TlsFailed(f) => f.id(),
            Self::Paused(p) | Self::Resumed(p) => p.flow_id,
            Self::WsMessage(m) => m.flow_id,
        }
    }

    /// The finished record, for every event but [`FlowEvent::Started`], [`FlowEvent::Paused`],
    /// [`FlowEvent::Resumed`] and [`FlowEvent::WsMessage`].
    #[must_use]
    pub fn flow(&self) -> Option<&Arc<Flow>> {
        match self {
            Self::Started(_) | Self::Paused(_) | Self::Resumed(_) | Self::WsMessage(_) => None,
            Self::Completed(f) | Self::Failed(f) | Self::TlsFailed(f) => Some(f),
        }
    }
}

/// The broadcast channel flow events travel on. Cloning is cheap.
#[derive(Debug, Clone)]
pub struct Bus {
    sender: broadcast::Sender<FlowEvent>,
}

impl Default for Bus {
    fn default() -> Self {
        Self::new()
    }
}

impl Bus {
    /// A bus with room for 4096 unread events per subscriber.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sender: broadcast::channel(BUS_CAPACITY).0,
        }
    }

    /// A receiver of every event published from now on. A receiver more than
    /// 4096 events behind gets `RecvError::Lagged` and skips ahead.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<FlowEvent> {
        self.sender.subscribe()
    }

    /// Publishes `event`; without subscribers it is dropped.
    pub fn publish(&self, event: FlowEvent) {
        // An error only means nobody is subscribed, which is fine.
        let _ = self.sender.send(event);
    }
}

/// A flow as the store holds it: in progress or finished.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", content = "flow", rename_all = "snake_case")]
pub enum StoredFlow {
    /// The request head arrived; the exchange has not ended yet.
    Pending(Arc<Started>),
    /// The exchange, tunnel or failed handshake is over.
    Done(Arc<Flow>),
}

impl StoredFlow {
    /// The flow id.
    #[must_use]
    pub fn id(&self) -> u64 {
        match self {
            Self::Pending(s) => s.id,
            Self::Done(f) => f.id(),
        }
    }

    /// `(host, method, status)` for filtering; host and method are empty for records that
    /// have none.
    fn facets(&self) -> (String, &str, Option<u16>) {
        match self {
            Self::Pending(s) => (host_of(&s.url), s.method.as_str(), None),
            Self::Done(f) => match &f.record {
                Event::Exchange(x) => (host_of(&x.url), x.method.as_str(), x.status),
                Event::TlsFailure(t) => (t.sni.clone().unwrap_or_default(), "", None),
                Event::Tunnel(t) => (t.target.clone(), "", None),
            },
        }
    }
}

fn host_of(url: &str) -> String {
    url.parse::<http::Uri>()
        .ok()
        .and_then(|uri| uri.host().map(str::to_owned))
        .unwrap_or_default()
}

/// Which flows [`FlowStore::list`] returns. Empty fields match everything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    /// Substring of the host (case-insensitive).
    pub host: Option<String>,
    /// Exact method, such as `GET` (case-insensitive).
    pub method: Option<String>,
    /// Exact response status.
    pub status: Option<u16>,
    /// At most this many flows, the newest ones.
    pub limit: Option<usize>,
    /// A parsed search query (`?q=`), see [`crate::query`].
    pub query: Option<Arc<crate::query::Query>>,
}

impl Filter {
    /// Whether `flow` passes every set condition.
    #[must_use]
    pub fn matches(&self, flow: &StoredFlow) -> bool {
        self.matches_with_ws(flow, None)
    }

    /// [`matches`](Self::matches), with `ws` holding the messages a `ws:` query searches.
    #[must_use]
    pub fn matches_with_ws(&self, flow: &StoredFlow, ws: Option<&WsStore>) -> bool {
        let (host, method, status) = flow.facets();
        self.host.as_ref().is_none_or(|want| {
            host.to_ascii_lowercase()
                .contains(&want.to_ascii_lowercase())
        }) && self
            .method
            .as_ref()
            .is_none_or(|want| method.eq_ignore_ascii_case(want))
            && self.status.is_none_or(|want| status == Some(want))
            && self
                .query
                .as_ref()
                .is_none_or(|query| query.matches_with_ws(flow, ws))
    }
}

/// The last N flows in memory, oldest first. Cloning is cheap and shares the buffer.
#[derive(Debug, Clone)]
pub struct FlowStore {
    inner: Arc<Mutex<Ring>>,
    /// WebSocket messages of the held flows; evicted with their flow.
    ws: WsStore,
}

#[derive(Debug)]
struct Ring {
    capacity: usize,
    flows: VecDeque<StoredFlow>,
}

impl FlowStore {
    /// An empty store that keeps at most `capacity` flows (at least one).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self::with_ws_messages(capacity, crate::ws::DEFAULT_WS_MAX_MESSAGES)
    }

    /// Like [`new`](Self::new), keeping at most `max_messages` WebSocket messages per flow.
    #[must_use]
    pub fn with_ws_messages(capacity: usize, max_messages: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Ring {
                capacity: capacity.max(1),
                flows: VecDeque::new(),
            })),
            ws: WsStore::new(max_messages),
        }
    }

    /// The WebSocket messages of the held flows.
    #[must_use]
    pub fn ws(&self) -> &WsStore {
        &self.ws
    }

    /// Applies events from `events` until the bus closes. Lagging skips the missed events.
    #[must_use = "the task runs on its own; keep the handle only to abort it"]
    pub fn follow(
        &self,
        mut events: broadcast::Receiver<FlowEvent>,
    ) -> tokio::task::JoinHandle<()> {
        let store = self.clone();
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(event) => store.apply(&event),
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        })
    }

    /// Records one event: a start adds a pending flow, an end replaces it (or adds the flow
    /// when its start was evicted or never published). The oldest flow goes when full.
    pub fn apply(&self, event: &FlowEvent) {
        let mut ring = self.lock();
        let id = event.id();
        if let Some(flow) = event.flow() {
            // Ends usually arrive soon after their start, so search from the back.
            if let Some(slot) = ring.flows.iter_mut().rev().find(|f| f.id() == id) {
                *slot = StoredFlow::Done(Arc::clone(flow));
                return;
            }
            let evicted = ring.push(StoredFlow::Done(Arc::clone(flow)));
            self.evict(evicted);
        } else if let FlowEvent::Started(started) = event {
            let evicted = ring.push(StoredFlow::Pending(Arc::clone(started)));
            self.evict(evicted);
        } else if let FlowEvent::WsMessage(message) = event {
            // Messages of flows no longer held are dropped, so nothing outlives its flow.
            let Some(StoredFlow::Done(flow)) = ring.flows.iter_mut().rev().find(|f| f.id() == id)
            else {
                return;
            };
            if let Event::Exchange(x) = &mut Arc::make_mut(flow).record {
                x.ws_messages = Some(message.seq.saturating_add(1));
            }
            self.ws.push(Arc::clone(message));
        }
    }

    fn evict(&self, evicted: Option<StoredFlow>) {
        if let Some(flow) = evicted {
            self.ws.remove(flow.id());
        }
    }

    /// The flow with `id`, if it is still held.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<StoredFlow> {
        self.lock()
            .flows
            .iter()
            .rev()
            .find(|f| f.id() == id)
            .cloned()
    }

    /// Flows whose id is in `ids` and that pass `filter`, oldest first.
    #[must_use]
    pub fn list(&self, ids: impl RangeBounds<u64>, filter: &Filter) -> Vec<StoredFlow> {
        let ring = self.lock();
        let mut found: Vec<StoredFlow> = ring
            .flows
            .iter()
            .rev()
            .filter(|f| ids.contains(&f.id()) && filter.matches_with_ws(f, Some(&self.ws)))
            .take(filter.limit.unwrap_or(usize::MAX))
            .cloned()
            .collect();
        found.reverse();
        found
    }

    /// Number of flows held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().flows.len()
    }

    /// Whether no flow is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Ring> {
        self.inner.lock().expect("flow store lock poisoned")
    }
}

impl Ring {
    /// Appends `flow`; returns the flow dropped to make room, if any.
    fn push(&mut self, flow: StoredFlow) -> Option<StoredFlow> {
        let evicted = if self.flows.len() == self.capacity {
            self.flows.pop_front()
        } else {
            None
        };
        self.flows.push_back(flow);
        evicted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::Tunnel;

    fn started(id: u64, url: &str) -> FlowEvent {
        FlowEvent::Started(Arc::new(Started {
            schema_version: SCHEMA_VERSION,
            id,
            time: String::new(),
            client: SocketAddr::from(([127, 0, 0, 1], 1)),
            method: "GET".to_owned(),
            url: url.to_owned(),
            client_version: "h2".to_owned(),
            request_headers: Vec::new(),
            tls: None,
        }))
    }

    fn tunnel(id: u64) -> FlowEvent {
        FlowEvent::finished(Event::Tunnel(Tunnel {
            id,
            time: String::new(),
            client: SocketAddr::from(([127, 0, 0, 1], 1)),
            target: "example.com:22".to_owned(),
            bytes_up: 0,
            bytes_down: 0,
            error: None,
            reason: None,
            tls: None,
            duration_ms: None,
        }))
    }

    #[test]
    fn the_ring_evicts_the_oldest_flow() {
        let store = FlowStore::new(3);
        for id in 1..=5 {
            store.apply(&tunnel(id));
        }
        let ids: Vec<u64> = store
            .list(.., &Filter::default())
            .iter()
            .map(StoredFlow::id)
            .collect();
        assert_eq!(ids, [3, 4, 5]);
        assert!(store.get(2).is_none());
        assert!(store.get(5).is_some());
    }

    #[test]
    fn an_end_replaces_its_start_in_place() {
        let store = FlowStore::new(10);
        store.apply(&started(1, "https://a.test/"));
        store.apply(&started(2, "https://b.test/"));
        assert!(matches!(store.get(1), Some(StoredFlow::Pending(_))));
        store.apply(&tunnel(1));
        assert!(matches!(store.get(1), Some(StoredFlow::Done(_))));
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn list_filters_by_range_host_method_and_limit() {
        let store = FlowStore::new(10);
        store.apply(&started(1, "https://api.example.com/x"));
        store.apply(&started(2, "https://other.test/"));
        store.apply(&started(3, "https://example.com/y"));
        let host = Filter {
            host: Some("EXAMPLE".to_owned()),
            ..Filter::default()
        };
        let ids: Vec<u64> = store.list(.., &host).iter().map(StoredFlow::id).collect();
        assert_eq!(ids, [1, 3]);
        let ids: Vec<u64> = store.list(2.., &host).iter().map(StoredFlow::id).collect();
        assert_eq!(ids, [3]);
        let newest = Filter {
            limit: Some(1),
            ..Filter::default()
        };
        assert_eq!(store.list(.., &newest)[0].id(), 3);
        let post = Filter {
            method: Some("post".to_owned()),
            ..Filter::default()
        };
        assert!(store.list(.., &post).is_empty());
    }

    #[test]
    fn records_carry_the_schema_version_and_keep_their_fields() -> serde_json::Result<()> {
        let FlowEvent::Completed(flow) = tunnel(7) else {
            panic!("a clean tunnel is completed");
        };
        let json = serde_json::to_value(&*flow)?;
        assert_eq!(json["schema_version"], SCHEMA_VERSION);
        assert_eq!(json["type"], "tunnel");
        assert_eq!(json["id"], 7);
        assert_eq!(json["target"], "example.com:22");
        Ok(())
    }
}
