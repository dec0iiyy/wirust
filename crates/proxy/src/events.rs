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
///
/// A bus made with [`Bus::with_store`] records each event in its [`FlowStore`] before
/// broadcasting it, so the store never depends on a subscriber keeping up: a receiver that
/// falls more than 4096 events behind loses some, the store loses none.
#[derive(Debug, Clone)]
pub struct Bus {
    sender: broadcast::Sender<FlowEvent>,
    store: Option<FlowStore>,
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
            store: None,
        }
    }

    /// A bus that applies every published event to `store` first, losslessly.
    #[must_use]
    pub fn with_store(store: FlowStore) -> Self {
        Self {
            store: Some(store),
            ..Self::new()
        }
    }

    /// A receiver of every event published from now on. A receiver more than
    /// 4096 events behind gets `RecvError::Lagged` and skips ahead.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<FlowEvent> {
        self.sender.subscribe()
    }

    /// Publishes `event`: records it in the store, if any, then broadcasts it; without
    /// subscribers the broadcast is dropped.
    pub fn publish(&self, event: FlowEvent) {
        if let Some(store) = &self.store {
            store.apply(&event);
        }
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

/// Flows the byte budget never evicts: the newest ones stay even when they alone exceed it.
const MIN_KEPT: usize = 8;

/// Bytes the [`FlowStore`] holds and may hold, as `GET /api/v1/info` reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MemoryUse {
    /// Estimated bytes of the held flows and their WebSocket messages
    /// ([`crate::memory::stored_flow`], [`crate::memory::ws_message`]).
    pub used: usize,
    /// The budget (`--max-memory`).
    pub budget: usize,
}

/// The last flows in memory, oldest first. Cloning is cheap and shares the buffer.
///
/// Two caps apply: at most `capacity` flows (`--max-flows`; the oldest goes first) and at
/// most a byte budget (`--max-memory`; the oldest finished flows go first, pending ones
/// stay, and so do the newest eight).
#[derive(Debug, Clone)]
pub struct FlowStore {
    inner: Arc<Mutex<Ring>>,
    /// WebSocket messages of the held flows; evicted with their flow.
    ws: WsStore,
}

#[derive(Debug)]
struct Ring {
    capacity: usize,
    budget: usize,
    /// Sum of the `bytes` of every slot.
    bytes: usize,
    flows: VecDeque<Slot>,
}

/// A held flow and its estimated size, WebSocket messages included.
#[derive(Debug)]
struct Slot {
    flow: StoredFlow,
    bytes: usize,
}

impl Slot {
    fn new(flow: StoredFlow) -> Self {
        let bytes = crate::memory::stored_flow(&flow);
        Self { flow, bytes }
    }
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
        Self::with_limits(capacity, max_messages, crate::memory::DEFAULT_MAX_MEMORY)
    }

    /// Like [`with_ws_messages`](Self::with_ws_messages), holding about `max_memory` bytes
    /// of flow data at most.
    #[must_use]
    pub fn with_limits(capacity: usize, max_messages: usize, max_memory: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Ring {
                capacity: capacity.max(1),
                budget: max_memory,
                bytes: 0,
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

    /// The estimated bytes held and the budget.
    #[must_use]
    pub fn memory(&self) -> MemoryUse {
        let ring = self.lock();
        MemoryUse {
            used: ring.bytes,
            budget: ring.budget,
        }
    }

    /// Records one event: a start adds a pending flow, an end replaces it (or adds the flow
    /// when its start was evicted or never published), a WebSocket message joins its flow.
    /// Flows over the count or byte cap are evicted.
    pub fn apply(&self, event: &FlowEvent) {
        let mut ring = self.lock();
        let evicted = match event {
            FlowEvent::Started(started) => ring.insert(StoredFlow::Pending(Arc::clone(started))),
            FlowEvent::Completed(flow) | FlowEvent::Failed(flow) | FlowEvent::TlsFailed(flow) => {
                ring.finish(flow)
            }
            FlowEvent::WsMessage(message) => self.add_message(&mut ring, message),
            FlowEvent::Paused(_) | FlowEvent::Resumed(_) => Vec::new(),
        };
        // Under the ring lock, so a message of an evicted flow cannot slip in between.
        for id in evicted {
            self.ws.remove(id);
        }
    }

    /// Adds `message` to its finished flow; messages of flows no longer held are dropped,
    /// so nothing outlives its flow. Returns the flows evicted to stay in budget.
    fn add_message(&self, ring: &mut Ring, message: &Arc<WsMessage>) -> Vec<u64> {
        let Some(slot) = ring.slot_mut(message.flow_id) else {
            return Vec::new();
        };
        let StoredFlow::Done(flow) = &mut slot.flow else {
            return Vec::new();
        };
        if let Event::Exchange(x) = &mut Arc::make_mut(flow).record {
            x.ws_messages = Some(message.seq.saturating_add(1));
        }
        let added = crate::memory::ws_message(message);
        let dropped = self.ws.push(Arc::clone(message));
        slot.bytes = (slot.bytes + added).saturating_sub(dropped);
        ring.bytes = (ring.bytes + added).saturating_sub(dropped);
        ring.shrink()
    }

    /// The flow with `id`, if it is still held.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<StoredFlow> {
        self.lock().slot(id).map(|slot| slot.flow.clone())
    }

    /// Flows whose id is in `ids` and that pass `filter`, oldest first.
    ///
    /// The candidates are copied out (cheap `Arc` clones) and matched after the lock is
    /// released, so a slow search never holds up the proxy recording flows.
    #[must_use]
    pub fn list(&self, ids: impl RangeBounds<u64>, filter: &Filter) -> Vec<StoredFlow> {
        self.list_by(ids, filter.limit.unwrap_or(usize::MAX), |flow| {
            filter.matches_with_ws(flow, Some(&self.ws))
        })
    }

    /// The newest `limit` flows with an id in `ids` that pass `keep`, oldest first; `keep`
    /// runs without the store lock.
    fn list_by(
        &self,
        ids: impl RangeBounds<u64>,
        limit: usize,
        mut keep: impl FnMut(&StoredFlow) -> bool,
    ) -> Vec<StoredFlow> {
        let candidates: Vec<StoredFlow> = self
            .lock()
            .flows
            .iter()
            .filter(|slot| ids.contains(&slot.flow.id()))
            .map(|slot| slot.flow.clone())
            .collect();
        let mut found: Vec<StoredFlow> = candidates
            .into_iter()
            .rev()
            .filter(|flow| keep(flow))
            .take(limit)
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
    /// Ends usually arrive soon after their start, so search from the back.
    fn position(&self, id: u64) -> Option<usize> {
        self.flows.iter().rposition(|slot| slot.flow.id() == id)
    }

    fn slot(&self, id: u64) -> Option<&Slot> {
        self.position(id).and_then(|at| self.flows.get(at))
    }

    fn slot_mut(&mut self, id: u64) -> Option<&mut Slot> {
        self.position(id).and_then(|at| self.flows.get_mut(at))
    }

    /// Appends `flow`; returns the ids of the flows dropped to make room.
    fn insert(&mut self, flow: StoredFlow) -> Vec<u64> {
        let mut evicted = Vec::new();
        if self.flows.len() >= self.capacity
            && let Some(oldest) = self.flows.pop_front()
        {
            self.bytes = self.bytes.saturating_sub(oldest.bytes);
            evicted.push(oldest.flow.id());
        }
        let slot = Slot::new(flow);
        self.bytes += slot.bytes;
        self.flows.push_back(slot);
        evicted.extend(self.shrink());
        evicted
    }

    /// Puts the finished `flow` in place of its pending start, keeping the WebSocket
    /// messages already counted, or appends it.
    fn finish(&mut self, flow: &Arc<Flow>) -> Vec<u64> {
        let done = StoredFlow::Done(Arc::clone(flow));
        let Some(slot) = self.slot_mut(flow.id()) else {
            return self.insert(done);
        };
        let old = crate::memory::stored_flow(&slot.flow);
        let new = crate::memory::stored_flow(&done);
        slot.flow = done;
        slot.bytes = (slot.bytes + new).saturating_sub(old);
        self.bytes = (self.bytes + new).saturating_sub(old);
        self.shrink()
    }

    /// Evicts the oldest finished flows until the held bytes fit the budget, sparing
    /// pending flows and the newest [`MIN_KEPT`]. Returns the evicted ids.
    fn shrink(&mut self) -> Vec<u64> {
        let mut evicted = Vec::new();
        while self.bytes > self.budget && self.flows.len() > MIN_KEPT {
            let spare_from = self.flows.len() - MIN_KEPT;
            let Some(at) = (self.flows.iter().take(spare_from))
                .position(|slot| matches!(slot.flow, StoredFlow::Done(_)))
            else {
                break;
            };
            let Some(slot) = self.flows.remove(at) else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(slot.bytes);
            evicted.push(slot.flow.id());
        }
        evicted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{BodyRecord, Tunnel};

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

    /// A finished exchange with `body` bytes of text in each direction.
    fn big(id: u64, body: usize) -> FlowEvent {
        let mut x = crate::query::tests::exchange(id, "POST", "https://big.test/", 200);
        let text = "a".repeat(body);
        x.request_body = BodyRecord::from_bytes(text.as_bytes(), body as u64, false);
        x.response_body = Some(BodyRecord::from_bytes(text.as_bytes(), body as u64, false));
        FlowEvent::finished(Event::Exchange(Box::new(x)))
    }

    fn ids(store: &FlowStore) -> Vec<u64> {
        store
            .list(.., &Filter::default())
            .iter()
            .map(StoredFlow::id)
            .collect()
    }

    #[tokio::test]
    async fn a_flooded_bus_never_loses_an_end_in_the_store() {
        let store = FlowStore::new(10_000);
        let bus = Bus::with_store(store.clone());
        // A subscriber that never reads lags far behind; the store must not care.
        let mut slow = bus.subscribe();
        bus.publish(started(1, "https://a.test/"));
        bus.publish(tunnel(1));
        for id in 2..6000 {
            bus.publish(tunnel(id));
        }
        assert!(matches!(store.get(1), Some(StoredFlow::Done(_))));
        assert_eq!(store.len(), 5999);
        assert!(matches!(
            slow.recv().await,
            Err(broadcast::error::RecvError::Lagged(_))
        ));
    }

    #[test]
    fn the_budget_evicts_the_oldest_finished_flows_and_spares_pending_ones() {
        let one = crate::memory::stored_flow(&StoredFlow::Done(
            big(0, 10_000).flow().cloned().expect("finished"),
        ));
        // Room for about ten big flows.
        let store = FlowStore::with_limits(1000, 10, one * 10 + one / 2);
        store.apply(&started(1, "https://pending.test/"));
        for id in 2..=30 {
            store.apply(&big(id, 10_000));
        }
        let held = ids(&store);
        assert_eq!(held.first(), Some(&1), "the pending flow stays: {held:?}");
        assert_eq!(held.len(), 11, "pending plus ten finished: {held:?}");
        assert_eq!(held.last(), Some(&30));
        assert_eq!(held[1], 21, "the oldest finished went first: {held:?}");
        let memory = store.memory();
        assert!(memory.used <= memory.budget, "{memory:?}");
        // Its end arrives: now it is the oldest finished flow and goes next.
        store.apply(&big(1, 10_000));
        assert_eq!(ids(&store).first(), Some(&21));
        assert!(store.get(1).is_none());
    }

    #[test]
    fn the_budget_keeps_the_newest_flows_even_when_they_exceed_it() {
        let store = FlowStore::with_limits(1000, 10, 1);
        for id in 1..=20 {
            store.apply(&big(id, 1000));
        }
        assert_eq!(ids(&store), (13..=20).collect::<Vec<u64>>());
        assert!(store.memory().used > 1);
    }

    #[test]
    fn accounting_follows_starts_ends_messages_and_evictions() {
        let store = FlowStore::with_limits(2, 2, usize::MAX);
        assert_eq!(store.memory().used, 0);
        store.apply(&started(1, "https://a.test/"));
        let pending = store.memory().used;
        assert!(pending > 0);
        store.apply(&big(1, 5000));
        let done = store.memory().used;
        assert!(done >= pending + 10_000, "{pending} -> {done}");
        let message = |seq| {
            let parsed = crate::ws::Parsed {
                kind: crate::ws::Kind::Text,
                kept: vec![b'x'; 3000],
                size: 3000,
                compression: None,
            };
            let message = crate::ws::message(1, seq, crate::ws::Direction::ServerToClient, &parsed);
            FlowEvent::WsMessage(Arc::new(message))
        };
        store.apply(&message(0));
        let with_message = store.memory().used;
        assert!(with_message >= done + 3000, "{done} -> {with_message}");
        store.apply(&message(1));
        store.apply(&message(2));
        // Two messages per flow at most: the third replaced the first.
        assert_eq!(store.memory().used - with_message, with_message - done);
        store.apply(&tunnel(2));
        store.apply(&tunnel(3));
        assert_eq!(ids(&store), [2, 3]);
        assert_eq!(store.ws().len(1), 0);
        let two_tunnels = 2 * crate::memory::stored_flow(&StoredFlow::Done(
            tunnel(2).flow().cloned().expect("finished"),
        ));
        assert_eq!(store.memory().used, two_tunnels);
    }

    #[test]
    fn list_matches_outside_the_store_lock() {
        let store = FlowStore::new(10);
        store.apply(&started(1, "https://a.test/"));
        store.apply(&started(2, "https://b.test/"));
        // The predicate takes the store lock itself: it would deadlock if `list` held it.
        let found = store.list_by(.., usize::MAX, |flow| store.get(flow.id()).is_some());
        assert_eq!(found.len(), 2);
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
