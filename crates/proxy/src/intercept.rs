//! The interceptor chain: rules that look at or change an exchange on its way through.
//!
//! [`Interceptors`] runs each [`Interceptor`] in registration order. `on_request` runs before
//! the proxy contacts the server, `on_response` after the response head (and, when asked
//! for, the buffered body) arrives. An empty chain costs one `is_empty` check per exchange.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode};
use serde::Serialize;
use tokio::sync::oneshot;

use crate::events::{Bus, FlowEvent, PauseEvent};
use crate::flow::Flag;
use crate::throttle::Throttle;

/// Default time a [`Action::Pause`] waits for a decision before the exchange goes on.
pub const DEFAULT_PAUSE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// The request as interceptors see and change it.
#[derive(Debug, Clone)]
pub struct RequestCtx {
    /// Flow id, the same as in the flow record.
    pub id: u64,
    /// The client's address.
    pub client: SocketAddr,
    /// `http` or `https`. With `host` and `port`, may be changed (map-remote): the proxy
    /// then opens a connection to the new server, and the client still sees its own URL.
    pub scheme: &'static str,
    /// The server host (the CONNECT host, or the host of the absolute URL); may be changed.
    pub host: String,
    /// The server port; may be changed.
    pub port: u16,
    /// Request method; may be changed.
    pub method: Method,
    /// Path and query, such as `/a?b=1`; may be changed.
    pub path: String,
    /// Request headers; may be changed.
    pub headers: HeaderMap,
    /// The whole request body, when an interceptor asked for it with
    /// [`Interceptor::needs_request_body`] and it fit the limit; may be replaced.
    pub body: Option<Bytes>,
    /// Flags to add to the flow record, such as [`Flag::Rule`].
    pub flags: Vec<Flag>,
    /// State an interceptor keeps between `on_request` and `on_response` of this exchange.
    pub extensions: http::Extensions,
}

/// The response as interceptors see and change it.
#[derive(Debug, Clone)]
pub struct ResponseCtx {
    /// Response status; may be changed.
    pub status: StatusCode,
    /// Response headers; may be changed.
    pub headers: HeaderMap,
    /// The whole response body, when an interceptor asked for it with
    /// [`Interceptor::needs_response_body`] and it fit the limit; may be replaced.
    pub body: Option<Bytes>,
    /// Flags to add to the flow record.
    pub flags: Vec<Flag>,
    /// Streams the response body to the client at this rate, when set.
    pub throttle: Option<Throttle>,
}

/// What the chain does after an interceptor ran.
#[derive(Debug)]
pub enum Action {
    /// Go on to the next interceptor, then to the server or the client.
    Continue,
    /// Answer the client with this response and stop the chain. From `on_request` the
    /// server is never contacted (mock, map-local, block).
    Respond(Response<Bytes>),
    /// Wait this long, then go on (throttling, latency simulation).
    Delay(Duration),
    /// Wait until another task resolves the pause (breakpoints), or the pause timeout.
    Pause(PauseHandle),
}

/// A rule in the chain. Implementations must be cheap when they do not apply: they run on
/// every exchange.
pub trait Interceptor: Send + Sync {
    /// A short name for logs and the UI.
    fn name(&self) -> &str;

    /// Whether `on_request` needs the whole request body in [`RequestCtx::body`].
    fn needs_request_body(&self) -> bool {
        false
    }

    /// Whether `on_response` needs the whole response body in [`ResponseCtx::body`].
    fn needs_response_body(&self) -> bool {
        false
    }

    /// Looks at or changes the request before it goes to the server.
    fn on_request(&self, request: &mut RequestCtx) -> Action {
        let _ = request;
        Action::Continue
    }

    /// Looks at or changes the response before it goes to the client.
    fn on_response(&self, request: &RequestCtx, response: &mut ResponseCtx) -> Action {
        let _ = (request, response);
        Action::Continue
    }
}

/// The registered interceptors, in order. Cloning is cheap.
#[derive(Clone, Default)]
pub struct Interceptors {
    chain: Vec<Arc<dyn Interceptor>>,
}

impl std::fmt::Debug for Interceptors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.chain.iter().map(|i| i.name()))
            .finish()
    }
}

impl Interceptors {
    /// An empty chain.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends `interceptor`; it runs after every one added before it.
    pub fn push(&mut self, interceptor: Arc<dyn Interceptor>) {
        self.chain.push(interceptor);
    }

    /// Whether no interceptor is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    /// Whether any interceptor needs the request body buffered.
    #[must_use]
    pub fn needs_request_body(&self) -> bool {
        self.chain.iter().any(|i| i.needs_request_body())
    }

    /// Whether any interceptor needs the response body buffered.
    #[must_use]
    pub fn needs_response_body(&self) -> bool {
        self.chain.iter().any(|i| i.needs_response_body())
    }

    /// Runs `on_request` of each interceptor, applying delays and pauses, until one responds.
    pub async fn run_request(&self, ctx: &mut RequestCtx, timeout: Duration) -> Outcome {
        let mut outcome = Outcome::default();
        for interceptor in &self.chain {
            let action = interceptor.on_request(ctx);
            if let Some(response) = outcome
                .settle(action, timeout, |edit| edit.apply_request(ctx))
                .await
            {
                outcome.response = Some(response);
                outcome.by = Some(interceptor.name().to_owned());
                break;
            }
        }
        outcome
    }

    /// Runs `on_response` of each interceptor, applying delays and pauses, until one responds.
    pub async fn run_response(
        &self,
        request: &RequestCtx,
        ctx: &mut ResponseCtx,
        timeout: Duration,
    ) -> Outcome {
        let mut outcome = Outcome::default();
        for interceptor in &self.chain {
            let action = interceptor.on_response(request, ctx);
            if let Some(response) = outcome
                .settle(action, timeout, |edit| edit.apply_response(ctx))
                .await
            {
                outcome.response = Some(response);
                outcome.by = Some(interceptor.name().to_owned());
                break;
            }
        }
        outcome
    }
}

/// What a chain run decided, beyond the edits it made to the context.
#[derive(Debug, Default)]
pub struct Outcome {
    /// The response an interceptor answered with, which ends the chain.
    pub response: Option<Response<Bytes>>,
    /// The name of that interceptor.
    pub by: Option<String>,
    /// Whether a pause ran out of time and the exchange went on unchanged.
    pub pause_timed_out: bool,
    /// Whether a pause was aborted (then `response` is the abort response).
    pub aborted: bool,
}

impl Outcome {
    async fn settle(
        &mut self,
        action: Action,
        timeout: Duration,
        edit: impl FnOnce(Edit),
    ) -> Option<Response<Bytes>> {
        match action {
            Action::Continue => None,
            Action::Respond(response) => Some(response),
            Action::Delay(delay) => {
                tokio::time::sleep(delay).await;
                None
            }
            Action::Pause(handle) => match handle.wait(timeout).await {
                Resolution::Resume => None,
                Resolution::Edit(change) => {
                    edit(change);
                    None
                }
                Resolution::Abort => {
                    self.aborted = true;
                    Some(plain(StatusCode::BAD_GATEWAY, "aborted at a breakpoint\n"))
                }
                Resolution::TimedOut => {
                    self.pause_timed_out = true;
                    None
                }
            },
        }
    }
}

/// How a pause was resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// Go on unchanged.
    Resume,
    /// Apply the edit, then go on.
    Edit(Edit),
    /// Answer the client with `502` and do not contact the server.
    Abort,
    /// Nobody decided in time; go on unchanged.
    TimedOut,
}

/// Changes a breakpoint applies to the paused request or response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Edit {
    /// Headers to remove, applied before `set_headers`.
    pub remove_headers: Vec<HeaderName>,
    /// Headers to set (replacing every value of the same name).
    pub set_headers: Vec<(HeaderName, HeaderValue)>,
    /// A new body.
    pub body: Option<Bytes>,
    /// A new status (responses only).
    pub status: Option<StatusCode>,
    /// A new method (requests only).
    pub method: Option<Method>,
    /// A new path and query, such as `/a?b=1` (requests only).
    pub path: Option<String>,
    /// A new server (requests only): the request goes there, like map-remote.
    pub server: Option<Server>,
}

/// A server an [`Edit`] sends the request to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    /// `http` or `https`.
    pub scheme: &'static str,
    /// Host name or IP literal, without brackets.
    pub host: String,
    /// Port.
    pub port: u16,
}

impl Edit {
    fn apply_request(self, ctx: &mut RequestCtx) {
        for name in self.remove_headers {
            ctx.headers.remove(name);
        }
        for (name, value) in self.set_headers {
            ctx.headers.insert(name, value);
        }
        if let Some(body) = self.body {
            ctx.body = Some(body);
        }
        if let Some(method) = self.method {
            ctx.method = method;
        }
        if let Some(path) = self.path {
            ctx.path = path;
        }
        if let Some(server) = self.server {
            ctx.scheme = server.scheme;
            ctx.host = server.host;
            ctx.port = server.port;
        }
    }

    fn apply_response(self, ctx: &mut ResponseCtx) {
        for name in self.remove_headers {
            ctx.headers.remove(name);
        }
        for (name, value) in self.set_headers {
            ctx.headers.insert(name, value);
        }
        if let Some(body) = self.body {
            ctx.body = Some(body);
        }
        if let Some(status) = self.status {
            ctx.status = status;
        }
    }
}

/// Which half of the exchange a pause holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Before the request goes to the server.
    Request,
    /// Before the response goes to the client.
    Response,
}

/// A pending pause, as the control plane lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PauseInfo {
    /// The pause id, used to resolve it.
    pub id: u64,
    /// The flow it holds.
    pub flow_id: u64,
    /// Which half of the exchange.
    pub phase: Phase,
}

/// What a pause holds, so the control plane can show it before it is edited.
#[derive(Debug, Clone)]
pub struct Paused {
    /// The request as it would go to the server (after the earlier interceptors).
    pub request: PausedRequest,
    /// The response as it would go to the client; `None` for a request pause.
    pub response: Option<PausedResponse>,
}

/// The request half of a [`Paused`] exchange.
#[derive(Debug, Clone)]
pub struct PausedRequest {
    /// Request method.
    pub method: Method,
    /// Absolute URL of the server the request goes to.
    pub url: String,
    /// Request headers.
    pub headers: HeaderMap,
    /// Request body.
    pub body: PausedBody,
}

/// The response half of a [`Paused`] exchange.
#[derive(Debug, Clone)]
pub struct PausedResponse {
    /// Response status.
    pub status: StatusCode,
    /// Response headers.
    pub headers: HeaderMap,
    /// Response body.
    pub body: PausedBody,
}

/// A paused body, as far as the proxy buffered it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PausedBody {
    /// The whole body.
    Whole(Bytes),
    /// The body is larger than the proxy's body limit; it streams on unchanged unless an
    /// edit replaces it.
    TooLarge,
    /// No interceptor asked for the body, so it was not buffered.
    NotBuffered,
}

impl PausedBody {
    fn of(body: Option<&Bytes>, flags: &[Flag]) -> Self {
        match body {
            Some(bytes) => Self::Whole(bytes.clone()),
            None if flags.contains(&Flag::RewriteSkippedBodyTooLarge) => Self::TooLarge,
            None => Self::NotBuffered,
        }
    }
}

impl Paused {
    /// The request of `ctx`, before it goes to the server.
    #[must_use]
    pub fn of_request(ctx: &RequestCtx) -> Self {
        Self {
            request: PausedRequest::of(ctx),
            response: None,
        }
    }

    /// The exchange of `request` and `response`, before the response goes to the client.
    #[must_use]
    pub fn of_response(request: &RequestCtx, response: &ResponseCtx) -> Self {
        Self {
            request: PausedRequest::of(request),
            response: Some(PausedResponse {
                status: response.status,
                headers: response.headers.clone(),
                body: PausedBody::of(response.body.as_ref(), &response.flags),
            }),
        }
    }
}

impl PausedRequest {
    fn of(ctx: &RequestCtx) -> Self {
        let host = if ctx.host.contains(':') {
            format!("[{}]", ctx.host)
        } else {
            ctx.host.clone()
        };
        let default_port = if ctx.scheme == "https" { 443 } else { 80 };
        let url = if ctx.port == default_port {
            format!("{}://{host}{}", ctx.scheme, ctx.path)
        } else {
            format!("{}://{host}:{}{}", ctx.scheme, ctx.port, ctx.path)
        };
        Self {
            method: ctx.method.clone(),
            url,
            headers: ctx.headers.clone(),
            body: PausedBody::of(ctx.body.as_ref(), &ctx.flags),
        }
    }
}

/// One registry entry: what the list shows, what the pause holds, and the waiter.
#[derive(Debug)]
struct Pending {
    info: PauseInfo,
    detail: Option<Arc<Paused>>,
    sender: oneshot::Sender<Resolution>,
}

/// The pending pauses, shared by the interceptors that create them and the control plane
/// that resolves them. Cloning is cheap.
#[derive(Debug, Clone, Default)]
pub struct Pauses {
    inner: Arc<PausesInner>,
}

#[derive(Debug, Default)]
struct PausesInner {
    next_id: AtomicU64,
    pending: Mutex<HashMap<u64, Pending>>,
    /// Where [`FlowEvent::Paused`] and [`FlowEvent::Resumed`] go, once attached.
    bus: std::sync::OnceLock<Bus>,
}

impl Pauses {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Publishes [`FlowEvent::Paused`] and [`FlowEvent::Resumed`] on `bus` from now on.
    /// Only the first bus attached is used.
    pub fn attach(&self, bus: Bus) {
        let _ = self.inner.bus.set(bus);
    }

    /// Registers a pause of `flow_id` and returns the handle to put in [`Action::Pause`].
    #[must_use]
    pub fn pause(&self, flow_id: u64, phase: Phase) -> PauseHandle {
        self.register(flow_id, phase, None)
    }

    /// Like [`pause`](Self::pause), and keeps `detail` for [`detail`](Self::detail).
    #[must_use]
    pub fn pause_with(&self, flow_id: u64, phase: Phase, detail: Paused) -> PauseHandle {
        self.register(flow_id, phase, Some(Arc::new(detail)))
    }

    fn register(&self, flow_id: u64, phase: Phase, detail: Option<Arc<Paused>>) -> PauseHandle {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (sender, receiver) = oneshot::channel();
        let info = PauseInfo { id, flow_id, phase };
        self.publish(&info, None);
        self.lock().insert(
            id,
            Pending {
                info: info.clone(),
                detail,
                sender,
            },
        );
        PauseHandle {
            id,
            info,
            receiver,
            pauses: self.clone(),
        }
    }

    /// The phase of pending pause `id`.
    #[must_use]
    pub fn phase(&self, id: u64) -> Option<Phase> {
        self.lock().get(&id).map(|pending| pending.info.phase)
    }

    /// Pending pause `id` and what it holds (`None` when it was registered without detail).
    #[must_use]
    pub fn detail(&self, id: u64) -> Option<(PauseInfo, Option<Arc<Paused>>)> {
        self.lock()
            .get(&id)
            .map(|pending| (pending.info.clone(), pending.detail.clone()))
    }

    fn publish(&self, info: &PauseInfo, resolution: Option<&Resolution>) {
        let Some(bus) = self.inner.bus.get() else {
            return;
        };
        let event = PauseEvent::new(info, resolution);
        bus.publish(if resolution.is_some() {
            FlowEvent::Resumed(Arc::new(event))
        } else {
            FlowEvent::Paused(Arc::new(event))
        });
    }

    /// Resolves pause `id`. Returns `false` when there is no such pending pause.
    pub fn resolve(&self, id: u64, resolution: Resolution) -> bool {
        let Some(pending) = self.lock().remove(&id) else {
            return false;
        };
        // The waiter may have timed out a moment ago; then the decision is moot.
        pending.sender.send(resolution).is_ok()
    }

    /// The pending pauses, by id.
    #[must_use]
    pub fn list(&self) -> Vec<PauseInfo> {
        let mut list: Vec<PauseInfo> = self
            .lock()
            .values()
            .map(|pending| pending.info.clone())
            .collect();
        list.sort_by_key(|info| info.id);
        list
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Pending>> {
        self.inner
            .pending
            .lock()
            .expect("pause registry lock poisoned")
    }
}

/// One pending pause; the chain waits on it.
#[derive(Debug)]
pub struct PauseHandle {
    id: u64,
    info: PauseInfo,
    receiver: oneshot::Receiver<Resolution>,
    pauses: Pauses,
}

impl PauseHandle {
    /// The pause id.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Waits for the resolution, at most `timeout`. Removes the pause from the registry
    /// whatever happens, so a forgotten breakpoint cannot hold the client forever.
    pub async fn wait(self, timeout: Duration) -> Resolution {
        let result = tokio::time::timeout(timeout, self.receiver).await;
        self.pauses.lock().remove(&self.id);
        let resolution = match result {
            Ok(Ok(resolution)) => resolution,
            // The registry dropped the sender without deciding: treat it like a timeout.
            Ok(Err(_)) | Err(_) => Resolution::TimedOut,
        };
        self.pauses.publish(&self.info, Some(&resolution));
        resolution
    }
}

/// A short `text/plain` response.
#[must_use]
pub fn plain(status: StatusCode, message: &str) -> Response<Bytes> {
    let mut response = Response::new(Bytes::from(message.to_owned()));
    *response.status_mut() = status;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

/// Adds and removes request headers (`--add-header`, `--remove-header`).
#[derive(Debug, Clone, Default)]
pub struct HeaderRules {
    add: Vec<(HeaderName, HeaderValue)>,
    remove: Vec<HeaderName>,
}

impl HeaderRules {
    /// Rules that remove `remove`, then set each of `add`.
    #[must_use]
    pub fn new(add: Vec<(HeaderName, HeaderValue)>, remove: Vec<HeaderName>) -> Self {
        Self { add, remove }
    }

    /// Parses `Name: value`, the form `--add-header` takes.
    ///
    /// # Errors
    ///
    /// Fails without a colon, or on an invalid name or value.
    pub fn parse_header(text: &str) -> anyhow::Result<(HeaderName, HeaderValue)> {
        let (name, value) = text
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("expected `Name: value`, got {text:?}"))?;
        Ok((
            HeaderName::from_bytes(name.trim().as_bytes())?,
            HeaderValue::from_str(value.trim())?,
        ))
    }
}

impl Interceptor for HeaderRules {
    fn name(&self) -> &'static str {
        "header-rules"
    }

    fn on_request(&self, request: &mut RequestCtx) -> Action {
        for name in &self.remove {
            request.headers.remove(name);
        }
        for (name, value) in &self.add {
            request.headers.insert(name.clone(), value.clone());
        }
        Action::Continue
    }
}

/// Answers requests to the listed hosts (and their subdomains) itself (`--block-host`).
#[derive(Debug, Clone)]
pub struct BlockHost {
    hosts: Vec<String>,
    status: StatusCode,
}

impl BlockHost {
    /// Blocks `hosts` with `status`.
    #[must_use]
    pub fn new(hosts: Vec<String>, status: StatusCode) -> Self {
        let hosts = hosts
            .into_iter()
            .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
            .collect();
        Self { hosts, status }
    }

    fn blocks(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.hosts.iter().any(|blocked| {
            host == *blocked
                || host
                    .strip_suffix(blocked.as_str())
                    .is_some_and(|rest| rest.ends_with('.'))
        })
    }
}

impl Interceptor for BlockHost {
    fn name(&self) -> &'static str {
        "block-host"
    }

    fn on_request(&self, request: &mut RequestCtx) -> Action {
        if self.blocks(&request.host) {
            Action::Respond(plain(
                self.status,
                &format!("{} blocked {}\n", crate::NAME, request.host),
            ))
        } else {
            Action::Continue
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(host: &str) -> RequestCtx {
        RequestCtx {
            id: 1,
            client: SocketAddr::from(([127, 0, 0, 1], 1)),
            scheme: "https",
            host: host.to_owned(),
            port: 443,
            method: Method::GET,
            path: "/".to_owned(),
            headers: HeaderMap::new(),
            body: None,
            flags: Vec::new(),
            extensions: http::Extensions::new(),
        }
    }

    /// Appends its name to the `x-order` header, then does `action`.
    struct Mark(&'static str, fn() -> Action);

    impl Interceptor for Mark {
        fn name(&self) -> &'static str {
            self.0
        }

        fn on_request(&self, request: &mut RequestCtx) -> Action {
            let order = request
                .headers
                .get("x-order")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            let order = format!("{order}{}", self.0);
            request.headers.insert(
                "x-order",
                HeaderValue::from_str(&order).expect("ascii names"),
            );
            (self.1)()
        }
    }

    #[tokio::test]
    async fn the_chain_runs_in_order_and_stops_at_respond() {
        let mut chain = Interceptors::new();
        chain.push(Arc::new(Mark("a", || Action::Continue)));
        chain.push(Arc::new(Mark("b", || {
            Action::Respond(plain(StatusCode::IM_A_TEAPOT, "no"))
        })));
        chain.push(Arc::new(Mark("c", || Action::Continue)));
        let mut request = ctx("x.test");
        let outcome = chain.run_request(&mut request, DEFAULT_PAUSE_TIMEOUT).await;
        assert_eq!(request.headers["x-order"], "ab", "c must not run");
        assert_eq!(outcome.by.as_deref(), Some("b"));
        assert_eq!(
            outcome.response.map(|r| r.status()),
            Some(StatusCode::IM_A_TEAPOT)
        );
    }

    #[tokio::test]
    async fn delay_waits_then_continues() {
        let mut chain = Interceptors::new();
        chain.push(Arc::new(Mark("a", || {
            Action::Delay(Duration::from_millis(30))
        })));
        chain.push(Arc::new(Mark("b", || Action::Continue)));
        let started = std::time::Instant::now();
        let mut request = ctx("x.test");
        let outcome = chain.run_request(&mut request, DEFAULT_PAUSE_TIMEOUT).await;
        assert!(started.elapsed() >= Duration::from_millis(30));
        assert!(outcome.response.is_none());
        assert_eq!(request.headers["x-order"], "ab");
    }

    #[tokio::test]
    async fn a_pause_is_resumed_with_an_edit() {
        let pauses = Pauses::new();
        let handle = pauses.pause(9, Phase::Request);
        assert_eq!(
            pauses.list(),
            [PauseInfo {
                id: handle.id(),
                flow_id: 9,
                phase: Phase::Request
            }]
        );
        let edit = Edit {
            body: Some(Bytes::from_static(b"new")),
            ..Edit::default()
        };
        let waiter = tokio::spawn(handle.wait(DEFAULT_PAUSE_TIMEOUT));
        assert!(pauses.resolve(1, Resolution::Edit(edit.clone())));
        assert_eq!(waiter.await.expect("no panic"), Resolution::Edit(edit));
        assert_eq!(pauses.list(), []);
        assert!(!pauses.resolve(1, Resolution::Resume), "already resolved");
    }

    #[tokio::test]
    async fn an_aborted_pause_answers_502_without_continuing() {
        struct Break(Pauses);
        impl Interceptor for Break {
            fn name(&self) -> &'static str {
                "break"
            }
            fn on_request(&self, request: &mut RequestCtx) -> Action {
                Action::Pause(self.0.pause(request.id, Phase::Request))
            }
        }
        let pauses = Pauses::new();
        let mut chain = Interceptors::new();
        chain.push(Arc::new(Break(pauses.clone())));
        let resolver = {
            let pauses = pauses.clone();
            tokio::spawn(async move {
                loop {
                    if let Some(info) = pauses.list().first() {
                        return pauses.resolve(info.id, Resolution::Abort);
                    }
                    tokio::task::yield_now().await;
                }
            })
        };
        let mut request = ctx("x.test");
        let outcome = chain.run_request(&mut request, DEFAULT_PAUSE_TIMEOUT).await;
        assert!(resolver.await.expect("no panic"));
        assert!(outcome.aborted);
        assert_eq!(
            outcome.response.map(|r| r.status()),
            Some(StatusCode::BAD_GATEWAY)
        );
    }

    #[tokio::test]
    async fn a_forgotten_pause_times_out_and_leaves_the_registry() {
        let pauses = Pauses::new();
        let handle = pauses.pause(1, Phase::Response);
        let resolution = handle.wait(Duration::from_millis(20)).await;
        assert_eq!(resolution, Resolution::TimedOut);
        assert_eq!(pauses.list(), []);
    }

    #[test]
    fn a_paused_request_has_an_absolute_url_and_knows_a_skipped_body() {
        let mut request = ctx("::1");
        request.port = 8443;
        request.path = "/a?b=1".to_owned();
        request.flags.push(Flag::RewriteSkippedBodyTooLarge);
        let paused = Paused::of_request(&request);
        assert_eq!(paused.request.url, "https://[::1]:8443/a?b=1");
        assert_eq!(paused.request.body, PausedBody::TooLarge);
        let mut request = ctx("x.test");
        request.body = Some(Bytes::from_static(b"hi"));
        let paused = Paused::of_request(&request);
        assert_eq!(paused.request.url, "https://x.test/");
        assert_eq!(
            paused.request.body,
            PausedBody::Whole(Bytes::from_static(b"hi"))
        );
        assert_eq!(
            Paused::of_request(&ctx("x.test")).request.body,
            PausedBody::NotBuffered
        );
    }

    #[test]
    fn block_host_matches_the_host_and_its_subdomains_only() {
        let block = BlockHost::new(vec!["Ads.Test".to_owned()], StatusCode::FORBIDDEN);
        assert!(block.blocks("ads.test"));
        assert!(block.blocks("x.ads.test."));
        assert!(!block.blocks("badads.test"));
        assert!(!block.blocks("ads.test.evil"));
    }

    #[test]
    fn header_flags_parse() -> anyhow::Result<()> {
        let (name, value) = HeaderRules::parse_header("X-Debug:  on ")?;
        assert_eq!((name.as_str(), value.to_str()?), ("x-debug", "on"));
        assert!(HeaderRules::parse_header("no colon").is_err());
        Ok(())
    }
}
