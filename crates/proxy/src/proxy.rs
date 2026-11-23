//! The listener, CONNECT tunnels, TLS interception and request forwarding.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use bytes::Bytes;
use fingerprint::known::{self, Match};
use fingerprint::{ClientHello, Ja3, Ja4, Transport};
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::uri::Scheme;
use http::{Method, Request, Response, StatusCode, Version};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt as _, Empty, Full};
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;

use crate::access::{Denied, Guard};
use crate::body::{self, Buffered, Capture, OnEnd, SharedCapture, Tee};
use crate::ca::Ca;
use crate::certs::CertCache;
use crate::clock::Utc;
use crate::events::{Bus, DEFAULT_MAX_FLOWS, FlowEvent, FlowStore, SCHEMA_VERSION, Started};
use crate::flow::{
    BodyRecord, ClientTls, Event, Exchange, Flag, Timing, TlsFailure, Tunnel, TunnelTls,
};
use crate::hello::{self, Peeked, Prefixed};
use crate::intercept::{
    DEFAULT_PAUSE_TIMEOUT, Interceptors, Outcome, Pauses, RequestCtx, ResponseCtx,
};
use crate::magic;
use crate::pairing::{Pairing, Verdict};
use crate::passthrough::{self, Passthrough};
use crate::replay::ReplayTag;
use crate::upstream::{self, Connector, Opened, Sender};
use crate::upstream_proxy::{Bypass, Route, UpstreamProxy};
use crate::ws::{self, WsLimits};

/// Body type of every request and response the proxy forwards or makes.
pub(crate) type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Limit on the TLS handshake with the client.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether the proxy may listen on an address other hosts can reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RemoteAccess {
    /// Only loopback addresses may be bound.
    #[default]
    LoopbackOnly,
    /// Any address may be bound (`--allow-remote`).
    Allow,
}

/// How the proxy checks server certificates.
#[derive(Debug, Clone)]
pub enum UpstreamTls {
    /// Verify against the Mozilla roots of `webpki-roots` plus `extra_roots`.
    Verify {
        /// Additional trusted roots, such as a test CA.
        extra_roots: Vec<CertificateDer<'static>>,
    },
    /// Accept any certificate (`--upstream-insecure`).
    Insecure,
}

impl Default for UpstreamTls {
    fn default() -> Self {
        Self::Verify {
            extra_roots: Vec::new(),
        }
    }
}

/// Settings of a [`Proxy`].
#[derive(Debug, Clone)]
pub struct Config {
    /// Address to listen on.
    pub listen: SocketAddr,
    /// Whether a non-loopback `listen` is allowed.
    pub remote: RemoteAccess,
    /// Body bytes kept per request and per response for the log.
    pub body_limit: usize,
    /// Server certificate checking.
    pub upstream: UpstreamTls,
    /// Directory holding the CA.
    pub config_dir: PathBuf,
    /// Flows the in-memory [`FlowStore`] keeps.
    pub max_flows: usize,
    /// How long a breakpoint pause waits before the exchange goes on.
    pub pause_timeout: Duration,
    /// The interceptor chain, in order.
    pub interceptors: Interceptors,
    /// The registry pausing interceptors register with; the control plane resolves them.
    pub pauses: Pauses,
    /// Device pairing: when set, only loopback and approved clients may use the proxy.
    pub pairing: Option<Pairing>,
    /// Hosts relayed without decryption (`--passthrough`, `--decrypt-only`), live.
    pub passthrough: Passthrough,
    /// WebSocket capture limits (`--ws-body-limit`, `--ws-max-messages`).
    pub ws: WsLimits,
    /// Another proxy every outbound connection goes through (`--upstream-proxy`).
    pub upstream_proxy: Option<UpstreamProxy>,
    /// Destinations that skip `upstream_proxy` (`--upstream-bypass`).
    pub upstream_bypass: Bypass,
}

impl Config {
    /// The defaults: `127.0.0.1:8080`, loopback only, verified upstream TLS, the CA in
    /// `config_dir`, no interceptors.
    #[must_use]
    pub fn new(config_dir: PathBuf) -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            remote: RemoteAccess::LoopbackOnly,
            body_limit: crate::DEFAULT_BODY_LIMIT,
            upstream: UpstreamTls::default(),
            config_dir,
            max_flows: DEFAULT_MAX_FLOWS,
            pause_timeout: DEFAULT_PAUSE_TIMEOUT,
            interceptors: Interceptors::new(),
            pauses: Pauses::new(),
            pairing: None,
            passthrough: Passthrough::default(),
            ws: WsLimits::default(),
            upstream_proxy: None,
            upstream_bypass: Bypass::default(),
        }
    }
}

/// Refuses a non-loopback `addr` unless `remote` allows it.
///
/// # Errors
///
/// Fails for a non-loopback address with [`RemoteAccess::LoopbackOnly`].
pub fn check_listen(addr: SocketAddr, remote: RemoteAccess) -> anyhow::Result<()> {
    if addr.ip().is_loopback() || remote == RemoteAccess::Allow {
        return Ok(());
    }
    bail!(
        "refusing to listen on {addr}: anyone who can reach it could use the proxy, and the CA \
         key signs certificates for every host; pass --allow-remote if that is intended"
    )
}

/// A bound proxy, ready to [`run`](Self::run).
#[derive(Debug)]
pub struct Proxy {
    listener: TcpListener,
    state: Arc<State>,
    store: FlowStore,
    pauses: Pauses,
}

#[derive(Debug)]
pub(crate) struct State {
    certs: CertCache,
    pub(crate) connector: Connector,
    body_limit: usize,
    bus: Bus,
    next_id: AtomicU64,
    interceptors: Interceptors,
    pause_timeout: Duration,
    /// The proxy's own listening address.
    pub(crate) listen: SocketAddr,
    /// Which clients may use the proxy; `None` serves everyone who can connect.
    pub(crate) pairing: Option<Pairing>,
    passthrough: Passthrough,
    /// WebSocket capture limits.
    ws: WsLimits,
    /// Open WebSocket connections that accept injected messages (shared with the store).
    ws_live: ws::Live,
}

impl State {
    pub(crate) fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(crate) fn emit(&self, event: Event) {
        self.bus.publish(FlowEvent::finished(event));
    }

    pub(crate) fn ca(&self) -> &Ca {
        self.certs.ca()
    }

    /// The addresses no dial may reach (see [`Guard::check`]).
    pub(crate) fn guard(&self) -> &Guard {
        self.connector.guard()
    }
}

impl Proxy {
    /// Checks the address, loads or creates the CA, binds the listener and starts the
    /// [`FlowStore`], which follows the event bus from here on.
    ///
    /// # Errors
    ///
    /// Fails on a refused address (see [`check_listen`]), a CA error or a bind error.
    pub async fn bind(config: Config) -> anyhow::Result<Self> {
        check_listen(config.listen, config.remote)?;
        let ca = Ca::load_or_create(&config.config_dir)?;
        let listener = TcpListener::bind(config.listen)
            .await
            .with_context(|| format!("binding {}", config.listen))?;
        let listen = listener.local_addr()?;
        let guard = Guard::new(listen);
        if let Some(proxy) = &config.upstream_proxy
            && guard.check_name(IpAddr::from([127, 0, 0, 1]), proxy.host(), proxy.port())
                == Err(Denied::OwnListener)
        {
            bail!("the upstream proxy {proxy} is this proxy's own listener {listen}");
        }
        let bus = Bus::new();
        config.pauses.attach(bus.clone());
        let store = FlowStore::with_ws_messages(config.max_flows, config.ws.max_messages);
        // The task ends when the bus closes, which is when the proxy is dropped.
        drop(store.follow(bus.subscribe()));
        let state = State {
            certs: CertCache::new(ca),
            connector: Connector::new(
                &config.upstream,
                Route::new(config.upstream_proxy, config.upstream_bypass),
                guard,
            )?,
            body_limit: config.body_limit,
            bus,
            next_id: AtomicU64::new(0),
            interceptors: config.interceptors,
            pause_timeout: config.pause_timeout,
            listen,
            pairing: config.pairing,
            passthrough: config.passthrough,
            ws: config.ws,
            ws_live: store.ws().live().clone(),
        };
        Ok(Self {
            listener,
            state: Arc::new(state),
            store,
            pauses: config.pauses,
        })
    }

    /// A receiver of every [`FlowEvent`] published from now on.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<FlowEvent> {
        self.state.bus.subscribe()
    }

    /// The event bus.
    #[must_use]
    pub fn bus(&self) -> &Bus {
        &self.state.bus
    }

    /// The in-memory flow store.
    #[must_use]
    pub fn store(&self) -> &FlowStore {
        &self.store
    }

    /// The pause registry breakpoints use.
    #[must_use]
    pub fn pauses(&self) -> &Pauses {
        &self.pauses
    }

    /// The live passthrough lists; [`Passthrough::replace`] changes them for new tunnels.
    #[must_use]
    pub fn passthrough(&self) -> &Passthrough {
        &self.state.passthrough
    }

    /// The shared state, for replays sent by the control plane. Call it after the last
    /// [`refuse_target`](Self::refuse_target).
    pub(crate) fn shared_state(&self) -> Arc<State> {
        Arc::clone(&self.state)
    }

    /// Makes the proxy refuse requests addressed to `addr` (with `403`), so a proxied page
    /// cannot reach the control plane through the proxy.
    ///
    /// # Panics
    ///
    /// Never in practice: the state is shared only by [`run`](Self::run), which consumes
    /// the proxy.
    pub fn refuse_target(&mut self, addr: SocketAddr) {
        Arc::get_mut(&mut self.state)
            .expect("the state is shared only once run() starts, which consumes the proxy")
            .connector
            .refuse(addr);
    }

    /// The bound address.
    ///
    /// # Errors
    ///
    /// Fails if the OS cannot report it.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// The CA in use.
    #[must_use]
    pub fn ca(&self) -> &Ca {
        self.state.certs.ca()
    }

    /// Accepts and serves clients until the listener fails.
    ///
    /// # Errors
    ///
    /// Fails when accepting fails.
    pub async fn run(self) -> anyhow::Result<()> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let _ = stream.set_nodelay(true);
            tokio::spawn(serve_client(Arc::clone(&self.state), stream, peer));
        }
    }
}

/// Serves the plain HTTP/1.1 connection from the client: CONNECT and absolute-form requests.
async fn serve_client(state: Arc<State>, stream: TcpStream, peer: SocketAddr) {
    let service = service_fn(move |request: Request<Incoming>| {
        let state = Arc::clone(&state);
        async move {
            // An unpaired client gets no answer: the error makes hyper close the connection.
            if let Some(pairing) = &state.pairing
                && pairing.screen(peer.ip(), &request, Instant::now()) == Verdict::Reject
            {
                return Err(NotPaired);
            }
            Ok(proxy_request(state, peer, request).await)
        }
    });
    // A client that disconnects mid-request is normal for a proxy; there is no one to tell.
    let _ = http1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await;
}

/// Why a connection was closed without an answer.
#[derive(Debug)]
struct NotPaired;

impl std::fmt::Display for NotPaired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("client is not paired")
    }
}

impl std::error::Error for NotPaired {}

async fn proxy_request(
    state: Arc<State>,
    peer: SocketAddr,
    request: Request<Incoming>,
) -> Response<ProxyBody> {
    if request.method() == Method::CONNECT {
        let Some(authority) = request.uri().authority().cloned() else {
            return text(StatusCode::BAD_REQUEST, "CONNECT needs host:port\n");
        };
        let host = unbracket(authority.host()).to_owned();
        let port = authority.port_u16().unwrap_or(443);
        // A name is checked again on the address it resolves to, when it is dialled.
        if let Err(denied) = state.guard().check_name(peer.ip(), &host, port) {
            return refusal(denied);
        }
        tokio::spawn(async move {
            if let Ok(upgraded) = hyper::upgrade::on(request).await {
                tunnel(state, peer, host, port, TokioIo::new(upgraded)).await;
            }
        });
        return Response::new(empty());
    }
    // Origin-form: a browser opened http://IP:PORT/ directly. Serve the setup page.
    let Some(authority) = request.uri().authority().cloned() else {
        return magic_response(&state, peer, &request);
    };
    let host = unbracket(authority.host());
    if let Err(denied) =
        (state.guard()).check_name(peer.ip(), host, authority.port_u16().unwrap_or(80))
    {
        return refusal(denied);
    }
    if host.eq_ignore_ascii_case(crate::MAGIC_HOST) {
        return magic_response(&state, peer, &request);
    }
    if request.uri().scheme() != Some(&Scheme::HTTP) {
        return text(
            StatusCode::BAD_REQUEST,
            "only http:// is proxied without CONNECT\n",
        );
    }
    let target = Target {
        scheme: "http",
        host: unbracket(authority.host()).to_owned(),
        port: authority.port_u16().unwrap_or(80),
        server_name: String::new(),
        offer_h2: false,
        tls: None,
    };
    forward(&state, peer, &target, None, request).await
}

/// Handles the bytes of a CONNECT tunnel: TLS is intercepted, anything else passed through.
async fn tunnel<S>(state: Arc<State>, peer: SocketAddr, host: String, port: u16, mut io: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let peeked = match hello::peek(&mut io).await {
        Ok(peeked) => peeked,
        Err(e) => return state.emit(tunnel_failure(&state, peer, (&host, port), &e)),
    };
    let (raw, message) = match peeked {
        Peeked::Tls { raw, message } => (raw, message),
        Peeked::Other { raw } => return pass_through(&state, peer, &host, port, raw, io).await,
    };
    let client_hello = ClientHello::parse(&message);
    let sni = hello::sni(&client_hello);
    let ja4 = Ja4::new(&client_hello, Transport::Tcp);
    let known_client = known_name(&ja4);
    let server_name = sni.clone().unwrap_or_else(|| host.clone());
    if state
        .passthrough
        .current()
        .tunnels(&host, port, sni.as_deref())
    {
        let tls = TunnelTls {
            sni,
            alpn_offered: (client_hello.alpn.iter())
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .collect(),
            ja4: ja4.hashed().to_owned(),
            ja3_hash: Ja3::new(&client_hello).hash().to_owned(),
            known_client,
        };
        return passthrough::relay(&state, peer, (&host, port), tls, raw, io).await;
    }
    let failure = |reason: String| {
        Event::TlsFailure(TlsFailure {
            id: state.next_id(),
            time: Utc::now().rfc3339(),
            client: peer,
            target: format!("{host}:{port}"),
            sni: sni.clone(),
            ja4: ja4.hashed().to_owned(),
            known_client: known_client.clone(),
            reason,
        })
    };
    let config = match state.certs.server_config(&server_name) {
        Ok(config) => config,
        Err(e) => return state.emit(failure(format!("cannot issue a certificate: {e:#}"))),
    };
    let accept = TlsAcceptor::from(config).accept(Prefixed::new(raw, io));
    let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, accept).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => return state.emit(failure(e.to_string())),
        Err(_) => return state.emit(failure("handshake timed out".to_owned())),
    };
    let session = tls.get_ref().1;
    let h2 = session.alpn_protocol() == Some(b"h2");
    let client_tls = ClientTls {
        version: session.protocol_version().map(|v| format!("{v:?}")),
        alpn: session
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned()),
        sni,
        ja4: ja4.hashed().to_owned(),
        ja3_hash: Ja3::new(&client_hello).hash().to_owned(),
        client: known_client,
    };
    let target = Arc::new(Target {
        scheme: "https",
        host,
        port,
        server_name,
        offer_h2: client_hello.alpn.iter().any(|p| p == b"h2"),
        tls: Some(client_tls),
    });
    let pool: Arc<Pool> = Arc::default();
    let service = service_fn(move |request| {
        let (state, target, pool) = (Arc::clone(&state), Arc::clone(&target), Arc::clone(&pool));
        async move { Ok::<_, Infallible>(forward(&state, peer, &target, Some(&pool), request).await) }
    });
    let io = TokioIo::new(tls);
    // Connection errors end the tunnel; each request already logged its own outcome.
    let _ = if h2 {
        http2::Builder::new(TokioExecutor::new())
            .serve_connection(io, service)
            .await
    } else {
        http1::Builder::new()
            .preserve_header_case(true)
            .serve_connection(io, service)
            .with_upgrades()
            .await
    };
}

/// The record of a tunnel that ended before anything was relayed, such as a ClientHello
/// that never completed.
fn tunnel_failure(
    state: &State,
    peer: SocketAddr,
    (host, port): (&str, u16),
    error: &std::io::Error,
) -> Event {
    Event::Tunnel(Tunnel {
        id: state.next_id(),
        time: Utc::now().rfc3339(),
        client: peer,
        target: format!("{host}:{port}"),
        bytes_up: 0,
        bytes_down: 0,
        error: Some(error.to_string()),
        reason: None,
        tls: None,
        duration_ms: None,
    })
}

/// Copies a non-TLS tunnel both ways and logs its size.
async fn pass_through<S>(
    state: &State,
    peer: SocketAddr,
    host: &str,
    port: u16,
    raw: Vec<u8>,
    mut io: S,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut record = Tunnel {
        id: state.next_id(),
        time: String::new(),
        client: peer,
        target: format!("{host}:{port}"),
        bytes_up: raw.len() as u64,
        bytes_down: 0,
        error: None,
        reason: None,
        tls: None,
        duration_ms: None,
    };
    let result = async {
        let mut server = upstream::open_raw(&state.connector, peer.ip(), host, port).await?;
        server.write_all(&raw).await?;
        let (up, down) = tokio::io::copy_bidirectional(&mut io, &mut server).await?;
        anyhow::Ok((up, down))
    }
    .await;
    match result {
        Ok((up, down)) => {
            record.bytes_up += up;
            record.bytes_down = down;
        }
        Err(e) => record.error = Some(format!("{e:#}")),
    }
    record.time = Utc::now().rfc3339();
    state.emit(Event::Tunnel(record));
}

/// Serves a TCP connection the WireGuard capture mode terminated, as if `peer` had sent
/// CONNECT to `dst`: TLS goes through [`tunnel`] under its SNI, plain HTTP on port 80 is
/// forwarded request by request under its `Host` header, anything else is relayed raw.
///
/// Destinations the guard refuses for a peer on another machine (loopback, unspecified,
/// link-local, the control plane, the proxy's own listener, and an SNI or `Host` naming
/// them) are dropped, so a peer cannot reach services that listen on loopback only. Names
/// are checked again on the address they resolve to, when they are dialled.
#[cfg(feature = "wireguard")]
pub(crate) async fn serve_transparent<S>(
    state: Arc<State>,
    peer: SocketAddr,
    dst: SocketAddr,
    io: S,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let local = |state: &State, host: &str, port: u16| {
        state.guard().check_name(peer.ip(), host, port).is_err()
    };
    let ip = dst.ip().to_string();
    if state.guard().check(peer.ip(), dst).is_err() {
        return;
    }
    if dst.port() == 80 {
        let service = service_fn(move |request: Request<Incoming>| {
            let state = Arc::clone(&state);
            async move {
                let host = (request.headers().get(header::HOST))
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<http::uri::Authority>().ok())
                    .map_or_else(|| dst.ip().to_string(), |a| unbracket(a.host()).to_owned());
                if let Err(denied) = state.guard().check_name(peer.ip(), &host, dst.port()) {
                    return Ok::<_, Infallible>(refusal(denied));
                }
                let target = Target {
                    scheme: "http",
                    host,
                    port: dst.port(),
                    server_name: String::new(),
                    offer_h2: false,
                    tls: None,
                };
                Ok(forward(&state, peer, &target, None, request).await)
            }
        });
        // A client that disconnects mid-request is normal; there is no one to tell.
        let _ = http1::Builder::new()
            .preserve_header_case(true)
            .serve_connection(TokioIo::new(io), service)
            .with_upgrades()
            .await;
        return;
    }
    let mut io = io;
    let peeked = match hello::peek(&mut io).await {
        Ok(peeked) => peeked,
        Err(e) => return state.emit(tunnel_failure(&state, peer, (&ip, dst.port()), &e)),
    };
    let (host, raw) = match peeked {
        Peeked::Tls { raw, message } => {
            let sni = hello::sni(&ClientHello::parse(&message));
            (sni.unwrap_or(ip), raw)
        }
        Peeked::Other { raw } => (ip, raw),
    };
    if local(&state, &host, dst.port()) {
        return;
    }
    tunnel(state, peer, host, dst.port(), Prefixed::new(raw, io)).await;
}

/// Where a tunnel or request goes, and what the client leg looked like.
#[derive(Debug)]
struct Target {
    scheme: &'static str,
    host: String,
    port: u16,
    /// Name for the server's certificate: the client's SNI, else the CONNECT host.
    server_name: String,
    offer_h2: bool,
    tls: Option<ClientTls>,
}

impl Target {
    fn authority(&self) -> String {
        let default_port = if self.scheme == "https" { 443 } else { 80 };
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == default_port {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// The interceptors' view of a request to this target; takes the headers from `parts`.
    fn request_ctx(
        &self,
        id: u64,
        client: SocketAddr,
        parts: &mut http::request::Parts,
        path: String,
    ) -> RequestCtx {
        let mut extensions = http::Extensions::new();
        if let Some(tls) = &self.tls {
            extensions.insert(crate::intercept::ClientInfo {
                ja4: tls.ja4.clone(),
                known_client: tls.client.clone(),
            });
        }
        RequestCtx {
            id,
            client,
            scheme: self.scheme,
            host: self.host.clone(),
            port: self.port,
            method: parts.method.clone(),
            path,
            headers: std::mem::take(&mut parts.headers),
            body: None,
            flags: Vec::new(),
            extensions,
        }
    }

    /// The server `req` names when an interceptor changed it (map-remote), else `None`.
    fn remap(&self, req: &RequestCtx) -> Option<Self> {
        let same = req.scheme == self.scheme && req.host == self.host && req.port == self.port;
        (!same).then(|| Self {
            scheme: req.scheme,
            host: req.host.clone(),
            port: req.port,
            server_name: String::new(),
            offer_h2: self.offer_h2,
            tls: self.tls.clone(),
        })
    }

    async fn open(
        &self,
        connector: &Connector,
        peer: IpAddr,
        upgrades: bool,
    ) -> anyhow::Result<Opened> {
        if self.scheme == "https" {
            // The CONNECT host is dialled (and checked); the SNI only names the certificate.
            let name = if self.server_name.is_empty() {
                &self.host
            } else {
                &self.server_name
            };
            let server = (self.host.as_str(), self.port);
            upstream::open_tls(connector, peer, server, name, self.offer_h2, upgrades).await
        } else {
            upstream::open_plain(connector, peer, &self.host, self.port, upgrades).await
        }
    }
}

/// The server connection of one tunnel, opened by its first request.
type Pool = tokio::sync::Mutex<Option<Sender>>;

/// Forwards one request, logging it when the response body ends.
///
/// Publishes [`FlowEvent::Started`] first. With interceptors registered, the request runs
/// through their `on_request` before the server is contacted and the response through
/// their `on_response` before the client sees it; bodies are buffered only when one of
/// them asks for it. The record shows what the client sent and what it received.
#[expect(clippy::too_many_lines, reason = "the exchange reads top to bottom")]
async fn forward<B>(
    state: &State,
    peer: SocketAddr,
    target: &Target,
    pool: Option<&Pool>,
    mut request: Request<B>,
) -> Response<ProxyBody>
where
    B: hyper::body::Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<BoxError> + std::fmt::Display,
{
    if target.host.eq_ignore_ascii_case(crate::MAGIC_HOST) {
        return magic_response(state, peer, &request);
    }
    let start = Instant::now();
    let client_version = request.version();
    let authority = target.authority();
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str)
        .to_owned();
    let mut record = start_record(state, peer, target, &request, &authority, &path);
    let upgrade = is_upgrade(&request);
    let client_upgrade = upgrade.then(|| hyper::upgrade::on(&mut request));
    let (mut parts, incoming) = request.into_parts();
    let websocket = upgrade && ws::is_websocket(&parts.headers);
    if websocket && state.ws.strip_compression && ws::strip_extensions(&mut parts.headers) {
        record.flags.push(Flag::WsExtensionsStripped);
    }
    let request_capture: SharedCapture = Arc::new(Mutex::new(Capture::new(state.body_limit)));
    let tee = Tee::new(incoming, Arc::clone(&request_capture), None);

    // Upgrades are joined byte for byte and skip the chain; so do replays without rules.
    let rules = (parts.extensions.get::<ReplayTag>()).is_none_or(|tag| tag.apply_rules);
    let intercepting = !state.interceptors.is_empty() && !upgrade && rules;
    let mut ctx = None;
    let body = if intercepting {
        let mut req = target.request_ctx(record.id, peer, &mut parts, path);
        match intercept_request(state, &mut req, &mut parts, tee, &mut record).await {
            Ok(body) => {
                ctx = Some(req);
                body
            }
            Err(Stop::Respond(response)) => {
                return respond_locally(
                    state,
                    record,
                    &request_capture,
                    start,
                    *response,
                    client_version,
                );
            }
            Err(Stop::Fail(error)) => return fail(state, record, &request_capture, start, &error),
        }
    } else {
        boxed(tee)
    };

    let remapped = remap(target, ctx.as_ref(), &mut record);
    let (target, pool) = remapped.as_ref().map_or((target, pool), |r| (r, None));
    let sender = match connect(
        state,
        dialer(peer, remapped.as_ref()),
        target,
        pool,
        upgrade,
        &mut record.timing,
    )
    .await
    {
        Ok(sender) => sender,
        Err(e) => return fail_connect(state, record, &request_capture, start, &e),
    };
    if sender.via_upstream_proxy() {
        record.flags.push(Flag::UpstreamProxy);
    }
    if let Err(e) = prepare(
        &mut parts,
        sender.version(),
        target.scheme,
        &target.authority(),
        upgrade,
    ) {
        return fail(state, record, &request_capture, start, &format!("{e:#}"));
    }
    let mut response = match sender.send(Request::from_parts(parts, body)).await {
        Ok(response) => response,
        Err(e) => return fail(state, record, &request_capture, start, &error_chain(&e)),
    };
    record.timing.first_byte_ms = Some(ms(start.elapsed()));
    record.upstream_version = Some(version_name(response.version()));

    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        set_response_head(&mut record, response.status(), response.headers());
        let capture = websocket.then(|| {
            let extensions = ws::negotiated(response.headers());
            if extensions != ws::Extensions::None {
                record.flags.push(Flag::WsCompressed);
            }
            record.ws_messages = Some(0);
            (
                state.bus.clone(),
                state.ws,
                extensions,
                record.id,
                state.ws_live.clone(),
            )
        });
        if let Some(client_upgrade) = client_upgrade {
            join_upgrades(client_upgrade, hyper::upgrade::on(&mut response), capture);
        }
        record.request_body =
            BodyRecord::from_capture(&lock(&request_capture), &record.request_headers);
        record.timing.total_ms = ms(start.elapsed());
        state.emit(Event::Exchange(Box::new(record)));
        let (parts, _) = response.into_parts();
        return Response::from_parts(parts, empty());
    }

    let (mut parts, incoming) = response.into_parts();
    strip_hop_by_hop(&mut parts.headers, false);
    parts.version = client_version;
    let body = match &ctx {
        None => boxed(incoming),
        Some(req) => {
            match intercept_response(state, req, &mut parts, incoming, &mut record).await {
                Ok(body) => body,
                Err(e) => return fail(state, record, &request_capture, start, &error_chain(&e)),
            }
        }
    };
    set_response_head(&mut record, parts.status, &parts.headers);
    let response_capture: SharedCapture = Arc::new(Mutex::new(Capture::new(state.body_limit)));
    let on_end: OnEnd = {
        let bus = state.bus.clone();
        let response_capture = Arc::clone(&response_capture);
        Box::new(move |error| {
            record.request_body =
                BodyRecord::from_capture(&lock(&request_capture), &record.request_headers);
            let response = lock(&response_capture);
            record.response_body = Some(BodyRecord::from_capture(
                &response,
                &record.response_headers,
            ));
            record.response_trailers = response.trailers().to_vec();
            drop(response);
            record.timing.total_ms = ms(start.elapsed());
            record.error = error;
            bus.publish(FlowEvent::finished(Event::Exchange(Box::new(record))));
        })
    };
    Response::from_parts(parts, boxed(Tee::new(body, response_capture, Some(on_end))))
}

/// Sends a request the control plane made (replay, compose) to `scheme://host:port` through
/// the same path as client requests; `request` carries a [`ReplayTag`]. The record's client
/// is `peer`.
pub(crate) async fn send(
    state: &State,
    peer: SocketAddr,
    (scheme, host, port): (&'static str, &str, u16),
    request: Request<ProxyBody>,
) -> Response<ProxyBody> {
    let target = Target {
        scheme,
        host: host.to_owned(),
        port,
        server_name: String::new(),
        offer_h2: true,
        tls: None,
    };
    forward(state, peer, &target, None, request).await
}

/// Map-remote: the server an interceptor switched `req` to, if it did, recorded in `record`
/// (the record keeps the client's URL). [`connect`] refuses the control plane's address.
fn remap(target: &Target, req: Option<&RequestCtx>, record: &mut Exchange) -> Option<Target> {
    let (req, remote) = req.and_then(|req| Some((req, target.remap(req)?)))?;
    record.flags.push(Flag::MapRemote);
    record.upstream_url = Some(format!(
        "{}://{}{}",
        remote.scheme,
        remote.authority(),
        req.path
    ));
    Some(remote)
}

/// Builds the flow record from the request head and publishes [`FlowEvent::Started`].
fn start_record<B>(
    state: &State,
    peer: SocketAddr,
    target: &Target,
    request: &Request<B>,
    authority: &str,
    path: &str,
) -> Exchange {
    let tag = request.extensions().get::<ReplayTag>();
    let record = Exchange {
        id: tag.map_or_else(|| state.next_id(), |tag| tag.id),
        time: Utc::now().rfc3339(),
        client: peer,
        method: request.method().to_string(),
        url: format!("{}://{authority}{path}", target.scheme),
        client_version: version_name(request.version()),
        upstream_version: None,
        status: None,
        reason: None,
        request_headers: header_list(request.headers()),
        response_headers: Vec::new(),
        request_body: BodyRecord::from(&Capture::new(0)),
        response_body: None,
        timing: Timing::default(),
        tls: target.tls.clone(),
        error: None,
        flags: tag.map(|_| vec![Flag::Replay]).unwrap_or_default(),
        upstream_url: None,
        replay_of: tag.and_then(|tag| tag.of),
        ws_messages: None,
        response_trailers: Vec::new(),
    };
    state.bus.publish(FlowEvent::Started(Arc::new(Started {
        schema_version: SCHEMA_VERSION,
        id: record.id,
        time: record.time.clone(),
        client: peer,
        method: record.method.clone(),
        url: record.url.clone(),
        client_version: record.client_version.clone(),
        request_headers: record.request_headers.clone(),
        tls: record.tls.clone(),
    })));
    record
}

/// Joins both sides of a `101 Switching Protocols` once both upgrades finish: byte for byte,
/// or through the WebSocket pump (`ws::pump`, same bytes, messages recorded) when `capture`
/// carries the bus, limits, negotiated extensions and flow id of a WebSocket upgrade.
fn join_upgrades(
    client: hyper::upgrade::OnUpgrade,
    server: hyper::upgrade::OnUpgrade,
    capture: Option<(Bus, WsLimits, ws::Extensions, u64, ws::Live)>,
) {
    tokio::spawn(async move {
        if let (Ok(client), Ok(server)) = tokio::join!(client, server) {
            let (mut client, mut server) = (TokioIo::new(client), TokioIo::new(server));
            match capture {
                Some((bus, limits, extensions, id, live)) => {
                    ws::pump((client, server), id, bus, limits, extensions, &live).await;
                }
                None => {
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                }
            }
        }
    });
}

/// Why the request half of the chain ended the exchange early.
enum Stop {
    /// An interceptor answered.
    Respond(Box<Response<Bytes>>),
    /// Reading the body failed or the rewritten request is invalid.
    Fail(String),
}

/// Runs the request half of the chain, buffering the body first when an interceptor needs
/// it, and applies the result to `parts`. Returns the body to send to the server.
async fn intercept_request<B>(
    state: &State,
    req: &mut RequestCtx,
    parts: &mut http::request::Parts,
    tee: Tee<B>,
    record: &mut Exchange,
) -> Result<ProxyBody, Stop>
where
    B: hyper::body::Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<BoxError> + std::fmt::Display,
{
    let mut body = None;
    if state.interceptors.needs_request_body() {
        match body::buffer(tee, state.body_limit).await {
            Ok(Buffered::Whole(bytes)) => req.body = Some(bytes),
            Ok(Buffered::TooLarge(rest)) => {
                // On the context, so a breakpoint can tell; it reaches the record below.
                req.flags.push(Flag::RewriteSkippedBodyTooLarge);
                body = Some(boxed(rest));
            }
            Err(e) => return Err(Stop::Fail(error_chain(&*e.into()))),
        }
    } else {
        body = Some(boxed(tee));
    }
    let outcome = state
        .interceptors
        .run_request(req, state.pause_timeout)
        .await;
    record.flags.append(&mut req.flags);
    add_flags(record, &outcome);
    if let Some(response) = outcome.response {
        return Err(Stop::Respond(Box::new(response)));
    }
    parts.method = req.method.clone();
    parts.headers = req.headers.clone();
    parts.uri = req
        .path
        .parse()
        .map_err(|e| Stop::Fail(format!("rewritten path: {e}")))?;
    Ok(match &req.body {
        Some(bytes) => {
            set_length(&mut parts.headers, bytes.len());
            full(bytes.clone())
        }
        None => body.unwrap_or_else(empty),
    })
}

/// Runs the response half of the chain, buffering the body first when an interceptor
/// needs it. Changes `parts` in place and returns the body to send to the client.
async fn intercept_response(
    state: &State,
    request: &RequestCtx,
    parts: &mut http::response::Parts,
    incoming: Incoming,
    record: &mut Exchange,
) -> Result<ProxyBody, hyper::Error> {
    let mut ctx = ResponseCtx {
        status: parts.status,
        headers: std::mem::take(&mut parts.headers),
        body: None,
        flags: Vec::new(),
        throttle: None,
    };
    let mut body = None;
    if state.interceptors.needs_response_body() {
        match body::buffer(incoming, state.body_limit).await? {
            Buffered::Whole(bytes) => ctx.body = Some(bytes),
            Buffered::TooLarge(rest) => {
                ctx.flags.push(Flag::RewriteSkippedBodyTooLarge);
                body = Some(boxed(rest));
            }
        }
    } else {
        body = Some(boxed(incoming));
    }
    let outcome = state
        .interceptors
        .run_response(request, &mut ctx, state.pause_timeout)
        .await;
    record.flags.append(&mut ctx.flags);
    add_flags(record, &outcome);
    if let Some(response) = outcome.response {
        let (new_parts, bytes) = response.into_parts();
        parts.status = new_parts.status;
        parts.headers = new_parts.headers;
        set_length(&mut parts.headers, bytes.len());
        return Ok(full(bytes));
    }
    parts.status = ctx.status;
    parts.headers = ctx.headers;
    let body = match ctx.body {
        Some(bytes) => {
            set_length(&mut parts.headers, bytes.len());
            full(bytes)
        }
        None => body.unwrap_or_else(empty),
    };
    Ok(match ctx.throttle {
        Some(throttle) => boxed(throttle.wrap(body)),
        None => body,
    })
}

fn add_flags(record: &mut Exchange, outcome: &Outcome) {
    if outcome.response.is_some() {
        record.flags.push(Flag::Responded);
    }
    if outcome.aborted {
        record.flags.push(Flag::Aborted);
    }
    if outcome.pause_timed_out {
        record.flags.push(Flag::PauseTimedOut);
    }
}

fn set_response_head(record: &mut Exchange, status: StatusCode, headers: &HeaderMap) {
    record.status = Some(status.as_u16());
    record.reason = status.canonical_reason().map(str::to_owned);
    record.response_headers = header_list(headers);
}

/// Answers with an interceptor's response, without the server, and logs the exchange.
fn respond_locally(
    state: &State,
    mut record: Exchange,
    request_capture: &SharedCapture,
    start: Instant,
    response: Response<Bytes>,
    version: Version,
) -> Response<ProxyBody> {
    let (mut parts, bytes) = response.into_parts();
    parts.version = version;
    set_length(&mut parts.headers, bytes.len());
    set_response_head(&mut record, parts.status, &parts.headers);
    let mut capture = Capture::new(state.body_limit);
    capture.push(&bytes);
    record.request_body = BodyRecord::from_capture(&lock(request_capture), &record.request_headers);
    record.response_body = Some(BodyRecord::from_capture(&capture, &record.response_headers));
    record.timing.total_ms = ms(start.elapsed());
    state.emit(Event::Exchange(Box::new(record)));
    Response::from_parts(parts, full(bytes))
}

/// Serves the magic host, converting the body for the client connection.
fn magic_response<B>(state: &State, peer: SocketAddr, request: &Request<B>) -> Response<ProxyBody> {
    let (mut parts, bytes) = magic::respond(
        state,
        peer.ip(),
        request.method(),
        request.uri().path(),
        request.headers(),
    )
    .into_parts();
    parts.version = request.version();
    Response::from_parts(parts, full(bytes))
}

fn set_length(headers: &mut HeaderMap, len: usize) {
    headers.remove(header::TRANSFER_ENCODING);
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
}

/// The answer to a target the guard refused: `508` for the proxy's own listener (a loop),
/// `403` otherwise.
fn refusal(denied: Denied) -> Response<ProxyBody> {
    let status = match denied {
        Denied::OwnListener => StatusCode::LOOP_DETECTED,
        Denied::ControlPlane | Denied::Local => StatusCode::FORBIDDEN,
    };
    text(status, &format!("{denied}\n"))
}

/// The client the guard judges a dial for: `peer`, or this machine for a target the owner's
/// rules chose (map-remote, a breakpoint or script edit), so a rule may send a device's
/// requests to a local server on purpose. The control plane and the listener stay refused.
fn dialer(peer: SocketAddr, remapped: Option<&Target>) -> IpAddr {
    match remapped {
        Some(_) => IpAddr::from([127, 0, 0, 1]),
        None => peer.ip(),
    }
}

/// The tunnel's pooled server connection, or a new one; records connect and TLS times when
/// this request opens it. Upgrades always get their own connection. `peer` is the client
/// the guard judges the dial for (see [`dialer`]).
async fn connect(
    state: &State,
    peer: IpAddr,
    target: &Target,
    pool: Option<&Pool>,
    upgrade: bool,
    timing: &mut Timing,
) -> anyhow::Result<Sender> {
    let mut guard = match pool {
        Some(pool) if !upgrade => Some(pool.lock().await),
        _ => None,
    };
    if let Some(sender) = guard.as_deref().and_then(Option::as_ref)
        && !sender.is_closed()
    {
        return Ok(sender.clone());
    }
    // The guard checks the address really dialled, map-remote targets included.
    // Boxed: the dial (resolve, connect, TLS, HTTP setup, each with a limit) is large and
    // runs once per connection, not per request.
    let opened = Box::pin(target.open(&state.connector, peer, upgrade)).await?;
    timing.connect_ms = Some(ms(opened.connect));
    timing.tls_ms = opened.tls.map(ms);
    if let Some(guard) = guard.as_deref_mut() {
        *guard = Some(opened.sender.clone());
    }
    Ok(opened.sender)
}

/// Rewrites the request for the server's protocol: origin-form and `Host` for HTTP/1.1,
/// absolute URI and no `Host` for HTTP/2.
fn prepare(
    parts: &mut http::request::Parts,
    version: Version,
    scheme: &str,
    authority: &str,
    upgrade: bool,
) -> anyhow::Result<()> {
    strip_hop_by_hop(&mut parts.headers, upgrade);
    let path = parts
        .uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str)
        .to_owned();
    if version == Version::HTTP_2 {
        parts.uri = format!("{scheme}://{authority}{path}").parse()?;
        parts.headers.remove(header::HOST);
    } else {
        parts.uri = path.parse()?;
        if !parts.headers.contains_key(header::HOST) {
            parts
                .headers
                .insert(header::HOST, HeaderValue::from_str(authority)?);
        }
        // HTTP/2 clients may split cookies into several fields; HTTP/1.1 wants one.
        let cookies: Vec<HeaderValue> = parts
            .headers
            .get_all(header::COOKIE)
            .iter()
            .cloned()
            .collect();
        if cookies.len() > 1 {
            let joined = cookies
                .iter()
                .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
                .collect::<Vec<_>>()
                .join("; ");
            parts
                .headers
                .insert(header::COOKIE, HeaderValue::from_str(&joined)?);
        }
    }
    parts.version = version;
    Ok(())
}

/// Removes connection-specific headers, which apply to one hop only. An upgrade keeps
/// `Connection` and `Upgrade`, which the server needs to switch protocols.
fn strip_hop_by_hop(headers: &mut HeaderMap, upgrade: bool) {
    let named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .filter(|name| !(upgrade && name == header::UPGRADE))
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in [
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "transfer-encoding",
    ] {
        headers.remove(name);
    }
    if !upgrade {
        headers.remove(header::CONNECTION);
        headers.remove(header::UPGRADE);
    }
    if headers
        .get(header::TE)
        .is_some_and(|te| te.as_bytes() != b"trailers")
    {
        headers.remove(header::TE);
    }
}

fn is_upgrade<B>(request: &Request<B>) -> bool {
    request.version() == Version::HTTP_11 && request.headers().contains_key(header::UPGRADE)
}

/// [`fail`] for a server connection that could not be opened; a target the guard refused
/// is answered with [`refusal`].
fn fail_connect(
    state: &State,
    record: Exchange,
    request_capture: &SharedCapture,
    start: Instant,
    error: &anyhow::Error,
) -> Response<ProxyBody> {
    let response = fail(state, record, request_capture, start, &format!("{error:#}"));
    if let Some(denied) = error.downcast_ref::<Denied>() {
        return refusal(*denied);
    }
    if error.downcast_ref::<upstream::TimedOut>().is_some() {
        return text(
            StatusCode::GATEWAY_TIMEOUT,
            &format!("{} proxy error: {error:#}\n", crate::NAME),
        );
    }
    response
}

fn fail(
    state: &State,
    mut record: Exchange,
    request_capture: &SharedCapture,
    start: Instant,
    error: &str,
) -> Response<ProxyBody> {
    record.request_body = BodyRecord::from_capture(&lock(request_capture), &record.request_headers);
    record.timing.total_ms = ms(start.elapsed());
    record.error = Some(error.to_owned());
    state.emit(Event::Exchange(Box::new(record)));
    text(
        StatusCode::BAD_GATEWAY,
        &format!("{} proxy error: {error}\n", crate::NAME),
    )
}

fn known_name(ja4: &Ja4) -> Option<String> {
    match known::lookup(ja4) {
        Match::Exact(client) => Some(format!("{} {}", client.family(), client.version())),
        Match::Ciphers(client) => Some(format!("like {} {}", client.family(), client.version())),
        Match::Unknown => None,
    }
}

fn header_list(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

fn version_name(version: Version) -> String {
    match version {
        Version::HTTP_09 => "http/0.9",
        Version::HTTP_10 => "http/1.0",
        Version::HTTP_11 => "http/1.1",
        Version::HTTP_2 => "h2",
        Version::HTTP_3 => "h3",
        _ => "unknown",
    }
    .to_owned()
}

fn error_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text = format!("{text}: {cause}");
        source = cause.source();
    }
    text
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn unbracket(host: &str) -> &str {
    host.trim_start_matches('[').trim_end_matches(']')
}

fn lock(capture: &SharedCapture) -> std::sync::MutexGuard<'_, Capture> {
    capture.lock().expect("capture lock poisoned")
}

fn boxed<B>(body: B) -> ProxyBody
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    body.map_err(Into::into).boxed_unsync()
}

fn empty() -> ProxyBody {
    boxed(Empty::<Bytes>::new().map_err(|never| match never {}))
}

fn full(bytes: Bytes) -> ProxyBody {
    boxed(Full::new(bytes).map_err(|never| match never {}))
}

fn text(status: StatusCode, message: &str) -> Response<ProxyBody> {
    let mut response = Response::new(full(Bytes::from(message.to_owned())));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_is_allowed_and_remote_needs_the_flag() {
        let local: SocketAddr = "127.0.0.1:8080".parse().expect("valid");
        let v6: SocketAddr = "[::1]:8080".parse().expect("valid");
        let any: SocketAddr = "0.0.0.0:8080".parse().expect("valid");
        assert!(check_listen(local, RemoteAccess::LoopbackOnly).is_ok());
        assert!(check_listen(v6, RemoteAccess::LoopbackOnly).is_ok());
        assert!(check_listen(any, RemoteAccess::LoopbackOnly).is_err());
        assert!(check_listen(any, RemoteAccess::Allow).is_ok());
    }

    #[test]
    fn strips_hop_by_hop_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, HeaderValue::from_static("close, x-hop"));
        headers.insert("x-hop", HeaderValue::from_static("1"));
        headers.insert("proxy-connection", HeaderValue::from_static("keep-alive"));
        headers.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
        strip_hop_by_hop(&mut headers, false);
        assert_eq!(headers.len(), 1, "{headers:?}");
    }
}
