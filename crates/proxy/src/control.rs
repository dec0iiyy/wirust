//! The control plane: a second HTTP listener (off unless `--ui`) with a JSON API under
//! `/api/v1/` and the embedded web UI.
//!
//! A local web server that controls a MITM proxy is an attack target: any page the user
//! opens can send requests to localhost, and DNS rebinding lets a hostile page read the
//! answers. So every request must name this listener in `Host` (and in `Origin`, when sent),
//! the API needs the start-up token, state changes are `POST` only, no CORS header is ever
//! sent, and the proxy refuses to forward requests to this address.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Context as _;
use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body::{Body, Frame};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};

use crate::events::{Bus, Filter, FlowStore};
use crate::intercept::{Pauses, Resolution};
use crate::proxy::{Proxy, RemoteAccess, check_listen};
use crate::rules::{Rules, file_name};
use crate::rules_api;

/// The cookie the UI page may set after reading the token from the URL fragment.
pub const TOKEN_COOKIE: &str = "token";

/// Policy for the static UI pages: scripts and styles from this origin only, no inline code.
const PAGE_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
    img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; \
    frame-ancestors 'none'";

/// Policy for API answers, which are never rendered.
const API_CSP: &str = "default-src 'none'; frame-ancestors 'none'";

/// The embedded UI: request path, content type, bytes. Files live in `crates/proxy/ui/`.
const ASSETS: &[(&str, &str, &[u8])] = &[
    (
        "/",
        "text/html; charset=utf-8",
        include_bytes!("../ui/index.html"),
    ),
    (
        "/theme.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../ui/theme.js"),
    ),
    (
        "/panels.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../ui/panels.js"),
    ),
    (
        "/app.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../ui/app.js"),
    ),
    (
        "/style.css",
        "text/css; charset=utf-8",
        include_bytes!("../ui/style.css"),
    ),
    (
        "/ws.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../ui/ws.js"),
    ),
    (
        "/ws.css",
        "text/css; charset=utf-8",
        include_bytes!("../ui/ws.css"),
    ),
    (
        "/grpc.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../ui/grpc.js"),
    ),
    (
        "/grpc.css",
        "text/css; charset=utf-8",
        include_bytes!("../ui/grpc.css"),
    ),
    (
        "/replay.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../ui/replay.js"),
    ),
    (
        "/replay.css",
        "text/css; charset=utf-8",
        include_bytes!("../ui/replay.css"),
    ),
    (
        "/script.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../ui/script.js"),
    ),
    (
        "/codegen.js",
        "text/javascript; charset=utf-8",
        include_bytes!("../ui/codegen.js"),
    ),
    (
        "/codegen.css",
        "text/css; charset=utf-8",
        include_bytes!("../ui/codegen.css"),
    ),
];

type ControlBody = UnsyncBoxBody<Bytes, Infallible>;

/// A bound control plane, ready to [`run`](Self::run).
#[derive(Debug)]
pub struct ControlPlane {
    listener: TcpListener,
    state: Arc<State>,
}

struct State {
    token: String,
    listen: SocketAddr,
    remote: RemoteAccess,
    store: FlowStore,
    bus: Bus,
    pauses: Pauses,
    ca_pem: String,
    /// The rules engine `/api/v1/rules` manages, once [`ControlPlane::set_rules`] ran.
    rules: std::sync::OnceLock<Rules>,
    /// The proxy listener, for `/api/v1/info`.
    proxy_addr: SocketAddr,
    /// SHA-256 of the CA certificate (DER), colon-separated upper-case hex.
    ca_fingerprint: String,
    /// The `--session` file, once [`ControlPlane::set_session_file`] ran.
    session_file: std::sync::OnceLock<PathBuf>,
    /// Replay, compose and the passthrough lists (`replay_api.rs`).
    replay: crate::replay_api::Handles,
    /// The `--proto` schemas, once [`ControlPlane::set_schemas`] ran.
    schemas: std::sync::OnceLock<crate::schema::Schemas>,
    /// The `--script` files `/api/v1/script` reports, once [`ControlPlane::set_scripts`] ran.
    scripts: std::sync::OnceLock<crate::script::Scripts>,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The token is a secret: never in Debug output.
        f.debug_struct("State")
            .field("listen", &self.listen)
            .finish_non_exhaustive()
    }
}

impl ControlPlane {
    /// Binds the control plane on `listen` for `proxy`, generates a fresh token and makes
    /// the proxy refuse requests addressed to this listener.
    ///
    /// # Errors
    ///
    /// Fails on a non-loopback address without [`RemoteAccess::Allow`], when the system
    /// random generator fails, or on a bind error.
    pub async fn bind(
        listen: SocketAddr,
        remote: RemoteAccess,
        proxy: &mut Proxy,
    ) -> anyhow::Result<Self> {
        check_listen(listen, remote)?;
        let token = new_token()?;
        let listener = TcpListener::bind(listen)
            .await
            .with_context(|| format!("binding the control plane on {listen}"))?;
        let listen = listener.local_addr()?;
        proxy.refuse_target(listen);
        let state = State {
            token,
            listen,
            remote,
            store: proxy.store().clone(),
            bus: proxy.bus().clone(),
            pauses: proxy.pauses().clone(),
            ca_pem: proxy.ca().cert_pem().to_owned(),
            rules: std::sync::OnceLock::new(),
            proxy_addr: proxy.local_addr()?,
            ca_fingerprint: sha256_fingerprint(&proxy.ca().cert_der()?),
            session_file: std::sync::OnceLock::new(),
            replay: crate::replay_api::Handles::new(proxy),
            schemas: std::sync::OnceLock::new(),
            scripts: std::sync::OnceLock::new(),
        };
        Ok(Self {
            listener,
            state: Arc::new(state),
        })
    }

    /// Serves `rules` at `/api/v1/rules` (see `docs/rules.md`). Only the first call counts.
    pub fn set_rules(&self, rules: Rules) {
        let _ = self.state.rules.set(rules);
    }

    /// Decodes gRPC messages with `schemas` and serves them at `/api/v1/proto` (see
    /// `docs/grpc.md`). Only the first call counts.
    pub fn set_schemas(&self, schemas: crate::schema::Schemas) {
        let _ = self.state.schemas.set(schemas);
    }

    /// Reports `scripts` at `/api/v1/script` (see `docs/scripting.md`). Only the first call
    /// counts.
    pub fn set_scripts(&self, scripts: crate::script::Scripts) {
        let _ = self.state.scripts.set(scripts);
    }

    /// Names the `--session` file, if any, in `/api/v1/info`. Only the first file counts.
    pub fn set_session_file(&self, path: Option<PathBuf>) {
        if let Some(path) = path {
            let _ = self.state.session_file.set(path);
        }
    }

    /// The bound address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.state.listen
    }

    /// The API token (32 hex digits, 128 random bits).
    #[must_use]
    pub fn token(&self) -> &str {
        &self.state.token
    }

    /// The URL to open: the token rides in the fragment, which browsers never send.
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}/#token={}", self.state.listen, self.state.token)
    }

    /// Serves until accepting fails.
    ///
    /// # Errors
    ///
    /// Fails when accepting fails.
    pub async fn run(self) -> anyhow::Result<()> {
        loop {
            let (stream, _) = self.listener.accept().await?;
            let state = Arc::clone(&self.state);
            let service = service_fn(move |request: Request<Incoming>| {
                let state = Arc::clone(&state);
                async move {
                    // Bodies (rule sets, pause edits) are small: read them whole, bounded.
                    let (parts, body) = request.into_parts();
                    let response = match Limited::new(body, rules_api::MAX_BODY).collect().await {
                        Ok(body) => handle(&state, &Request::from_parts(parts, body.to_bytes())),
                        Err(_) => harden(error(StatusCode::PAYLOAD_TOO_LARGE, "body too large")),
                    };
                    Ok::<_, Infallible>(response)
                }
            });
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    }
}

fn new_token() -> anyhow::Result<String> {
    use std::fmt::Write as _;
    let mut bytes = [0_u8; 16];
    rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("the system random generator failed"))?;
    Ok(bytes.iter().fold(String::with_capacity(32), |mut hex, b| {
        let _ = write!(hex, "{b:02x}");
        hex
    }))
}

/// Compares in time that depends on the length only.
fn same_secret(given: &[u8], expected: &[u8]) -> bool {
    given.len() == expected.len()
        && std::hint::black_box(
            given
                .iter()
                .zip(expected)
                .fold(0_u8, |acc, (a, b)| acc | (a ^ b)),
        ) == 0
}

fn handle(state: &State, request: &Request<Bytes>) -> Response<ControlBody> {
    harden(route(state, request))
}

/// Adds the security headers every answer carries.
fn harden(mut response: Response<ControlBody>) -> Response<ControlBody> {
    let page = response
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|t| t.as_bytes().starts_with(b"text/html"));
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(if page { PAGE_CSP } else { API_CSP }),
    );
    response
}

/// The API routes that live in their own modules: WebSocket messages, HAR, rules and
/// pauses, replay and passthrough. Each module answers only the paths it owns; `None` means
/// none of them did.
fn module_routes(
    state: &State,
    request: &Request<Bytes>,
    segments: &[&str],
) -> Option<Response<ControlBody>> {
    let method = request.method();
    let query = request.uri().query().unwrap_or_default();
    if let Some(response) =
        crate::ws_api::route(&state.store, method, segments, query, request.body())
    {
        return Some(response.map(|body| Full::new(body).boxed_unsync()));
    }
    if let Some(response) = crate::har_api::route(&state.store, method, segments, query) {
        return Some(response.map(|body| Full::new(body).boxed_unsync()));
    }
    if let Some(response) =
        crate::grpc_api::route(&state.store, state.schemas.get(), method, segments)
    {
        return Some(response.map(|body| Full::new(body).boxed_unsync()));
    }
    if let Some((status, body)) = rules_api::route(
        state.rules.get(),
        &state.pauses,
        method,
        segments,
        request.body(),
    ) {
        return Some(json(status, &body));
    }
    if let Some((status, body)) =
        crate::script_api::route(state.scripts.get(), method, segments, query)
    {
        return Some(json(status, &body));
    }
    crate::replay_api::route(
        &state.replay,
        &state.store,
        method,
        segments,
        request.body(),
    )
    .map(|(status, body)| json(status, &body))
}

fn route(state: &State, request: &Request<Bytes>) -> Response<ControlBody> {
    let headers = request.headers();
    let Some(host) = headers.get(header::HOST).and_then(|h| h.to_str().ok()) else {
        return error(StatusCode::MISDIRECTED_REQUEST, "missing Host");
    };
    if !state.host_ok(host) {
        return error(StatusCode::MISDIRECTED_REQUEST, "wrong Host");
    }
    if let Some(origin) = headers.get(header::ORIGIN)
        && origin.as_bytes() != format!("http://{host}").as_bytes()
    {
        return error(StatusCode::FORBIDDEN, "cross-origin requests are refused");
    }
    let path = request.uri().path();
    let Some(api) = path.strip_prefix("/api/v1/") else {
        return asset(request.method(), path);
    };
    if !state.authorized(headers) {
        return error(StatusCode::UNAUTHORIZED, "missing or wrong token");
    }
    let segments: Vec<&str> = api.split('/').collect();
    if let Some(response) = module_routes(state, request, &segments) {
        return response;
    }
    let method = request.method();
    match (method, segments.as_slice()) {
        (&Method::GET, ["flows"]) => {
            let filter = match filter(request.uri().query().unwrap_or_default()) {
                Ok(filter) => filter,
                Err(e) => return error(StatusCode::BAD_REQUEST, &e),
            };
            let after = query_value(request.uri().query().unwrap_or_default(), "after")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            json(
                StatusCode::OK,
                &state.store.list(after.saturating_add(1).., &filter),
            )
        }
        (&Method::GET, ["flows", id]) => match id.parse().ok().and_then(|id| state.store.get(id)) {
            Some(flow) => json(StatusCode::OK, &flow),
            None => error(StatusCode::NOT_FOUND, "no such flow"),
        },
        (&Method::GET, ["events"]) => events(state.bus.subscribe()),
        (&Method::GET, ["pauses"]) => json(StatusCode::OK, &state.pauses.list()),
        (&Method::GET, ["info"]) => json(StatusCode::OK, &state.info()),
        (&Method::POST, ["pauses", id, verb @ ("resume" | "abort")]) => {
            let resolution = if *verb == "resume" {
                Resolution::Resume
            } else {
                Resolution::Abort
            };
            match id.parse() {
                Ok(id) if state.pauses.resolve(id, resolution) => {
                    json(StatusCode::OK, &Resolved { resolved: id })
                }
                _ => error(StatusCode::NOT_FOUND, "no such pending pause"),
            }
        }
        (&Method::GET, ["ca.pem"]) => {
            let mut response = bytes(StatusCode::OK, Bytes::from(state.ca_pem.clone()));
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/x-pem-file"),
            );
            response
        }
        (
            _,
            ["flows" | "events" | "pauses" | "ca.pem" | "info"]
            | ["flows" | "pauses", _]
            | ["pauses", _, "resume" | "abort"],
        ) => error(StatusCode::METHOD_NOT_ALLOWED, "wrong method"),
        _ => error(StatusCode::NOT_FOUND, "no such endpoint"),
    }
}

#[derive(Serialize)]
struct Resolved {
    resolved: u64,
}

/// The answer of `GET /api/v1/info`: what the UI's Connect popover shows. The rules and
/// session files appear by file name only: a full path would show the home directory.
#[derive(Serialize)]
struct Info<'a> {
    name: &'static str,
    version: &'static str,
    proxy_addr: SocketAddr,
    magic_host: &'static str,
    ca_fingerprint_sha256: &'a str,
    rules_file: Option<String>,
    session_file: Option<String>,
    listen_is_loopback: bool,
}

/// SHA-256 of `der` as colon-separated upper-case hex, the form certificate viewers show.
fn sha256_fingerprint(der: &[u8]) -> String {
    use sha2::Digest as _;
    let hex: Vec<String> = sha2::Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    hex.join(":")
}

impl State {
    fn info(&self) -> Info<'_> {
        Info {
            name: crate::NAME,
            version: env!("CARGO_PKG_VERSION"),
            proxy_addr: self.proxy_addr,
            magic_host: crate::MAGIC_HOST,
            ca_fingerprint_sha256: &self.ca_fingerprint,
            rules_file: (self.rules.get())
                .and_then(|rules| rules.report().file)
                .map(|file| file_name(&file)),
            session_file: self.session_file.get().map(|file| file_name(file)),
            listen_is_loopback: self.proxy_addr.ip().is_loopback(),
        }
    }

    /// `Host` must name this listener: its own address, `localhost:PORT` on loopback, or any
    /// IP literal with this port when bound to all interfaces with `--allow-remote`. A DNS
    /// name that merely resolves here (rebinding) never matches.
    fn host_ok(&self, host: &str) -> bool {
        let port = self.listen.port();
        if host == self.listen.to_string() {
            return true;
        }
        if self.listen.ip().is_loopback() {
            return host == format!("localhost:{port}");
        }
        self.remote == RemoteAccess::Allow
            && self.listen.ip().is_unspecified()
            && host
                .parse::<SocketAddr>()
                .is_ok_and(|addr| addr.port() == port)
    }

    /// `Authorization: Bearer TOKEN`, or the token cookie, compared in constant time.
    fn authorized(&self, headers: &HeaderMap) -> bool {
        let expected = self.token.as_bytes();
        let bearer = headers
            .get_all(header::AUTHORIZATION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .filter_map(|v| v.strip_prefix("Bearer "))
            .any(|token| same_secret(token.trim().as_bytes(), expected));
        let cookie = headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(';'))
            .filter_map(|pair| pair.trim().split_once('='))
            .any(|(name, value)| name == TOKEN_COOKIE && same_secret(value.as_bytes(), expected));
        bearer || cookie
    }
}

fn query_value<'q>(query: &'q str, key: &str) -> Option<&'q str> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find_map(|(k, v)| (k == key).then_some(v))
}

/// `host`, `method`, `status`, `limit` and `q` query parameters; a bad `q` is an error.
fn filter(query: &str) -> Result<Filter, String> {
    Ok(Filter {
        host: query_value(query, "host").map(str::to_owned),
        method: query_value(query, "method").map(str::to_owned),
        status: query_value(query, "status").and_then(|v| v.parse().ok()),
        limit: query_value(query, "limit").and_then(|v| v.parse().ok()),
        query: crate::har_api::search(query)?,
    })
}

fn asset(method: &Method, path: &str) -> Response<ControlBody> {
    if method != Method::GET && method != Method::HEAD {
        return error(StatusCode::METHOD_NOT_ALLOWED, "wrong method");
    }
    let Some((_, content_type, data)) = ASSETS.iter().find(|(p, _, _)| *p == path) else {
        return error(StatusCode::NOT_FOUND, "not found");
    };
    let mut response = bytes(StatusCode::OK, Bytes::from_static(data));
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

/// Server-Sent Events: one `data:` line of JSON per [`FlowEvent`](crate::events::FlowEvent).
fn events(mut bus: broadcast::Receiver<crate::events::FlowEvent>) -> Response<ControlBody> {
    let (sender, receiver) = mpsc::channel::<Bytes>(64);
    tokio::spawn(async move {
        loop {
            let chunk = tokio::select! {
                event = bus.recv() => match event {
                    Ok(event) => match serde_json::to_string(&event) {
                        Ok(json) => format!("data: {json}\n\n"),
                        Err(_) => continue,
                    },
                    Err(broadcast::error::RecvError::Lagged(n)) => format!(": lagged {n}\n\n"),
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                () = sender.closed() => break,
            };
            if sender.send(Bytes::from(chunk)).await.is_err() {
                break;
            }
        }
    });
    let mut response = Response::new(ChannelBody { receiver }.boxed_unsync());
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    response
}

/// A streaming body fed by a channel; it ends when the sender is dropped.
struct ChannelBody {
    receiver: mpsc::Receiver<Bytes>,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.get_mut()
            .receiver
            .poll_recv(cx)
            .map(|chunk| chunk.map(|data| Ok(Frame::data(data))))
    }
}

fn bytes(status: StatusCode, data: Bytes) -> Response<ControlBody> {
    let mut response = Response::new(Full::new(data).boxed_unsync());
    *response.status_mut() = status;
    response
}

fn json<T: Serialize>(status: StatusCode, value: &T) -> Response<ControlBody> {
    match serde_json::to_vec(value) {
        Ok(body) => {
            let mut response = bytes(status, Bytes::from(body));
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            response
        }
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

fn error(status: StatusCode, message: &str) -> Response<ControlBody> {
    let mut response = json(StatusCode::OK, &ErrorBody { error: message });
    *response.status_mut() = status;
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_128_random_bits_in_hex() -> anyhow::Result<()> {
        let (a, b) = (new_token()?, new_token()?);
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
        Ok(())
    }

    #[test]
    fn secrets_compare_whole() {
        assert!(same_secret(b"abcd", b"abcd"));
        assert!(!same_secret(b"abce", b"abcd"));
        assert!(!same_secret(b"abc", b"abcd"));
        assert!(!same_secret(b"", b"abcd"));
    }

    #[test]
    fn fingerprints_are_sha256_in_colon_hex() {
        // FIPS 180-2 test vector for "abc".
        let want = "BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:\
                    B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD";
        assert_eq!(sha256_fingerprint(b"abc"), want);
    }

    #[test]
    fn query_values_and_filters_parse() -> Result<(), String> {
        let f = filter("host=example&status=404&limit=2&x=1")?;
        assert_eq!(f.host.as_deref(), Some("example"));
        assert_eq!((f.status, f.limit, f.method), (Some(404), Some(2), None));
        assert!(filter("q=method%3APOST+-status%3A5xx")?.query.is_some());
        assert!(filter("q=(").is_err());
        Ok(())
    }
}
