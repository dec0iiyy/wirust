//! Replay and compose: requests the control plane sends through the proxy's own forwarding
//! path, recorded as new flows flagged [`Flag::Replay`](crate::flow::Flag::Replay).
//!
//! `Replayer` sends; `replay_api.rs` validates the API bodies; [`send_via`] is the
//! `replay` command, which goes through a running proxy as an ordinary client instead.
//! `docs/replay.md` has the API, the limits and the safety notes.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use base64::Engine as _;
use bytes::Bytes;
use http::header::{self, HeaderName, HeaderValue};
use http::{Method, Request};
use http_body_util::{BodyExt as _, Full};
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::flow::{BodyRecord, Exchange};
use crate::intercept::{Edit, Server};
use crate::proxy::{self, State};

/// Most replays whose responses have not ended yet.
pub const MAX_IN_FLIGHT: usize = 8;

/// Most replays started in any one-second window.
pub const MAX_PER_SECOND: usize = 20;

/// Marks a request as made by the control plane; `forward` reads it from the extensions.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReplayTag {
    /// The new flow's id, allocated before the request is sent.
    pub(crate) id: u64,
    /// The replayed flow, `None` for a composed request.
    pub(crate) of: Option<u64>,
    /// Whether the interceptor chain runs.
    pub(crate) apply_rules: bool,
}

/// A request ready to send.
#[derive(Debug, Clone)]
pub(crate) struct Outgoing {
    pub(crate) method: Method,
    pub(crate) server: Server,
    /// Path and query, starting with `/`.
    pub(crate) path: String,
    /// In the original order; `host` and `content-length` are recomputed and never here.
    pub(crate) headers: Vec<(HeaderName, HeaderValue)>,
    pub(crate) body: Bytes,
    pub(crate) replay_of: Option<u64>,
    pub(crate) apply_rules: bool,
}

/// Why a replay could not be built from a stored flow.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BuildError {
    /// The stored flow cannot be replayed as it is (`409`).
    Conflict(String),
    /// The stored flow or the edit is invalid (`400`).
    Invalid(String),
}

impl Outgoing {
    /// The request `flow` made, changed by `edit`.
    ///
    /// # Errors
    ///
    /// [`BuildError::Conflict`] when the stored body was cut by `--body-limit` and the edit
    /// gives no new one; [`BuildError::Invalid`] for an unreadable stored URL, method or
    /// header.
    pub(crate) fn from_flow(
        flow: &Exchange,
        edit: Edit,
        apply_rules: bool,
    ) -> Result<Self, BuildError> {
        let invalid = |what: &str| BuildError::Invalid(format!("the stored flow has {what}"));
        let (server, path) =
            crate::rules_api::parse_url(&flow.url).map_err(|_| invalid("an unreadable url"))?;
        let server = server.ok_or_else(|| invalid("no absolute url"))?;
        let method = match edit.method {
            Some(method) => method,
            None => Method::from_bytes(flow.method.as_bytes())
                .map_err(|_| invalid("an invalid method"))?,
        };
        let mut headers = Vec::with_capacity(flow.request_headers.len());
        for (name, value) in &flow.request_headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| invalid("an invalid header name"))?;
            let value =
                HeaderValue::from_str(value).map_err(|_| invalid("an invalid header value"))?;
            headers.push((name, value));
        }
        headers.retain(|(name, _)| !edit.remove_headers.contains(name));
        // The stored body is decoded; it goes as identity unless the edit names a coding.
        if flow.request_body.is_decoded() {
            headers.retain(|(name, _)| name != header::CONTENT_ENCODING);
        }
        set_headers(&mut headers, edit.set_headers);
        let body = match edit.body {
            Some(body) => body,
            None => stored_body(&flow.request_body)?,
        };
        Ok(Self {
            method,
            server: edit.server.unwrap_or(server),
            path: edit.path.unwrap_or(path),
            headers: without_recomputed(headers),
            body,
            replay_of: Some(flow.id),
            apply_rules,
        })
    }
}

/// Replaces every value of each name in `set`, appending the new ones in `set`'s order.
pub(crate) fn set_headers(
    headers: &mut Vec<(HeaderName, HeaderValue)>,
    set: Vec<(HeaderName, HeaderValue)>,
) {
    headers.retain(|(name, _)| !set.iter().any(|(n, _)| n == name));
    headers.extend(set);
}

/// Drops `host` and `content-length`, which the forwarding path computes for the server.
pub(crate) fn without_recomputed(
    mut headers: Vec<(HeaderName, HeaderValue)>,
) -> Vec<(HeaderName, HeaderValue)> {
    headers.retain(|(name, _)| name != header::HOST && name != header::CONTENT_LENGTH);
    headers
}

fn stored_body(record: &BodyRecord) -> Result<Bytes, BuildError> {
    if record.truncated {
        return Err(BuildError::Conflict(format!(
            "the stored request body is incomplete ({} of {} bytes kept, see --body-limit); \
             send a new body or body_base64 with the replay",
            stored_len(record),
            record.size
        )));
    }
    if record.encoding == "base64" {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&record.data)
            .map_err(|e| BuildError::Invalid(format!("the stored body is not base64: {e}")))?;
        return Ok(Bytes::from(bytes));
    }
    Ok(Bytes::from(record.data.clone()))
}

fn stored_len(record: &BodyRecord) -> usize {
    if record.encoding == "base64" {
        record.data.len() / 4 * 3
    } else {
        record.data.len()
    }
}

/// Why a replay was not sent.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The target is the control plane or the proxy itself (`403`).
    SelfTarget,
    /// A limit was hit (`429`); the text says which.
    Busy(String),
    /// The request cannot be sent (`400`).
    Invalid(String),
}

/// Sends replays through the proxy's forwarding path. Cloning shares the limits.
#[derive(Debug, Clone)]
pub(crate) struct Replayer {
    state: Arc<State>,
    in_flight: Arc<Semaphore>,
    starts: Arc<Mutex<VecDeque<Instant>>>,
}

impl Replayer {
    pub(crate) fn new(state: Arc<State>) -> Self {
        Self {
            state,
            in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            starts: Arc::default(),
        }
    }

    /// Checks the target and the limits, then sends `out` in the background and returns
    /// the new flow's id. The flow's `Started` event follows shortly on the bus.
    ///
    /// # Errors
    ///
    /// [`Refusal::SelfTarget`] for the control plane's or the proxy's own address,
    /// [`Refusal::Busy`] past [`MAX_IN_FLIGHT`] or [`MAX_PER_SECOND`].
    pub(crate) fn start(&self, out: Outgoing) -> Result<u64, Refusal> {
        let (host, port) = (out.server.host.as_str(), out.server.port);
        // Replays come from this machine, so only the control plane and the listener count.
        let local = std::net::IpAddr::from([127, 0, 0, 1]);
        if self.state.guard().check_name(local, host, port).is_err() {
            return Err(Refusal::SelfTarget);
        }
        let uri = (out.path.parse()).map_err(|_| Refusal::Invalid("invalid path".to_owned()))?;
        let permit = self.admit()?;
        let id = self.state.next_id();
        let mut request = Request::new(
            Full::new(out.body)
                .map_err(|never| match never {})
                .boxed_unsync(),
        );
        *request.method_mut() = out.method;
        *request.uri_mut() = uri;
        let headers = request.headers_mut();
        for (name, value) in out.headers {
            headers.append(name, value);
        }
        request.extensions_mut().insert(ReplayTag {
            id,
            of: out.replay_of,
            apply_rules: out.apply_rules,
        });
        let state = Arc::clone(&self.state);
        tokio::spawn(async move {
            let server = (out.server.scheme, out.server.host.as_str(), out.server.port);
            let response = proxy::send(&state, state.listen, server, request).await;
            // Reading the body to its end is what finishes and publishes the record.
            let _ = response.into_body().collect().await;
            drop(permit);
        });
        Ok(id)
    }

    /// Takes an in-flight slot and a start in the one-second window, or says which limit
    /// is full.
    fn admit(&self) -> Result<OwnedSemaphorePermit, Refusal> {
        let mut starts = self.starts.lock().expect("replay rate lock poisoned");
        let now = Instant::now();
        while starts
            .front()
            .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(1))
        {
            starts.pop_front();
        }
        if starts.len() >= MAX_PER_SECOND {
            return Err(Refusal::Busy(format!(
                "more than {MAX_PER_SECOND} replays per second"
            )));
        }
        let permit = Arc::clone(&self.in_flight)
            .try_acquire_owned()
            .map_err(|_| Refusal::Busy(format!("{MAX_IN_FLIGHT} replays are in flight")))?;
        starts.push_back(now);
        Ok(permit)
    }
}

/// Changes the `replay` command applies to a flow from a session file.
#[derive(Debug, Clone, Default)]
pub struct CliEdits {
    /// `--set-header 'N: V'`, in order.
    pub set_headers: Vec<(HeaderName, HeaderValue)>,
    /// `--method M`.
    pub method: Option<Method>,
    /// `--url U`: a path or an absolute `http(s)` URL.
    pub url: Option<String>,
}

/// Sends `flow`, changed by `edits`, through the proxy at `via` as an ordinary client (an
/// absolute-form request for `http://`, CONNECT and TLS for `https://`, trusting the CA in
/// `config_dir`), and returns the response's status line.
///
/// # Errors
///
/// Fails on an invalid edit, an incomplete stored body, a missing CA file, or any network
/// or TLS error.
pub async fn send_via(
    flow: &Exchange,
    edits: CliEdits,
    via: SocketAddr,
    config_dir: &Path,
) -> anyhow::Result<String> {
    let (server, path) = match &edits.url {
        Some(url) => crate::rules_api::parse_url(url).map_err(anyhow::Error::msg)?,
        None => (None, String::new()),
    };
    let edit = Edit {
        set_headers: edits.set_headers,
        method: edits.method,
        path: (!path.is_empty()).then_some(path),
        server,
        ..Edit::default()
    };
    let out = match Outgoing::from_flow(flow, edit, false) {
        Ok(out) => out,
        Err(BuildError::Conflict(e) | BuildError::Invalid(e)) => bail!(e),
    };
    let authority = match (out.server.scheme, out.server.port) {
        ("https", 443) | ("http", 80) => bracket(&out.server.host),
        (_, port) => format!("{}:{port}", bracket(&out.server.host)),
    };
    let mut builder = Request::builder().method(out.method.clone());
    for (name, value) in &out.headers {
        builder = builder.header(name, value);
    }
    let builder = builder.header(header::HOST, &authority);
    let tcp = TcpStream::connect(via)
        .await
        .with_context(|| format!("connecting to the proxy at {via}"))?;
    let response = if out.server.scheme == "https" {
        let tcp = connect_tunnel(tcp, &authority, out.server.port).await?;
        let roots = ca_roots(config_dir)?;
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let name = ServerName::try_from(out.server.host.clone()).context("server name")?;
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await
            .context("TLS through the proxy (is the CA in --config-dir the proxy's?)")?;
        let request = builder.uri(&out.path).body(Full::new(out.body))?;
        send_h1(TokioIo::new(tls), request).await?
    } else {
        let url = format!("http://{authority}{}", out.path);
        let request = builder.uri(url).body(Full::new(out.body))?;
        send_h1(TokioIo::new(tcp), request).await?
    };
    Ok(format!(
        "HTTP/1.1 {} {}",
        response.as_u16(),
        response.canonical_reason().unwrap_or_default()
    ))
}

async fn send_h1<I>(
    io: TokioIo<I>,
    request: Request<Full<Bytes>>,
) -> anyhow::Result<http::StatusCode>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(connection);
    let response = sender.send_request(request).await?;
    let status = response.status();
    response.into_body().collect().await?;
    Ok(status)
}

async fn connect_tunnel(
    mut tcp: TcpStream,
    authority: &str,
    port: u16,
) -> anyhow::Result<TcpStream> {
    let target = if authority.contains(':') && !authority.ends_with(']') {
        authority.to_owned()
    } else {
        format!("{authority}:{port}")
    };
    tcp.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await?;
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        anyhow::ensure!(head.len() < 8192, "the proxy's CONNECT answer is too long");
        head.push(tcp.read_u8().await?);
    }
    anyhow::ensure!(
        head.starts_with(b"HTTP/1.1 200"),
        "the proxy refused CONNECT: {}",
        String::from_utf8_lossy(&head)
            .lines()
            .next()
            .unwrap_or_default()
    );
    Ok(tcp)
}

fn ca_roots(config_dir: &Path) -> anyhow::Result<rustls::RootCertStore> {
    let path = crate::ca::Ca::cert_path(config_dir);
    let ca = CertificateDer::from_pem_file(&path)
        .with_context(|| format!("reading the proxy CA {}", path.display()))?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca)?;
    Ok(roots)
}

fn bracket(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_headers_replace_every_value_and_keep_the_rest_in_order() {
        let h = |n: &'static str, v: &'static str| {
            (HeaderName::from_static(n), HeaderValue::from_static(v))
        };
        let mut headers = vec![h("a", "1"), h("b", "2"), h("a", "3"), h("c", "4")];
        set_headers(&mut headers, vec![h("a", "x")]);
        assert_eq!(headers, [h("b", "2"), h("c", "4"), h("a", "x")]);
        let headers =
            without_recomputed(vec![h("host", "h"), h("content-length", "1"), h("d", "5")]);
        assert_eq!(headers, [h("d", "5")]);
    }
}
