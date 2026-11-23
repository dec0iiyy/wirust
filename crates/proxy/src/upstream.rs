//! Connections from the proxy to servers.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use http::{HeaderValue, Request, Response};
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::access::Guard;
use crate::proxy::{ProxyBody, UpstreamTls};
use crate::upstream_proxy::{self, Kind, Route};

/// Limit on connecting to a server, DNS included.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Limit on the TLS handshake with a server, after the TCP connection is up.
const TLS_TIMEOUT: Duration = Duration::from_secs(10);
/// Limit on the HTTP/1.1 or HTTP/2 connection setup over an open connection.
const HTTP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A step toward the server took longer than its limit; the proxy answers `504`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TimedOut(&'static str);

impl std::fmt::Display for TimedOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} timed out", self.0)
    }
}

impl std::error::Error for TimedOut {}

/// Runs `step` within `limit`, failing with [`TimedOut`] naming `what`.
async fn within<T>(
    limit: Duration,
    what: &'static str,
    step: impl Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    tokio::time::timeout(limit, step)
        .await
        .map_err(|_| TimedOut(what))?
}

/// TLS settings toward servers: one config offering h2 and HTTP/1.1, one offering only
/// HTTP/1.1, picked by what the client offered.
/// Also holds the route (which connections go through an upstream proxy) and the guard
/// every dial is checked against.
#[derive(Debug, Clone)]
pub(crate) struct Connector {
    h2: Arc<ClientConfig>,
    h1: Arc<ClientConfig>,
    route: Route,
    guard: Guard,
}

impl Connector {
    pub(crate) fn new(tls: &UpstreamTls, route: Route, guard: Guard) -> anyhow::Result<Self> {
        let base = match tls {
            UpstreamTls::Verify { extra_roots } => {
                let mut roots = RootCertStore {
                    roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                };
                for root in extra_roots {
                    roots.add(root.clone()).context("adding an upstream root")?;
                }
                ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth()
            }
            UpstreamTls::Insecure => ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAny::new()))
                .with_no_client_auth(),
        };
        let with_alpn = |alpn: &[&[u8]]| {
            let mut config = base.clone();
            config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
            Arc::new(config)
        };
        Ok(Self {
            h2: with_alpn(&[b"h2", b"http/1.1"]),
            h1: with_alpn(&[b"http/1.1"]),
            route,
            guard,
        })
    }

    /// The addresses no dial may reach.
    pub(crate) fn guard(&self) -> &Guard {
        &self.guard
    }

    /// Adds a control plane address to the guard.
    pub(crate) fn refuse(&mut self, addr: std::net::SocketAddr) {
        self.guard.refuse(addr);
    }
}

/// A connection ready for requests.
#[derive(Debug, Clone)]
pub(crate) struct Sender {
    conn: Conn,
    via: Via,
}

#[derive(Debug, Clone)]
enum Conn {
    H1(Arc<tokio::sync::Mutex<http1::SendRequest<ProxyBody>>>),
    H2(http2::SendRequest<ProxyBody>),
}

/// How a connection reaches the server.
#[derive(Debug, Clone)]
enum Via {
    Direct,
    /// A tunnel through the upstream proxy (CONNECT or SOCKS5).
    Tunnel,
    /// An HTTP upstream proxy taking absolute-form requests for the server `authority`
    /// (`host:port`), with its `Proxy-Authorization` value.
    Forward {
        auth: Option<HeaderValue>,
        authority: String,
    },
}

impl Sender {
    pub(crate) fn is_closed(&self) -> bool {
        match &self.conn {
            Conn::H1(sender) => sender.try_lock().is_ok_and(|s| s.is_closed()),
            Conn::H2(sender) => sender.is_closed(),
        }
    }

    pub(crate) fn version(&self) -> http::Version {
        match &self.conn {
            Conn::H1(_) => http::Version::HTTP_11,
            Conn::H2(_) => http::Version::HTTP_2,
        }
    }

    /// Whether the connection goes through the upstream proxy.
    pub(crate) fn via_upstream_proxy(&self) -> bool {
        !matches!(self.via, Via::Direct)
    }

    /// Sends `request`. HTTP/1.1 requests wait for the previous response body to finish.
    /// Through an HTTP upstream proxy, the target becomes absolute-form and the proxy's
    /// credentials are added after the request was recorded.
    pub(crate) async fn send(
        &self,
        mut request: Request<ProxyBody>,
    ) -> hyper::Result<Response<Incoming>> {
        if let Via::Forward { auth, authority } = &self.via {
            absolute_form(&mut request, authority, auth.as_ref());
        }
        match &self.conn {
            Conn::H1(sender) => {
                let mut sender = sender.lock().await;
                sender.ready().await?;
                let response = sender.send_request(request);
                drop(sender);
                response.await
            }
            Conn::H2(sender) => sender.clone().send_request(request).await,
        }
    }
}

/// Rewrites an origin-form HTTP/1.1 request to `http://authority/path` for an HTTP proxy.
/// `authority` is the server the connection was opened for, not the `Host` header, which a
/// client or a rule may have set to something else.
fn absolute_form(request: &mut Request<ProxyBody>, authority: &str, auth: Option<&HeaderValue>) {
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    if let Ok(uri) = format!("http://{authority}{path}").parse() {
        *request.uri_mut() = uri;
    }
    if let Some(auth) = auth {
        request
            .headers_mut()
            .insert(http::header::PROXY_AUTHORIZATION, auth.clone());
    }
}

/// A new connection and how long its steps took.
#[derive(Debug)]
pub(crate) struct Opened {
    pub(crate) sender: Sender,
    pub(crate) connect: Duration,
    pub(crate) tls: Option<Duration>,
}

/// A TCP stream to `host:port` for the client `peer`, tunnelled through the upstream proxy
/// when the route says so. A direct connection resolves `host` once, checks every address
/// with the guard and dials exactly those; through the upstream proxy, which resolves the
/// name itself, only IP literals and `localhost` names can be checked.
async fn tcp(
    connector: &Connector,
    peer: IpAddr,
    host: &str,
    port: u16,
) -> anyhow::Result<(TcpStream, Via)> {
    if let Some(proxy) = connector.route.via(host) {
        connector.guard.check_name(peer, host, port)?;
        let stream = upstream_proxy::tunnel(proxy, host, port, CONNECT_TIMEOUT).await?;
        return Ok((stream, Via::Tunnel));
    }
    let attempt = async {
        let addrs = connector.guard.resolve(peer, host, port).await?;
        TcpStream::connect(addrs.as_slice())
            .await
            .with_context(|| format!("connecting to {host}:{port}"))
    };
    let stream = within(CONNECT_TIMEOUT, "connecting", attempt)
        .await
        .with_context(|| format!("{host}:{port}"))?;
    stream.set_nodelay(true)?;
    Ok((stream, Via::Direct))
}

/// The client side of a TLS handshake over `io`, within [`TLS_TIMEOUT`].
async fn tls_handshake<I>(
    config: &Arc<ClientConfig>,
    name: ServerName<'static>,
    io: I,
) -> anyhow::Result<tokio_rustls::client::TlsStream<I>>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let connect = TlsConnector::from(Arc::clone(config)).connect(name, io);
    within(TLS_TIMEOUT, "the TLS handshake", async {
        Ok(connect.await?)
    })
    .await
}

/// Opens a TLS connection to `host:port`, sending and verifying the server name `name`
/// (the client's SNI), offering h2 when `offer_h2`.
pub(crate) async fn open_tls(
    connector: &Connector,
    peer: IpAddr,
    (host, port): (&str, u16),
    name: &str,
    offer_h2: bool,
    upgrades: bool,
) -> anyhow::Result<Opened> {
    let start = Instant::now();
    let (tcp, via) = tcp(connector, peer, host, port).await?;
    let connect = start.elapsed();
    let config = if offer_h2 && !upgrades {
        &connector.h2
    } else {
        &connector.h1
    };
    let name = ServerName::try_from(name.to_owned()).context("invalid server name")?;
    let tls = tls_handshake(config, name, tcp)
        .await
        .with_context(|| format!("TLS handshake with {host}:{port}"))?;
    let tls_time = start.elapsed().saturating_sub(connect);
    let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
    let conn = handshake(TokioIo::new(tls), h2, upgrades).await?;
    Ok(Opened {
        sender: Sender { conn, via },
        connect,
        tls: Some(tls_time),
    })
}

/// Opens a plain HTTP/1.1 connection to `host:port`. Through an HTTP upstream proxy,
/// ordinary requests go to the proxy in absolute form; upgrades take a CONNECT tunnel.
pub(crate) async fn open_plain(
    connector: &Connector,
    peer: IpAddr,
    host: &str,
    port: u16,
    upgrades: bool,
) -> anyhow::Result<Opened> {
    let start = Instant::now();
    let (tcp, via) = match connector.route.via(host) {
        Some(proxy) if proxy.kind() == Kind::Http && !upgrades => {
            connector.guard.check_name(peer, host, port)?;
            let stream = upstream_proxy::connect_forward(proxy, CONNECT_TIMEOUT).await?;
            let auth = proxy
                .basic_auth()
                .map(|auth| {
                    let mut value = HeaderValue::from_str(&auth)?;
                    value.set_sensitive(true);
                    anyhow::Ok(value)
                })
                .transpose()?;
            let authority = if host.contains(':') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            };
            (stream, Via::Forward { auth, authority })
        }
        _ => tcp(connector, peer, host, port).await?,
    };
    let connect = start.elapsed();
    let conn = handshake(TokioIo::new(tcp), false, upgrades).await?;
    Ok(Opened {
        sender: Sender { conn, via },
        connect,
        tls: None,
    })
}

/// Opens a raw TCP connection for a pass-through tunnel.
pub(crate) async fn open_raw(
    connector: &Connector,
    peer: IpAddr,
    host: &str,
    port: u16,
) -> anyhow::Result<TcpStream> {
    Ok(tcp(connector, peer, host, port).await?.0)
}

async fn handshake<I>(io: TokioIo<I>, h2: bool, upgrades: bool) -> anyhow::Result<Conn>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let setup = http_handshake(io, h2, upgrades);
    within(HTTP_HANDSHAKE_TIMEOUT, "the HTTP handshake", setup).await
}

async fn http_handshake<I>(io: TokioIo<I>, h2: bool, upgrades: bool) -> anyhow::Result<Conn>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if h2 {
        let (sender, connection) = http2::Builder::new(TokioExecutor::new())
            .handshake(io)
            .await?;
        tokio::spawn(connection);
        return Ok(Conn::H2(sender));
    }
    let (sender, connection) = http1::Builder::new()
        .preserve_header_case(true)
        .handshake(io)
        .await?;
    if upgrades {
        tokio::spawn(connection.with_upgrades());
    } else {
        tokio::spawn(connection);
    }
    Ok(Conn::H1(Arc::new(tokio::sync::Mutex::new(sender))))
}

/// Accepts any server certificate; used only with `--upstream-insecure`. Signatures are
/// still checked, so the session is encrypted to whoever holds the presented key.
#[derive(Debug)]
struct AcceptAny {
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl AcceptAny {
    fn new() -> Self {
        Self {
            algorithms: rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A server that accepts the connection and never answers the ClientHello.
    #[tokio::test(start_paused = true)]
    async fn a_silent_server_times_out_the_tls_handshake() -> anyhow::Result<()> {
        let connector = Connector::new(
            &UpstreamTls::Insecure,
            Route::default(),
            Guard::new("127.0.0.1:1".parse()?),
        )?;
        let (client, server) = tokio::io::duplex(64 * 1024);
        let name = ServerName::try_from("example.com")?;
        let attempt = tls_handshake(&connector.h1, name, client);
        let outcome = tokio::time::timeout(TLS_TIMEOUT * 10, attempt).await;
        let error = outcome
            .expect("the handshake gives up by itself")
            .expect_err("no TLS");
        assert_eq!(
            error.downcast_ref::<TimedOut>(),
            Some(&TimedOut("the TLS handshake"))
        );
        drop(server);
        Ok(())
    }
}
