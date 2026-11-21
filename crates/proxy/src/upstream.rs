//! Connections from the proxy to servers.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, anyhow};
use http::{Request, Response};
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::proxy::{ProxyBody, UpstreamTls};

/// Limit on connecting to a server, DNS included.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// TLS settings toward servers: one config offering h2 and HTTP/1.1, one offering only
/// HTTP/1.1, picked by what the client offered.
#[derive(Debug, Clone)]
pub(crate) struct Connector {
    h2: Arc<ClientConfig>,
    h1: Arc<ClientConfig>,
}

impl Connector {
    pub(crate) fn new(tls: &UpstreamTls) -> anyhow::Result<Self> {
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
        })
    }
}

/// A connection ready for requests.
#[derive(Debug, Clone)]
pub(crate) enum Sender {
    H1(Arc<tokio::sync::Mutex<http1::SendRequest<ProxyBody>>>),
    H2(http2::SendRequest<ProxyBody>),
}

impl Sender {
    pub(crate) fn is_closed(&self) -> bool {
        match self {
            Self::H1(sender) => sender.try_lock().is_ok_and(|s| s.is_closed()),
            Self::H2(sender) => sender.is_closed(),
        }
    }

    pub(crate) fn version(&self) -> http::Version {
        match self {
            Self::H1(_) => http::Version::HTTP_11,
            Self::H2(_) => http::Version::HTTP_2,
        }
    }

    /// Sends `request`. HTTP/1.1 requests wait for the previous response body to finish.
    pub(crate) async fn send(
        &self,
        request: Request<ProxyBody>,
    ) -> hyper::Result<Response<Incoming>> {
        match self {
            Self::H1(sender) => {
                let mut sender = sender.lock().await;
                sender.ready().await?;
                let response = sender.send_request(request);
                drop(sender);
                response.await
            }
            Self::H2(sender) => sender.clone().send_request(request).await,
        }
    }
}

/// A new connection and how long its steps took.
#[derive(Debug)]
pub(crate) struct Opened {
    pub(crate) sender: Sender,
    pub(crate) connect: Duration,
    pub(crate) tls: Option<Duration>,
}

async fn tcp(host: &str, port: u16) -> anyhow::Result<TcpStream> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .map_err(|_| anyhow!("connecting to {host}:{port} timed out"))?
        .with_context(|| format!("connecting to {host}:{port}"))?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// Opens a TLS connection to `host:port`, offering h2 when `offer_h2`.
pub(crate) async fn open_tls(
    connector: &Connector,
    host: &str,
    port: u16,
    offer_h2: bool,
    upgrades: bool,
) -> anyhow::Result<Opened> {
    let start = Instant::now();
    let tcp = tcp(host, port).await?;
    let connect = start.elapsed();
    let config = if offer_h2 && !upgrades {
        &connector.h2
    } else {
        &connector.h1
    };
    let name = ServerName::try_from(host.to_owned()).context("invalid server name")?;
    let tls = TlsConnector::from(Arc::clone(config))
        .connect(name, tcp)
        .await
        .with_context(|| format!("TLS handshake with {host}:{port}"))?;
    let tls_time = start.elapsed().saturating_sub(connect);
    let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
    let sender = handshake(TokioIo::new(tls), h2, upgrades).await?;
    Ok(Opened {
        sender,
        connect,
        tls: Some(tls_time),
    })
}

/// Opens a plain HTTP/1.1 connection to `host:port`.
pub(crate) async fn open_plain(host: &str, port: u16, upgrades: bool) -> anyhow::Result<Opened> {
    let start = Instant::now();
    let tcp = tcp(host, port).await?;
    let connect = start.elapsed();
    let sender = handshake(TokioIo::new(tcp), false, upgrades).await?;
    Ok(Opened {
        sender,
        connect,
        tls: None,
    })
}

/// Opens a raw TCP connection for a pass-through tunnel.
pub(crate) async fn open_raw(host: &str, port: u16) -> anyhow::Result<TcpStream> {
    tcp(host, port).await
}

async fn handshake<I>(io: TokioIo<I>, h2: bool, upgrades: bool) -> anyhow::Result<Sender>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if h2 {
        let (sender, connection) = http2::Builder::new(TokioExecutor::new())
            .handshake(io)
            .await?;
        tokio::spawn(connection);
        return Ok(Sender::H2(sender));
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
    Ok(Sender::H1(Arc::new(tokio::sync::Mutex::new(sender))))
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
