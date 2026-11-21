//! Shared harness: an in-process HTTPS server, the proxy and a client that goes through it
//! with CONNECT. Everything runs on loopback with random ports.

#![allow(
    dead_code,
    reason = "each test crate uses a different part of the harness"
)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use wirust::events::FlowEvent;
use wirust::flow::{Event, Exchange};
use wirust::{Config, Proxy, UpstreamTls};

pub type TestResult = anyhow::Result<()>;

/// Size of the `/big` response body.
pub const BIG: usize = 3000;

pub fn temp_dir() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "proxy-it-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// A test CA and a `localhost` certificate it signed.
pub struct UpstreamCerts {
    pub ca: CertificateDer<'static>,
    pub leaf: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
}

pub fn upstream_certs() -> anyhow::Result<UpstreamCerts> {
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, ca_key);
    let key = KeyPair::generate()?;
    let leaf = CertificateParams::new(vec!["localhost".to_owned()])?.signed_by(&key, &issuer)?;
    Ok(UpstreamCerts {
        ca: ca.der().clone(),
        leaf: leaf.der().clone(),
        key: PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    })
}

async fn respond(request: Request<Incoming>) -> anyhow::Result<Response<Full<Bytes>>> {
    let path = request.uri().path().to_owned();
    let body = match path.as_str() {
        "/big" => Bytes::from(vec![b'x'; BIG]),
        "/echo" => request.into_body().collect().await?.to_bytes(),
        "/headers" => {
            let get = |name: &str| {
                request
                    .headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("-")
                    .to_owned()
            };
            Bytes::from(format!("{}|{}", get("x-added"), get("x-req")))
        }
        _ => Bytes::from(format!("hello from {path}")),
    };
    Ok(Response::builder()
        .header("x-test", "1")
        .body(Full::new(body))?)
}

/// Serves HTTPS (h2 or HTTP/1.1 by ALPN) on a random port; returns the port.
pub async fn https_server(certs: &UpstreamCerts) -> anyhow::Result<u16> {
    https_server_with_alpn(certs, &[b"h2", b"http/1.1"]).await
}

/// Like [`https_server`], but offering only `alpn`: `&[b"http/1.1"]` is a server that never
/// speaks h2, whatever the client offers.
pub async fn https_server_with_alpn(certs: &UpstreamCerts, alpn: &[&[u8]]) -> anyhow::Result<u16> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certs.leaf.clone()], certs.key.clone_key())?;
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                let io = TokioIo::new(tls);
                let service = service_fn(respond);
                let _ = if h2 {
                    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(io, service)
                        .await
                } else {
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await
                };
            });
        }
    });
    Ok(port)
}

/// Serves plain HTTP/1.1 on a random port; returns the port.
pub async fn http_server() -> anyhow::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), service_fn(respond)),
            );
        }
    });
    Ok(port)
}

pub struct Running {
    pub addr: SocketAddr,
    pub ca_pem: String,
    pub events: broadcast::Receiver<FlowEvent>,
    pub dir: PathBuf,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A test config: random loopback port, a fresh config dir, the upstream test CA trusted.
pub fn test_config(
    upstream_ca: &CertificateDer<'static>,
    body_limit: usize,
) -> anyhow::Result<Config> {
    Ok(Config {
        listen: "127.0.0.1:0".parse()?,
        body_limit,
        upstream: UpstreamTls::Verify {
            extra_roots: vec![upstream_ca.clone()],
        },
        ..Config::new(temp_dir())
    })
}

pub async fn start_proxy(
    upstream_ca: &CertificateDer<'static>,
    body_limit: usize,
) -> anyhow::Result<Running> {
    let config = test_config(upstream_ca, body_limit)?;
    let dir = config.config_dir.clone();
    Ok(spawn(Proxy::bind(config).await?, dir))
}

/// Subscribes to `proxy` and runs it; `dir` is removed when the result drops.
pub fn spawn(proxy: Proxy, dir: PathBuf) -> Running {
    let running = Running {
        addr: proxy.local_addr().expect("bound"),
        ca_pem: proxy.ca().cert_pem().to_owned(),
        events: proxy.subscribe(),
        dir,
    };
    tokio::spawn(proxy.run());
    running
}

/// The next bus event of any kind.
pub async fn next_bus_event(
    events: &mut broadcast::Receiver<FlowEvent>,
) -> anyhow::Result<FlowEvent> {
    Ok(tokio::time::timeout(Duration::from_secs(10), events.recv()).await??)
}

/// The next finished record, skipping `Started` events.
pub async fn next_event(events: &mut broadcast::Receiver<FlowEvent>) -> anyhow::Result<Event> {
    loop {
        if let Some(flow) = next_bus_event(events).await?.flow() {
            return Ok(flow.record.clone());
        }
    }
}

pub async fn next_exchange(
    events: &mut broadcast::Receiver<FlowEvent>,
) -> anyhow::Result<Exchange> {
    match next_event(events).await? {
        Event::Exchange(exchange) => Ok(*exchange),
        other => anyhow::bail!("expected an exchange, got {other}"),
    }
}

/// Opens a CONNECT tunnel through the proxy and a TLS session inside it that trusts `roots`.
pub async fn tunnel(
    proxy: SocketAddr,
    port: u16,
    roots: &[CertificateDer<'static>],
    alpn: &[u8],
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    tunnel_to(proxy, "localhost", port, roots, alpn).await
}

/// Sends `CONNECT host:port` and returns the proxy's response head.
pub async fn connect_head(
    proxy: SocketAddr,
    host: &str,
    port: u16,
) -> anyhow::Result<(TcpStream, Vec<u8>)> {
    let mut tcp = TcpStream::connect(proxy).await?;
    tcp.write_all(
        format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").as_bytes(),
    )
    .await?;
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let byte = tcp.read_u8().await?;
        head.push(byte);
    }
    Ok((tcp, head))
}

/// Opens a CONNECT tunnel to `host:port` and a TLS session for `host` inside it.
pub async fn tunnel_to(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    roots: &[CertificateDer<'static>],
    alpn: &[u8],
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let (tcp, head) = connect_head(proxy, host, port).await?;
    anyhow::ensure!(
        head.starts_with(b"HTTP/1.1 200"),
        "CONNECT refused: {}",
        String::from_utf8_lossy(&head)
    );
    let mut store = RootCertStore::empty();
    for root in roots {
        store.add(root.clone())?;
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(store)
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    let name = ServerName::try_from(host.to_owned())?;
    Ok(TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await?)
}

/// Sends one request through a tunnel speaking the protocol `alpn` names.
pub async fn request(
    proxy: &Running,
    port: u16,
    alpn: &[u8],
    path: &str,
    body: &'static [u8],
) -> anyhow::Result<(StatusCode, Bytes)> {
    let ca = CertificateDer::from_pem_slice(proxy.ca_pem.as_bytes())?;
    let tls = tunnel(proxy.addr, port, &[ca], alpn).await?;
    let io = TokioIo::new(tls);
    let request = Request::builder()
        .method(if body.is_empty() { "GET" } else { "POST" })
        .header("x-req", "abc");
    let response = if alpn == b"h2" {
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), io).await?;
        tokio::spawn(connection);
        let request = request
            .uri(format!("https://localhost:{port}{path}"))
            .body(Full::new(Bytes::from_static(body)))?;
        sender.send_request(request).await?
    } else {
        let (mut sender, connection) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(connection);
        let request = request
            .uri(path)
            .header("host", format!("localhost:{port}"))
            .body(Full::new(Bytes::from_static(body)))?;
        sender.send_request(request).await?
    };
    let status = response.status();
    Ok((status, response.into_body().collect().await?.to_bytes()))
}
