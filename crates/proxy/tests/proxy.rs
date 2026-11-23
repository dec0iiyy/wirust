//! End-to-end tests of forwarding and logging: an in-process HTTPS server, the proxy and a
//! client that goes through it with CONNECT.

mod common;

use std::path::PathBuf;

use bytes::Bytes;
use common::*;
use http::{Request, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper_util::rt::TokioIo;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;
use tokio::net::TcpStream;
use wirust::flow::{Event, TlsFailure};
use wirust::{Config, Proxy, RemoteAccess, UpstreamTls};

async fn exchange_over(alpn: &[u8], version: &str) -> TestResult {
    let certs = upstream_certs()?;
    let port = https_server(&certs).await?;
    let mut proxy = start_proxy(&certs.ca, 1024).await?;
    let (status, body) = request(&proxy, port, alpn, "/echo", b"ping").await?;
    assert_eq!((status, &body[..]), (StatusCode::OK, &b"ping"[..]));
    let record = next_exchange(&mut proxy.events).await?;
    assert_eq!(record.method, "POST");
    assert_eq!(record.url, format!("https://localhost:{port}/echo"));
    assert_eq!(record.status, Some(200));
    assert_eq!(record.client_version, version);
    assert_eq!(record.upstream_version.as_deref(), Some(version));
    assert_eq!(record.protocol(), version, "both legs agree: one name");
    assert!(
        record
            .request_headers
            .contains(&("x-req".to_owned(), "abc".to_owned()))
    );
    assert!(
        record
            .response_headers
            .contains(&("x-test".to_owned(), "1".to_owned()))
    );
    assert_eq!(record.request_body.data, "ping");
    assert_eq!(
        record.response_body.as_ref().map(|b| b.data.as_str()),
        Some("ping")
    );
    assert_eq!(record.error, None);
    let tls = record
        .tls
        .ok_or_else(|| anyhow::anyhow!("no TLS details"))?;
    assert!(tls.ja4.starts_with("t13"), "ja4 {}", tls.ja4);
    assert_eq!(tls.sni.as_deref(), Some("localhost"));
    assert_eq!(tls.alpn.as_deref().map(str::as_bytes), Some(alpn));
    assert_eq!(tls.ja3_hash.len(), 32);
    Ok(())
}

/// The CONNECT host is dialled; the SNI only names the certificate the server must show.
#[tokio::test]
async fn an_intercepted_tunnel_dials_the_connect_host_not_the_sni() -> TestResult {
    // The reserved `.invalid` name never resolves, so dialling the SNI would fail.
    let sni = "wirust-sni.invalid";
    let certs = upstream_certs_for(&[sni])?;
    let port = https_server_with_alpn(&certs, &[b"http/1.1"]).await?;
    let mut proxy = start_proxy(&certs.ca, 1024).await?;
    let ca = CertificateDer::from_pem_slice(proxy.ca_pem.as_bytes())?;
    let tls = tunnel_with_sni(proxy.addr, ("127.0.0.1", port), sni, &[ca], b"http/1.1").await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    tokio::spawn(connection);
    let request = Request::builder()
        .uri("/dialled")
        .header("host", sni)
        .body(Full::new(Bytes::new()))?;
    let response = sender.send_request(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    assert_eq!(
        (status, &body[..]),
        (StatusCode::OK, &b"hello from /dialled"[..])
    );
    let record = next_exchange(&mut proxy.events).await?;
    assert_eq!(record.url, format!("https://127.0.0.1:{port}/dialled"));
    assert_eq!(record.tls.and_then(|tls| tls.sni).as_deref(), Some(sni));
    Ok(())
}

#[tokio::test]
async fn http1_exchange_is_forwarded_and_logged() -> TestResult {
    exchange_over(b"http/1.1", "http/1.1").await
}

#[tokio::test]
async fn http2_exchange_is_forwarded_and_logged() -> TestResult {
    exchange_over(b"h2", "h2").await
}

/// Regression: the log line showed the server leg (`http/1.1`) while the web UI showed the
/// client leg (`h2`) for the same flow. Both now come from `Exchange::protocol`.
#[tokio::test]
async fn an_h2_client_of_an_http1_only_server_shows_both_legs() -> TestResult {
    let certs = upstream_certs()?;
    let port = https_server_with_alpn(&certs, &[b"http/1.1"]).await?;
    let mut proxy = start_proxy(&certs.ca, 1024).await?;
    let (status, _) = request(&proxy, port, b"h2", "/x", b"").await?;
    assert_eq!(status, StatusCode::OK);
    let record = next_exchange(&mut proxy.events).await?;
    assert_eq!(record.client_version, "h2", "what the client spoke");
    assert_eq!(record.upstream_version.as_deref(), Some("http/1.1"));
    assert_eq!(record.protocol(), "h2→http/1.1");
    let line = Event::Exchange(Box::new(record)).to_string();
    assert!(line.contains("  h2→http/1.1  "), "{line}");
    Ok(())
}

#[tokio::test]
async fn an_http1_client_of_an_http1_only_server_is_http1_on_both_legs() -> TestResult {
    let certs = upstream_certs()?;
    let port = https_server_with_alpn(&certs, &[b"http/1.1"]).await?;
    let mut proxy = start_proxy(&certs.ca, 1024).await?;
    request(&proxy, port, b"http/1.1", "/x", b"").await?;
    let record = next_exchange(&mut proxy.events).await?;
    assert_eq!(record.protocol(), "http/1.1");
    Ok(())
}

#[tokio::test]
async fn untrusting_client_is_logged_and_the_proxy_keeps_working() -> TestResult {
    let certs = upstream_certs()?;
    let port = https_server(&certs).await?;
    let mut proxy = start_proxy(&certs.ca, 1024).await?;
    // Trusts the upstream CA only, not the proxy's.
    let refused = tunnel(proxy.addr, port, std::slice::from_ref(&certs.ca), b"h2").await;
    assert!(
        refused.is_err(),
        "the client must reject the proxy certificate"
    );
    let Event::TlsFailure(TlsFailure {
        sni, reason, ja4, ..
    }) = next_event(&mut proxy.events).await?
    else {
        anyhow::bail!("expected a TLS failure");
    };
    assert_eq!(sni.as_deref(), Some("localhost"));
    assert_ne!(reason, "", "the failure carries a reason");
    assert!(ja4.starts_with("t13"));
    let (status, body) = request(&proxy, port, b"h2", "/after", b"").await?;
    assert_eq!(
        (status, &body[..]),
        (StatusCode::OK, &b"hello from /after"[..])
    );
    Ok(())
}

#[tokio::test]
async fn body_limit_truncates_the_log_not_the_body() -> TestResult {
    let certs = upstream_certs()?;
    let port = https_server(&certs).await?;
    let mut proxy = start_proxy(&certs.ca, 100).await?;
    let (_, body) = request(&proxy, port, b"http/1.1", "/big", b"").await?;
    assert_eq!(body.len(), BIG, "the client gets the whole body");
    let record = next_exchange(&mut proxy.events).await?;
    let logged = record
        .response_body
        .ok_or_else(|| anyhow::anyhow!("no body"))?;
    assert!(logged.truncated);
    assert_eq!((logged.size, logged.data.len()), (BIG as u64, 100));
    Ok(())
}

#[tokio::test]
async fn plain_http_absolute_form_is_logged() -> TestResult {
    let certs = upstream_certs()?;
    let port = http_server().await?;
    let mut proxy = start_proxy(&certs.ca, 1024).await?;
    let tcp = TcpStream::connect(proxy.addr).await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(connection);
    let url = format!("http://127.0.0.1:{port}/plain");
    let request = Request::get(&url)
        .header("host", format!("127.0.0.1:{port}"))
        .body(Full::new(Bytes::new()))?;
    let response = sender.send_request(request).await?;
    let body = response.into_body().collect().await?.to_bytes();
    assert_eq!(&body[..], b"hello from /plain");
    let record = next_exchange(&mut proxy.events).await?;
    assert_eq!(
        (record.url.as_str(), record.status),
        (url.as_str(), Some(200))
    );
    assert!(record.tls.is_none());
    assert_eq!(record.protocol(), "http/1.1");
    Ok(())
}

#[tokio::test]
async fn the_ca_is_reused_across_restarts() -> TestResult {
    let dir = temp_dir();
    let config = |dir: &PathBuf| -> anyhow::Result<Config> {
        Ok(Config {
            listen: "127.0.0.1:0".parse()?,
            ..Config::new(dir.clone())
        })
    };
    let first = Proxy::bind(config(&dir)?).await?.ca().cert_pem().to_owned();
    let second = Proxy::bind(config(&dir)?).await?.ca().cert_pem().to_owned();
    assert_eq!(first, second);
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

#[tokio::test]
async fn non_loopback_bind_needs_allow_remote() -> TestResult {
    let dir = temp_dir();
    let config = Config {
        listen: "0.0.0.0:0".parse()?,
        remote: RemoteAccess::LoopbackOnly,
        upstream: UpstreamTls::default(),
        ..Config::new(dir.clone())
    };
    let error = Proxy::bind(config)
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("bind must fail"))?;
    assert!(error.to_string().contains("--allow-remote"), "{error}");
    assert!(!dir.exists(), "no CA is created for a refused start");
    Ok(())
}
