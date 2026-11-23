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

/// Absolute-form requests on one client connection reuse one server connection instead of
/// opening (and leaving in `TIME_WAIT`) one per request.
#[tokio::test]
async fn plain_requests_on_one_connection_share_a_server_connection() -> TestResult {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            let ok = |_| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(
                    Bytes::from_static(b"ok"),
                )))
            };
            tokio::spawn(
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), hyper::service::service_fn(ok)),
            );
        }
    });
    let certs = upstream_certs()?;
    let proxy = start_proxy(&certs.ca, 1024).await?;
    let client = TokioIo::new(TcpStream::connect(proxy.addr).await?);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(client).await?;
    tokio::spawn(connection);
    for _ in 0..3 {
        let request = Request::get(format!("http://127.0.0.1:{port}/"))
            .header(http::header::HOST, format!("127.0.0.1:{port}"))
            .body(Full::new(Bytes::new()))?;
        let response = sender.send_request(request).await?;
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect().await?;
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 1, "one server connection");
    Ok(())
}

/// Running out of file descriptors is not fatal: the proxy keeps running and accepts again
/// once descriptors are free.
#[cfg(unix)]
#[test]
fn out_of_file_descriptors_does_not_stop_the_proxy() -> TestResult {
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    let dir = temp_dir();
    let mut proxy = Command::new("/bin/sh")
        .arg("-c")
        .arg(r#"ulimit -n 64 && exec "$0" --listen 127.0.0.1:0 --config-dir "$1""#)
        .arg(env!("CARGO_BIN_EXE_wirust"))
        .arg(&dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stderr = BufReader::new(proxy.stderr.take().expect("piped stderr"));
    let mut line = String::new();
    let addr = loop {
        line.clear();
        anyhow::ensure!(
            stderr.read_line(&mut line)? > 0,
            "the proxy exited at start"
        );
        if let Some(rest) = line.split("listening on ").nth(1) {
            break rest
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_owned();
        }
    };
    // Keep reading stderr so the proxy never blocks on a full pipe.
    std::thread::spawn(move || std::io::copy(&mut stderr, &mut std::io::sink()));
    let clients: Vec<std::net::TcpStream> = (0..100)
        .filter_map(|_| std::net::TcpStream::connect(&addr).ok())
        .collect();
    std::thread::sleep(Duration::from_millis(500));
    let exited = proxy.try_wait()?;
    drop(clients);
    std::thread::sleep(Duration::from_millis(500));
    let answer = (|| -> std::io::Result<String> {
        let mut client = std::net::TcpStream::connect(&addr)?;
        client.set_read_timeout(Some(Duration::from_secs(5)))?;
        client.write_all(b"GET http://wirust.test/ HTTP/1.1\r\nHost: wirust.test\r\n\r\n")?;
        let mut head = [0; 12];
        client.read_exact(&mut head)?;
        Ok(String::from_utf8_lossy(&head).into_owned())
    })();
    let _ = proxy.kill();
    let _ = proxy.wait();
    std::fs::remove_dir_all(&dir)?;
    assert!(exited.is_none(), "the proxy exited: {exited:?}");
    assert!(answer?.starts_with("HTTP/1.1 "), "the proxy answers again");
    Ok(())
}
