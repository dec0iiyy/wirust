//! Phone setup over the proxy port: the origin-form setup page, the profile download, and
//! pairing leaving loopback clients alone.

mod common;

use bytes::Bytes;
use common::*;
use http::{HeaderMap, Request, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use wirust::Proxy;
use wirust::pairing::Pairing;

const IPHONE: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 27_0 like Mac OS X) Safari/604.1";

/// Sends `uri` (origin-form or absolute-form) straight to the proxy port.
async fn get(
    proxy: &Running,
    uri: &str,
    host: &str,
    user_agent: &str,
) -> anyhow::Result<(StatusCode, HeaderMap, Bytes)> {
    let tcp = TcpStream::connect(proxy.addr).await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(connection);
    let request = Request::get(uri)
        .header("host", host)
        .header("user-agent", user_agent)
        .body(Full::new(Bytes::new()))?;
    let response = sender.send_request(request).await?;
    let (parts, body) = response.into_parts();
    Ok((
        parts.status,
        parts.headers,
        body.collect().await?.to_bytes(),
    ))
}

#[tokio::test]
async fn a_browser_opening_the_proxy_port_gets_the_setup_page() -> TestResult {
    let certs = upstream_certs()?;
    let running = start_proxy(&certs.ca, 1024).await?;
    let host = running.addr.to_string();
    let (status, headers, page) = get(&running, "/", &host, IPHONE).await?;
    assert_eq!(status, StatusCode::OK);
    let page = String::from_utf8_lossy(&page);
    assert!(page.contains("/ca.mobileconfig") && page.contains("Certificate Trust Settings"));
    let csp = headers["content-security-policy"].to_str()?;
    assert!(csp.contains("script-src 'self'") && !csp.contains("unsafe-inline"));

    let (status, headers, profile) = get(&running, "/ca.mobileconfig", &host, IPHONE).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-type"], "application/x-apple-aspen-config");
    assert!(String::from_utf8_lossy(&profile).contains("com.apple.security.root"));

    let (status, _, help) = get(&running, "/mobile-help", &host, "").await?;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&help).contains("<h1>"));
    let (_, _, js) = get(&running, "/setup.js", &host, "").await?;
    assert!(String::from_utf8_lossy(&js).contains("/pairing-status"));

    // Proxy requests still work on the same port.
    let port = http_server().await?;
    let (status, _, body) = get(
        &running,
        &format!("http://127.0.0.1:{port}/plain"),
        &format!("127.0.0.1:{port}"),
        "",
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"hello from /plain");
    Ok(())
}

#[tokio::test]
async fn pairing_never_affects_loopback_clients() -> TestResult {
    let certs = upstream_certs()?;
    let mut config = test_config(&certs.ca, 1024)?;
    let (pairing, mut notices) = Pairing::new(Vec::new());
    config.pairing = Some(pairing);
    let dir = config.config_dir.clone();
    let running = spawn(Proxy::bind(config).await?, dir);

    let port = https_server(&certs).await?;
    let (status, body) = request(&running, port, b"http/1.1", "/hi", b"").await?;
    assert_eq!(
        (status, &body[..]),
        (StatusCode::OK, &b"hello from /hi"[..])
    );
    let plain = http_server().await?;
    let (status, _, _) = get(
        &running,
        &format!("http://127.0.0.1:{plain}/x"),
        &format!("127.0.0.1:{plain}"),
        "",
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    // A loopback client sees the page without a pairing box and never triggers a prompt.
    let (_, _, page) = get(&running, "/", &running.addr.to_string(), IPHONE).await?;
    assert!(!String::from_utf8_lossy(&page).contains("id=\"pairing\""));
    let (_, _, status) = get(&running, "/pairing-status", "x", "").await?;
    assert_eq!(&status[..], b"approved\n");
    assert!(notices.try_recv().is_err());
    Ok(())
}
