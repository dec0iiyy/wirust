//! End-to-end tests of the extension seams: the event bus, the interceptor chain and the
//! magic host.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use common::*;
use http::{HeaderName, HeaderValue, Request, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper_util::rt::TokioIo;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;
use tokio::net::{TcpListener, TcpStream};
use wirust::Proxy;
use wirust::events::{FlowEvent, StoredFlow};
use wirust::flow::Flag;
use wirust::intercept::{Action, BlockHost, HeaderRules, Interceptor, RequestCtx};

#[tokio::test]
async fn started_comes_before_completed_and_ids_are_unique() -> TestResult {
    let certs = upstream_certs()?;
    let port = https_server(&certs).await?;
    let config = test_config(&certs.ca, 1024)?;
    let dir = config.config_dir.clone();
    let proxy = Proxy::bind(config).await?;
    let store = proxy.store().clone();
    let mut running = spawn(proxy, dir);
    let mut ids = Vec::new();
    for path in ["/one", "/two"] {
        request(&running, port, b"h2", path, b"").await?;
        let FlowEvent::Started(started) = next_bus_event(&mut running.events).await? else {
            anyhow::bail!("the first event of an exchange must be Started");
        };
        let FlowEvent::Completed(done) = next_bus_event(&mut running.events).await? else {
            anyhow::bail!("then Completed");
        };
        assert_eq!(started.id, done.id());
        assert!(started.url.ends_with(path));
        ids.push(started.id);
    }
    assert_ne!(ids[0], ids[1]);
    // The store follows the same bus; give its task a moment to apply the last event.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(matches!(store.get(ids[1]), Some(StoredFlow::Done(_))));
    Ok(())
}

/// Counts TCP connections and serves nothing.
async fn counting_server() -> anyhow::Result<(u16, Arc<AtomicUsize>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    tokio::spawn(async move {
        while listener.accept().await.is_ok() {
            seen.fetch_add(1, Ordering::SeqCst);
        }
    });
    Ok((port, count))
}

#[tokio::test]
async fn block_host_answers_without_contacting_the_server() -> TestResult {
    let certs = upstream_certs()?;
    let (port, connections) = counting_server().await?;
    let mut config = test_config(&certs.ca, 1024)?;
    config.interceptors.push(Arc::new(BlockHost::new(
        vec!["localhost".to_owned()],
        StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
    )));
    let dir = config.config_dir.clone();
    let mut running = spawn(Proxy::bind(config).await?, dir);
    let (status, body) = request(&running, port, b"http/1.1", "/x", b"").await?;
    assert_eq!(status, StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
    assert!(String::from_utf8_lossy(&body).contains("blocked localhost"));
    let record = next_exchange(&mut running.events).await?;
    assert_eq!(record.status, Some(451));
    assert_eq!(record.flags, [Flag::Responded]);
    assert_eq!(
        connections.load(Ordering::SeqCst),
        0,
        "no upstream connection"
    );
    Ok(())
}

#[tokio::test]
async fn header_rules_change_what_the_server_receives() -> TestResult {
    let certs = upstream_certs()?;
    let port = https_server(&certs).await?;
    let mut config = test_config(&certs.ca, 1024)?;
    config.interceptors.push(Arc::new(HeaderRules::new(
        vec![(
            HeaderName::from_static("x-added"),
            HeaderValue::from_static("yes"),
        )],
        vec![HeaderName::from_static("x-req")],
    )));
    let dir = config.config_dir.clone();
    let mut running = spawn(Proxy::bind(config).await?, dir);
    for alpn in [&b"h2"[..], b"http/1.1"] {
        let (_, body) = request(&running, port, alpn, "/headers", b"").await?;
        assert_eq!(&body[..], b"yes|-", "over {alpn:?}");
        let record = next_exchange(&mut running.events).await?;
        // The record shows what the client sent.
        assert!(
            record
                .request_headers
                .contains(&("x-req".to_owned(), "abc".to_owned()))
        );
    }
    Ok(())
}

/// Upper-cases request bodies; needs them buffered.
struct Shout;

impl Interceptor for Shout {
    fn name(&self) -> &'static str {
        "shout"
    }

    fn needs_request_body(&self) -> bool {
        true
    }

    fn on_request(&self, request: &mut RequestCtx) -> Action {
        if let Some(body) = &request.body {
            request.body = Some(Bytes::from(body.to_ascii_uppercase()));
        }
        Action::Continue
    }
}

#[tokio::test]
async fn body_rules_see_bodies_under_the_limit_and_skip_larger_ones() -> TestResult {
    let certs = upstream_certs()?;
    let port = https_server(&certs).await?;
    let mut config = test_config(&certs.ca, 8)?;
    config.interceptors.push(Arc::new(Shout));
    let dir = config.config_dir.clone();
    let mut running = spawn(Proxy::bind(config).await?, dir);
    let (_, body) = request(&running, port, b"h2", "/echo", b"ping").await?;
    assert_eq!(&body[..], b"PING");
    assert_eq!(next_exchange(&mut running.events).await?.flags, []);
    let big = b"a body over eight bytes";
    let (_, body) = request(&running, port, b"http/1.1", "/echo", big).await?;
    assert_eq!(&body[..], big, "passed through untouched");
    let record = next_exchange(&mut running.events).await?;
    assert_eq!(record.flags, [Flag::RewriteSkippedBodyTooLarge]);
    Ok(())
}

async fn plain_get(proxy: &Running, url: &str) -> anyhow::Result<(StatusCode, Bytes)> {
    let tcp = TcpStream::connect(proxy.addr).await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(connection);
    let host = url
        .parse::<http::Uri>()?
        .authority()
        .map(ToString::to_string)
        .unwrap_or_default();
    let response = sender
        .send_request(
            Request::get(url)
                .header("host", host)
                .body(Full::new(Bytes::new()))?,
        )
        .await?;
    let status = response.status();
    Ok((status, response.into_body().collect().await?.to_bytes()))
}

#[tokio::test]
async fn the_magic_host_serves_the_ca_over_http_and_https() -> TestResult {
    let certs = upstream_certs()?;
    let running = start_proxy(&certs.ca, 1024).await?;
    let host = wirust::MAGIC_HOST;
    let (status, page) = plain_get(&running, &format!("http://{host}/")).await?;
    assert_eq!(status, StatusCode::OK);
    let page = String::from_utf8_lossy(&page);
    assert!(page.contains("/ca.crt") && page.contains(&running.addr.to_string()));
    let (_, pem) = plain_get(&running, &format!("http://{host}/ca.pem")).await?;
    assert_eq!(&pem[..], running.ca_pem.as_bytes());
    let (_, der) = plain_get(&running, &format!("http://{host}/ca.crt")).await?;
    let ca = CertificateDer::from_pem_slice(running.ca_pem.as_bytes())?;
    assert_eq!(&der[..], &ca[..]);

    // Over HTTPS the proxy presents a leaf for the magic host, signed by its CA.
    let tls = tunnel_to(running.addr, host, 443, &[ca], b"http/1.1").await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    tokio::spawn(connection);
    let response = sender
        .send_request(
            Request::get("/ca.pem")
                .header("host", host)
                .body(Full::new(Bytes::new()))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await?.to_bytes();
    assert_eq!(&body[..], running.ca_pem.as_bytes());
    Ok(())
}
