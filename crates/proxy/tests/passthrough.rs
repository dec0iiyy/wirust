//! TLS passthrough: hosts relayed without decryption still get a tunnel record with the
//! ClientHello facts; `--decrypt-only`; the live API.

mod common;

use std::net::SocketAddr;

use bytes::Bytes;
use common::*;
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper_util::rt::TokioIo;
use rustls::pki_types::CertificateDer;
use tokio::net::TcpStream;
use wirust::control::ControlPlane;
use wirust::flow::{Event, Tunnel, TunnelReason};
use wirust::passthrough::{Lists, Passthrough};
use wirust::{Proxy, RemoteAccess};

struct Setup {
    running: Running,
    certs: UpstreamCerts,
    port: u16,
    api: SocketAddr,
    token: String,
}

async fn start(passthrough: &[&str], decrypt_only: &[&str]) -> anyhow::Result<Setup> {
    let certs = upstream_certs()?;
    let port = https_server(&certs).await?;
    let owned = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let mut config = test_config(&certs.ca, 1024)?;
    config.passthrough = Passthrough::new(
        Lists::parse(&owned(passthrough), &owned(decrypt_only)).map_err(anyhow::Error::msg)?,
    );
    let dir = config.config_dir.clone();
    let mut proxy = Proxy::bind(config).await?;
    let control = ControlPlane::bind(
        "127.0.0.1:0".parse()?,
        RemoteAccess::LoopbackOnly,
        &mut proxy,
    )
    .await?;
    let (api, token) = (control.local_addr(), control.token().to_owned());
    tokio::spawn(control.run());
    Ok(Setup {
        running: spawn(proxy, dir),
        certs,
        port,
        api,
        token,
    })
}

impl Setup {
    /// A request through a tunnel that trusts only the upstream's own CA: it works only when
    /// the proxy does not intercept. Returns the body and the certificate the client saw.
    async fn direct_get(&self) -> anyhow::Result<(Bytes, CertificateDer<'static>)> {
        let tls = tunnel(
            self.running.addr,
            self.port,
            std::slice::from_ref(&self.certs.ca),
            b"http/1.1",
        )
        .await?;
        let cert = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first().cloned())
            .ok_or_else(|| anyhow::anyhow!("no peer certificate"))?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
        tokio::spawn(connection);
        let request = Request::builder()
            .uri("/pass")
            .header("host", "localhost")
            .header("connection", "close")
            .body(Full::new(Bytes::new()))?;
        let body = sender
            .send_request(request)
            .await?
            .into_body()
            .collect()
            .await?;
        Ok((body.to_bytes(), cert))
    }

    async fn tunnel_record(&mut self) -> anyhow::Result<Tunnel> {
        match next_event(&mut self.running.events).await? {
            Event::Tunnel(t) => Ok(t),
            other => anyhow::bail!("expected a tunnel, got {other}"),
        }
    }

    async fn api(
        &self,
        method: Method,
        body: &str,
    ) -> anyhow::Result<(StatusCode, serde_json::Value)> {
        let tcp = TcpStream::connect(self.api).await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
        tokio::spawn(connection);
        let request = Request::builder()
            .method(method)
            .uri("/api/v1/passthrough")
            .header("host", self.api.to_string())
            .header("authorization", format!("Bearer {}", self.token))
            .body(Full::new(Bytes::from(body.to_owned())))?;
        let response = sender.send_request(request).await?;
        let status = response.status();
        let bytes = response.into_body().collect().await?.to_bytes();
        Ok((status, serde_json::from_slice(&bytes)?))
    }
}

#[tokio::test]
async fn a_passthrough_host_keeps_its_own_certificate_and_is_recorded() -> TestResult {
    let mut setup = start(&["LOCALHOST"], &[]).await?;
    let (body, cert) = setup.direct_get().await?;
    assert_eq!(body, Bytes::from_static(b"hello from /pass"));
    assert_eq!(
        cert, setup.certs.leaf,
        "the client must see the server's own certificate"
    );
    let record = setup.tunnel_record().await?;
    assert_eq!(record.reason, Some(TunnelReason::Passthrough));
    let tls = record
        .tls
        .clone()
        .ok_or_else(|| anyhow::anyhow!("no tls facts"))?;
    assert_eq!(tls.sni.as_deref(), Some("localhost"));
    assert_eq!(tls.alpn_offered, ["http/1.1"]);
    assert!(tls.ja4.starts_with("t13d"), "{}", tls.ja4);
    assert_ne!(tls.ja3_hash, "");
    assert!(
        record.bytes_up > 200 && record.bytes_down > 200,
        "{record:?}"
    );
    assert!(record.duration_ms.is_some());
    assert_eq!(record.error, None);
    let line = Event::Tunnel(record).to_string();
    assert!(line.contains("TLS passthrough, sni localhost"), "{line}");
    Ok(())
}

#[tokio::test]
async fn decrypt_only_intercepts_matching_hosts_and_relays_the_rest() -> TestResult {
    let mut relayed = start(&[], &["*.example.com"]).await?;
    relayed.direct_get().await?;
    assert_eq!(
        relayed.tunnel_record().await?.reason,
        Some(TunnelReason::Passthrough)
    );

    let decrypted = start(&[], &["localhost:*"]).await;
    assert!(decrypted.is_err(), "a bad port is refused at start-up");
    let mut decrypted = start(&[], &["localhost"]).await?;
    assert!(
        decrypted.direct_get().await.is_err(),
        "intercepted: the upstream CA fails"
    );
    let (status, body) =
        request(&decrypted.running, decrypted.port, b"http/1.1", "/x", b"").await?;
    assert_eq!(
        (status, body),
        (StatusCode::OK, Bytes::from_static(b"hello from /x"))
    );
    loop {
        if let Event::Exchange(_) = next_event(&mut decrypted.running.events).await? {
            break;
        }
    }
    Ok(())
}

#[tokio::test]
async fn the_lists_are_swapped_live_and_validated() -> TestResult {
    let mut setup = start(&[], &[]).await?;
    assert!(setup.direct_get().await.is_err(), "intercepted by default");
    let (status, body) = setup
        .api(
            Method::PUT,
            r#"{"passthrough":["localhost:443","*.localhost","localhost"]}"#,
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        serde_json::json!({"passthrough":["localhost:443","*.localhost","localhost"],"decrypt_only":[]})
    );
    assert_eq!(setup.api(Method::GET, "").await?.1, body);
    setup.direct_get().await?;
    loop {
        if let Event::Tunnel(t) = next_event(&mut setup.running.events).await? {
            assert_eq!(t.reason, Some(TunnelReason::Passthrough));
            break;
        }
    }
    for bad in [
        r#"{"passthrough":["a.*.b"]}"#,
        r#"{"passthrough":"x"}"#,
        r#"{"other":[]}"#,
    ] {
        let (status, body) = setup.api(Method::PUT, bad).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }
    assert_eq!(
        setup.api(Method::GET, "").await?.1["passthrough"][2],
        "localhost",
        "a refused PUT keeps the old lists"
    );
    assert_eq!(
        setup.api(Method::POST, "{}").await?.0,
        StatusCode::METHOD_NOT_ALLOWED
    );
    Ok(())
}
