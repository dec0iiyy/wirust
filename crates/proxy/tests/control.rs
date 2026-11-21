//! The control plane's API and its security checks: token, Host, Origin, loopback-only
//! binding, POST-only state changes, response headers, and the proxy refusing to reach it.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use common::*;
use http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use wirust::control::ControlPlane;
use wirust::intercept::{Action, Interceptor, Pauses, Phase, RequestCtx};
use wirust::{Proxy, RemoteAccess};

struct Ui {
    proxy: Running,
    addr: SocketAddr,
    token: String,
}

/// Pauses every request at the request phase.
struct BreakAll(Pauses);

impl Interceptor for BreakAll {
    fn name(&self) -> &'static str {
        "break-all"
    }

    fn on_request(&self, request: &mut RequestCtx) -> Action {
        Action::Pause(self.0.pause(request.id, Phase::Request))
    }
}

async fn start_ui(break_all: bool) -> anyhow::Result<Ui> {
    let certs = upstream_certs()?;
    let mut config = test_config(&certs.ca, 1024)?;
    if break_all {
        config
            .interceptors
            .push(Arc::new(BreakAll(config.pauses.clone())));
    }
    let dir = config.config_dir.clone();
    let mut proxy = Proxy::bind(config).await?;
    let control = ControlPlane::bind(
        "127.0.0.1:0".parse()?,
        RemoteAccess::LoopbackOnly,
        &mut proxy,
    )
    .await?;
    let (addr, token) = (control.local_addr(), control.token().to_owned());
    assert_eq!(control.url(), format!("http://{addr}/#token={token}"));
    tokio::spawn(control.run());
    Ok(Ui {
        proxy: spawn(proxy, dir),
        addr,
        token,
    })
}

/// One request to `addr` with exactly `headers` (no implicit Host).
async fn call(
    addr: SocketAddr,
    method: Method,
    path: &str,
    headers: &[(&str, String)],
) -> anyhow::Result<(StatusCode, HeaderMap, Bytes)> {
    let tcp = TcpStream::connect(addr).await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(connection);
    let mut request = Request::builder().method(method).uri(path);
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    let response = sender
        .send_request(request.body(Full::new(Bytes::new()))?)
        .await?;
    let (parts, body) = response.into_parts();
    Ok((
        parts.status,
        parts.headers,
        body.collect().await?.to_bytes(),
    ))
}

impl Ui {
    fn host(&self) -> (&'static str, String) {
        ("host", self.addr.to_string())
    }

    fn bearer(&self) -> (&'static str, String) {
        ("authorization", format!("Bearer {}", self.token))
    }

    async fn get(&self, path: &str) -> anyhow::Result<(StatusCode, HeaderMap, Bytes)> {
        call(self.addr, Method::GET, path, &[self.host(), self.bearer()]).await
    }
}

#[tokio::test]
async fn the_api_needs_the_token_in_a_header_or_cookie_never_the_query() -> TestResult {
    let ui = start_ui(false).await?;
    let (status, ..) = call(ui.addr, Method::GET, "/api/v1/flows", &[ui.host()]).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let wrong = ("authorization", format!("Bearer {}", "0".repeat(32)));
    let (status, ..) = call(ui.addr, Method::GET, "/api/v1/flows", &[ui.host(), wrong]).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let query = format!("/api/v1/flows?token={}", ui.token);
    let (status, ..) = call(ui.addr, Method::GET, &query, &[ui.host()]).await?;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "query-string tokens are not accepted"
    );
    let (status, _, body) = ui.get("/api/v1/flows").await?;
    assert_eq!((status, &body[..]), (StatusCode::OK, &b"[]"[..]));
    let cookie = ("cookie", format!("a=b; token={}", ui.token));
    let (status, ..) = call(ui.addr, Method::GET, "/api/v1/flows", &[ui.host(), cookie]).await?;
    assert_eq!(status, StatusCode::OK);
    let (status, _, pem) = ui.get("/api/v1/ca.pem").await?;
    assert_eq!(
        (status, &pem[..]),
        (StatusCode::OK, ui.proxy.ca_pem.as_bytes())
    );
    Ok(())
}

#[tokio::test]
async fn a_wrong_host_or_origin_is_refused() -> TestResult {
    let ui = start_ui(false).await?;
    let port = ui.addr.port();
    for host in [
        format!("evil.test:{port}"),
        "127.0.0.1:1".to_owned(),
        String::new(),
    ] {
        let (status, ..) = call(
            ui.addr,
            Method::GET,
            "/api/v1/flows",
            &[("host", host.clone()), ui.bearer()],
        )
        .await?;
        assert_eq!(status, StatusCode::MISDIRECTED_REQUEST, "host {host:?}");
        let (status, ..) = call(ui.addr, Method::GET, "/", &[("host", host.clone())]).await?;
        assert_eq!(
            status,
            StatusCode::MISDIRECTED_REQUEST,
            "page with host {host:?}"
        );
    }
    let localhost = ("host", format!("localhost:{port}"));
    let (status, ..) = call(ui.addr, Method::GET, "/", &[localhost]).await?;
    assert_eq!(status, StatusCode::OK);
    let evil = ("origin", "http://evil.test".to_owned());
    let (status, headers, _) = call(
        ui.addr,
        Method::GET,
        "/api/v1/flows",
        &[ui.host(), ui.bearer(), evil],
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        headers
            .keys()
            .all(|name| !name.as_str().starts_with("access-control-"))
    );
    let same = ("origin", format!("http://{}", ui.addr));
    let (status, ..) = call(
        ui.addr,
        Method::GET,
        "/api/v1/flows",
        &[ui.host(), ui.bearer(), same],
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn binding_beyond_loopback_needs_allow_remote() -> TestResult {
    let certs = upstream_certs()?;
    let config = test_config(&certs.ca, 16)?;
    let dir = config.config_dir.clone();
    let mut proxy = Proxy::bind(config).await?;
    let error = ControlPlane::bind("0.0.0.0:0".parse()?, RemoteAccess::LoopbackOnly, &mut proxy)
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("bind must fail"))?;
    assert!(error.to_string().contains("--allow-remote"), "{error}");
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[tokio::test]
async fn state_changes_are_post_only_and_responses_are_hardened() -> TestResult {
    let ui = start_ui(false).await?;
    let (status, ..) = ui.get("/api/v1/pauses/1/resume").await?;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    let (status, ..) = call(
        ui.addr,
        Method::POST,
        "/api/v1/flows",
        &[ui.host(), ui.bearer()],
    )
    .await?;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    let (status, ..) = call(
        ui.addr,
        Method::POST,
        "/api/v1/pauses/99/abort",
        &[ui.host(), ui.bearer()],
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "POST reaches the handler; no such pause"
    );
    for path in ["/", "/app.js", "/api/v1/flows", "/api/v1/nope"] {
        let (_, headers, _) = ui.get(path).await?;
        assert_eq!(headers["cache-control"], "no-store", "{path}");
        assert_eq!(headers["x-content-type-options"], "nosniff", "{path}");
        assert_eq!(headers["referrer-policy"], "no-referrer", "{path}");
        assert!(
            headers
                .keys()
                .all(|name| !name.as_str().starts_with("access-control-"))
        );
    }
    let (_, headers, page) = ui.get("/").await?;
    let csp = headers["content-security-policy"].to_str()?;
    assert!(
        csp.starts_with("default-src 'none'") && csp.contains("script-src 'self'"),
        "{csp}"
    );
    assert!(!csp.contains("unsafe"), "{csp}");
    assert!(String::from_utf8_lossy(&page).contains("/app.js"));
    Ok(())
}

#[tokio::test]
async fn the_proxy_refuses_to_reach_the_control_plane() -> TestResult {
    let ui = start_ui(false).await?;
    let port = ui.addr.port();
    for host in ["127.0.0.1", "localhost", "127.0.0.2", "0.0.0.0"] {
        let (_, head) = connect_head(ui.proxy.addr, host, port).await?;
        assert!(
            head.starts_with(b"HTTP/1.1 403"),
            "CONNECT {host}: {}",
            String::from_utf8_lossy(&head)
        );
    }
    let url = format!("http://127.0.0.1:{port}/api/v1/flows");
    let (status, ..) = call(ui.proxy.addr, Method::GET, &url, &[ui.host(), ui.bearer()]).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn pauses_are_listed_and_resolved_through_the_api() -> TestResult {
    let ui = start_ui(true).await?;
    let port = http_server().await?;
    let get = |path: &'static str| {
        let addr = ui.proxy.addr;
        async move {
            let url = format!("http://127.0.0.1:{port}{path}");
            call(
                addr,
                Method::GET,
                &url,
                &[("host", format!("127.0.0.1:{port}"))],
            )
            .await
        }
    };
    for (verb, path, want) in [
        ("resume", "/go", StatusCode::OK),
        ("abort", "/stop", StatusCode::BAD_GATEWAY),
    ] {
        let pending = tokio::spawn(get(path));
        let id = loop {
            let (_, _, body) = ui.get("/api/v1/pauses").await?;
            let list: serde_json::Value = serde_json::from_slice(&body)?;
            if let Some(id) = list[0]["id"].as_u64() {
                assert_eq!(list[0]["phase"], "request");
                break id;
            }
            tokio::task::yield_now().await;
        };
        let path_post = format!("/api/v1/pauses/{id}/{verb}");
        let (status, ..) =
            call(ui.addr, Method::POST, &path_post, &[ui.host(), ui.bearer()]).await?;
        assert_eq!(status, StatusCode::OK);
        let (status, ..) = pending.await??;
        assert_eq!(status, want, "{verb}");
    }
    let (_, _, body) = ui.get("/api/v1/flows").await?;
    let flows: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(flows.as_array().map(Vec::len), Some(2));
    let id = flows[1]["flow"]["id"].as_u64().unwrap_or_default();
    let (status, _, body) = ui.get(&format!("/api/v1/flows/{id}")).await?;
    assert_eq!(status, StatusCode::OK);
    let flow: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(flow["state"], "done");
    assert_eq!(flow["flow"]["schema_version"], 1);
    assert_eq!(flow["flow"]["flags"][0], "responded");
    Ok(())
}

#[tokio::test]
async fn events_stream_as_server_sent_events() -> TestResult {
    let ui = start_ui(false).await?;
    let port = http_server().await?;
    let tcp = TcpStream::connect(ui.addr).await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(connection);
    let request = Request::get("/api/v1/events")
        .header("host", ui.addr.to_string())
        .header("authorization", format!("Bearer {}", ui.token))
        .body(Full::new(Bytes::new()))?;
    let response = sender.send_request(request).await?;
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let mut body = response.into_body();
    let url = format!("http://127.0.0.1:{port}/sse");
    call(
        ui.proxy.addr,
        Method::GET,
        &url,
        &[("host", format!("127.0.0.1:{port}"))],
    )
    .await?;
    let mut seen = String::new();
    while !seen.contains("\"event\":\"completed\"") {
        let frame = tokio::time::timeout(std::time::Duration::from_secs(10), body.frame())
            .await?
            .ok_or_else(|| anyhow::anyhow!("stream ended"))??;
        if let Some(data) = frame.data_ref() {
            seen.push_str(&String::from_utf8_lossy(data));
        }
    }
    let started = seen
        .find("\"event\":\"started\"")
        .ok_or_else(|| anyhow::anyhow!("no start: {seen}"))?;
    assert!(started < seen.find("\"event\":\"completed\"").unwrap_or(0));
    assert!(seen.starts_with("data: "));
    Ok(())
}
