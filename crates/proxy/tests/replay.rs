//! Replay and compose through the control plane: what reaches the server, the new flow's
//! record and events, edits, refusals and limits.

mod common;

use std::net::SocketAddr;

use bytes::Bytes;
use common::*;
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use wirust::control::ControlPlane;
use wirust::events::FlowEvent;
use wirust::flow::{Event, Exchange, Flag};
use wirust::rules::{Rules, RulesFile};
use wirust::{Proxy, RemoteAccess};

/// What the recording server saw: method, path and query, headers in order, body.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Bytes,
}

/// A plain HTTP/1.1 server that reports every request and answers `200 ok`.
async fn recording_server() -> anyhow::Result<(u16, mpsc::UnboundedReceiver<Seen>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let (sender, receiver) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let sender = sender.clone();
            let service = service_fn(move |request: Request<Incoming>| {
                let sender = sender.clone();
                async move {
                    let (parts, body) = request.into_parts();
                    let body = body.collect().await?.to_bytes();
                    let _ = sender.send(Seen {
                        method: parts.method.to_string(),
                        path: parts.uri.to_string(),
                        headers: parts
                            .headers
                            .iter()
                            .map(|(n, v)| {
                                (n.to_string(), String::from_utf8_lossy(v.as_bytes()).into())
                            })
                            .collect(),
                        body,
                    });
                    Ok::<_, hyper::Error>(hyper::Response::new(Full::new(Bytes::from("ok"))))
                }
            });
            tokio::spawn(
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), service),
            );
        }
    });
    Ok((port, receiver))
}

struct Setup {
    running: Running,
    api: SocketAddr,
    token: String,
    port: u16,
    seen: mpsc::UnboundedReceiver<Seen>,
}

async fn start(body_limit: usize, rules: Option<&str>) -> anyhow::Result<Setup> {
    let certs = upstream_certs()?;
    let (port, seen) = recording_server().await?;
    let mut config = test_config(&certs.ca, body_limit)?;
    if let Some(toml) = rules {
        let file: RulesFile = toml::from_str(toml)?;
        let rules = Rules::new();
        rules.replace(&file).map_err(anyhow::Error::msg)?;
        for stage in rules.interceptors(&config.pauses) {
            config.interceptors.push(stage);
        }
    }
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
        api,
        token,
        port,
        seen,
    })
}

impl Setup {
    async fn api(
        &self,
        method: Method,
        path: &str,
        body: &str,
    ) -> anyhow::Result<(StatusCode, serde_json::Value)> {
        let tcp = TcpStream::connect(self.api).await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
        tokio::spawn(connection);
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", self.api.to_string())
            .header("authorization", format!("Bearer {}", self.token))
            .body(Full::new(Bytes::from(body.to_owned())))?;
        let response = sender.send_request(request).await?;
        let status = response.status();
        let bytes = response.into_body().collect().await?.to_bytes();
        Ok((status, serde_json::from_slice(&bytes)?))
    }

    /// Sends a plain `http://` request through the proxy and returns its finished record.
    async fn original(&mut self, path: &str, body: &'static str) -> anyhow::Result<Exchange> {
        let tcp = TcpStream::connect(self.running.addr).await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
        tokio::spawn(connection);
        let request = Request::builder()
            .method("POST")
            .uri(format!("http://127.0.0.1:{}{path}", self.port))
            .header("X-Custom", "one")
            .header("accept", "*/*")
            .header("connection", "keep-alive")
            .body(Full::new(Bytes::from_static(body.as_bytes())))?;
        sender
            .send_request(request)
            .await?
            .into_body()
            .collect()
            .await?;
        self.next_seen().await?;
        next_exchange(&mut self.running.events).await
    }

    async fn next_seen(&mut self) -> anyhow::Result<Seen> {
        let seen = tokio::time::timeout(std::time::Duration::from_secs(10), self.seen.recv());
        seen.await?
            .ok_or_else(|| anyhow::anyhow!("the server stopped"))
    }

    async fn replay(&self, id: u64, body: &str) -> anyhow::Result<(StatusCode, serde_json::Value)> {
        self.api(Method::POST, &format!("/api/v1/flows/{id}/replay"), body)
            .await
    }

    /// Waits for flow `id`: whether `Started` came before the finished record, and the record.
    async fn flow(&mut self, id: u64) -> anyhow::Result<(bool, Exchange)> {
        let mut started = false;
        loop {
            match next_bus_event(&mut self.running.events).await? {
                FlowEvent::Started(s) if s.id == id => started = true,
                event => {
                    if let Some(flow) = event.flow()
                        && flow.id() == id
                        && let Event::Exchange(x) = &flow.record
                    {
                        return Ok((started, (**x).clone()));
                    }
                }
            }
        }
    }
}

fn flow_id(body: &serde_json::Value) -> anyhow::Result<u64> {
    body["flow_id"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("no flow_id in {body}"))
}

#[tokio::test]
async fn a_replay_sends_the_same_request_and_records_a_new_flow() -> TestResult {
    let mut setup = start(1024, None).await?;
    let original = setup.original("/path?q=1", "hello").await?;
    let (status, body) = setup.replay(original.id, "").await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = flow_id(&body)?;
    assert_ne!(id, original.id);
    let seen = setup.next_seen().await?;
    assert_eq!(
        (seen.method.as_str(), seen.path.as_str()),
        ("POST", "/path?q=1")
    );
    assert_eq!(seen.body, Bytes::from_static(b"hello"));
    let names: Vec<&str> = seen.headers.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        ["x-custom", "accept", "host", "content-length"],
        "order kept, hop-by-hop dropped, host and length recomputed"
    );
    let (started_first, record) = setup.flow(id).await?;
    assert!(
        started_first,
        "Started must come before the finished record"
    );
    assert_eq!(record.flags, [Flag::Replay]);
    assert_eq!(record.replay_of, Some(original.id));
    assert_eq!(record.status, Some(200));
    let json = serde_json::to_value(&record)?;
    assert_eq!(json["flags"], serde_json::json!(["replay"]));
    Ok(())
}

#[tokio::test]
async fn edits_change_the_replayed_request() -> TestResult {
    let mut setup = start(1024, None).await?;
    let original = setup.original("/a", "old").await?;
    let edit = r#"{"method":"PUT","url":"/b?x=2","set_headers":{"x-custom":"two","x-new":"3"},
        "remove_headers":["accept"],"body":"new"}"#;
    let (status, body) = setup.replay(original.id, edit).await?;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let seen = setup.next_seen().await?;
    assert_eq!(
        (seen.method.as_str(), seen.path.as_str()),
        ("PUT", "/b?x=2")
    );
    assert_eq!(seen.body, Bytes::from_static(b"new"));
    let header = |name: &str| {
        seen.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    };
    assert_eq!(header("x-custom").as_deref(), Some("two"));
    assert_eq!(header("x-new").as_deref(), Some("3"));
    assert_eq!(header("accept"), None);
    Ok(())
}

#[tokio::test]
async fn invalid_edits_unknown_flows_and_truncated_bodies_are_refused() -> TestResult {
    let mut setup = start(4, None).await?;
    let original = setup.original("/a", "0123456789").await?;
    assert!(original.request_body.truncated);
    let (status, body) = setup.replay(original.id, "").await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("incomplete")
    );
    let (status, _) = setup.replay(original.id, r#"{"body":"fresh"}"#).await?;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(setup.next_seen().await?.body, Bytes::from_static(b"fresh"));
    for bad in [
        r#"{"set_headers":{"x-a":"v\r\nInjected: 1"}}"#,
        r#"{"set_headers":{"bad name":"v"}}"#,
        r#"{"url":"http://u:p@h/x"}"#,
        r#"{"url":"ftp://h/x"}"#,
        r#"{"status":200}"#,
        r#"{"apply_rules":"yes"}"#,
        "not json",
    ] {
        let (status, body) = setup.replay(original.id, bad).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }
    assert_eq!(setup.replay(999, "").await?.0, StatusCode::NOT_FOUND);
    assert_eq!(
        setup
            .api(
                Method::GET,
                &format!("/api/v1/flows/{}/replay", original.id),
                ""
            )
            .await?
            .0,
        StatusCode::METHOD_NOT_ALLOWED
    );
    Ok(())
}

#[tokio::test]
async fn the_control_plane_and_the_proxy_itself_are_refused() -> TestResult {
    let setup = start(1024, None).await?;
    for target in [
        format!("http://127.0.0.1:{}/api/v1/flows", setup.api.port()),
        format!("http://localhost:{}/", setup.api.port()),
        format!("http://127.0.0.1:{}/", setup.running.addr.port()),
    ] {
        let body = format!(r#"{{"method":"GET","url":"{target}"}}"#);
        let (status, answer) = setup.api(Method::POST, "/api/v1/compose", &body).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{target}: {answer}");
    }
    Ok(())
}

#[tokio::test]
async fn compose_sends_a_request_from_scratch() -> TestResult {
    let mut setup = start(1024, None).await?;
    let body = format!(
        r#"{{"method":"PATCH","url":"http://127.0.0.1:{}/c?d=1",
            "headers":[["x-b","2"],["x-a","1"]],"body_base64":"aGk="}}"#,
        setup.port
    );
    let (status, answer) = setup.api(Method::POST, "/api/v1/compose", &body).await?;
    assert_eq!(status, StatusCode::CREATED, "{answer}");
    let id = flow_id(&answer)?;
    let seen = setup.next_seen().await?;
    assert_eq!(
        (seen.method.as_str(), seen.path.as_str()),
        ("PATCH", "/c?d=1")
    );
    assert_eq!(seen.body, Bytes::from_static(b"hi"));
    assert_eq!(
        seen.headers[..2],
        [
            ("x-b".to_owned(), "2".to_owned()),
            ("x-a".to_owned(), "1".to_owned())
        ]
    );
    let (_, record) = setup.flow(id).await?;
    assert_eq!(
        (record.flags.as_slice(), record.replay_of),
        ([Flag::Replay].as_slice(), None)
    );
    Ok(())
}

#[tokio::test]
async fn apply_rules_switches_the_interceptor_chain() -> TestResult {
    let rules = r#"
[[rules]]
name = "block"
match = { path = "/blocked" }
action = { type = "block", status = 403 }
"#;
    let mut setup = start(1024, Some(rules)).await?;
    let url = format!("http://127.0.0.1:{}/blocked", setup.port);
    let body = format!(r#"{{"method":"GET","url":"{url}"}}"#);
    let (_, answer) = setup.api(Method::POST, "/api/v1/compose", &body).await?;
    let (_, record) = setup.flow(flow_id(&answer)?).await?;
    assert_eq!(record.status, Some(200), "rules are off by default");
    assert_eq!(setup.next_seen().await?.path, "/blocked");

    let body = format!(r#"{{"method":"GET","url":"{url}","apply_rules":true}}"#);
    let (_, answer) = setup.api(Method::POST, "/api/v1/compose", &body).await?;
    let (_, record) = setup.flow(flow_id(&answer)?).await?;
    assert_eq!(record.status, Some(403));
    assert_eq!(
        record.flags,
        [
            Flag::Replay,
            Flag::Rule("block".to_owned()),
            Flag::Responded
        ]
    );
    assert!(
        setup.seen.try_recv().is_err(),
        "the server must not be reached"
    );
    Ok(())
}

#[tokio::test]
async fn the_cli_replays_a_session_flow_through_a_running_proxy() -> TestResult {
    let mut setup = start(1024, None).await?;
    let original = setup.original("/cli", "body").await?;
    let edits = wirust::replay::CliEdits {
        set_headers: vec![(
            http::HeaderName::from_static("x-custom"),
            http::HeaderValue::from_static("cli"),
        )],
        method: Some(Method::PUT),
        url: None,
    };
    let line = wirust::replay::send_via(&original, edits, setup.running.addr, &temp_dir()).await?;
    assert_eq!(line, "HTTP/1.1 200 OK");
    let seen = setup.next_seen().await?;
    assert_eq!((seen.method.as_str(), seen.path.as_str()), ("PUT", "/cli"));
    assert_eq!(seen.body, Bytes::from_static(b"body"));
    assert!(
        seen.headers
            .contains(&("x-custom".to_owned(), "cli".to_owned()))
    );
    let record = next_exchange(&mut setup.running.events).await?;
    assert!(
        record.flags.is_empty(),
        "an ordinary client request: {:?}",
        record.flags
    );
    Ok(())
}

#[tokio::test]
async fn too_many_replays_get_429() -> TestResult {
    let setup = start(1024, None).await?;
    let body = format!(
        r#"{{"method":"GET","url":"http://127.0.0.1:{}/r"}}"#,
        setup.port
    );
    let mut statuses = Vec::new();
    for _ in 0..30 {
        statuses.push(setup.api(Method::POST, "/api/v1/compose", &body).await?.0);
    }
    let created = statuses
        .iter()
        .filter(|s| **s == StatusCode::CREATED)
        .count();
    let limited = statuses
        .iter()
        .filter(|s| **s == StatusCode::TOO_MANY_REQUESTS)
        .count();
    assert_eq!(created + limited, 30, "{statuses:?}");
    assert!((1..=20).contains(&created), "{statuses:?}");
    assert!(limited >= 10, "{statuses:?}");
    Ok(())
}
