//! The request and response path of plain HTTP/1.1 exchanges with the chain registered:
//! upgrade requests run the request phase, per-exchange body buffering keeps streams
//! streaming, bodiless responses keep their headers, map-remote sends the new `Host`.
//! A raw origin on loopback answers by path, so every header is exactly what the test wrote.

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use common::{TestResult, next_exchange, spawn, temp_dir};
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use wirust::flow::Flag;
use wirust::intercept::BlockHost;
use wirust::rules::{Rules, RulesFile};
use wirust::{Config, Proxy};

/// What the origin saw: the request line and `Host` of each request.
type Log = Arc<Mutex<Vec<String>>>;

/// Gap between two server-sent events of `/sse`.
const EVENT_GAP: Duration = Duration::from_millis(200);

/// Number of events `/sse` sends.
const EVENTS: usize = 4;

async fn read_head(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await?);
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

fn header<'a>(head: &'a str, name: &str) -> &'a str {
    head.lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
        .unwrap_or("")
}

/// A raw HTTP/1.1 origin, one request per connection, answering by path.
async fn origin() -> anyhow::Result<(u16, Log)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let log: Log = Arc::default();
    let seen = Arc::clone(&log);
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let Ok(head) = read_head(&mut tcp).await else {
                    return;
                };
                let line = head.lines().next().unwrap_or("").to_owned();
                let host = header(&head, "host").to_owned();
                seen.lock()
                    .expect("log")
                    .push(format!("{line} host={host}"));
                let path = line.split_whitespace().nth(1).unwrap_or("/").to_owned();
                let _ = answer(&mut tcp, &path, &host).await;
            });
        }
    });
    Ok((port, log))
}

async fn answer(tcp: &mut TcpStream, path: &str, host: &str) -> std::io::Result<()> {
    let fixed = |status: &str, headers: &str, body: &str| {
        format!(
            "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\n\r\n{body}",
            body.len()
        )
    };
    let head = match path {
        "/sse" => return events(tcp).await,
        "/head" => "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n".to_owned(),
        "/204" => "HTTP/1.1 204 No Content\r\nX-Kept: 1\r\n\r\n".to_owned(),
        "/304" => {
            "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nContent-Length: 1000\r\n\r\n".to_owned()
        }
        "/host" => fixed("200 OK", "", host),
        _ => fixed("200 OK", "", "from origin"),
    };
    tcp.write_all(head.as_bytes()).await?;
    tcp.shutdown().await
}

/// A chunked `text/event-stream`: one event every [`EVENT_GAP`].
async fn events(tcp: &mut TcpStream) -> std::io::Result<()> {
    tcp.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
    )
    .await?;
    for n in 0..EVENTS {
        tokio::time::sleep(EVENT_GAP).await;
        let event = format!("data: {n}\n\n");
        tcp.write_all(format!("{:x}\r\n{event}\r\n", event.len()).as_bytes())
            .await?;
        tcp.flush().await?;
    }
    tcp.write_all(b"0\r\n\r\n").await?;
    tcp.shutdown().await
}

/// A proxy with `rules` and `--block-host blocked.test,localhost`.
async fn start(rules: &str) -> anyhow::Result<common::Running> {
    let file: RulesFile = toml::from_str(rules)?;
    let compiled = Rules::new();
    compiled.replace(&file).map_err(anyhow::Error::msg)?;
    let mut config = Config {
        listen: "127.0.0.1:0".parse()?,
        body_limit: 64 * 1024,
        ..Config::new(temp_dir())
    };
    config.interceptors.push(Arc::new(BlockHost::new(
        vec!["blocked.test".to_owned(), "localhost".to_owned()],
        StatusCode::FORBIDDEN,
    )));
    for stage in compiled.interceptors(&config.pauses) {
        config.interceptors.push(stage);
    }
    let dir = config.config_dir.clone();
    Ok(spawn(Proxy::bind(config).await?, dir))
}

/// Sends an absolute-form request for `url` with extra `headers` straight to the proxy.
async fn send(
    running: &common::Running,
    method: Method,
    url: &str,
    headers: &[(&str, &str)],
) -> anyhow::Result<http::Response<hyper::body::Incoming>> {
    let tcp = TcpStream::connect(running.addr).await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(connection.with_upgrades());
    let host = url
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("");
    let mut request = Request::builder()
        .method(method)
        .uri(url)
        .header("host", host);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    Ok(sender
        .send_request(request.body(Empty::<Bytes>::new())?)
        .await?)
}

async fn get(running: &common::Running, url: &str) -> anyhow::Result<(StatusCode, String)> {
    let response = send(running, Method::GET, url, &[]).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

#[tokio::test]
async fn upgrade_requests_run_the_request_phase() -> TestResult {
    let (port, log) = origin().await?;
    let running = start(
        r#"
[[rules]]
name = "deny"
match = { path = "/denied" }
action = { type = "block", status = 451 }
"#,
    )
    .await?;
    for upgrade in ["foo", "websocket"] {
        let headers = [("connection", "Upgrade"), ("upgrade", upgrade)];
        let url = format!("http://localhost:{port}/");
        let blocked = send(&running, Method::GET, &url, &headers).await?;
        assert_eq!(blocked.status(), StatusCode::FORBIDDEN, "{upgrade}");
        let url = format!("http://127.0.0.1:{port}/denied");
        let denied = send(&running, Method::GET, &url, &headers).await?;
        assert_eq!(denied.status().as_u16(), 451, "{upgrade}");
    }
    assert!(log.lock().expect("log").is_empty(), "{log:?}");
    // An upgrade the server declines still reaches it.
    let headers = [("connection", "Upgrade"), ("upgrade", "foo")];
    let url = format!("http://127.0.0.1:{port}/open");
    assert_eq!(
        send(&running, Method::GET, &url, &headers).await?.status(),
        StatusCode::OK
    );
    let (status, body) = get(&running, &url).await?;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "from origin"));
    Ok(())
}

#[tokio::test]
async fn bodiless_responses_keep_their_length_under_body_rules() -> TestResult {
    let (port, _log) = origin().await?;
    let running = start(
        r#"
[[rules]]
name = "edit"
action = { type = "rewrite_body", phase = "response", replace = [{ regex = "origin", with = "the rule" }] }
"#,
    )
    .await?;
    let length = |response: &http::Response<_>| {
        let value = response.headers().get("content-length");
        value.and_then(|v| v.to_str().ok()).map(str::to_owned)
    };
    let url = |path: &str| format!("http://127.0.0.1:{port}{path}");
    let head = send(&running, Method::HEAD, &url("/head"), &[]).await?;
    assert_eq!(length(&head).as_deref(), Some("1000"), "{head:?}");
    let none = send(&running, Method::GET, &url("/204"), &[]).await?;
    assert_eq!(none.status(), StatusCode::NO_CONTENT);
    assert_eq!(length(&none), None, "{none:?}");
    let same = send(&running, Method::GET, &url("/304"), &[]).await?;
    assert_eq!(same.status(), StatusCode::NOT_MODIFIED);
    // hyper's server never writes `Content-Length` on a 304, with or without rules; the
    // proxy must not invent a `0` either.
    assert_ne!(length(&same).as_deref(), Some("0"), "{same:?}");
    assert!(same.headers().contains_key("etag"), "{same:?}");
    // A body the rule changes gets its new length.
    let changed = send(&running, Method::GET, &url("/plain"), &[]).await?;
    assert_eq!(length(&changed).as_deref(), Some("13"), "{changed:?}");
    let body = changed.into_body().collect().await?.to_bytes();
    assert_eq!(&body[..], b"from the rule");
    Ok(())
}

#[tokio::test]
async fn unmatched_streams_stream_while_body_rules_exist() -> TestResult {
    let (port, _log) = origin().await?;
    let mut running = start(
        r#"
[[rules]]
name = "elsewhere"
match = { host = "other.example" }
action = { type = "rewrite_body", phase = "response", replace = [{ regex = "data", with = "x" }] }

[[rules]]
name = "elsewhere-request"
match = { host = "other.example" }
action = { type = "rewrite_body", replace = [{ regex = "a", with = "b" }] }

[[rules]]
name = "pause"
match = { path = "/paused" }
action = { type = "breakpoint", request = true, response = true }
"#,
    )
    .await?;
    let started = Instant::now();
    let url = format!("http://127.0.0.1:{port}/sse");
    let response = send(&running, Method::GET, &url, &[]).await?;
    let head_at = started.elapsed();
    let mut body = response.into_body();
    let mut arrivals = Vec::new();
    let mut text = String::new();
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame?.into_data() {
            arrivals.push(started.elapsed());
            text.push_str(&String::from_utf8_lossy(&data));
        }
    }
    let expected: Vec<String> = (0..EVENTS).map(|n| format!("data: {n}\n\n")).collect();
    assert_eq!(text, expected.concat());
    // Buffered, every event arrives at once after the last one was sent. Streamed, they
    // arrive in order about EVENT_GAP apart; only the order and a half-gap spread are checked.
    assert!(arrivals.len() >= 2, "one piece: {arrivals:?}");
    let (first, last) = (arrivals[0], arrivals[arrivals.len() - 1]);
    assert!(
        last.saturating_sub(first) >= EVENT_GAP / 2,
        "events arrived together: {arrivals:?}"
    );
    assert!(head_at < last, "head {head_at:?}, events {arrivals:?}");
    let record = next_exchange(&mut running.events).await?;
    assert!(
        !record.flags.contains(&Flag::Rule("pause".to_owned())),
        "{:?}",
        record.flags
    );
    Ok(())
}
