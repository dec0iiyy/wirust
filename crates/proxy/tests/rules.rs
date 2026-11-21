//! End-to-end tests of the rules engine through the proxy with real clients: every action,
//! precedence, the map-local jail, hot reload, the rules and pause-edit API, snapshots.

mod common;

use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use bytes::Bytes;
use common::*;
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use wirust::control::ControlPlane;
use wirust::events::FlowEvent;
use wirust::flow::{Exchange, Flag};
use wirust::rules::{Rules, RulesFile};
use wirust::{Proxy, RemoteAccess};

struct Setup {
    running: Running,
    /// The HTTPS upstream's port.
    port: u16,
    rules: Rules,
}

fn rules_from(toml: &str) -> anyhow::Result<Rules> {
    let file: RulesFile = toml::from_str(toml)?;
    let rules = Rules::new();
    rules.replace(&file).map_err(anyhow::Error::msg)?;
    Ok(rules)
}

async fn start(rules: Rules) -> anyhow::Result<Setup> {
    let certs = upstream_certs()?;
    let port = https_server(&certs).await?;
    let mut config = test_config(&certs.ca, 64 * 1024)?;
    for stage in rules.interceptors(&config.pauses) {
        config.interceptors.push(stage);
    }
    let dir = config.config_dir.clone();
    Ok(Setup {
        running: spawn(Proxy::bind(config).await?, dir),
        port,
        rules,
    })
}

impl Setup {
    async fn get(&self, path: &str) -> anyhow::Result<(StatusCode, String)> {
        let (status, body) = request(&self.running, self.port, b"http/1.1", path, b"").await?;
        Ok((status, String::from_utf8_lossy(&body).into_owned()))
    }

    async fn exchange(&mut self) -> anyhow::Result<Exchange> {
        next_exchange(&mut self.running.events).await
    }
}

fn rule(name: &str) -> Flag {
    Flag::Rule(name.to_owned())
}

#[tokio::test]
async fn rules_run_in_order_and_an_answer_stops_the_chain() -> TestResult {
    let mut setup = start(rules_from(
        r#"
[[rules]]
name = "tag"
action = { type = "rewrite_headers", set = { "x-added" = "by-rule" } }

[[rules]]
name = "off"
enabled = false
match = { path = "/headers" }
action = { type = "block", status = 500 }

[[rules]]
name = "block"
match = { path = "/blocked*", method = ["GET"] }
action = { type = "block", status = 418, body = "nope" }

[[rules]]
name = "never"
match = { path = "/blocked" }
action = { type = "block", status = 403 }
"#,
    )?)
    .await?;
    assert_eq!(
        setup.get("/headers").await?,
        (StatusCode::OK, "by-rule|abc".to_owned())
    );
    assert_eq!(setup.exchange().await?.flags, [rule("tag")]);
    assert_eq!(
        setup.get("/blocked").await?,
        (StatusCode::IM_A_TEAPOT, "nope".to_owned())
    );
    let record = setup.exchange().await?;
    assert_eq!(
        record.flags,
        [rule("tag"), rule("block"), Flag::Responded],
        "`never` must not run"
    );
    Ok(())
}

#[tokio::test]
async fn response_rules_change_status_headers_and_bodies() -> TestResult {
    let mut setup = start(rules_from(
        r#"
[[rules]]
name = "status"
match = { path = "/s", status = 200 }
action = { type = "status", status = 201 }

[[rules]]
name = "body"
match = { path = "/b", header = { name = "x-test", value = "^1$" } }
action = { type = "rewrite_body", phase = "response", replace = [{ regex = "hello", with = "bye" }] }

[[rules]]
name = "json"
match = { path = "/echo" }
action = { type = "rewrite_body", json_set = [{ path = "user.name", value = "rule" }] }
"#,
    )?)
    .await?;
    assert_eq!(setup.get("/s").await?.0, StatusCode::CREATED);
    assert_eq!(setup.exchange().await?.flags, [rule("status")]);
    assert_eq!(setup.get("/b").await?.1, "bye from /b");
    assert_eq!(setup.exchange().await?.status, Some(200));
    let (_, body) = request(
        &setup.running,
        setup.port,
        b"h2",
        "/echo",
        br#"{"user":{"id":1}}"#,
    )
    .await?;
    let body: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(body, serde_json::json!({"user": {"id": 1, "name": "rule"}}));
    Ok(())
}

#[tokio::test]
async fn delay_and_throttle_slow_the_exchange_down() -> TestResult {
    let mut setup = start(rules_from(
        r#"
[[rules]]
name = "slow"
match = { path = "/d" }
action = { type = "delay", ms = 150 }

[[rules]]
name = "narrow"
match = { path = "/big" }
action = { type = "throttle", bytes_per_second = 10000, latency_ms = 20 }
"#,
    )?)
    .await?;
    let started = Instant::now();
    setup.get("/d").await?;
    assert!(started.elapsed() >= Duration::from_millis(150));
    assert_eq!(setup.exchange().await?.flags, [rule("slow")]);
    // 3000 bytes at 10 000 B/s after 20 ms: about 320 ms.
    let started = Instant::now();
    let (_, body) = setup.get("/big").await?;
    let elapsed = started.elapsed();
    assert_eq!(body.len(), BIG);
    assert!(
        elapsed >= Duration::from_millis(280) && elapsed < Duration::from_millis(900),
        "took {elapsed:?}"
    );
    Ok(())
}

#[tokio::test]
async fn map_remote_sends_the_request_elsewhere_and_records_both_urls() -> TestResult {
    let plain = http_server().await?;
    let mut setup = start(rules_from(&format!(
        r#"
[[rules]]
name = "remote"
match = {{ path = "/old/*" }}
action = {{ type = "map_remote", scheme = "http", host = "127.0.0.1", port = {plain}, path_from = "/old", path_to = "/new" }}
"#
    ))?)
    .await?;
    assert_eq!(setup.get("/old/x?q=1").await?.1, "hello from /new/x");
    let record = setup.exchange().await?;
    assert_eq!(record.flags, [rule("remote"), Flag::MapRemote]);
    assert!(
        record.url.starts_with("https://localhost:"),
        "{}",
        record.url
    );
    assert_eq!(
        record.upstream_url.as_deref(),
        Some(format!("http://127.0.0.1:{plain}/new/x?q=1").as_str())
    );
    Ok(())
}

/// A served directory, a secret next to it and a symlink from inside to the secret.
fn jail() -> anyhow::Result<std::path::PathBuf> {
    let base = temp_dir();
    let root = base.join("www");
    std::fs::create_dir_all(root.join("sub"))?;
    std::fs::write(root.join("index.html"), "<h1>home</h1>")?;
    std::fs::write(root.join("sub").join("data.json"), "{\"ok\":true}")?;
    std::fs::write(base.join("secret.txt"), "SECRET")?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(base.join("secret.txt"), root.join("link"))?;
    Ok(base)
}

#[tokio::test]
async fn map_local_serves_files_and_never_leaves_its_root() -> TestResult {
    let base = jail()?;
    let root = base.join("www");
    let mut setup = start(rules_from(&format!(
        r#"
[[rules]]
name = "local"
match = {{ path = "/static/*" }}
action = {{ type = "map_local", path = {root:?}, strip_prefix = "/static" }}

[[rules]]
name = "file"
match = {{ path = "/one" }}
action = {{ type = "map_local", path = {file:?} }}
"#,
        root = root.display().to_string(),
        file = root.join("index.html").display().to_string(),
    ))?)
    .await?;
    assert_eq!(
        setup.get("/static/").await?,
        (StatusCode::OK, "<h1>home</h1>".to_owned())
    );
    let record = setup.exchange().await?;
    assert_eq!(record.flags, [rule("local"), Flag::Responded]);
    assert!(
        record
            .response_headers
            .iter()
            .any(|(n, v)| n == "content-type" && v.starts_with("text/html"))
    );
    assert_eq!(
        setup.get("/static/sub/data.json?x=1").await?.1,
        "{\"ok\":true}"
    );
    assert_eq!(setup.get("/static/sub").await?.0, StatusCode::NOT_FOUND);
    assert_eq!(setup.get("/one").await?.1, "<h1>home</h1>");
    let refused = [
        ("/static/../secret.txt", StatusCode::BAD_REQUEST),
        ("/static/%2e%2e/secret.txt", StatusCode::BAD_REQUEST),
        ("/static/%2E%2E%2Fsecret.txt", StatusCode::BAD_REQUEST),
        ("/static/sub/..%2f..%2fsecret.txt", StatusCode::BAD_REQUEST),
        ("/static/..%5csecret.txt", StatusCode::BAD_REQUEST),
        (
            "/static/sub%5c..%5c..%5csecret.txt",
            StatusCode::BAD_REQUEST,
        ),
        ("/static/C:%5csecret.txt", StatusCode::BAD_REQUEST),
        ("/static/%00", StatusCode::BAD_REQUEST),
        ("/static/%zz", StatusCode::BAD_REQUEST),
        ("/static/./index.html", StatusCode::BAD_REQUEST),
        // Absolute segments land inside the root: there is no /etc there.
        ("/static//etc/passwd", StatusCode::NOT_FOUND),
        ("/static/%2fetc%2fpasswd", StatusCode::NOT_FOUND),
        #[cfg(unix)]
        ("/static/link", StatusCode::NOT_FOUND),
    ];
    for (path, want) in refused {
        let (status, body) = setup.get(path).await?;
        assert_eq!(status, want, "{path}");
        assert!(!body.contains("SECRET"), "{path} leaked the secret");
    }
    let _ = std::fs::remove_dir_all(base);
    Ok(())
}

async fn wait_for(what: &str, mut done: impl FnMut() -> bool) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !done() {
        anyhow::ensure!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(())
}

fn write_rules(path: &Path, text: &str) -> anyhow::Result<()> {
    // A distinct mtime even on file systems with coarse timestamps.
    let before = std::fs::metadata(path).and_then(|m| m.modified()).ok();
    std::fs::write(path, text)?;
    if let Some(before) = before
        && std::fs::metadata(path)?.modified()? == before
    {
        let later = before + Duration::from_secs(1);
        std::fs::File::options()
            .write(true)
            .open(path)?
            .set_modified(later)?;
    }
    Ok(())
}

#[tokio::test]
async fn the_file_is_reloaded_and_a_broken_one_keeps_the_previous_rules() -> TestResult {
    let dir = temp_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("rules.toml");
    let block = |status: u16| {
        format!("[[rules]]\nname = \"b\"\naction = {{ type = \"block\", status = {status} }}\n")
    };
    write_rules(&path, &block(451))?;
    let rules = Rules::from_file(&path)?;
    let watcher = rules.watch(Duration::from_millis(30));
    let setup = start(rules.clone()).await?;
    assert_eq!(
        setup.get("/").await?.0,
        StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
    );

    write_rules(
        &path,
        "[[rules]]\nname = \"b\"\naction = { type = \"block\", status = ",
    )?;
    wait_for("the load error", || rules.report().error.is_some()).await?;
    assert_eq!(
        setup.get("/").await?.0,
        StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
    );
    write_rules(&path, &block(429))?;
    wait_for("the reload", || rules.report().error.is_none()).await?;
    assert_eq!(setup.get("/").await?.0, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(rules.report().file.as_deref(), Some(path.as_path()));
    watcher.abort();
    drop(setup);
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

#[tokio::test]
async fn an_exchange_keeps_the_rules_it_started_with() -> TestResult {
    let body_rule = |with: &str| {
        format!(
            "[[rules]]\nname = \"say\"\naction = {{ type = \"rewrite_body\", phase = \"response\", \
             replace = [{{ regex = \"hello\", with = \"{with}\" }}] }}\n"
        )
    };
    let first = format!(
        "[[rules]]\nname = \"wait\"\nmatch = {{ path = \"/slow\" }}\n\
         action = {{ type = \"delay\", ms = 300 }}\n{}",
        body_rule("one")
    );
    let setup = start(rules_from(&first)?).await?;
    let slow = {
        let (running_addr, ca_pem, port) =
            (setup.running.addr, setup.running.ca_pem.clone(), setup.port);
        tokio::spawn(async move {
            let client = Running {
                addr: running_addr,
                ca_pem,
                events: wirust::events::Bus::new().subscribe(),
                dir: temp_dir(),
            };
            request(&client, port, b"http/1.1", "/slow", b"").await
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let second: RulesFile = toml::from_str(&body_rule("two"))?;
    setup.rules.replace(&second).map_err(anyhow::Error::msg)?;
    assert_eq!(setup.get("/fast").await?.1, "two from /fast");
    let (_, body) = slow.await??;
    assert_eq!(body, Bytes::from_static(b"one from /slow"));
    Ok(())
}

/// One request to the control plane with the token.
async fn api(
    addr: SocketAddr,
    token: &str,
    method: Method,
    path: &str,
    body: &str,
) -> anyhow::Result<(StatusCode, serde_json::Value)> {
    let tcp = TcpStream::connect(addr).await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(connection);
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", addr.to_string())
        .header("authorization", format!("Bearer {token}"))
        .body(Full::new(Bytes::from(body.to_owned())))?;
    let response = sender.send_request(request).await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&bytes)?))
}

const BREAK_HEADERS: &str = r#"
[[rules]]
name = "stop"
match = { path = "/headers" }
action = { type = "breakpoint" }
"#;

/// A proxy with `rules` and a control plane serving them: (proxy, upstream port, API
/// address, token).
async fn start_ui(rules: &Rules) -> anyhow::Result<(Running, u16, SocketAddr, String)> {
    let certs = upstream_certs()?;
    let port = https_server(&certs).await?;
    let mut config = test_config(&certs.ca, 1024)?;
    for stage in rules.interceptors(&config.pauses) {
        config.interceptors.push(stage);
    }
    let dir = config.config_dir.clone();
    let mut proxy = Proxy::bind(config).await?;
    let control = ControlPlane::bind(
        "127.0.0.1:0".parse()?,
        RemoteAccess::LoopbackOnly,
        &mut proxy,
    )
    .await?;
    control.set_rules(rules.clone());
    let (addr, token) = (control.local_addr(), control.token().to_owned());
    tokio::spawn(control.run());
    Ok((spawn(proxy, dir), port, addr, token))
}

#[tokio::test]
async fn breakpoints_publish_events_and_take_validated_edits() -> TestResult {
    let rules = rules_from(BREAK_HEADERS)?;
    let (mut running, port, addr, token) = start_ui(&rules).await?;
    let client = Running {
        addr: running.addr,
        ca_pem: running.ca_pem.clone(),
        events: wirust::events::Bus::new().subscribe(),
        dir: temp_dir(),
    };
    let pending =
        tokio::spawn(async move { request(&client, port, b"http/1.1", "/headers", b"").await });
    let paused = loop {
        if let FlowEvent::Paused(paused) = next_bus_event(&mut running.events).await? {
            break paused;
        }
    };
    let json = serde_json::to_value(FlowEvent::Paused(paused.clone()))?;
    assert_eq!(json["event"], "paused");
    assert_eq!(json["flow"]["type"], "paused");
    assert_eq!(json["flow"]["phase"], "request");
    let id = paused.pause_id;
    let (status, list) = api(addr, &token, Method::GET, "/api/v1/pauses", "").await?;
    assert_eq!((status, list[0]["id"].as_u64()), (StatusCode::OK, Some(id)));

    let edit = format!("/api/v1/pauses/{id}/edit");
    for bad in [
        r#"{"set_headers":{"x-added":"a\r\nx-evil: 1"}}"#,
        r#"{"set_headers":{"x added":"a"}}"#,
        r#"{"status":200}"#,
        r#"{"url":"javascript:alert(1)"}"#,
        "{",
    ] {
        let (status, _) = api(addr, &token, Method::POST, &edit, bad).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let (status, _) = api(addr, &token, Method::GET, &edit, "").await?;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    let (_, list) = api(addr, &token, Method::GET, "/api/v1/pauses", "").await?;
    assert_eq!(list.as_array().map(Vec::len), Some(1), "still pending");
    let big = format!(r#"{{"body":"{}"}}"#, "x".repeat(2 * 1024 * 1024));
    let (status, _) = api(addr, &token, Method::POST, &edit, &big)
        .await
        .unwrap_or((StatusCode::PAYLOAD_TOO_LARGE, serde_json::Value::Null));
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    let good = r#"{"set_headers":{"x-added":"edited"},"remove_headers":["x-req"]}"#;
    let (status, _) = api(addr, &token, Method::POST, &edit, good).await?;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = pending.await??;
    assert_eq!(body, Bytes::from_static(b"edited|-"));
    let resumed = loop {
        if let FlowEvent::Resumed(resumed) = next_bus_event(&mut running.events).await? {
            break resumed;
        }
    };
    assert_eq!(resumed.resolution, Some("edit"));
    Ok(())
}

#[tokio::test]
async fn the_rules_api_lists_toggles_and_replaces_atomically() -> TestResult {
    let rules = rules_from(BREAK_HEADERS)?;
    let (_running, _, addr, token) = start_ui(&rules).await?;
    let (status, report) = api(addr, &token, Method::GET, "/api/v1/rules", "").await?;
    assert_eq!(
        (status, &report["rules"][0]["name"]),
        (StatusCode::OK, &"stop".into())
    );
    let (status, toggled) =
        api(addr, &token, Method::POST, "/api/v1/rules/stop/toggle", "").await?;
    assert_eq!(
        (status, &toggled["enabled"]),
        (StatusCode::OK, &false.into())
    );
    let (status, _) = api(addr, &token, Method::POST, "/api/v1/rules/none/toggle", "").await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = api(addr, &token, Method::POST, "/api/v1/rules", "{}").await?;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    let broken = r#"{"rules":[{"name":"x","match":{"path_regex":"("},"action":{"type":"block"}}]}"#;
    let (status, error) = api(addr, &token, Method::PUT, "/api/v1/rules", broken).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(error["error"].as_str().is_some_and(|e| e.contains("regex")));
    assert_eq!(rules.current().len(), 1, "a refused set changes nothing");
    let fine = r#"{"rules":[{"name":"t","action":{"type":"block","status":409}}]}"#;
    let (status, _) = api(addr, &token, Method::PUT, "/api/v1/rules", fine).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rules.report().rules[0].name, "t");
    Ok(())
}
