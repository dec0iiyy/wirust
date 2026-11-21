//! `--script`: every example in docs/scripting.md through the real proxy against a local
//! origin, the client info over HTTPS, and the sandbox: limits, forbidden features, errors
//! that fail open, hot reload and the log.

mod common;

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use common::*;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use wirust::flow::{Exchange, Flag};
use wirust::intercept::{Action, RequestCtx};
use wirust::script::Scripts;
use wirust::{Config, Proxy};

const DOC: &str = include_str!("../../../docs/scripting.md");

/// The code of the example named `name` in docs/scripting.md.
fn example(name: &str) -> String {
    let marker = format!("<!-- example: {name} -->\n```rhai\n");
    let start = DOC.find(&marker).expect("example in the doc") + marker.len();
    let end = DOC[start..].find("\n```").expect("closed code block");
    DOC[start..=start + end].to_owned()
}

/// A directory for script files, removed on drop.
struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }

    fn write(&self, name: &str, code: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, code).expect("script written");
        path
    }

    /// Rewrites `name` and moves its modification time forward, so a reload sees a change
    /// whatever the file system's timestamp resolution.
    fn rewrite(&self, name: &str, code: &str, step: u64) {
        let path = self.0.join(name);
        let mut file = std::fs::File::create(&path).expect("script opened");
        file.write_all(code.as_bytes()).expect("script written");
        let time = SystemTime::now() + Duration::from_secs(step);
        file.set_modified(time).expect("mtime set");
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(data).expect("gzip");
    encoder.finish().expect("gzip")
}

async fn origin_respond(request: Request<Incoming>) -> anyhow::Result<Response<Full<Bytes>>> {
    let path = request.uri().path().to_owned();
    let response = Response::builder();
    Ok(match path.as_str() {
        "/headers" => {
            let added = (request.headers().get("x-added"))
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-")
                .to_owned();
            response.body(Full::new(Bytes::from(added)))?
        }
        "/json" => response
            .header("content-type", "application/json")
            .header("content-encoding", "gzip")
            .body(Full::new(Bytes::from(gzip(
                br#"{"name":"thing","price":10}"#,
            ))))?,
        "/big" => response.body(Full::new(Bytes::from(vec![b'x'; 100_000])))?,
        "/fail" => response
            .status(500)
            .body(Full::new(Bytes::from_static(b"down")))?,
        _ => response.body(Full::new(Bytes::from(format!("hello from {path}"))))?,
    })
}

/// A plain HTTP origin on 127.0.0.1; returns its port.
async fn origin() -> anyhow::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), service_fn(origin_respond)),
            );
        }
    });
    Ok(port)
}

struct Setup {
    running: Running,
    scripts: Scripts,
    origin: u16,
    _dir: Dir,
}

async fn start(code: &str) -> anyhow::Result<Setup> {
    let dir = Dir::new();
    let path = dir.write("test.rhai", code);
    let scripts = Scripts::load(&[path], 64 * 1024)?;
    let mut config = Config {
        listen: "127.0.0.1:0".parse()?,
        body_limit: 64 * 1024,
        ..Config::new(temp_dir())
    };
    for stage in scripts.interceptors() {
        config.interceptors.push(stage);
    }
    let config_dir = config.config_dir.clone();
    Ok(Setup {
        running: spawn(Proxy::bind(config).await?, config_dir),
        scripts,
        origin: origin().await?,
        _dir: dir,
    })
}

/// Sends `method url` through the plain-HTTP proxy at `proxy`.
async fn send(
    proxy: SocketAddr,
    method: Method,
    url: &str,
) -> anyhow::Result<(StatusCode, HeaderMap, String)> {
    let tcp = TcpStream::connect(proxy).await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(connection);
    let uri: http::Uri = url.parse()?;
    let host = uri.authority().map(ToString::to_string).unwrap_or_default();
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", host)
        .body(Full::new(Bytes::from_static(b"payload")))?;
    let response = sender.send_request(request).await?;
    let (parts, body) = response.into_parts();
    let body = body.collect().await?.to_bytes();
    Ok((
        parts.status,
        parts.headers,
        String::from_utf8_lossy(&body).into_owned(),
    ))
}

impl Setup {
    async fn get(&self, path: &str) -> anyhow::Result<(StatusCode, HeaderMap, String)> {
        let url = format!("http://127.0.0.1:{}{path}", self.origin);
        send(self.running.addr, Method::GET, &url).await
    }

    async fn exchange(&mut self) -> anyhow::Result<Exchange> {
        next_exchange(&mut self.running.events).await
    }
}

fn script_flag(name: &str) -> Flag {
    Flag::Script(name.to_owned())
}

#[tokio::test]
async fn example_add_header_sets_a_request_header() -> TestResult {
    let mut setup = start(&example("add-header")).await?;
    let (status, _, body) = setup.get("/headers").await?;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "by-script"));
    assert!(!setup.exchange().await?.flags.contains(&Flag::ScriptError));
    Ok(())
}

#[tokio::test]
async fn example_mock_json_answers_without_the_server() -> TestResult {
    let mut setup = start(&example("mock-json")).await?;
    let (status, headers, body) = setup.get("/api/user").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-type"], "application/json");
    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(json, serde_json::json!({"name": "mock", "id": 7}));
    assert!(setup.exchange().await?.flags.contains(&Flag::Responded));
    let (_, _, body) = setup.get("/other").await?;
    assert_eq!(body, "hello from /other", "other paths reach the server");
    Ok(())
}

#[tokio::test]
async fn example_rewrite_json_edits_a_gzip_response_and_sends_identity() -> TestResult {
    let setup = start(&example("rewrite-json")).await?;
    let (status, headers, body) = setup.get("/json").await?;
    assert_eq!(status, StatusCode::OK);
    assert!(headers.get("content-encoding").is_none(), "{headers:?}");
    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(json, serde_json::json!({"name": "thing", "price": 0}));
    assert_eq!(headers["content-length"], body.len().to_string());
    Ok(())
}

#[tokio::test]
async fn example_block_host_blocks_the_host_and_subdomains() -> TestResult {
    let setup = start(&example("block-host")).await?;
    for url in ["http://ads.example/x", "http://a.tracker.example/"] {
        let (status, _, _) = send(setup.running.addr, Method::GET, url).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{url}");
    }
    let (status, _, _) = setup.get("/fine").await?;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn example_delay_slows_down_one_path() -> TestResult {
    let setup = start(&example("delay")).await?;
    let started = Instant::now();
    let (status, _, _) = setup.get("/slow/a").await?;
    assert_eq!(status, StatusCode::OK);
    assert!(started.elapsed() >= Duration::from_millis(300));
    Ok(())
}

#[tokio::test]
async fn example_tag_flags_flows_in_both_hooks_and_logs() -> TestResult {
    let mut setup = start(&example("tag")).await?;
    let url = format!("http://127.0.0.1:{}/fail?debug=1", setup.origin);
    let (status, _, _) = send(setup.running.addr, Method::POST, &url).await?;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let flags = setup.exchange().await?.flags;
    for name in ["post", "debug", "server-error"] {
        assert!(flags.contains(&script_flag(name)), "{name} in {flags:?}");
    }
    let log = setup.scripts.log_after(0);
    assert_eq!(log.len(), 1, "{log:?}");
    assert_eq!(log[0].file, "test.rhai");
    assert_eq!(log[0].level, "log");
    assert_eq!(log[0].text, format!("debug request to {url}"));
    Ok(())
}

#[test]
fn every_doc_example_has_a_test() {
    let names: Vec<&str> = DOC
        .match_indices("<!-- example: ")
        .map(|(at, marker)| {
            let rest = &DOC[at + marker.len()..];
            &rest[..rest.find(" -->").expect("closed marker")]
        })
        .collect();
    assert_eq!(
        names,
        [
            "add-header",
            "mock-json",
            "rewrite-json",
            "block-host",
            "delay",
            "tag"
        ]
    );
}

#[tokio::test]
async fn https_requests_show_the_client_ja4() -> TestResult {
    let certs = upstream_certs()?;
    let port = https_server(&certs).await?;
    let dir = Dir::new();
    let path = dir.write(
        "ja4.rhai",
        r#"fn on_request(req) { req.headers.set("x-added", req.client.ja4 + "/" + req.scheme); }"#,
    );
    let scripts = Scripts::load(&[path], 64 * 1024)?;
    let mut config = test_config(&certs.ca, 64 * 1024)?;
    for stage in scripts.interceptors() {
        config.interceptors.push(stage);
    }
    let config_dir = config.config_dir.clone();
    let running = spawn(Proxy::bind(config).await?, config_dir);
    let (_, body) = request(&running, port, b"http/1.1", "/headers", b"").await?;
    let body = String::from_utf8_lossy(&body);
    let (ja4, scheme) = body.split_once('|').map_or(("", ""), |(added, _)| {
        added.rsplit_once('/').unwrap_or(("", ""))
    });
    assert!(ja4.starts_with("t13"), "{body}");
    assert_eq!(scheme, "https");
    Ok(())
}

// ---------------------------------------------------------------------------------------
// The sandbox, called directly on a request context.
// ---------------------------------------------------------------------------------------

fn ctx() -> RequestCtx {
    RequestCtx {
        id: 1,
        client: SocketAddr::from(([127, 0, 0, 1], 5000)),
        scheme: "http",
        host: "example.test".to_owned(),
        port: 80,
        method: Method::GET,
        path: "/a?b=1".to_owned(),
        headers: HeaderMap::new(),
        body: None,
        flags: Vec::new(),
        extensions: http::Extensions::new(),
    }
}

fn load(dir: &Dir, code: &str) -> anyhow::Result<Scripts> {
    Scripts::load(&[dir.write("s.rhai", code)], 64 * 1024)
}

/// Runs `on_request` of the only script; returns the request, the action and the elapsed time.
fn run(scripts: &Scripts) -> (RequestCtx, Action, Duration) {
    let stage = scripts.interceptors().pop().expect("one stage");
    let mut request = ctx();
    let started = Instant::now();
    let action = stage.on_request(&mut request);
    (request, action, started.elapsed())
}

/// Asserts that the script failed open: no change, `script_error`, the error recorded.
fn assert_fails_open(code: &str, error_part: &str) -> TestResult {
    let dir = Dir::new();
    let scripts = load(&dir, code)?;
    let (request, action, elapsed) = run(&scripts);
    assert!(matches!(action, Action::Continue), "{action:?}");
    assert_eq!(request.flags, [Flag::ScriptError]);
    assert!(request.headers.is_empty(), "changes are dropped");
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    let report = scripts.report();
    let error = report[0].error.clone().unwrap_or_default();
    assert!(error.contains(error_part), "{error}");
    assert!(
        !error.contains(&*dir.0.to_string_lossy()),
        "no directory: {error}"
    );
    Ok(())
}

#[test]
fn an_infinite_loop_is_stopped() -> TestResult {
    assert_fails_open(
        r#"fn on_request(req) { req.headers.set("x", "y"); loop { } }"#,
        "on_request",
    )
}

#[test]
fn a_slow_loop_hits_the_operation_or_time_limit() -> TestResult {
    assert_fails_open(
        r#"fn on_request(req) { req.headers.set("x", "y"); let s = 0; while true { s += "abc".len(); } }"#,
        "on_request",
    )
}

#[test]
fn deep_recursion_is_stopped() -> TestResult {
    assert_fails_open(
        r#"fn down(n) { down(n + 1) } fn on_request(req) { req.headers.set("x", "y"); down(0); }"#,
        "on_request",
    )
}

#[test]
fn huge_strings_are_stopped() -> TestResult {
    assert_fails_open(
        r#"fn on_request(req) { req.headers.set("x", "y"); let s = "xxxxxxxx"; loop { s += s; } }"#,
        "on_request",
    )
}

#[test]
fn huge_arrays_are_stopped() -> TestResult {
    assert_fails_open(
        r#"fn on_request(req) { req.headers.set("x", "y"); let a = [0]; loop { a += a; } }"#,
        "on_request",
    )
}

#[test]
fn unknown_functions_and_runtime_errors_fail_open() -> TestResult {
    assert_fails_open(
        r#"fn on_request(req) { req.headers.set("x", "y"); open_file("/etc/passwd"); }"#,
        "open_file",
    )?;
    assert_fails_open(
        r#"fn on_request(req) { req.headers.set("x", "y"); throw "boom"; }"#,
        "boom",
    )?;
    assert_fails_open(
        r#"fn on_request(req) { req.headers.set("bad name", "y"); }"#,
        "invalid header name",
    )?;
    assert_fails_open("fn on_request(req) { block(1234); }", "invalid status")
}

#[test]
fn eval_import_and_syntax_errors_refuse_to_load() {
    let dir = Dir::new();
    for code in [
        r#"fn on_request(req) { eval("1") }"#,
        r#"import "x" as y; fn on_request(req) { }"#,
        "fn on_request(req) { let = ; }",
    ] {
        let error = load(&dir, code).expect_err(code).to_string();
        assert!(error.starts_with("s.rhai: "), "{error}");
        assert!(!error.contains(&*dir.0.to_string_lossy()), "{error}");
    }
}

#[test]
fn an_error_is_logged_once_per_distinct_message() -> TestResult {
    let dir = Dir::new();
    let scripts = load(&dir, r#"fn on_request(req) { throw "same"; }"#)?;
    for _ in 0..3 {
        let (request, _, _) = run(&scripts);
        assert_eq!(request.flags, [Flag::ScriptError]);
    }
    let log = scripts.log_after(0);
    assert_eq!(log.len(), 1, "{log:?}");
    assert_eq!((log[0].level, log[0].file.as_str()), ("error", "s.rhai"));
    Ok(())
}

#[test]
fn respond_short_circuits_with_status_headers_and_body() -> TestResult {
    let dir = Dir::new();
    let scripts = load(
        &dir,
        r#"fn on_request(req) { respond(418, #{ "x-from": "script" }, base64_decode("dGVh")); }"#,
    )?;
    let (_, action, _) = run(&scripts);
    let Action::Respond(response) = action else {
        panic!("expected a response, got {action:?}");
    };
    assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
    assert_eq!(response.headers()["x-from"], "script");
    assert_eq!(response.body(), &Bytes::from_static(b"tea"));
    Ok(())
}

#[test]
fn helpers_and_request_fields_work() -> TestResult {
    let dir = Dir::new();
    let scripts = load(
        &dir,
        r##"
fn on_request(req) {
    let h = req.headers;
    h.set("x-url", req.url);
    h.set("x-parts", `${req.host}|${req.port}|${req.path}|${req.query}|${req.client.address}`);
    h.set("x-regex", regex_replace("a1b22", "[0-9]+", "#") + regex_captures("k=v", "(\\w)=(\\w)")[2]);
    h.set("x-json", json_stringify(json_parse(`{"a":[1,true,null]}`)));
    h.set("x-b64", base64_encode("tea"));
    h.set("x-now", if now() > 1700000000000 { "ok" } else { "bad" });
    h.set("x-has", `${h.has("X-URL")}`);
    req.path = "/changed";
    req.query = "q=2";
    req.method = "PUT";
    flag("seen");
}
"##,
    )?;
    let (request, action, _) = run(&scripts);
    assert!(matches!(action, Action::Continue));
    let header = |name: &str| {
        request.headers[name]
            .to_str()
            .unwrap_or_default()
            .to_owned()
    };
    assert_eq!(header("x-url"), "http://example.test/a?b=1");
    assert_eq!(header("x-parts"), "example.test|80|/a|b=1|127.0.0.1:5000");
    assert_eq!(header("x-regex"), "a#b#v");
    assert_eq!(header("x-json"), r#"{"a":[1,true,null]}"#);
    assert_eq!(header("x-b64"), "dGVh");
    assert_eq!(header("x-now"), "ok");
    assert_eq!(header("x-has"), "true");
    assert_eq!(
        (request.method, request.path.as_str()),
        (Method::PUT, "/changed?q=2")
    );
    assert_eq!(request.flags, [script_flag("seen")]);
    Ok(())
}

#[test]
fn hot_reload_keeps_the_last_good_version() -> TestResult {
    let dir = Dir::new();
    let good =
        |value: &str| format!(r#"fn on_request(req) {{ req.headers.set("x-v", "{value}"); }}"#);
    let scripts = load(&dir, &good("1"))?;
    let version = |scripts: &Scripts| {
        let (request, _, _) = run(scripts);
        request.headers["x-v"]
            .to_str()
            .unwrap_or_default()
            .to_owned()
    };
    assert_eq!(version(&scripts), "1");

    dir.rewrite("s.rhai", "fn on_request(req) { let = ; }", 10);
    assert_eq!(scripts.reload_if_changed(), 0);
    assert_eq!(
        version(&scripts),
        "1",
        "the broken file keeps the old version"
    );
    let error = scripts.report()[0].error.clone().unwrap_or_default();
    assert!(error.contains("keeping the previous version"), "{error}");

    dir.rewrite("s.rhai", &good("2"), 20);
    assert_eq!(scripts.reload_if_changed(), 1);
    assert_eq!(version(&scripts), "2");
    assert_eq!(scripts.report()[0].error, None);
    assert_eq!(scripts.reload_if_changed(), 0, "no change, no reload");
    Ok(())
}

#[test]
fn wants_body_and_hooks_are_reported() -> TestResult {
    let dir = Dir::new();
    let scripts = load(
        &dir,
        "const WANTS_BODY = #{ response: true }; fn on_response(req, resp) { }",
    )?;
    let report = &scripts.report()[0];
    assert_eq!(report.file, "s.rhai");
    assert!(report.loaded && report.response.defined && report.response.body);
    assert!(!report.request.defined && !report.request.body);
    let stage = scripts.interceptors().pop().expect("one stage");
    assert!(stage.needs_response_body() && !stage.needs_request_body());
    Ok(())
}

#[tokio::test]
async fn a_looping_script_fails_open_through_the_proxy() -> TestResult {
    let mut setup = start("fn on_request(req) { loop { } }").await?;
    let (status, _, body) = setup.get("/still").await?;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::OK, "hello from /still")
    );
    assert!(setup.exchange().await?.flags.contains(&Flag::ScriptError));
    Ok(())
}

#[tokio::test]
async fn a_body_over_the_limit_streams_on_with_the_skip_flag() -> TestResult {
    let mut setup = start(
        r#"const WANTS_BODY = #{ response: true };
fn on_response(req, resp) { if resp.has_body { resp.body = "changed"; } }"#,
    )
    .await?;
    let (_, _, body) = setup.get("/big").await?;
    assert_eq!(body.len(), 100_000);
    let flags = setup.exchange().await?.flags;
    assert!(
        flags.contains(&Flag::RewriteSkippedBodyTooLarge),
        "{flags:?}"
    );
    let (_, _, body) = setup.get("/small").await?;
    assert_eq!(body, "changed");
    Ok(())
}

async fn api_get(addr: SocketAddr, token: &str, path: &str) -> anyhow::Result<serde_json::Value> {
    let tcp = TcpStream::connect(addr).await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(connection);
    let request = Request::builder()
        .uri(path)
        .header("host", addr.to_string())
        .header("authorization", format!("Bearer {token}"))
        .body(Full::new(Bytes::new()))?;
    let body = sender.send_request(request).await?.into_body();
    Ok(serde_json::from_slice(&body.collect().await?.to_bytes())?)
}

#[tokio::test]
async fn the_api_reports_file_names_and_the_log() -> TestResult {
    let dir = Dir::new();
    let path = dir.write("api.rhai", r#"fn on_request(req) { log("hi"); }"#);
    let scripts = Scripts::load(&[path], 1024)?;
    let mut config = Config {
        listen: "127.0.0.1:0".parse()?,
        ..Config::new(temp_dir())
    };
    for stage in scripts.interceptors() {
        config.interceptors.push(stage);
    }
    let config_dir = config.config_dir.clone();
    let mut proxy = Proxy::bind(config).await?;
    let control = wirust::control::ControlPlane::bind(
        "127.0.0.1:0".parse()?,
        wirust::RemoteAccess::LoopbackOnly,
        &mut proxy,
    )
    .await?;
    control.set_scripts(scripts.clone());
    let (addr, token) = (control.local_addr(), control.token().to_owned());
    tokio::spawn(control.run());
    let running = spawn(proxy, config_dir);
    let port = origin().await?;
    send(
        running.addr,
        Method::GET,
        &format!("http://127.0.0.1:{port}/"),
    )
    .await?;

    let report = api_get(addr, &token, "/api/v1/script").await?;
    assert_eq!(report["scripts"][0]["file"], "api.rhai");
    assert_eq!(report["scripts"][0]["loaded"], true);
    assert_eq!(report["scripts"][0]["request"]["defined"], true);
    assert!(!report.to_string().contains(&*dir.0.to_string_lossy()));
    let log = api_get(addr, &token, "/api/v1/script/log").await?;
    assert_eq!(log["entries"][0]["text"], "hi");
    assert_eq!(log["entries"][0]["seq"], 1);
    let later = api_get(addr, &token, "/api/v1/script/log?after=1").await?;
    assert_eq!(later["entries"], serde_json::json!([]));
    Ok(())
}
