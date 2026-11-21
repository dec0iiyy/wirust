//! The embedded web UI: every file in `crates/proxy/ui/` is served with the right content
//! type and a strict CSP, and no file uses an HTML sink, `eval` or an external URL.

mod common;

use std::net::SocketAddr;
use std::path::Path;

use bytes::Bytes;
use common::*;
use http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use wirust::control::ControlPlane;
use wirust::{Proxy, RemoteAccess};

/// Text that must never appear in a UI file: HTML sinks, dynamic code, remote resources.
const FORBIDDEN: &[&str] = &[
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
    "eval(",
    "new Function",
    "http://",
    "https://",
    "javascript:",
];

struct Ui {
    _proxy: Running,
    addr: SocketAddr,
    token: String,
}

async fn start_ui() -> anyhow::Result<Ui> {
    let certs = upstream_certs()?;
    let config = test_config(&certs.ca, 1024)?;
    let dir = config.config_dir.clone();
    let mut proxy = Proxy::bind(config).await?;
    let control = ControlPlane::bind(
        "127.0.0.1:0".parse()?,
        RemoteAccess::LoopbackOnly,
        &mut proxy,
    )
    .await?;
    let (addr, token) = (control.local_addr(), control.token().to_owned());
    tokio::spawn(control.run());
    Ok(Ui {
        _proxy: spawn(proxy, dir),
        addr,
        token,
    })
}

impl Ui {
    async fn get(&self, path: &str) -> anyhow::Result<(StatusCode, HeaderMap, Bytes)> {
        let tcp = TcpStream::connect(self.addr).await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
        tokio::spawn(connection);
        let request = Request::builder()
            .method(Method::GET)
            .uri(path)
            .header("host", self.addr.to_string())
            .header("authorization", format!("Bearer {}", self.token))
            .body(Full::new(Bytes::new()))?;
        let (parts, body) = sender.send_request(request).await?.into_parts();
        Ok((
            parts.status,
            parts.headers,
            body.collect().await?.to_bytes(),
        ))
    }
}

/// The UI files on disk with the path each is served at and its expected content type.
fn ui_files() -> anyhow::Result<Vec<(String, &'static str, String)>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("ui");
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        let content_type = match path.extension().and_then(|e| e.to_str()) {
            Some("html") => "text/html; charset=utf-8",
            Some("js") => "text/javascript; charset=utf-8",
            Some("css") => "text/css; charset=utf-8",
            other => anyhow::bail!("no expected content type for {name} ({other:?})"),
        };
        let served = if name == "index.html" {
            "/".to_owned()
        } else {
            format!("/{name}")
        };
        files.push((served, content_type, name));
    }
    files.sort();
    Ok(files)
}

#[tokio::test]
async fn every_ui_file_is_served_with_its_type_and_a_strict_csp() -> TestResult {
    let ui = start_ui().await?;
    let files = ui_files()?;
    assert!(files.len() >= 3, "{files:?}");
    for (path, content_type, name) in &files {
        let (status, headers, body) = ui.get(path).await?;
        assert_eq!(status, StatusCode::OK, "{name} is not in control::ASSETS");
        assert_eq!(headers["content-type"], *content_type, "{name}");
        assert_eq!(headers["x-content-type-options"], "nosniff", "{name}");
        let on_disk = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("ui").join(name))?;
        assert_eq!(&body[..], &on_disk[..], "{name}: the served copy is stale");
    }
    let (_, headers, _) = ui.get("/").await?;
    let csp = headers["content-security-policy"].to_str()?;
    for directive in [
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "frame-ancestors 'none'",
    ] {
        assert!(csp.contains(directive), "missing {directive:?} in {csp}");
    }
    assert!(!csp.contains("unsafe"), "{csp}");
    Ok(())
}

#[test]
fn ui_files_use_no_html_sinks_dynamic_code_or_remote_urls() -> TestResult {
    for (_, content_type, name) in ui_files()? {
        let text =
            std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("ui").join(&name))?;
        for needle in FORBIDDEN {
            assert!(!text.contains(needle), "{name} contains {needle:?}");
        }
        if content_type.starts_with("text/html") {
            let lower = text.to_ascii_lowercase();
            // Every script is an external file and nothing carries inline style or handlers.
            assert_eq!(
                lower.matches("<script").count(),
                lower.matches("<script src=\"/").count(),
                "{name} has an inline script"
            );
            assert!(!lower.contains(" style="), "{name} has an inline style");
            let handler = lower
                .split(|c: char| c.is_whitespace())
                .any(|word| word.starts_with("on") && word.contains('='));
            assert!(!handler, "{name} has an inline event handler");
        }
    }
    Ok(())
}

/// The source of `function NAME(...) { ... }` in `app.js`, up to its matching brace.
fn js_function<'a>(source: &'a str, name: &str) -> anyhow::Result<&'a str> {
    let start = source
        .find(&format!("function {name}("))
        .ok_or_else(|| anyhow::anyhow!("app.js has no function {name}"))?;
    let mut depth = 0_usize;
    for (offset, c) in source[start..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(&source[start..=start + offset]);
                }
            }
            _ => {}
        }
    }
    anyhow::bail!("function {name} in app.js is not closed")
}

/// Runs the row helpers of `app.js` in Node and checks them against the Rust side: the Proto
/// column must show what the terminal log shows (`Exchange::protocol`), and a passthrough
/// tunnel must give the Client column its known client and JA4 like a decrypted flow does.
/// Skipped, with a note, where Node is not installed (the CI runners have it).
#[test]
fn the_row_helpers_agree_with_the_log_and_name_passthrough_clients() -> TestResult {
    let node = std::process::Command::new("node").arg("--version").output();
    if node.is_err() {
        eprintln!("skipped: node is not installed");
        return Ok(());
    }
    let app = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("ui/app.js"))?;
    let helpers = format!(
        "{}\n{}\nreturn {{ protoLabel, tlsOf }};",
        js_function(&app, "protoLabel")?,
        js_function(&app, "tlsOf")?
    );
    let versions = [
        ("http/1.1", Some("http/1.1")),
        ("h2", Some("h2")),
        ("h2", Some("http/1.1")),
        ("http/1.1", Some("h2")),
        ("h2", None),
    ];
    let tunnel_tls = serde_json::json!({
        "sni": "a.test", "alpn_offered": ["h2", "http/1.1"], "ja4": "t13d1516h2_x_y",
        "ja3_hash": "z", "known_client": "Chrome 131",
    });
    let input = serde_json::json!({
        "exchanges": versions.iter()
            .map(|(client, server)| serde_json::json!({
                "client_version": client, "upstream_version": server,
            }))
            .collect::<Vec<_>>(),
        "tunnel": { "type": "tunnel", "tls": tunnel_tls },
        "plain_tunnel": { "type": "tunnel", "tls": null },
        "failure": { "type": "tls_failure", "sni": "b.test", "ja4": "t13d_f", "known_client": null },
    });
    let script = "const f = new Function(process.argv[1])(); const input = JSON.parse(process.argv[2]); \
        console.log(JSON.stringify({ protos: input.exchanges.map(f.protoLabel), \
        tunnel: f.tlsOf(input.tunnel), plain_tunnel: f.tlsOf(input.plain_tunnel), \
        failure: f.tlsOf(input.failure) }));";
    let output = std::process::Command::new("node")
        .args(["-e", script, &helpers, &input.to_string()])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "node failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let shown: serde_json::Value = serde_json::from_slice(&output.stdout)?;

    for (i, (client, server)) in versions.iter().enumerate() {
        let exchange: wirust::flow::Exchange = serde_json::from_value(serde_json::json!({
            "id": 1, "time": "2026-01-02T03:04:05Z", "client": "127.0.0.1:1", "method": "GET",
            "url": "https://example.test/", "client_version": client, "upstream_version": server,
            "status": null, "reason": null, "request_headers": [], "response_headers": [],
            "request_body": {"size": 0, "truncated": false, "encoding": "utf8", "data": ""},
            "response_body": null, "timing": {"total_ms": 1.0}, "tls": null, "error": null,
        }))?;
        assert_eq!(
            shown["protos"][i],
            exchange.protocol(),
            "the UI and the log disagree for client {client}, server {server:?}"
        );
    }
    assert_eq!(shown["tunnel"]["client"], "Chrome 131", "{shown}");
    assert_eq!(shown["tunnel"]["ja4"], "t13d1516h2_x_y", "{shown}");
    assert_eq!(shown["tunnel"]["alpn_offered"], tunnel_tls["alpn_offered"]);
    assert!(shown["plain_tunnel"].is_null(), "{shown}");
    assert_eq!(shown["failure"]["ja4"], "t13d_f", "{shown}");
    Ok(())
}

#[tokio::test]
async fn info_names_the_proxy_and_the_ca_fingerprint() -> TestResult {
    let ui = start_ui().await?;
    let (status, _, body) = ui.get("/api/v1/info").await?;
    assert_eq!(status, StatusCode::OK);
    let info: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(info["name"], wirust::NAME);
    assert_eq!(info["magic_host"], wirust::MAGIC_HOST);
    assert_eq!(info["listen_is_loopback"], true);
    assert!(
        info["version"].as_str().is_some_and(|v| !v.is_empty()),
        "{info}"
    );
    assert!(
        info["proxy_addr"]
            .as_str()
            .is_some_and(|a| a.parse::<SocketAddr>().is_ok()),
        "{info}"
    );
    assert!(
        info["session_file"].is_null() && info["rules_file"].is_null(),
        "{info}"
    );
    let fingerprint = info["ca_fingerprint_sha256"].as_str().unwrap_or_default();
    let pairs: Vec<&str> = fingerprint.split(':').collect();
    assert_eq!(pairs.len(), 32, "{fingerprint}");
    assert!(
        pairs
            .iter()
            .all(|p| p.len() == 2 && p.bytes().all(|c| c.is_ascii_hexdigit())),
        "{fingerprint}"
    );
    // Like every API route, it needs the token.
    let tcp = TcpStream::connect(ui.addr).await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(connection);
    let request = Request::builder()
        .uri("/api/v1/info")
        .header("host", ui.addr.to_string())
        .body(Full::new(Bytes::new()))?;
    assert_eq!(
        sender.send_request(request).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}

#[tokio::test]
async fn the_page_references_only_served_assets() -> TestResult {
    let ui = start_ui().await?;
    let (_, _, page) = ui.get("/").await?;
    let page = std::str::from_utf8(&page)?;
    let refs: Vec<&str> = page
        .split(['"', '\''])
        .filter(|s| s.starts_with('/') && s.len() > 1 && !s.contains(' '))
        .collect();
    assert!(
        refs.contains(&"/app.js") && refs.contains(&"/style.css") && refs.contains(&"/ws.js"),
        "{refs:?}"
    );
    for path in refs {
        let (status, ..) = ui.get(path).await?;
        assert_eq!(status, StatusCode::OK, "{path}");
    }
    Ok(())
}
