//! `--upstream-proxy` end to end: an in-process HTTP CONNECT proxy and SOCKS5 server stand
//! in for a corporate proxy. They send every tunnel to `127.0.0.1:<target port>`, so the
//! target names (`origin.test`, `192.0.2.10`) never leave the machine. Loopback only.

mod common;

use std::sync::{Arc, Mutex};

use common::{TestResult, connect_head, http_server, next_exchange, spawn, test_config};
use common::{https_server, tunnel_to, upstream_certs};
use http::{Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use wirust::flow::{Exchange, Flag};
use wirust::passthrough::{Lists, Passthrough};
use wirust::upstream_proxy::UpstreamProxy;
use wirust::{Config, Proxy, UpstreamTls};

const USER: &str = "alice";
const PASSWORD: &str = "hunter2-very-secret";
/// `alice:hunter2-very-secret` in base64, as the proxy sees it.
const BASIC: &str = "Basic YWxpY2U6aHVudGVyMi12ZXJ5LXNlY3JldA==";

/// What the fake proxies saw: one line per tunnel or request.
type Log = Arc<Mutex<Vec<String>>>;

async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<String> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await?);
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

fn target_port(authority: &str) -> Option<u16> {
    authority.rsplit_once(':')?.1.parse().ok()
}

/// An HTTP proxy: `CONNECT` tunnels and absolute-form requests, answered with `refuse`
/// when set, `407` when `auth` is set and the request lacks it.
async fn http_proxy(auth: Option<&'static str>, refuse: Option<u16>) -> anyhow::Result<(u16, Log)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let log: Log = Arc::default();
    let seen = Arc::clone(&log);
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let Ok(head) = read_head(&mut client).await else {
                    return;
                };
                let mut words = head.split_whitespace();
                let (method, target) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
                let authorized = auth.is_none_or(|auth| {
                    head.lines()
                        .any(|l| l.eq_ignore_ascii_case(&format!("proxy-authorization: {auth}")))
                });
                seen.lock()
                    .expect("log")
                    .push(format!("{method} {target} auth={authorized}"));
                let status = refuse.or((!authorized).then_some(407));
                if let Some(status) = status {
                    let answer = format!("HTTP/1.1 {status} No\r\nContent-Length: 0\r\n\r\n");
                    let _ = client.write_all(answer.as_bytes()).await;
                    return;
                }
                let authority = target.strip_prefix("http://").unwrap_or(target);
                let authority = authority.split('/').next().unwrap_or("");
                let Some(port) = target_port(authority) else {
                    return;
                };
                let Ok(mut server) = TcpStream::connect(("127.0.0.1", port)).await else {
                    return;
                };
                if method == "CONNECT" {
                    let _ = client
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await;
                } else {
                    let _ = server.write_all(head.as_bytes()).await;
                }
                let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
            });
        }
    });
    Ok((port, log))
}

/// A SOCKS5 server: user/password auth when `auth` is set, then `reply` (0 = success).
async fn socks5_server(
    auth: Option<(&'static str, &'static str)>,
    reply: u8,
) -> anyhow::Result<(u16, Log)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let log: Log = Arc::default();
    let seen = Arc::clone(&log);
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let _ = socks5_session(&mut client, auth, reply, &seen).await;
            });
        }
    });
    Ok((port, log))
}

async fn socks5_session(
    client: &mut TcpStream,
    auth: Option<(&str, &str)>,
    reply: u8,
    seen: &Log,
) -> anyhow::Result<()> {
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).await?;
    let mut methods = vec![0u8; usize::from(greeting[1])];
    client.read_exact(&mut methods).await?;
    if let Some((user, password)) = auth {
        if !methods.contains(&2) {
            client.write_all(&[5, 0xFF]).await?;
            return Ok(());
        }
        client.write_all(&[5, 2]).await?;
        let mut header = [0u8; 2];
        client.read_exact(&mut header).await?;
        let mut got_user = vec![0u8; usize::from(header[1])];
        client.read_exact(&mut got_user).await?;
        let mut got_password = vec![0u8; usize::from(client.read_u8().await?)];
        client.read_exact(&mut got_password).await?;
        let ok = got_user == user.as_bytes() && got_password == password.as_bytes();
        client.write_all(&[1, u8::from(!ok)]).await?;
        if !ok {
            seen.lock().expect("log").push("login rejected".to_owned());
            return Ok(());
        }
    } else {
        client.write_all(&[5, 0]).await?;
    }
    let mut request = [0u8; 4];
    client.read_exact(&mut request).await?;
    let host = match request[3] {
        1 => {
            let mut ip = [0u8; 4];
            client.read_exact(&mut ip).await?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let mut name = vec![0u8; usize::from(client.read_u8().await?)];
            client.read_exact(&mut name).await?;
            String::from_utf8(name)?
        }
        other => anyhow::bail!("address type {other}"),
    };
    let port = client.read_u16().await?;
    seen.lock().expect("log").push(format!("{host}:{port}"));
    client
        .write_all(&[5, reply, 0, 1, 0, 0, 0, 0, 0, 0])
        .await?;
    if reply != 0 {
        return Ok(());
    }
    let mut server = TcpStream::connect(("127.0.0.1", port)).await?;
    tokio::io::copy_bidirectional(client, &mut server).await?;
    Ok(())
}

/// A proxy using `upstream`; server certificates are not checked, because the test server's
/// certificate names `localhost` while the tests ask for `origin.test`.
async fn start(upstream: &str, bypass: &str) -> anyhow::Result<common::Running> {
    let certs = upstream_certs()?;
    let config = Config {
        upstream: UpstreamTls::Insecure,
        upstream_proxy: Some(upstream.parse()?),
        upstream_bypass: bypass.parse()?,
        ..test_config(&certs.ca, 4096)?
    };
    let dir = config.config_dir.clone();
    Ok(spawn(Proxy::bind(config).await?, dir))
}

/// `GET path` to `https://host:port` through the proxy; returns the status and body.
async fn https_get(
    running: &common::Running,
    host: &str,
    port: u16,
    path: &str,
) -> anyhow::Result<(StatusCode, String)> {
    let ca = CertificateDer::from_pem_slice(running.ca_pem.as_bytes())?;
    let tls = tunnel_to(running.addr, host, port, &[ca], b"http/1.1").await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    tokio::spawn(connection);
    let request = Request::get(path)
        .header("host", format!("{host}:{port}"))
        .body(Empty::<bytes::Bytes>::new())?;
    let response = sender.send_request(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

/// An absolute-form `GET url` straight to the proxy; returns the status and body.
async fn http_get(running: &common::Running, url: &str) -> anyhow::Result<(StatusCode, String)> {
    let tcp = TcpStream::connect(running.addr).await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(connection);
    let host = url
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .to_owned();
    let request = Request::get(url)
        .header("host", host)
        .body(Empty::<bytes::Bytes>::new())?;
    let response = sender.send_request(request).await?;
    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

fn log_of(log: &Log) -> Vec<String> {
    log.lock().expect("log").clone()
}

/// The record holds no trace of the password, in clear or encoded.
fn assert_no_secret(record: &Exchange) -> TestResult {
    let json = serde_json::to_string(record)?;
    assert!(!json.contains(PASSWORD), "{json}");
    assert!(!json.contains("aHVudGVy"), "{json}");
    Ok(())
}

#[tokio::test]
async fn https_goes_through_an_http_connect_proxy_with_credentials() -> TestResult {
    let certs = upstream_certs()?;
    let server = https_server(&certs).await?;
    let (proxy_port, log) = http_proxy(Some(BASIC), None).await?;
    let mut running = start(
        &format!("http://{USER}:{PASSWORD}@127.0.0.1:{proxy_port}"),
        "",
    )
    .await?;
    let (status, body) = https_get(&running, "origin.test", server, "/via").await?;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "hello from /via"));
    assert_eq!(
        log_of(&log),
        [format!("CONNECT origin.test:{server} auth=true")]
    );
    let record = next_exchange(&mut running.events).await?;
    assert!(
        record.flags.contains(&Flag::UpstreamProxy),
        "{:?}",
        record.flags
    );
    assert_no_secret(&record)
}

#[tokio::test]
async fn plain_http_goes_to_an_http_proxy_in_absolute_form() -> TestResult {
    let server = http_server().await?;
    let (proxy_port, log) = http_proxy(Some(BASIC), None).await?;
    let mut running = start(
        &format!("http://{USER}:{PASSWORD}@127.0.0.1:{proxy_port}"),
        "",
    )
    .await?;
    let (status, body) = http_get(&running, &format!("http://origin.test:{server}/abs")).await?;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "hello from /abs"));
    assert_eq!(
        log_of(&log),
        [format!("GET http://origin.test:{server}/abs auth=true")]
    );
    let record = next_exchange(&mut running.events).await?;
    assert!(record.flags.contains(&Flag::UpstreamProxy));
    assert_no_secret(&record)
}

#[tokio::test]
async fn rejected_credentials_give_a_502_naming_the_redacted_proxy() -> TestResult {
    let certs = upstream_certs()?;
    let server = https_server(&certs).await?;
    let (proxy_port, _log) = http_proxy(Some("Basic d3Jvbmc="), None).await?;
    let mut running = start(
        &format!("http://{USER}:{PASSWORD}@127.0.0.1:{proxy_port}"),
        "",
    )
    .await?;
    let (status, body) = https_get(&running, "origin.test", server, "/").await?;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(!body.contains(PASSWORD), "{body}");
    let record = next_exchange(&mut running.events).await?;
    let error = record.error.clone().unwrap_or_default();
    assert!(
        error.contains(&format!("http://{USER}:***@127.0.0.1:{proxy_port}")),
        "{error}"
    );
    assert!(error.contains("407"), "{error}");
    assert_no_secret(&record)
}

#[tokio::test]
async fn a_refused_connect_and_a_dead_proxy_give_502s() -> TestResult {
    let certs = upstream_certs()?;
    let server = https_server(&certs).await?;
    let (proxy_port, _log) = http_proxy(None, Some(403)).await?;
    let mut running = start(&format!("http://127.0.0.1:{proxy_port}"), "").await?;
    let (status, _) = https_get(&running, "origin.test", server, "/").await?;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let error = next_exchange(&mut running.events)
        .await?
        .error
        .unwrap_or_default();
    assert!(error.contains("CONNECT refused with status 403"), "{error}");

    let dead = TcpListener::bind("127.0.0.1:0").await?.local_addr()?.port();
    let mut running = start(&format!("socks5h://127.0.0.1:{dead}"), "").await?;
    let (status, _) = https_get(&running, "origin.test", server, "/").await?;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let error = next_exchange(&mut running.events)
        .await?
        .error
        .unwrap_or_default();
    assert!(
        error.contains(&format!("upstream proxy socks5h://127.0.0.1:{dead}")),
        "{error}"
    );
    Ok(())
}

#[tokio::test]
async fn socks5h_sends_the_host_name_and_logs_in() -> TestResult {
    let certs = upstream_certs()?;
    let server = https_server(&certs).await?;
    let (proxy_port, log) = socks5_server(Some((USER, PASSWORD)), 0).await?;
    let mut running = start(
        &format!("socks5h://{USER}:{PASSWORD}@127.0.0.1:{proxy_port}"),
        "",
    )
    .await?;
    let (status, body) = https_get(&running, "origin.test", server, "/socks").await?;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::OK, "hello from /socks")
    );
    assert_eq!(log_of(&log), [format!("origin.test:{server}")]);
    let record = next_exchange(&mut running.events).await?;
    assert!(record.flags.contains(&Flag::UpstreamProxy));
    assert_no_secret(&record)
}

#[tokio::test]
async fn socks5_carries_plain_http_to_an_ip_and_reports_reply_codes() -> TestResult {
    let server = http_server().await?;
    let (proxy_port, log) = socks5_server(None, 0).await?;
    let mut running = start(&format!("socks5://127.0.0.1:{proxy_port}"), "").await?;
    let (status, _) = http_get(&running, &format!("http://192.0.2.10:{server}/ip")).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(log_of(&log), [format!("192.0.2.10:{server}")]);
    assert!(
        next_exchange(&mut running.events)
            .await?
            .flags
            .contains(&Flag::UpstreamProxy)
    );

    let (refusing, _) = socks5_server(None, 5).await?;
    let mut running = start(&format!("socks5://127.0.0.1:{refusing}"), "").await?;
    let (status, _) = http_get(&running, &format!("http://192.0.2.10:{server}/")).await?;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let error = next_exchange(&mut running.events)
        .await?
        .error
        .unwrap_or_default();
    assert!(
        error.contains("SOCKS5 reply 5: connection refused"),
        "{error}"
    );

    let (strict, log) = socks5_server(Some((USER, PASSWORD)), 0).await?;
    let mut running = start(&format!("socks5://{USER}:wrong@127.0.0.1:{strict}"), "").await?;
    let (status, _) = http_get(&running, &format!("http://192.0.2.10:{server}/")).await?;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(log_of(&log), ["login rejected"]);
    let error = next_exchange(&mut running.events)
        .await?
        .error
        .unwrap_or_default();
    assert!(error.contains("rejected the credentials"), "{error}");
    Ok(())
}

#[tokio::test]
async fn loopback_hosts_go_direct() -> TestResult {
    // Bypass matching of names, domains and CIDRs is unit-tested in the library: dialling a
    // bypassed non-loopback address here would leave the machine.
    let server = http_server().await?;
    let (proxy_port, log) = http_proxy(None, None).await?;
    let mut running = start(&format!("http://127.0.0.1:{proxy_port}"), "*.corp.example").await?;
    for host in ["localhost", "127.0.0.1"] {
        let (status, _) = http_get(&running, &format!("http://{host}:{server}/direct")).await?;
        assert_eq!(status, StatusCode::OK);
        let record = next_exchange(&mut running.events).await?;
        assert!(!record.flags.contains(&Flag::UpstreamProxy));
    }
    assert!(log_of(&log).is_empty(), "{:?}", log_of(&log));
    Ok(())
}

#[tokio::test]
async fn the_proxy_refuses_itself_as_upstream_and_as_a_connect_target() -> TestResult {
    let certs = upstream_certs()?;
    let port = TcpListener::bind("127.0.0.1:0").await?.local_addr()?.port();
    let config = Config {
        listen: format!("127.0.0.1:{port}").parse()?,
        upstream_proxy: Some(format!("http://localhost:{port}").parse()?),
        ..test_config(&certs.ca, 1024)?
    };
    let dir = config.config_dir.clone();
    let error = Proxy::bind(config)
        .await
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(error.contains("own listener"), "{error}");
    let _ = std::fs::remove_dir_all(dir);

    let running = start("http://127.0.0.1:9", "").await?;
    let (_, head) = connect_head(running.addr, "127.0.0.1", running.addr.port()).await?;
    assert!(
        head.starts_with(b"HTTP/1.1 508"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    Ok(())
}

#[tokio::test]
async fn passthrough_tunnels_go_through_the_upstream_proxy() -> TestResult {
    let certs = upstream_certs()?;
    let server = https_server(&certs).await?;
    let (proxy_port, log) = http_proxy(None, None).await?;
    let config = Config {
        upstream_proxy: Some(format!("http://127.0.0.1:{proxy_port}").parse()?),
        passthrough: Passthrough::new(
            Lists::parse(&["origin.test".to_owned()], &[]).map_err(anyhow::Error::msg)?,
        ),
        ..test_config(&certs.ca, 1024)?
    };
    let dir = config.config_dir.clone();
    let running = spawn(Proxy::bind(config).await?, dir);
    let (tcp, head) = connect_head(running.addr, "origin.test", server).await?;
    assert!(head.starts_with(b"HTTP/1.1 200"));
    // Undecrypted: the client sees the server's own certificate, issued for localhost.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certs.ca.clone())?;
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost")?, tcp)
        .await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    tokio::spawn(connection);
    let request = Request::get("/pt")
        .header("host", "localhost")
        .body(Empty::<bytes::Bytes>::new())?;
    assert_eq!(sender.send_request(request).await?.status(), StatusCode::OK);
    assert_eq!(
        log_of(&log),
        [format!("CONNECT origin.test:{server} auth=true")]
    );
    Ok(())
}

#[tokio::test]
async fn websocket_upgrades_over_plain_http_take_a_connect_tunnel() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server = listener.local_addr()?.port();
    tokio::spawn(async move {
        let Ok((mut tcp, _)) = listener.accept().await else {
            return;
        };
        if read_head(&mut tcp).await.is_ok() {
            let answer = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                          Connection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
            let _ = tcp.write_all(answer.as_bytes()).await;
            let mut byte = [0u8; 1];
            if tcp.read_exact(&mut byte).await.is_ok() {
                let _ = tcp.write_all(&byte).await;
            }
        }
    });
    let (proxy_port, log) = http_proxy(Some(BASIC), None).await?;
    let mut running = start(
        &format!("http://{USER}:{PASSWORD}@127.0.0.1:{proxy_port}"),
        "",
    )
    .await?;
    let mut client = TcpStream::connect(running.addr).await?;
    let host = format!("origin.test:{server}");
    let request = format!(
        "GET http://{host}/ws HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await?;
    let head = read_head(&mut client).await?;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    client.write_all(b"x").await?;
    assert_eq!(client.read_u8().await?, b'x');
    assert_eq!(log_of(&log), [format!("CONNECT {host} auth=true")]);
    let record = next_exchange(&mut running.events).await?;
    assert!(record.flags.contains(&Flag::UpstreamProxy));
    assert_no_secret(&record)
}

#[test]
fn the_upstream_proxy_prints_without_its_password() -> TestResult {
    let proxy: UpstreamProxy = format!("socks5://{USER}:{PASSWORD}@10.1.2.3:1080").parse()?;
    assert_eq!(proxy.to_string(), "socks5://alice:***@10.1.2.3:1080");
    assert!(!format!("{proxy:?}").contains(PASSWORD));
    Ok(())
}
