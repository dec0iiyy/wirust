//! Client connection lifecycle: header, idle and preface timeouts and the connection cap.
//!
//! Every test runs on a paused clock, so minutes pass in an instant. The limits under test
//! are the documented defaults: 30 s for request headers, 5 min of idleness, 10 s for the
//! HTTP/2 preface.

mod common;

use std::time::Duration;

use bytes::Bytes;
use common::*;
use http::Request;
use http_body_util::{BodyExt as _, Empty};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, sleep, timeout};
use wirust::{Config, Proxy};

const HEADER_TIMEOUT: Duration = Duration::from_secs(30);
/// Well inside the header timeout.
const BEFORE_HEADER: Duration = Duration::from_secs(25);
/// Well inside the 5 min idle timeout, but long past the header timeout.
const BEFORE_IDLE: Duration = Duration::from_secs(4 * 60 + 30);

/// Lets real socket IO run without moving the paused clock.
async fn settle() {
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

/// Whether the peer closes `stream` within `within`; data is discarded. The paused clock
/// moves in 100 ms steps with IO settling between them, so a timer never jumps ahead of
/// bytes already in flight on loopback.
async fn closes_within<S: AsyncRead + Unpin>(stream: &mut S, within: Duration) -> bool {
    let end = Instant::now() + within;
    let mut buf = [0_u8; 4096];
    loop {
        settle().await;
        // A zero timeout polls the read once.
        match timeout(Duration::ZERO, stream.read(&mut buf)).await {
            Ok(Ok(0) | Err(_)) => return true,
            Ok(Ok(_)) => continue,
            Err(_) => {}
        }
        if Instant::now() >= end {
            return false;
        }
        tokio::time::advance(Duration::from_millis(100)).await;
    }
}

/// Whether `task` finishes within `limit`, moving the paused clock in 100 ms steps and
/// letting IO run between them.
async fn finishes_within<T>(task: &tokio::task::JoinHandle<T>, limit: Duration) -> bool {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        settle().await;
        if task.is_finished() {
            return true;
        }
        tokio::time::advance(Duration::from_millis(100)).await;
    }
    task.is_finished()
}

async fn plain_proxy() -> anyhow::Result<Running> {
    let certs = upstream_certs()?;
    start_proxy(&certs.ca, 1024).await
}

#[tokio::test(start_paused = true)]
async fn half_a_request_line_is_dropped_after_the_header_timeout() -> anyhow::Result<()> {
    let proxy = plain_proxy().await?;
    let mut client = TcpStream::connect(proxy.addr).await?;
    client.write_all(b"GET http://exa").await?;
    assert!(
        !closes_within(&mut client, BEFORE_HEADER).await,
        "closed before the header timeout"
    );
    assert!(
        closes_within(&mut client, Duration::from_secs(10)).await,
        "a half-sent request line kept the connection open"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_connection_that_sends_nothing_is_dropped() -> anyhow::Result<()> {
    let proxy = plain_proxy().await?;
    let mut client = TcpStream::connect(proxy.addr).await?;
    assert!(
        closes_within(&mut client, HEADER_TIMEOUT + Duration::from_secs(5)).await,
        "a silent connection stayed open"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn trickled_header_bytes_do_not_keep_a_connection_open() -> anyhow::Result<()> {
    let proxy = plain_proxy().await?;
    let mut client = TcpStream::connect(proxy.addr).await?;
    let started = Instant::now();
    let head =
        b"GET http://example.com/ HTTP/1.1\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    for byte in head {
        if client.write_all(&[*byte]).await.is_err()
            || closes_within(&mut client, Duration::from_secs(5)).await
        {
            let after = started.elapsed();
            assert!(
                after < HEADER_TIMEOUT + Duration::from_secs(10),
                "closed after {after:?}"
            );
            return Ok(());
        }
    }
    panic!("a trickled request head kept the connection open");
}

#[tokio::test(start_paused = true)]
async fn an_idle_keep_alive_connection_closes_after_the_idle_timeout() -> anyhow::Result<()> {
    let proxy = plain_proxy().await?;
    let port = http_server().await?;
    let tcp = TcpStream::connect(proxy.addr).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    let conn = tokio::spawn(conn);
    let request = Request::get(format!("http://127.0.0.1:{port}/"))
        .header("host", format!("127.0.0.1:{port}"))
        .body(Empty::<Bytes>::new())?;
    let response = sender.send_request(request).await?;
    response.into_body().collect().await?;
    assert!(
        !finishes_within(&conn, BEFORE_IDLE).await,
        "the keep-alive connection closed before the idle timeout"
    );
    assert!(
        finishes_within(&conn, Duration::from_secs(60)).await,
        "an idle keep-alive connection stayed open"
    );
    Ok(())
}

// The TLS setups below run on the real clock and pause it afterwards: an auto-advancing
// clock could fire the proxy's 2 s first-byte wait before a ClientHello crosses loopback.
#[tokio::test]
async fn an_idle_http2_connection_closes_after_the_idle_timeout() -> anyhow::Result<()> {
    let certs = upstream_certs()?;
    let proxy = start_proxy(&certs.ca, 1024).await?;
    let port = https_server_with_alpn(&certs, &[b"h2"]).await?;
    let ca = CertificateDer::from_pem_slice(proxy.ca_pem.as_bytes())?;
    let tls = tunnel(proxy.addr, port, &[ca], b"h2").await?;
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls)).await?;
    let conn = tokio::spawn(conn);
    let request = Request::get(format!("https://localhost:{port}/")).body(Empty::<Bytes>::new())?;
    let response = sender.send_request(request).await?;
    response.into_body().collect().await?;
    tokio::time::pause();
    // Stepped, not auto-advanced: the proxy's keep-alive PINGs need their answers to cross
    // real sockets before the clock jumps past the PING timeout.
    assert!(
        !finishes_within(&conn, BEFORE_IDLE).await,
        "the HTTP/2 connection closed before the idle timeout"
    );
    assert!(
        finishes_within(&conn, Duration::from_secs(90)).await,
        "an idle HTTP/2 connection stayed open"
    );
    Ok(())
}

#[tokio::test]
async fn an_http2_client_that_never_sends_the_preface_is_dropped() -> anyhow::Result<()> {
    let certs = upstream_certs()?;
    let proxy = start_proxy(&certs.ca, 1024).await?;
    let port = https_server_with_alpn(&certs, &[b"h2"]).await?;
    let ca = CertificateDer::from_pem_slice(proxy.ca_pem.as_bytes())?;
    let mut tls = tunnel(proxy.addr, port, &[ca], b"h2").await?;
    tokio::time::pause();
    assert!(
        closes_within(&mut tls, Duration::from_secs(20)).await,
        "an HTTP/2 connection without a preface stayed open"
    );
    Ok(())
}

/// A server that accepts and then never sends or closes anything.
async fn silent_server() -> anyhow::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((tcp, _)) = listener.accept().await {
            held.push(tcp);
        }
    });
    Ok(port)
}

#[tokio::test(start_paused = true)]
async fn a_connect_tunnel_without_any_bytes_closes_after_the_idle_timeout() -> anyhow::Result<()> {
    let proxy = plain_proxy().await?;
    let port = silent_server().await?;
    let (mut tcp, head) = connect_head(proxy.addr, "127.0.0.1", port).await?;
    assert!(
        head.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    assert!(
        !closes_within(&mut tcp, BEFORE_IDLE).await,
        "the tunnel closed before the idle timeout"
    );
    assert!(
        closes_within(&mut tcp, Duration::from_secs(90)).await,
        "a tunnel that never carried a byte stayed open"
    );
    Ok(())
}

/// A server whose response body trickles one byte every 20 s, `len` bytes in all.
async fn trickling_server(len: usize) -> anyhow::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        let Ok((mut tcp, _)) = listener.accept().await else {
            return;
        };
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let Ok(byte) = tcp.read_u8().await else {
                return;
            };
            head.push(byte);
        }
        let start = format!("HTTP/1.1 200 OK\r\ncontent-length: {len}\r\n\r\n");
        if tcp.write_all(start.as_bytes()).await.is_err() {
            return;
        }
        for _ in 0..len {
            sleep(Duration::from_secs(20)).await;
            if tcp.write_all(b"x").await.is_err() {
                return;
            }
        }
        sleep(Duration::from_secs(3600)).await;
    });
    Ok(port)
}

#[tokio::test(start_paused = true)]
async fn a_slow_download_that_keeps_moving_is_not_cut() -> anyhow::Result<()> {
    let proxy = plain_proxy().await?;
    // 45 bytes at one per 20 s: 15 minutes, three idle timeouts.
    let len = 45;
    let port = trickling_server(len).await?;
    let tcp = TcpStream::connect(proxy.addr).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(conn);
    let request = Request::get(format!("http://127.0.0.1:{port}/slow"))
        .header("host", format!("127.0.0.1:{port}"))
        .body(Empty::<Bytes>::new())?;
    // Stepped: an auto-advancing clock could jump past the proxy's dial timeout before the
    // loopback connect to the server completes.
    let download = tokio::spawn(async move {
        let response = sender.send_request(request).await?;
        let status = response.status();
        let body = response.into_body().collect().await?.to_bytes();
        anyhow::Ok((status, body))
    });
    assert!(
        finishes_within(&download, Duration::from_secs(20 * 60)).await,
        "the download did not finish"
    );
    let (status, body) = download.await??;
    assert_eq!(status, 200, "{body:?}");
    assert_eq!(body.len(), len, "the download was cut short");
    Ok(())
}

#[tokio::test]
async fn connections_over_the_cap_are_refused() -> anyhow::Result<()> {
    let certs = upstream_certs()?;
    let config = Config {
        max_clients: 2,
        ..test_config(&certs.ca, 1024)?
    };
    let dir = config.config_dir.clone();
    let proxy = spawn(Proxy::bind(config).await?, dir);
    let first = TcpStream::connect(proxy.addr).await?;
    let _second = TcpStream::connect(proxy.addr).await?;
    let mut third = TcpStream::connect(proxy.addr).await?;
    let mut answer = Vec::new();
    timeout(Duration::from_secs(10), third.read_to_end(&mut answer)).await??;
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 503"), "{answer}");
    assert!(answer.contains("too many client connections"), "{answer}");
    drop(first);
    // A freed slot is reused.
    let mut fourth = None;
    for _ in 0..50 {
        let mut tcp = TcpStream::connect(proxy.addr).await?;
        let mut byte = [0_u8; 1];
        match timeout(Duration::from_millis(200), tcp.read(&mut byte)).await {
            Err(_) => {
                fourth = Some(tcp);
                break;
            }
            Ok(_) => sleep(Duration::from_millis(50)).await,
        }
    }
    assert!(
        fourth.is_some(),
        "a closed connection did not free its slot"
    );
    Ok(())
}
