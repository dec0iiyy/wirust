//! WebSocket capture end to end: a hand-rolled WebSocket server, a client through the proxy
//! over `ws://` (absolute form) and `wss://` (CONNECT plus interception), and the recorded
//! messages on the bus and in the store. Loopback only, random ports.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{
    TestResult, UpstreamCerts, next_bus_event, spawn, test_config, tunnel, upstream_certs,
};
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, oneshot};
use tokio_rustls::TlsAcceptor;
use wirust::events::{FlowEvent, FlowStore};
use wirust::flow::{Exchange, Flag};
use wirust::ws::{Direction, Encoding, Kind, WsLimits, WsMessage};
use wirust::{Config, Proxy};

const KEY: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];

/// One frame; `mask` masks the payload as a client must.
fn frame(fin: bool, opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = vec![if fin { 0x80 } else { 0 } | opcode];
    let bit = if mask.is_some() { 0x80 } else { 0 };
    match payload.len() {
        n if n < 126 => out.push(bit | u8::try_from(n).expect("short")),
        n if n <= 0xFFFF => {
            out.push(bit | 0x7E);
            out.extend_from_slice(&u16::try_from(n).expect("16-bit").to_be_bytes());
        }
        n => {
            out.push(bit | 0x7F);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    match mask {
        Some(key) => {
            out.extend_from_slice(&key);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
        }
        None => out.extend_from_slice(payload),
    }
    out
}

fn close(code: u16, reason: &str, mask: Option<[u8; 4]>) -> Vec<u8> {
    let mut payload = code.to_be_bytes().to_vec();
    payload.extend_from_slice(reason.as_bytes());
    frame(true, 8, &payload, mask)
}

/// What the test server saw: the upgrade request head and every byte after it.
struct Seen {
    head: String,
    bytes: Vec<u8>,
}

/// The server's part: answer 101 (with `extra` headers), write `to_client`, read to EOF.
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    extra: &str,
    to_client: &[u8],
) -> std::io::Result<Seen> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await?);
    }
    let answer = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n{extra}\r\n"
    );
    stream.write_all(answer.as_bytes()).await?;
    stream.write_all(to_client).await?;
    stream.flush().await?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await?;
    Ok(Seen {
        head: String::from_utf8_lossy(&head).into_owned(),
        bytes,
    })
}

/// A one-connection WebSocket server; plain unless `tls` is given.
async fn ws_server(
    tls: Option<&UpstreamCerts>,
    extra: &'static str,
    to_client: Vec<u8>,
) -> anyhow::Result<(u16, oneshot::Receiver<Seen>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let acceptor = match tls {
        Some(certs) => {
            let mut config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![certs.leaf.clone()], certs.key.clone_key())?;
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Some(TlsAcceptor::from(Arc::new(config)))
        }
        None => None,
    };
    let (send, receive) = oneshot::channel();
    tokio::spawn(async move {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };
        let seen = match acceptor {
            Some(acceptor) => match acceptor.accept(tcp).await {
                Ok(tls) => serve(tls, extra, &to_client).await,
                Err(e) => Err(e),
            },
            None => serve(tcp, extra, &to_client).await,
        };
        if let Ok(seen) = seen {
            let _ = send.send(seen);
        }
    });
    Ok((port, receive))
}

fn upgrade_request(target: &str, host: &str) -> String {
    format!(
        "GET {target} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n"
    )
}

/// The client's part: send the upgrade, read the 101, write `to_server`, read `expect` bytes
/// back, then close the write side. Returns the bytes the client received after the head.
async fn client<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    request: &str,
    to_server: &[u8],
    expect: usize,
) -> anyhow::Result<Vec<u8>> {
    stream.write_all(request.as_bytes()).await?;
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await?);
    }
    anyhow::ensure!(
        head.starts_with(b"HTTP/1.1 101"),
        "no upgrade: {}",
        String::from_utf8_lossy(&head)
    );
    stream.write_all(to_server).await?;
    stream.flush().await?;
    let mut got = vec![0_u8; expect];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut got)).await??;
    stream.shutdown().await?;
    Ok(got)
}

struct Harness {
    running: common::Running,
    store: FlowStore,
    certs: UpstreamCerts,
}

async fn harness(limits: WsLimits) -> anyhow::Result<Harness> {
    let certs = upstream_certs()?;
    let config = Config {
        ws: limits,
        ..test_config(&certs.ca, 1024)?
    };
    let dir = config.config_dir.clone();
    let proxy = Proxy::bind(config).await?;
    let store = proxy.store().clone();
    Ok(Harness {
        running: spawn(proxy, dir),
        store,
        certs,
    })
}

/// The upgrade's record and the first `n` messages on the bus.
async fn recorded(
    events: &mut broadcast::Receiver<FlowEvent>,
    n: usize,
) -> anyhow::Result<(Exchange, Vec<WsMessage>)> {
    let mut exchange = None;
    let mut messages = Vec::new();
    while exchange.is_none() || messages.len() < n {
        match next_bus_event(events).await? {
            FlowEvent::Completed(flow) => {
                if let wirust::flow::Event::Exchange(x) = &flow.record {
                    exchange = Some((**x).clone());
                }
            }
            FlowEvent::WsMessage(m) => messages.push((*m).clone()),
            _ => {}
        }
    }
    Ok((exchange.expect("loop ends with a record"), messages))
}

fn of(messages: &[WsMessage], direction: Direction) -> Vec<&WsMessage> {
    messages
        .iter()
        .filter(|m| m.direction == direction)
        .collect()
}

#[tokio::test]
async fn plain_ws_forwards_unchanged_and_records_every_kind_in_order() -> TestResult {
    let mut h = harness(WsLimits::default()).await?;
    let mut to_server = frame(true, 1, b"hello", Some(KEY));
    to_server.extend(frame(true, 2, &[0, 1, 2, 255], Some(KEY)));
    to_server.extend(frame(false, 1, b"frag", Some(KEY)));
    to_server.extend(frame(true, 9, b"p", Some(KEY)));
    to_server.extend(frame(true, 0, b"mented", Some(KEY)));
    to_server.extend(close(1000, "bye", Some(KEY)));
    let mut to_client = frame(true, 1, br#"{"a":1}"#, None);
    to_client.extend(frame(true, 10, b"p", None));
    to_client.extend(close(1001, "away", None));
    let (port, seen) = ws_server(None, "", to_client.clone()).await?;
    let host = format!("127.0.0.1:{port}");
    let tcp = TcpStream::connect(h.running.addr).await?;
    let request = upgrade_request(&format!("http://{host}/socket"), &host);
    let got = client(tcp, &request, &to_server, to_client.len()).await?;
    assert_eq!(
        got, to_client,
        "the client gets the server's bytes unchanged"
    );
    let seen = tokio::time::timeout(Duration::from_secs(10), seen).await??;
    assert_eq!(
        seen.bytes, to_server,
        "the server gets the masked bytes unchanged"
    );
    assert!(
        seen.head
            .to_ascii_lowercase()
            .contains("sec-websocket-extensions: permessage-deflate"),
        "the extension offer reaches the server: {}",
        seen.head
    );

    let (record, messages) = recorded(&mut h.running.events, 8).await?;
    assert_eq!(record.status, Some(101));
    assert!(!record.flags.contains(&Flag::WsExtensionsStripped));
    assert!(!record.flags.contains(&Flag::WsCompressed));
    assert_eq!(record.ws_messages, Some(0), "counted later, in the store");
    let seqs: Vec<u64> = messages.iter().map(|m| m.seq).collect();
    assert_eq!(seqs, (0..8).collect::<Vec<u64>>());
    let up = of(&messages, Direction::ClientToServer);
    let kinds: Vec<Kind> = up.iter().map(|m| m.kind).collect();
    assert_eq!(
        kinds,
        [
            Kind::Text,
            Kind::Binary,
            Kind::Ping,
            Kind::Text,
            Kind::Close
        ]
    );
    assert_eq!(
        (up[0].data.as_str(), up[0].encoding),
        ("hello", Encoding::Utf8)
    );
    assert_eq!(
        (up[1].bytes(), up[1].encoding),
        (vec![0, 1, 2, 255], Encoding::Base64)
    );
    assert_eq!(
        up[3].data, "fragmented",
        "fragments are reassembled and unmasked"
    );
    assert_eq!(
        (up[4].close_code, up[4].close_reason.as_deref()),
        (Some(1000), Some("bye"))
    );
    let down = of(&messages, Direction::ServerToClient);
    assert_eq!(down[0].data, r#"{"a":1}"#);
    assert_eq!(down[1].kind, Kind::Pong);
    assert_eq!(down[2].close_code, Some(1001));

    // The store counts them on the upgrade's record and holds them for the API.
    let held = wait_for(&h.store, record.id, 8).await?;
    assert_eq!(held.len(), 8);
    Ok(())
}

async fn wait_for(store: &FlowStore, id: u64, n: usize) -> anyhow::Result<Vec<Arc<WsMessage>>> {
    for _ in 0..100 {
        let held = store.ws().list(id, None, usize::MAX);
        if held.len() >= n {
            return Ok(held);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!("the store holds {} messages", store.ws().len(id))
}

#[tokio::test]
async fn wss_through_connect_is_recorded() -> TestResult {
    let mut h = harness(WsLimits::default()).await?;
    let to_server = frame(true, 1, "привет".as_bytes(), Some(KEY));
    let to_client = frame(true, 1, b"world", None);
    let (port, seen) = ws_server(Some(&h.certs), "", to_client.clone()).await?;
    let ca = CertificateDer::from_pem_slice(h.running.ca_pem.as_bytes())?;
    let tls = tunnel(h.running.addr, port, &[ca], b"http/1.1").await?;
    let request = upgrade_request("/chat", &format!("localhost:{port}"));
    let got = client(tls, &request, &to_server, to_client.len()).await?;
    assert_eq!(got, to_client);
    let seen = tokio::time::timeout(Duration::from_secs(10), seen).await??;
    assert_eq!(seen.bytes, to_server);
    let (record, messages) = recorded(&mut h.running.events, 2).await?;
    assert!(
        record.url.starts_with("https://localhost:"),
        "{}",
        record.url
    );
    let up = of(&messages, Direction::ClientToServer);
    assert_eq!(up[0].data, "привет");
    assert_eq!(of(&messages, Direction::ServerToClient)[0].data, "world");
    Ok(())
}

#[tokio::test]
async fn a_two_mib_message_is_forwarded_whole_and_recorded_truncated() -> TestResult {
    let mut h = harness(WsLimits::default()).await?;
    let payload: Vec<u8> = (0..2 * 1024 * 1024).map(|i: u32| (i % 251) as u8).collect();
    let to_server = frame(true, 2, &payload, Some(KEY));
    let to_client = frame(true, 1, b"ok", None);
    let (port, seen) = ws_server(None, "", to_client.clone()).await?;
    let host = format!("127.0.0.1:{port}");
    let tcp = TcpStream::connect(h.running.addr).await?;
    let request = upgrade_request(&format!("http://{host}/big"), &host);
    client(tcp, &request, &to_server, to_client.len()).await?;
    let seen = tokio::time::timeout(Duration::from_secs(10), seen).await??;
    assert_eq!(seen.bytes.len(), to_server.len());
    assert!(seen.bytes == to_server, "the 2 MiB frame arrives unchanged");
    let (_, messages) = recorded(&mut h.running.events, 2).await?;
    let big = of(&messages, Direction::ClientToServer)[0];
    assert_eq!(big.size, payload.len() as u64);
    assert!(big.truncated);
    assert_eq!(big.bytes(), payload[..wirust::ws::DEFAULT_WS_BODY_LIMIT]);
    Ok(())
}

#[tokio::test]
async fn the_ring_keeps_only_the_newest_messages() -> TestResult {
    let mut h = harness(WsLimits {
        max_messages: 5,
        ..WsLimits::default()
    })
    .await?;
    let to_server: Vec<u8> = (0..12)
        .flat_map(|i| frame(true, 1, format!("m{i}").as_bytes(), Some(KEY)))
        .collect();
    let (port, _seen) = ws_server(None, "", Vec::new()).await?;
    let host = format!("127.0.0.1:{port}");
    let tcp = TcpStream::connect(h.running.addr).await?;
    client(
        tcp,
        &upgrade_request(&format!("http://{host}/r"), &host),
        &to_server,
        0,
    )
    .await?;
    let (record, _) = recorded(&mut h.running.events, 12).await?;
    // The ring holds at most 5; wait until the twelfth arrived.
    for _ in 0..100 {
        if h.store.ws().list(record.id, Some(10), 1).len() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let held: Vec<String> = h
        .store
        .ws()
        .list(record.id, None, usize::MAX)
        .iter()
        .map(|m| m.data.clone())
        .collect();
    assert_eq!(held, ["m7", "m8", "m9", "m10", "m11"]);
    Ok(())
}

#[tokio::test]
async fn garbage_after_the_upgrade_is_forwarded_and_not_parsed() -> TestResult {
    let mut h = harness(WsLimits::default()).await?;
    // 0xFF: reserved bits and an unknown opcode. Everything after it is raw bytes.
    let mut to_server = vec![0xFF; 64];
    to_server.extend(frame(true, 1, b"after garbage", Some(KEY)));
    let to_client = frame(true, 1, b"still parsed", None);
    let (port, seen) = ws_server(None, "", to_client.clone()).await?;
    let host = format!("127.0.0.1:{port}");
    let tcp = TcpStream::connect(h.running.addr).await?;
    let request = upgrade_request(&format!("http://{host}/g"), &host);
    let got = client(tcp, &request, &to_server, to_client.len()).await?;
    assert_eq!(got, to_client);
    let seen = tokio::time::timeout(Duration::from_secs(10), seen).await??;
    assert_eq!(
        seen.bytes, to_server,
        "raw bytes keep flowing after a violation"
    );
    let (_, messages) = recorded(&mut h.running.events, 1).await?;
    assert_eq!(messages[0].direction, Direction::ServerToClient);
    assert_eq!(messages[0].data, "still parsed");
    // Nothing from the client side shows up later either.
    let late = tokio::time::timeout(Duration::from_millis(300), async {
        loop {
            if let Ok(FlowEvent::WsMessage(m)) = h.running.events.recv().await {
                return m;
            }
        }
    })
    .await;
    assert!(late.is_err(), "no message parsed after the violation");
    // The proxy still serves new connections.
    let (port, _seen) = ws_server(None, "", frame(true, 1, b"x", None)).await?;
    let host = format!("127.0.0.1:{port}");
    let tcp = TcpStream::connect(h.running.addr).await?;
    client(
        tcp,
        &upgrade_request(&format!("http://{host}/"), &host),
        &[],
        3,
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn strip_compression_removes_the_offer() -> TestResult {
    let mut h = harness(WsLimits {
        strip_compression: true,
        ..WsLimits::default()
    })
    .await?;
    let to_client = frame(true, 1, b"plain", None);
    let (port, seen) = ws_server(None, "", to_client.clone()).await?;
    let host = format!("127.0.0.1:{port}");
    let tcp = TcpStream::connect(h.running.addr).await?;
    let request = upgrade_request(&format!("http://{host}/s"), &host);
    client(tcp, &request, &[], to_client.len()).await?;
    let seen = tokio::time::timeout(Duration::from_secs(10), seen).await??;
    assert!(
        !seen
            .head
            .to_ascii_lowercase()
            .contains("sec-websocket-extensions"),
        "the extension offer is stripped: {}",
        seen.head
    );
    let (record, _) = recorded(&mut h.running.events, 1).await?;
    assert!(record.flags.contains(&Flag::WsExtensionsStripped));
    Ok(())
}

/// Compresses `messages` as one `permessage-deflate` sender does (RFC 7692 section 7.2.1):
/// a sync flush per message with the `00 00 ff ff` tail removed; `takeover` keeps the
/// window between messages.
fn deflate(messages: &[&[u8]], takeover: bool) -> Vec<Vec<u8>> {
    let mut state = flate2::Compress::new(flate2::Compression::default(), false);
    messages
        .iter()
        .map(|message| {
            if !takeover {
                state.reset();
            }
            let mut out = Vec::with_capacity(message.len() + 1024);
            state
                .compress_vec(message, &mut out, flate2::FlushCompress::Sync)
                .expect("compress");
            assert!(out.ends_with(&[0, 0, 0xff, 0xff]), "sync flush tail");
            out.truncate(out.len() - 4);
            out
        })
        .collect()
}

/// A compressed message as frames: RSV1 on the first frame only, split in `parts`.
fn compressed(opcode: u8, payload: &[u8], parts: usize, mask: Option<[u8; 4]>) -> Vec<u8> {
    let size = payload.len().div_ceil(parts).max(1);
    let chunks: Vec<&[u8]> = payload.chunks(size).collect();
    let mut wire = Vec::new();
    for (i, chunk) in chunks.iter().enumerate() {
        let mut f = frame(
            i + 1 == chunks.len(),
            if i == 0 { opcode } else { 0 },
            chunk,
            mask,
        );
        if i == 0 {
            f[0] |= 0x40;
        }
        wire.extend(f);
    }
    wire
}

async fn deflate_round_trip(answer: &'static str, takeover: bool) -> TestResult {
    let mut h = harness(WsLimits::default()).await?;
    let down: [&[u8]; 2] = [b"{\"tick\":1,\"tick\":1}", b"{\"tick\":2,\"tick\":2}"];
    let up: [&[u8]; 2] = [b"subscribe subscribe", b"subscribe again"];
    let to_client: Vec<u8> = deflate(&down, takeover)
        .iter()
        .enumerate()
        .flat_map(|(i, p)| compressed(1, p, i + 1, None))
        .collect();
    let to_server: Vec<u8> = deflate(&up, takeover)
        .iter()
        .enumerate()
        .flat_map(|(i, p)| compressed(1, p, 2 - i, Some(KEY)))
        .collect();
    let (port, seen) = ws_server(None, answer, to_client.clone()).await?;
    let host = format!("127.0.0.1:{port}");
    let tcp = TcpStream::connect(h.running.addr).await?;
    let request = upgrade_request(&format!("http://{host}/d"), &host);
    let got = client(tcp, &request, &to_server, to_client.len()).await?;
    assert_eq!(
        got, to_client,
        "compressed bytes reach the client unchanged"
    );
    let seen = tokio::time::timeout(Duration::from_secs(10), seen).await??;
    assert_eq!(seen.bytes, to_server, "and the server");
    assert!(
        seen.head.contains("permessage-deflate"),
        "the offer is forwarded: {}",
        seen.head
    );
    let (record, messages) = recorded(&mut h.running.events, 4).await?;
    assert!(record.flags.contains(&Flag::WsCompressed));
    assert!(!record.flags.contains(&Flag::WsExtensionsStripped));
    for (direction, want) in [
        (Direction::ServerToClient, down),
        (Direction::ClientToServer, up),
    ] {
        let got = of(&messages, direction);
        let texts: Vec<&[u8]> = got.iter().map(|m| m.data.as_bytes()).collect();
        assert_eq!(texts, want, "{direction:?} takeover {takeover}");
        for m in got {
            assert!(m.compressed && !m.decode_failed, "{m:?}");
            assert_eq!(m.encoding, Encoding::Utf8);
            assert!(m.wire_size.is_some());
        }
    }
    Ok(())
}

#[tokio::test]
async fn permessage_deflate_with_context_takeover_is_inflated() -> TestResult {
    deflate_round_trip("Sec-WebSocket-Extensions: permessage-deflate\r\n", true).await
}

#[tokio::test]
async fn permessage_deflate_without_context_takeover_is_inflated() -> TestResult {
    deflate_round_trip(
        "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; \
         client_no_context_takeover\r\n",
        false,
    )
    .await
}

#[tokio::test]
async fn an_unknown_extension_gets_raw_records() -> TestResult {
    let mut h = harness(WsLimits::default()).await?;
    let mut to_client = frame(true, 1, &[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00], None);
    to_client[0] |= 0x40;
    let (port, _seen) = ws_server(
        None,
        "Sec-WebSocket-Extensions: x-custom-compression\r\n",
        to_client.clone(),
    )
    .await?;
    let host = format!("127.0.0.1:{port}");
    let tcp = TcpStream::connect(h.running.addr).await?;
    let request = upgrade_request(&format!("http://{host}/z"), &host);
    let got = client(tcp, &request, &[], to_client.len()).await?;
    assert_eq!(got, to_client);
    let (record, messages) = recorded(&mut h.running.events, 1).await?;
    assert!(record.flags.contains(&Flag::WsCompressed));
    assert!(messages[0].compressed && messages[0].decode_failed);
    assert_eq!(messages[0].encoding, Encoding::Base64);
    assert_eq!(messages[0].bytes(), to_client[2..]);
    Ok(())
}
