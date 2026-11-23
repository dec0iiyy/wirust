//! The experimental WireGuard capture mode, end to end on loopback: an in-process WireGuard
//! client (boringtun noise plus a smoltcp TCP/IP stack) opens a TCP connection through the
//! tunnel, and the exchange appears as a flow; a quinn client sends HTTP/3 through the same
//! tunnel. No TUN device, no routes, no root.

#![cfg(feature = "wireguard")]

mod common;

use std::collections::VecDeque;
use std::io::IoSliceMut;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use bytes::{Buf as _, Bytes};
use common::{
    TestResult, http_server, https_server, next_event, next_exchange, temp_dir, upstream_certs,
};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, ConnectionError, UdpPoller};
use rustls::pki_types::CertificateDer;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Packet, Ipv4Repr, UdpPacket, UdpRepr,
};
use tokio::io::AsyncReadExt as _;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use wirust::flow::Event;
use wirust::intercept::{Action, Interceptor, Interceptors, RequestCtx};
use wirust::passthrough::{Lists, Passthrough};

use wirust::wireguard::{Peer, Server, generate_key};
use wirust::{Config, Proxy, RemoteAccess, UpstreamTls};

/// The documentation range: never reachable, the interceptor below sends it to loopback.
const ORIGIN_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const CLIENT_ADDR: Ipv4Addr = Ipv4Addr::new(10, 233, 0, 2);

/// Sends requests for `origin.test` to a local test server (a map-remote rule).
struct ToLocalOrigin {
    scheme: &'static str,
    host: &'static str,
    port: u16,
}

impl ToLocalOrigin {
    /// The plain-HTTP origin on `port`.
    fn plain(port: u16) -> Self {
        Self {
            scheme: "http",
            host: "127.0.0.1",
            port,
        }
    }
}

impl Interceptor for ToLocalOrigin {
    fn name(&self) -> &'static str {
        "to-local-origin"
    }

    fn on_request(&self, request: &mut RequestCtx) -> Action {
        if request.host == "origin.test" {
            self.host.clone_into(&mut request.host);
            request.port = self.port;
            request.scheme = self.scheme;
        }
        Action::Continue
    }
}

/// What a harness differs in.
struct Setup<'a> {
    origin: ToLocalOrigin,
    /// The CA of a TLS origin, trusted for the upstream leg.
    upstream_ca: Option<CertificateDer<'static>>,
    passthrough: &'a [&'a str],
    decrypt_only: &'a [&'a str],
}

impl Setup<'_> {
    async fn plain() -> anyhow::Result<Self> {
        Ok(Self {
            origin: ToLocalOrigin::plain(http_server().await?),
            upstream_ca: None,
            passthrough: &[],
            decrypt_only: &[],
        })
    }
}

struct Harness {
    proxy_events: tokio::sync::broadcast::Receiver<wirust::events::FlowEvent>,
    server_addr: SocketAddr,
    server_public: PublicKey,
    client_key: StaticSecret,
    /// The proxy's CA certificate, DER.
    ca: Vec<u8>,
    dir: std::path::PathBuf,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn start() -> anyhow::Result<Harness> {
    start_with(Setup::plain().await?).await
}

async fn start_with(setup: Setup<'_>) -> anyhow::Result<Harness> {
    let dir = temp_dir();
    let mut interceptors = Interceptors::new();
    interceptors.push(Arc::new(setup.origin));
    let owned = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let lists = Lists::parse(&owned(setup.passthrough), &owned(setup.decrypt_only))
        .map_err(anyhow::Error::msg)?;
    let mut config = Config {
        listen: "127.0.0.1:0".parse()?,
        interceptors,
        passthrough: Passthrough::new(lists),
        ..Config::new(dir.clone())
    };
    if let Some(ca) = setup.upstream_ca {
        config.upstream = UpstreamTls::Verify {
            extra_roots: vec![ca],
        };
    }
    let proxy = Proxy::bind(config).await?;
    let client_key = generate_key()?;
    let peer = Peer {
        name: "test".to_owned(),
        public_key: PublicKey::from(&client_key).to_bytes(),
        address: CLIENT_ADDR,
    };
    let server = Server::bind(
        &proxy,
        "127.0.0.1:0".parse()?,
        RemoteAccess::LoopbackOnly,
        generate_key()?,
        vec![peer],
        None,
    )
    .await?;
    let harness = Harness {
        proxy_events: proxy.subscribe(),
        server_addr: server.local_addr()?,
        server_public: server.public_key(),
        client_key,
        ca: proxy.ca().cert_der()?,
        dir,
    };
    tokio::spawn(proxy.run());
    tokio::spawn(server.run());
    Ok(harness)
}

#[tokio::test]
async fn a_tunneled_http_request_becomes_a_flow() -> TestResult {
    let mut harness = start().await?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let mut tunn = Tunn::new(
        harness.client_key.clone(),
        harness.server_public,
        None,
        None,
        1,
        None,
    );
    let mut device = Queue::default();
    let mut iface = Interface::new(
        IfaceConfig::new(HardwareAddress::Ip),
        &mut device,
        SmolInstant::now(),
    );
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(CLIENT_ADDR), 32));
    });
    let _ = iface.routes_mut().add_default_ipv4_route(CLIENT_ADDR);
    let mut sockets = SocketSet::new(Vec::new());
    let mut tcp_socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 65_536]),
        tcp::SocketBuffer::new(vec![0; 65_536]),
    );
    tcp_socket.connect(iface.context(), (IpAddress::Ipv4(ORIGIN_IP), 80), 40_000)?;
    let handle = sockets.add(tcp_socket);
    let request =
        b"GET /through-the-tunnel HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n";
    let mut sent = false;
    let mut response = Vec::new();
    let mut out = vec![0_u8; 65_535];
    let mut datagram = vec![0_u8; 65_535];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        iface.poll(SmolInstant::now(), &mut device, &mut sockets);
        let socket_state = sockets.get_mut::<tcp::Socket>(handle);
        if !sent && socket_state.may_send() {
            socket_state.send_slice(request)?;
            sent = true;
        }
        while socket_state.can_recv() {
            socket_state.recv(|data| {
                response.extend_from_slice(data);
                (data.len(), ())
            })?;
        }
        if sent && !socket_state.may_recv() && !response.is_empty() {
            break;
        }
        iface.poll(SmolInstant::now(), &mut device, &mut sockets);
        while let Some(packet) = device.tx.pop_front() {
            if let TunnResult::WriteToNetwork(bytes) = tunn.encapsulate(&packet, &mut out) {
                socket.send_to(bytes, harness.server_addr).await?;
            }
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "no response through the tunnel; got {:?}",
            String::from_utf8_lossy(&response)
        );
        // Waits for the next datagram; the short bound only paces the TCP timers above.
        let Ok(received) =
            tokio::time::timeout(Duration::from_millis(50), socket.recv_from(&mut datagram)).await
        else {
            continue;
        };
        let (len, _) = received?;
        let mut input = &datagram[..len];
        loop {
            match tunn.decapsulate(None, input, &mut out) {
                TunnResult::WriteToNetwork(bytes) => {
                    socket.send_to(bytes, harness.server_addr).await?;
                    input = &[];
                }
                TunnResult::WriteToTunnelV4(packet, _) => {
                    device.rx.push_back(packet.to_vec());
                    break;
                }
                _ => break,
            }
        }
    }
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.ends_with("hello from /through-the-tunnel"), "{text}");
    let exchange = next_exchange(&mut harness.proxy_events).await?;
    assert_eq!(exchange.client.ip(), CLIENT_ADDR, "{exchange:?}");
    assert_eq!(exchange.client.port(), 40_000, "{exchange:?}");
    assert_eq!(exchange.status, Some(200));
    assert!(
        exchange.url.ends_with("/through-the-tunnel"),
        "{}",
        exchange.url
    );
    Ok(())
}

#[tokio::test]
async fn an_unknown_peer_gets_no_answer() -> TestResult {
    let harness = start().await?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let mut out = vec![0_u8; 2048];
    let mut stranger = Tunn::new(generate_key()?, harness.server_public, None, None, 7, None);
    let mut known = Tunn::new(
        harness.client_key.clone(),
        harness.server_public,
        None,
        None,
        1,
        None,
    );
    // The server handles datagrams in order on one task: the stranger's handshake first,
    // then the known peer's. The first answer must be for the known peer.
    for tunn in [&mut stranger, &mut known] {
        let TunnResult::WriteToNetwork(init) = tunn.format_handshake_initiation(&mut out, false)
        else {
            anyhow::bail!("no handshake initiation");
        };
        socket.send_to(init, harness.server_addr).await?;
    }
    let mut datagram = vec![0_u8; 2048];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(10), socket.recv_from(&mut datagram)).await??;
    let answer = Tunn::parse_incoming_packet(&datagram[..len])
        .map_err(|e| anyhow::anyhow!("bad answer: {e:?}"))?;
    let boringtun::noise::Packet::HandshakeResponse(response) = answer else {
        anyhow::bail!("expected a handshake response, got {answer:?}");
    };
    assert_eq!(response.receiver_idx >> 8, 1, "answered the stranger");
    assert!(matches!(
        known.decapsulate(None, &datagram[..len], &mut out),
        TunnResult::WriteToNetwork(_)
    ));
    Ok(())
}

#[tokio::test]
async fn a_tunneled_http3_request_becomes_an_h3_flow() -> TestResult {
    let mut harness = start().await?;
    let (endpoint, _pump) = quic_client(&harness).await?;
    let connection =
        (endpoint.connect(SocketAddr::new(ORIGIN_IP.into(), 443), "origin.test")?).await?;
    let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(connection)).await?;
    tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
    let request = http::Request::get("https://origin.test/over-quic").body(())?;
    let mut stream = send.send_request(request).await?;
    stream.finish().await?;
    let response = stream.recv_response().await?;
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["x-test"], "1");
    assert_eq!(String::from_utf8_lossy(&body), "hello from /over-quic");
    let exchange = next_exchange(&mut harness.proxy_events).await?;
    assert_eq!(exchange.client.ip(), CLIENT_ADDR, "{exchange:?}");
    assert_eq!(exchange.client_version, "h3", "{exchange:?}");
    assert_eq!(exchange.url, "https://origin.test/over-quic");
    assert_eq!(exchange.status, Some(200));
    let tls = exchange
        .tls
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no TLS record"))?;
    assert_eq!(tls.alpn.as_deref(), Some("h3"));
    assert_eq!(tls.sni.as_deref(), Some("origin.test"));

    // A request body streams up on a second request of the same connection.
    let request = http::Request::post("https://origin.test/echo").body(())?;
    let mut stream = send.send_request(request).await?;
    stream
        .send_data(Bytes::from_static(b"ping over h3"))
        .await?;
    stream.finish().await?;
    let response = stream.recv_response().await?;
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    assert_eq!(response.status(), 200);
    assert_eq!(String::from_utf8_lossy(&body), "ping over h3");
    let exchange = next_exchange(&mut harness.proxy_events).await?;
    assert_eq!(exchange.method, "POST");
    assert_eq!(exchange.client_version, "h3", "{exchange:?}");
    assert_eq!(exchange.request_body.size, 12, "{exchange:?}");
    Ok(())
}

#[tokio::test]
async fn http3_reaches_a_tls_origin_over_h2() -> TestResult {
    let certs = upstream_certs()?;
    let port = https_server(&certs).await?;
    let mut harness = start_with(Setup {
        origin: ToLocalOrigin {
            scheme: "https",
            host: "localhost",
            port,
        },
        upstream_ca: Some(certs.ca.clone()),
        passthrough: &[],
        decrypt_only: &[],
    })
    .await?;
    let (endpoint, _pump) = quic_client(&harness).await?;
    let (_, mut send) = h3_connect(&endpoint, "origin.test").await?;
    let (status, body) = get(&mut send, "https://origin.test/tls-upstream").await?;
    assert_eq!(status, 200);
    assert_eq!(body, "hello from /tls-upstream");
    let exchange = next_exchange(&mut harness.proxy_events).await?;
    assert_eq!(exchange.client_version, "h3", "{exchange:?}");
    assert_eq!(
        exchange.upstream_version.as_deref(),
        Some("h2"),
        "{exchange:?}"
    );
    Ok(())
}

#[tokio::test]
async fn quic_to_a_passthrough_host_is_refused_so_the_client_falls_back() -> TestResult {
    let mut harness = start_with(Setup {
        passthrough: &["origin.test"],
        ..Setup::plain().await?
    })
    .await?;
    assert_refused(&harness, "origin.test").await?;
    // The refusal is a `TLS-FAIL` record, as on the TCP path.
    let Event::TlsFailure(failure) = next_event(&mut harness.proxy_events).await? else {
        anyhow::bail!("expected a TLS failure");
    };
    assert_eq!(failure.client.ip(), CLIENT_ADDR);
    assert_eq!(failure.target, format!("{ORIGIN_IP}:443"));
    assert!(failure.reason.starts_with("QUIC: "), "{}", failure.reason);
    Ok(())
}

#[tokio::test]
async fn quic_to_a_host_outside_decrypt_only_is_refused() -> TestResult {
    let harness = start_with(Setup {
        decrypt_only: &["other.test"],
        ..Setup::plain().await?
    })
    .await?;
    assert_refused(&harness, "origin.test").await
}

#[tokio::test]
async fn quic_without_sni_is_refused() -> TestResult {
    let harness = start().await?;
    // An IP address as the server name: rustls sends no SNI.
    assert_refused(&harness, &ORIGIN_IP.to_string()).await
}

#[tokio::test]
async fn quic_naming_localhost_gets_no_requests() -> TestResult {
    let harness = start().await?;
    let (endpoint, _pump) = quic_client(&harness).await?;
    let connection =
        (endpoint.connect(SocketAddr::new(ORIGIN_IP.into(), 443), "localhost")?).await?;
    let closed = tokio::time::timeout(Duration::from_secs(10), connection.closed()).await?;
    let ConnectionError::ApplicationClosed(close) = closed else {
        anyhow::bail!("expected the server to close the connection, got {closed}");
    };
    assert_eq!(u64::from(close.error_code), 0x10b, "H3_REQUEST_REJECTED");
    Ok(())
}

#[tokio::test]
async fn a_client_that_disconnects_cancels_the_upstream_request() -> TestResult {
    // An origin that reads one request head, never answers, and reports when the proxy
    // closes the connection.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let (got_request, request_seen) = oneshot::channel();
    let (got_close, upstream_closed) = oneshot::channel();
    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let mut head = Vec::new();
        let mut buf = [0_u8; 4096];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => head.extend_from_slice(&buf[..n]),
            }
        }
        let _ = got_request.send(());
        while matches!(stream.read(&mut buf).await, Ok(n) if n > 0) {}
        let _ = got_close.send(());
    });
    let harness = start_with(Setup {
        origin: ToLocalOrigin::plain(port),
        ..Setup::plain().await?
    })
    .await?;
    let (endpoint, _pump) = quic_client(&harness).await?;
    let (connection, mut send) = h3_connect(&endpoint, "origin.test").await?;
    let request = http::Request::get("https://origin.test/never-answered").body(())?;
    let mut stream = send.send_request(request).await?;
    stream.finish().await?;
    tokio::time::timeout(Duration::from_secs(10), request_seen).await??;
    connection.close(0_u32.into(), b"gone");
    tokio::time::timeout(Duration::from_secs(10), upstream_closed).await??;
    Ok(())
}

/// Opens a QUIC connection to `origin.test` at [`ORIGIN_IP`] and an HTTP/3 session on it.
async fn h3_connect(
    endpoint: &quinn::Endpoint,
    name: &str,
) -> anyhow::Result<(
    quinn::Connection,
    h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
)> {
    let connection = (endpoint.connect(SocketAddr::new(ORIGIN_IP.into(), 443), name)?).await?;
    let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(connection.clone())).await?;
    tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
    Ok((connection, send))
}

/// Sends a GET for `url`; returns the status and the body as text.
async fn get(
    send: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    url: &str,
) -> anyhow::Result<(u16, String)> {
    let mut stream = send.send_request(http::Request::get(url).body(())?).await?;
    stream.finish().await?;
    let response = stream.recv_response().await?;
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    Ok((
        response.status().as_u16(),
        String::from_utf8_lossy(&body).into_owned(),
    ))
}

/// Asserts that the QUIC handshake for `name` fails with a TLS alert from the proxy.
async fn assert_refused(harness: &Harness, name: &str) -> TestResult {
    let (endpoint, _pump) = quic_client(harness).await?;
    let connecting = endpoint.connect(SocketAddr::new(ORIGIN_IP.into(), 443), name)?;
    let result = tokio::time::timeout(Duration::from_secs(10), connecting).await?;
    let Err(ConnectionError::ConnectionClosed(close)) = result else {
        anyhow::bail!("expected the proxy to abort the handshake, got {result:?}");
    };
    // 0x100..0x200: a TLS alert carried as a QUIC CRYPTO_ERROR (RFC 9001, section 4.8).
    let code = u64::from(close.error_code);
    assert!((0x100..0x200).contains(&code), "{close}");
    Ok(())
}

/// The client's port for QUIC.
const QUIC_SOURCE_PORT: u16 = 50_000;

/// A quinn client endpoint whose datagrams travel through a WireGuard tunnel to the
/// harness, and the task that carries them.
async fn quic_client(
    harness: &Harness,
) -> anyhow::Result<(quinn::Endpoint, tokio::task::JoinHandle<()>)> {
    let (to_tunnel, from_quinn) = mpsc::unbounded_channel();
    let (to_quinn, from_tunnel) = mpsc::unbounded_channel();
    let socket = Arc::new(TunnelUdp {
        incoming: Mutex::new(from_tunnel),
        outgoing: to_tunnel,
    });
    let tunn = Tunn::new(
        harness.client_key.clone(),
        harness.server_public,
        None,
        None,
        2,
        None,
    );
    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    let pump = tokio::spawn(pump(tunn, udp, harness.server_addr, from_quinn, to_quinn));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(harness.ca.clone()))?;
    let mut tls = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    Ok((endpoint, pump))
}

/// Moves IPv4 packets between quinn and the tunnel: encrypts what quinn sends, decrypts
/// what the harness answers, and runs the noise timers.
async fn pump(
    mut tunn: Tunn,
    udp: UdpSocket,
    server: SocketAddr,
    mut from_quinn: mpsc::UnboundedReceiver<Vec<u8>>,
    to_quinn: mpsc::UnboundedSender<(SocketAddr, Bytes)>,
) {
    let mut out = vec![0_u8; 65_535];
    let mut datagram = vec![0_u8; 65_535];
    let mut timers = tokio::time::interval(Duration::from_millis(100));
    loop {
        tokio::select! {
            Some(packet) = from_quinn.recv() => {
                if let TunnResult::WriteToNetwork(bytes) = tunn.encapsulate(&packet, &mut out) {
                    let _ = udp.send_to(bytes, server).await;
                }
            }
            Ok((len, _)) = udp.recv_from(&mut datagram) => {
                let mut input = &datagram[..len];
                loop {
                    match tunn.decapsulate(None, input, &mut out) {
                        TunnResult::WriteToNetwork(bytes) => {
                            let _ = udp.send_to(bytes, server).await;
                            input = &[];
                        }
                        TunnResult::WriteToTunnelV4(packet, _) => {
                            if let Some(received) = parse_udp(packet) {
                                let _ = to_quinn.send(received);
                            }
                            break;
                        }
                        _ => break,
                    }
                }
            }
            _ = timers.tick() => {
                if let TunnResult::WriteToNetwork(bytes) = tunn.update_timers(&mut out) {
                    let _ = udp.send_to(bytes, server).await;
                }
            }
        }
    }
}

/// The source and payload of an IPv4 UDP packet.
fn parse_udp(packet: &[u8]) -> Option<(SocketAddr, Bytes)> {
    let ip = Ipv4Packet::new_checked(packet).ok()?;
    let udp = UdpPacket::new_checked(ip.payload()).ok()?;
    let from = SocketAddr::new(IpAddr::V4(ip.src_addr()), udp.src_port());
    Some((from, Bytes::copy_from_slice(udp.payload())))
}

/// An IPv4 UDP packet from the client's tunnel address to `to`.
fn udp_packet(to: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let IpAddr::V4(dst) = to.ip() else {
        return None;
    };
    let udp = UdpRepr {
        src_port: QUIC_SOURCE_PORT,
        dst_port: to.port(),
    };
    let ip = Ipv4Repr {
        src_addr: CLIENT_ADDR,
        dst_addr: dst,
        next_header: IpProtocol::Udp,
        payload_len: udp.header_len() + payload.len(),
        hop_limit: 64,
    };
    let caps = ChecksumCapabilities::default();
    let mut buffer = vec![0_u8; ip.buffer_len() + ip.payload_len];
    let mut packet = Ipv4Packet::new_unchecked(&mut buffer[..]);
    ip.emit(&mut packet, &caps);
    let mut datagram = UdpPacket::new_unchecked(packet.payload_mut());
    udp.emit(
        &mut datagram,
        &IpAddress::Ipv4(CLIENT_ADDR),
        &IpAddress::Ipv4(dst),
        payload.len(),
        |out| out.copy_from_slice(payload),
        &caps,
    );
    Some(buffer)
}

/// The quinn client's socket: datagrams become IPv4 packets for [`pump`].
#[derive(Debug)]
struct TunnelUdp {
    incoming: Mutex<mpsc::UnboundedReceiver<(SocketAddr, Bytes)>>,
    outgoing: mpsc::UnboundedSender<Vec<u8>>,
}

impl AsyncUdpSocket for TunnelUdp {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable)
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> std::io::Result<()> {
        let size = transmit
            .segment_size
            .unwrap_or(transmit.contents.len())
            .max(1);
        for segment in transmit.contents.chunks(size) {
            if let Some(packet) = udp_packet(transmit.destination, segment) {
                let _ = self.outgoing.send(packet);
            }
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        let (Some(buf), Some(meta)) = (bufs.first_mut(), meta.first_mut()) else {
            return Poll::Ready(Ok(0));
        };
        let Ok(mut incoming) = self.incoming.lock() else {
            return Poll::Ready(Err(std::io::Error::other("poisoned")));
        };
        match incoming.poll_recv(cx) {
            Poll::Ready(Some((from, payload))) => {
                let len = payload.len().min(buf.len());
                buf[..len].copy_from_slice(&payload[..len]);
                *meta = RecvMeta {
                    addr: from,
                    len,
                    stride: len,
                    ecn: None,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(SocketAddr::new(CLIENT_ADDR.into(), QUIC_SOURCE_PORT))
    }
}

#[derive(Debug)]
struct Writable;

impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// The client's network device: two packet queues.
#[derive(Default)]
struct Queue {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

impl Device for Queue {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: SmolInstant) -> Option<(Rx, Tx<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((Rx(packet), Tx(&mut self.tx)))
    }

    fn transmit(&mut self, _: SmolInstant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1420;
        caps
    }
}

struct Rx(Vec<u8>);

impl RxToken for Rx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);

impl TxToken for Tx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0_u8; len];
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}
