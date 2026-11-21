//! The experimental WireGuard capture mode, end to end on loopback: an in-process WireGuard
//! client (boringtun noise plus a smoltcp TCP/IP stack) opens a TCP connection through the
//! tunnel, and the exchange appears as a flow. No TUN device, no routes, no root.

#![cfg(feature = "wireguard")]

mod common;

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use common::{TestResult, http_server, next_exchange, temp_dir};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::net::UdpSocket;
use wirust::intercept::{Action, Interceptor, Interceptors, RequestCtx};
use wirust::wireguard::{Peer, Server, generate_key};
use wirust::{Config, Proxy, RemoteAccess};

/// The documentation range: never reachable, the interceptor below sends it to loopback.
const ORIGIN_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const CLIENT_ADDR: Ipv4Addr = Ipv4Addr::new(10, 233, 0, 2);

/// Sends requests for `origin.test` to the local test server (a map-remote rule).
struct ToLocalOrigin(u16);

impl Interceptor for ToLocalOrigin {
    fn name(&self) -> &'static str {
        "to-local-origin"
    }

    fn on_request(&self, request: &mut RequestCtx) -> Action {
        if request.host == "origin.test" {
            "127.0.0.1".clone_into(&mut request.host);
            request.port = self.0;
        }
        Action::Continue
    }
}

struct Harness {
    proxy_events: tokio::sync::broadcast::Receiver<wirust::events::FlowEvent>,
    server_addr: SocketAddr,
    server_public: PublicKey,
    client_key: StaticSecret,
    dir: std::path::PathBuf,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn start() -> anyhow::Result<Harness> {
    let origin = http_server().await?;
    let dir = temp_dir();
    let mut interceptors = Interceptors::new();
    interceptors.push(Arc::new(ToLocalOrigin(origin)));
    let config = Config {
        listen: "127.0.0.1:0".parse()?,
        interceptors,
        ..Config::new(dir.clone())
    };
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
