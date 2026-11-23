//! The WireGuard listener: noise sessions per configured peer, a userspace TCP/IP stack that
//! terminates every tunneled TCP connection, a QUIC endpoint for UDP port 443, and a DNS
//! relay.
//!
//! One task owns the UDP socket, the noise sessions and the TCP/IP stack. Each accepted TCP
//! connection is bridged to an in-memory stream that [`serve_transparent`] reads as if the
//! peer had sent CONNECT to the original destination. QUIC datagrams go to [`quic`]'s
//! endpoint, whose replies come back like DNS answers.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use bytes::Bytes;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Packet, Ipv4Repr, TcpPacket, UdpPacket,
    UdpRepr,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::config::{PREFIX_LEN, Peer, SERVER_ADDR};
use super::quic::{self, Datagram, QUIC_PORT};
use crate::clock::Utc;
use crate::flow::{Event, Tunnel};
use crate::proxy::{State, serve_transparent};
use crate::{Proxy, RemoteAccess, check_listen};

/// The tunnel MTU: the WireGuard app's default, so the stack never sees larger packets.
const MTU: usize = 1420;

/// How often the noise timers run (handshake retries, keepalives, session expiry).
const TIMER_TICK: Duration = Duration::from_millis(250);

/// How soon the loop retries a connection whose handler is not reading yet.
const BLOCKED_RETRY: Duration = Duration::from_millis(5);

/// Bytes each side of a terminated TCP connection buffers in the stack and in the bridge.
const TCP_BUFFER: usize = 64 * 1024;

/// How long a relayed DNS query waits for the host's resolver.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// Packets waiting to be encrypted for the peers (DNS answers, QUIC datagrams).
const INJECT_QUEUE: usize = 256;

/// Largest UDP datagram.
const DATAGRAM: usize = 65_535;

/// A bound WireGuard listener, ready to [`run`](Self::run).
pub struct Server {
    socket: UdpSocket,
    state: Arc<State>,
    key: StaticSecret,
    peers: Vec<Peer>,
    resolver: Option<SocketAddr>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("socket", &self.socket)
            .field("peers", &self.peers)
            .field("resolver", &self.resolver)
            .finish_non_exhaustive()
    }
}

impl Server {
    /// Binds the UDP listener for `proxy`; terminated connections become `proxy`'s flows.
    ///
    /// `resolver` receives the DNS queries peers send; without one they are dropped.
    ///
    /// # Errors
    ///
    /// Fails on a non-loopback `listen` without [`RemoteAccess::Allow`] or a bind error.
    pub async fn bind(
        proxy: &Proxy,
        listen: SocketAddr,
        remote: RemoteAccess,
        key: StaticSecret,
        peers: Vec<Peer>,
        resolver: Option<SocketAddr>,
    ) -> anyhow::Result<Self> {
        check_listen(listen, remote)?;
        let socket = UdpSocket::bind(listen)
            .await
            .with_context(|| format!("binding UDP {listen}"))?;
        Ok(Self {
            socket,
            state: proxy.shared_state(),
            key,
            peers,
            resolver,
        })
    }

    /// The bound UDP address.
    ///
    /// # Errors
    ///
    /// Fails if the OS cannot report it.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// The server's public key, for client configurations.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.key)
    }

    /// Serves peers until the socket fails.
    ///
    /// # Errors
    ///
    /// Fails when sending on the UDP socket fails.
    pub async fn run(self) -> anyhow::Result<()> {
        let Self {
            socket,
            state,
            key,
            peers,
            resolver,
        } = self;
        let (down_tx, mut down_rx) = mpsc::channel(256);
        // Packets from the DNS relay and the QUIC endpoint; QUIC waits when it is full.
        let (inject_tx, mut inject_rx) = mpsc::channel(INJECT_QUEUE);
        let quic = match quic::start(Arc::clone(&state), inject_tx.clone()) {
            Ok(quic) => Some(quic),
            Err(e) => {
                eprintln!(
                    "{}: wireguard: HTTP/3 is off, QUIC will be dropped: {e:#}",
                    crate::NAME
                );
                None
            }
        };
        let mut engine = Engine::new(state, key, peers, resolver, down_tx, inject_tx);
        engine.quic = quic;
        let mut datagram = vec![0_u8; DATAGRAM];
        let mut next_timers = tokio::time::Instant::now() + TIMER_TICK;
        loop {
            let delay = engine.poll_delay();
            let wake = tokio::select! {
                received = socket.recv_from(&mut datagram) => match received {
                    Ok((len, from)) => Wake::Datagram(len, from),
                    // An ICMP error for an earlier send; the next datagram is unaffected.
                    Err(_) => Wake::Timer,
                },
                Some((handle, data)) = down_rx.recv() => Wake::Down(handle, data),
                Some(packet) = inject_rx.recv() => Wake::Inject(packet),
                () = tokio::time::sleep(delay) => Wake::Timer,
            };
            match wake {
                Wake::Datagram(len, from) => {
                    engine.datagram(&socket, &datagram[..len], from).await?;
                }
                Wake::Down(handle, data) => engine.down(handle, data),
                Wake::Inject(packet) => engine.device.tx.push_back(packet),
                Wake::Timer => {}
            }
            if tokio::time::Instant::now() >= next_timers {
                engine.timers(&socket).await?;
                next_timers = tokio::time::Instant::now() + TIMER_TICK;
            }
            engine.service();
            engine.flush(&socket).await?;
        }
    }
}

enum Wake {
    Datagram(usize, SocketAddr),
    Down(SocketHandle, Option<Bytes>),
    Inject(Vec<u8>),
    Timer,
}

/// One configured peer and its noise session.
struct PeerState {
    peer: Peer,
    tunn: Tunn,
    /// Where the peer's last authenticated datagram came from.
    endpoint: Option<SocketAddr>,
}

/// One terminated TCP connection.
struct Conn {
    /// Whether the handler was spawned (after the handshake completed).
    started: bool,
    /// Bytes from the peer to the handler; `None` once the peer finished sending.
    up: Option<mpsc::Sender<Bytes>>,
    /// Bytes from the handler not yet accepted by the stack.
    pending: Vec<u8>,
    /// Whether the handler finished sending.
    down_closed: bool,
}

/// Everything the loop owns besides the socket and the receivers.
struct Engine {
    state: Arc<State>,
    key: StaticSecret,
    public: PublicKey,
    peers: Vec<PeerState>,
    resolver: Option<SocketAddr>,
    iface: Interface,
    device: Queue,
    sockets: SocketSet<'static>,
    conns: HashMap<SocketHandle, Conn>,
    blocked: bool,
    down_tx: mpsc::Sender<(SocketHandle, Option<Bytes>)>,
    inject_tx: mpsc::Sender<Vec<u8>>,
    /// The QUIC endpoint's datagram queue; `None` when it could not start.
    quic: Option<mpsc::Sender<Datagram>>,
    quic_reported: bool,
    dropped_ports: HashSet<u16>,
    out: Vec<u8>,
}

impl Engine {
    fn new(
        state: Arc<State>,
        key: StaticSecret,
        peers: Vec<Peer>,
        resolver: Option<SocketAddr>,
        down_tx: mpsc::Sender<(SocketHandle, Option<Bytes>)>,
        inject_tx: mpsc::Sender<Vec<u8>>,
    ) -> Self {
        let public = PublicKey::from(&key);
        let peers = (peers.into_iter().enumerate())
            .map(|(index, peer)| PeerState {
                // The index tags every session of the peer, so data packets find it.
                tunn: Tunn::new(
                    key.clone(),
                    PublicKey::from(peer.public_key),
                    None,
                    None,
                    u32::try_from(index).unwrap_or(u32::MAX) & 0x00ff_ffff,
                    None,
                ),
                peer,
                endpoint: None,
            })
            .collect();
        let mut device = Queue::default();
        let mut config = IfaceConfig::new(HardwareAddress::Ip);
        let mut seed = [0_u8; 8];
        // A fixed seed only makes initial sequence numbers predictable inside the tunnel.
        let _ = aws_lc_rs::rand::fill(&mut seed);
        config.random_seed = u64::from_le_bytes(seed);
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());
        iface.update_ip_addrs(|addrs| {
            let cidr = IpCidr::new(IpAddress::Ipv4(SERVER_ADDR), PREFIX_LEN);
            // The list is empty, so the push cannot overflow.
            let _ = addrs.push(cidr);
        });
        // Every destination is routed via our own address, which with any_ip makes the
        // stack accept packets for any address: the transparent part.
        let _ = iface.routes_mut().add_default_ipv4_route(SERVER_ADDR);
        iface.set_any_ip(true);
        Self {
            state,
            key,
            public,
            peers,
            resolver,
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            conns: HashMap::new(),
            blocked: false,
            down_tx,
            inject_tx,
            quic: None,
            quic_reported: false,
            dropped_ports: HashSet::new(),
            out: vec![0; DATAGRAM],
        }
    }

    fn poll_delay(&mut self) -> Duration {
        let stack = (self.iface.poll_delay(SmolInstant::now(), &self.sockets))
            .map_or(TIMER_TICK, |d| Duration::from_micros(d.total_micros()));
        let delay = stack.min(TIMER_TICK);
        if self.blocked {
            delay.min(BLOCKED_RETRY)
        } else {
            delay
        }
    }

    /// Handles one UDP datagram: handshakes only for configured keys, data only for
    /// established sessions.
    async fn datagram(
        &mut self,
        socket: &UdpSocket,
        datagram: &[u8],
        from: SocketAddr,
    ) -> anyhow::Result<()> {
        let index = match Tunn::parse_incoming_packet(datagram) {
            Ok(Packet::HandshakeInit(init)) => {
                let Ok(half) = parse_handshake_anon(&self.key, &self.public, &init) else {
                    return Ok(());
                };
                let found = (self.peers.iter())
                    .position(|state| state.peer.public_key == half.peer_static_public);
                // An unknown key gets no answer at all, so scanning reveals nothing.
                let Some(index) = found else { return Ok(()) };
                index
            }
            Ok(Packet::HandshakeResponse(p)) => (p.receiver_idx >> 8) as usize,
            Ok(Packet::PacketCookieReply(p)) => (p.receiver_idx >> 8) as usize,
            Ok(Packet::PacketData(p)) => (p.receiver_idx >> 8) as usize,
            Err(_) => return Ok(()),
        };
        let Some(state) = self.peers.get_mut(index) else {
            return Ok(());
        };
        let mut packets = Vec::new();
        let mut input = datagram;
        loop {
            match state
                .tunn
                .decapsulate(Some(from.ip()), input, &mut self.out)
            {
                TunnResult::WriteToNetwork(reply) => {
                    socket.send_to(reply, from).await?;
                    state.endpoint = Some(from);
                    // The docs ask for repeated calls until Done, to flush queued packets.
                    input = &[];
                }
                TunnResult::WriteToTunnelV4(packet, source) => {
                    state.endpoint = Some(from);
                    // The peer may only send from its own tunnel address.
                    if source == state.peer.address {
                        packets.push(packet.to_vec());
                    }
                    break;
                }
                TunnResult::WriteToTunnelV6(..) => {
                    state.endpoint = Some(from);
                    break;
                }
                TunnResult::Done | TunnResult::Err(_) => break,
            }
        }
        let client = state.peer.address;
        for packet in packets {
            self.ip_packet(client, packet);
        }
        Ok(())
    }

    /// Routes one IPv4 packet from a peer: TCP into the stack, UDP to the DNS relay or away.
    fn ip_packet(&mut self, client: Ipv4Addr, packet: Vec<u8>) {
        let Ok(ip) = Ipv4Packet::new_checked(&packet[..]) else {
            return;
        };
        match ip.next_header() {
            IpProtocol::Tcp => {
                if let Ok(segment) = TcpPacket::new_checked(ip.payload())
                    && segment.syn()
                    && !segment.ack()
                {
                    let src = SocketAddr::new(IpAddr::V4(ip.src_addr()), segment.src_port());
                    let dst = SocketAddr::new(IpAddr::V4(ip.dst_addr()), segment.dst_port());
                    self.listen_for(src, dst);
                }
                self.device.rx.push_back(packet);
            }
            IpProtocol::Udp => self.udp(client, &ip),
            // ICMP and the rest: the stack would only answer pings to its own address.
            _ => {}
        }
    }

    /// Opens a listening socket for a new connection from `src` to `dst`, unless one exists.
    fn listen_for(&mut self, src: SocketAddr, dst: SocketAddr) {
        let IpAddr::V4(dst_ip) = dst.ip() else { return };
        if !terminable(dst_ip) {
            return;
        }
        let exists = self.conns.keys().any(|handle| {
            let socket = self.sockets.get::<tcp::Socket>(*handle);
            let local = socket
                .local_endpoint()
                .map(|e| endpoint_addr(e.addr, e.port));
            let remote = socket
                .remote_endpoint()
                .map(|e| endpoint_addr(e.addr, e.port));
            let listening = socket.state() == tcp::State::Listen
                && socket.listen_endpoint().port == dst.port()
                && socket.listen_endpoint().addr == Some(IpAddress::Ipv4(dst_ip));
            listening || (remote == Some(src) && local == Some(dst))
        });
        if exists {
            return;
        }
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
        );
        if socket
            .listen((IpAddress::Ipv4(dst_ip), dst.port()))
            .is_err()
        {
            return;
        }
        let handle = self.sockets.add(socket);
        self.conns.insert(
            handle,
            Conn {
                started: false,
                up: None,
                pending: Vec::new(),
                down_closed: false,
            },
        );
    }

    /// DNS goes to the host's resolver, QUIC to the QUIC endpoint, the rest of UDP is dropped.
    fn udp(&mut self, client: Ipv4Addr, ip: &Ipv4Packet<&[u8]>) {
        let Ok(udp) = UdpPacket::new_checked(ip.payload()) else {
            return;
        };
        match udp.dst_port() {
            53 => {
                let Some(resolver) = self.resolver else {
                    self.report_dropped(53, "no DNS resolver is configured");
                    return;
                };
                let query = udp.payload().to_vec();
                let reply_from = SocketAddr::new(IpAddr::V4(ip.dst_addr()), 53);
                let reply_to = SocketAddr::new(IpAddr::V4(client), udp.src_port());
                tokio::spawn(relay_dns(
                    resolver,
                    query,
                    reply_from,
                    reply_to,
                    self.inject_tx.clone(),
                ));
            }
            QUIC_PORT => {
                let Some(quic) = &self.quic else {
                    if !self.quic_reported {
                        self.quic_reported = true;
                        self.report_quic(client, ip.dst_addr());
                    }
                    return;
                };
                if !terminable(ip.dst_addr()) {
                    return;
                }
                // A full queue drops the datagram, as a congested link would; QUIC resends.
                let _ = quic.try_send(Datagram {
                    from: SocketAddr::new(IpAddr::V4(client), udp.src_port()),
                    to: ip.dst_addr(),
                    payload: Bytes::copy_from_slice(udp.payload()),
                });
            }
            port => self.report_dropped(port, "only DNS is relayed over UDP"),
        }
    }

    /// Puts one line in the flow log: QUIC is dropped on purpose and clients fall back to TCP.
    fn report_quic(&self, client: Ipv4Addr, dst: Ipv4Addr) {
        self.state.emit(Event::Tunnel(Tunnel {
            id: self.state.next_id(),
            time: Utc::now().rfc3339(),
            client: SocketAddr::new(IpAddr::V4(client), 0),
            target: format!("{dst}:443"),
            bytes_up: 0,
            bytes_down: 0,
            error: Some(
                "UDP/443 (QUIC, HTTP/3) is dropped: the QUIC endpoint did not start; clients \
                 fall back to TCP. Reported once."
                    .to_owned(),
            ),
            reason: None,
            tls: None,
            duration_ms: None,
        }));
    }

    fn report_dropped(&mut self, port: u16, why: &str) {
        if self.dropped_ports.insert(port) {
            eprintln!(
                "{}: wireguard: dropping UDP to port {port}: {why} (reported once per port)",
                crate::NAME
            );
        }
    }

    /// Data the handler of `handle` sent back; `None` when it finished.
    fn down(&mut self, handle: SocketHandle, data: Option<Bytes>) {
        let Some(conn) = self.conns.get_mut(&handle) else {
            return;
        };
        match data {
            Some(bytes) => conn.pending.extend_from_slice(&bytes),
            None => conn.down_closed = true,
        }
    }

    /// Runs the stack and moves bytes between its sockets and the handlers.
    fn service(&mut self) {
        self.iface
            .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
        self.blocked = false;
        let mut finished = Vec::new();
        for (handle, conn) in &mut self.conns {
            let socket = self.sockets.get_mut::<tcp::Socket>(*handle);
            if !conn.started && socket.state() == tcp::State::Established {
                let (Some(local), Some(remote)) =
                    (socket.local_endpoint(), socket.remote_endpoint())
                else {
                    continue;
                };
                conn.started = true;
                let (near, far) = tokio::io::duplex(TCP_BUFFER);
                let (up_tx, up_rx) = mpsc::channel(16);
                conn.up = Some(up_tx);
                tokio::spawn(bridge(far, up_rx, self.down_tx.clone(), *handle));
                tokio::spawn(serve_transparent(
                    Arc::clone(&self.state),
                    endpoint_addr(remote.addr, remote.port),
                    endpoint_addr(local.addr, local.port),
                    near,
                ));
            }
            if conn.started {
                while socket.can_recv() {
                    let Some(up) = &conn.up else { break };
                    let closed = match up.try_reserve() {
                        Ok(permit) => {
                            let read =
                                socket.recv(|data| (data.len(), Bytes::copy_from_slice(data)));
                            if let Ok(bytes) = read {
                                permit.send(bytes);
                            }
                            false
                        }
                        Err(mpsc::error::TrySendError::Full(())) => {
                            // Leaving the bytes in the stack shrinks the peer's window.
                            self.blocked = true;
                            break;
                        }
                        Err(mpsc::error::TrySendError::Closed(())) => true,
                    };
                    if closed {
                        conn.up = None;
                        socket.abort();
                        break;
                    }
                }
                if !socket.may_recv() && !socket.can_recv() {
                    // The peer sent FIN: the handler sees the end of its input.
                    conn.up = None;
                }
                if !conn.pending.is_empty()
                    && socket.can_send()
                    && let Ok(sent) = socket.send_slice(&conn.pending)
                {
                    conn.pending.drain(..sent);
                }
                if conn.down_closed && conn.pending.is_empty() {
                    socket.close();
                }
            }
            if matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait) {
                finished.push(*handle);
            }
        }
        for handle in finished {
            self.conns.remove(&handle);
            self.sockets.remove(handle);
        }
        // Send what the sockets queued in this round.
        self.iface
            .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
    }

    /// Encrypts and sends every packet the stack or the DNS relay produced.
    async fn flush(&mut self, socket: &UdpSocket) -> anyhow::Result<()> {
        while let Some(packet) = self.device.tx.pop_front() {
            let Some(IpAddr::V4(dst)) = Tunn::dst_address(&packet) else {
                continue;
            };
            let Some(state) = self.peers.iter_mut().find(|s| s.peer.address == dst) else {
                continue;
            };
            let Some(endpoint) = state.endpoint else {
                continue;
            };
            if let TunnResult::WriteToNetwork(datagram) =
                state.tunn.encapsulate(&packet, &mut self.out)
            {
                socket.send_to(datagram, endpoint).await?;
            }
        }
        Ok(())
    }

    /// Runs the noise timers of every peer that has been seen.
    async fn timers(&mut self, socket: &UdpSocket) -> anyhow::Result<()> {
        for state in &mut self.peers {
            let Some(endpoint) = state.endpoint else {
                continue;
            };
            if let TunnResult::WriteToNetwork(datagram) = state.tunn.update_timers(&mut self.out) {
                socket.send_to(datagram, endpoint).await?;
            }
        }
        Ok(())
    }
}

/// Whether connections to `dst` are terminated: not the tunnel's own address, broadcast,
/// multicast, unspecified or loopback.
fn terminable(dst: Ipv4Addr) -> bool {
    !(dst == SERVER_ADDR
        || dst.is_broadcast()
        || dst.is_multicast()
        || dst.is_unspecified()
        || dst.is_loopback())
}

fn endpoint_addr(addr: IpAddress, port: u16) -> SocketAddr {
    match addr {
        IpAddress::Ipv4(v4) => SocketAddr::new(IpAddr::V4(v4), port),
    }
}

/// Copies between the handler's in-memory stream and the loop's channels.
async fn bridge(
    far: DuplexStream,
    mut up: mpsc::Receiver<Bytes>,
    down: mpsc::Sender<(SocketHandle, Option<Bytes>)>,
    handle: SocketHandle,
) {
    let (mut reader, mut writer) = tokio::io::split(far);
    let to_handler = async {
        while let Some(bytes) = up.recv().await {
            if writer.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    };
    let from_handler = async {
        let mut buf = vec![0_u8; 16 * 1024];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = down.send((handle, None)).await;
                    break;
                }
                Ok(n) => {
                    let bytes = Bytes::copy_from_slice(&buf[..n]);
                    if down.send((handle, Some(bytes))).await.is_err() {
                        break;
                    }
                }
            }
        }
    };
    tokio::join!(to_handler, from_handler);
}

/// Sends one DNS query to `resolver` and injects the answer as a UDP packet from
/// `reply_from` to `reply_to`.
async fn relay_dns(
    resolver: SocketAddr,
    query: Vec<u8>,
    reply_from: SocketAddr,
    reply_to: SocketAddr,
    inject: mpsc::Sender<Vec<u8>>,
) {
    let bind: SocketAddr = if resolver.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let Ok(socket) = UdpSocket::bind(bind).await else {
        return;
    };
    if socket.send_to(&query, resolver).await.is_err() {
        return;
    }
    let mut answer = vec![0_u8; DATAGRAM];
    let Ok(Ok((len, from))) =
        tokio::time::timeout(DNS_TIMEOUT, socket.recv_from(&mut answer)).await
    else {
        return;
    };
    if from != resolver {
        return;
    }
    if let Some(packet) = udp_packet(reply_from, reply_to, &answer[..len]) {
        let _ = inject.send(packet).await;
    }
}

/// An IPv4 UDP packet; `None` for IPv6 addresses.
pub(super) fn udp_packet(from: SocketAddr, to: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let (IpAddr::V4(src), IpAddr::V4(dst)) = (from.ip(), to.ip()) else {
        return None;
    };
    let udp = UdpRepr {
        src_port: from.port(),
        dst_port: to.port(),
    };
    let ip = Ipv4Repr {
        src_addr: src,
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
        &IpAddress::Ipv4(src),
        &IpAddress::Ipv4(dst),
        payload.len(),
        |out| out.copy_from_slice(payload),
        &caps,
    );
    Some(buffer)
}

/// The stack's network device: two packet queues the loop fills and drains.
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
        caps.max_transmission_unit = MTU;
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
