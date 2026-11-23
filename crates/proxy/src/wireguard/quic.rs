//! HTTP/3 in the WireGuard capture mode: QUIC to UDP port 443 is terminated in process.
//!
//! The loop in [`super::server`] hands each tunneled datagram to [`TunnelSocket`], which quinn
//! reads as if it were a UDP socket bound to every address: a datagram's destination becomes
//! the connection's local address, and replies leave from it. One quinn endpoint serves every
//! destination. The client leg is HTTP/3 (`h3`); each request then goes through the same
//! forwarding path as an intercepted TLS tunnel, so the upstream leg is HTTP/2 or HTTP/1.1
//! over TCP and every interceptor sees the request as usual.

use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::{Buf as _, Bytes};
use h3::server::{RequestResolver, RequestStream};
use http::{Request, Response};
use http_body_util::BodyExt as _;
use http_body_util::channel::{self, Channel};
use quinn::crypto::rustls::{HandshakeData, QuicServerConfig};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Endpoint, EndpointConfig, Incoming, UdpPoller};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinSet;

use super::server::udp_packet;
use crate::clock::Utc;
use crate::flow::{ClientTls, Event, TlsFailure};
use crate::idle;
use crate::proxy::{HANDSHAKE_TIMEOUT, ProxyBody, QuicClient, State};

/// The UDP port QUIC is terminated on.
pub(super) const QUIC_PORT: u16 = 443;

/// Datagrams queued for quinn before more are dropped, as a congested link would.
const QUEUE: usize = 256;

/// Request body chunks buffered between the HTTP/3 stream and the forwarding path.
const BODY_CHUNKS: usize = 4;

/// QUIC handshakes in progress at once. Separate from the client slots, so a peer that
/// floods Initials cannot take the slots the HTTP listener needs.
const MAX_HANDSHAKES: usize = 64;

/// Largest request header section a client may send (QPACK-decoded), in bytes.
const MAX_HEADERS: u64 = 256 * 1024;

/// Bytes a client may have in flight on one request stream, and on the whole connection.
const STREAM_WINDOW: u32 = 1024 * 1024;
const CONNECTION_WINDOW: u32 = 4 * 1024 * 1024;

/// Concurrent request streams per connection; more wait for the client's flow control.
const MAX_REQUESTS: u32 = 64;

/// Unidirectional streams per connection: HTTP/3 needs three (control, QPACK encoder and
/// decoder); the rest leaves room for the reserved "grease" streams clients send.
const MAX_UNI_STREAMS: u32 = 8;

/// UDP payload QUIC sends: the QUIC minimum, which fits the tunnel MTU (1420) with the IPv4
/// and UDP headers (28 bytes) to spare.
const UDP_PAYLOAD: u16 = 1200;

/// HTTP/3 error code a connection is closed with when its SNI names a refused address
/// (`H3_REQUEST_REJECTED`, RFC 9114).
const REJECTED: u32 = 0x10b;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// One tunneled UDP datagram for port 443.
#[derive(Debug)]
pub(super) struct Datagram {
    /// The peer's tunnel address and source port.
    pub(super) from: SocketAddr,
    /// The address the peer sent to; replies come from it.
    pub(super) to: Ipv4Addr,
    pub(super) payload: Bytes,
}

/// Starts the QUIC endpoint; returns where the loop sends the datagrams for it. Replies
/// come back as IPv4 packets on `inject`, like DNS answers.
///
/// # Errors
///
/// Fails when quinn rejects the TLS configuration or the endpoint cannot start.
pub(super) fn start(
    state: Arc<State>,
    inject: mpsc::Sender<Vec<u8>>,
) -> anyhow::Result<mpsc::Sender<Datagram>> {
    let (tx, rx) = mpsc::channel(QUEUE);
    let socket = Arc::new(TunnelSocket {
        incoming: Mutex::new(rx),
        inject,
    });
    let mut tls = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Certs(Arc::clone(&state))));
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    config.transport_config(Arc::new(transport()?));
    config.max_incoming(MAX_HANDSHAKES);
    let endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    tokio::spawn(accept(endpoint, state));
    Ok(tx)
}

/// The per-connection limits; see `docs/wireguard.md`.
fn transport() -> anyhow::Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    // At most: the client's own idle timeout applies when it is shorter.
    transport.max_idle_timeout(Some(idle::IDLE_TIMEOUT.try_into()?));
    transport.stream_receive_window(STREAM_WINDOW.into());
    transport.receive_window(CONNECTION_WINDOW.into());
    transport.max_concurrent_bidi_streams(MAX_REQUESTS.into());
    transport.max_concurrent_uni_streams(MAX_UNI_STREAMS.into());
    // The tunnel MTU is fixed, and quinn's MTU discovery would probe past it: datagrams stay
    // at the QUIC minimum instead.
    transport.mtu_discovery_config(None);
    transport.initial_mtu(UDP_PAYLOAD);
    transport.min_mtu(UDP_PAYLOAD);
    Ok(transport)
}

/// Accepts connections until the endpoint closes. A handshake takes one of
/// [`MAX_HANDSHAKES`] permits; a completed connection then takes a client slot, like a
/// connection to the HTTP proxy listener. Destinations the guard refuses get no answer.
async fn accept(endpoint: Endpoint, state: Arc<State>) {
    let handshakes = Arc::new(Semaphore::new(MAX_HANDSHAKES));
    while let Some(incoming) = endpoint.accept().await {
        let peer = incoming.remote_address();
        let Some(local) = incoming.local_ip() else {
            incoming.ignore();
            continue;
        };
        if state
            .guard()
            .check(peer.ip(), SocketAddr::new(local, QUIC_PORT))
            .is_err()
        {
            incoming.ignore();
            continue;
        }
        let Ok(permit) = Arc::clone(&handshakes).try_acquire_owned() else {
            incoming.refuse();
            continue;
        };
        tokio::spawn(handshake(Arc::clone(&state), peer, local, incoming, permit));
    }
}

/// Completes one handshake under `permit`, then serves the connection under a client slot.
/// A failed handshake becomes a `TLS-FAIL` record, as on the TCP path.
async fn handshake(
    state: Arc<State>,
    peer: SocketAddr,
    local: IpAddr,
    incoming: Incoming,
    permit: OwnedSemaphorePermit,
) {
    let result = tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming).await;
    drop(permit);
    let reason = match result {
        Ok(Ok(connection)) => {
            let Some(slot) = state.client_slot() else {
                connection.close(REJECTED.into(), b"too many clients");
                return;
            };
            serve_connection(state, peer, connection).await;
            return drop(slot);
        }
        Ok(Err(e)) => e.to_string(),
        Err(_) => "handshake timed out".to_owned(),
    };
    state.emit(Event::TlsFailure(TlsFailure {
        id: state.next_id(),
        time: Utc::now().rfc3339(),
        client: peer,
        target: SocketAddr::new(local, QUIC_PORT).to_string(),
        // quinn reports neither the SNI nor the ClientHello of a failed handshake.
        sni: None,
        ja4: String::new(),
        known_client: None,
        reason: format!("QUIC: {reason}"),
    }));
}

/// Serves the connection's requests, each on its own task; returns when the connection and
/// all its requests are done.
async fn serve_connection(state: Arc<State>, peer: SocketAddr, connection: quinn::Connection) {
    let Some(host) = (connection.handshake_data())
        .and_then(|data| data.downcast::<HandshakeData>().ok())
        .and_then(|data| data.server_name)
    else {
        return;
    };
    // An SNI naming a refused address (`localhost`) gets no requests. An IP literal is not
    // a valid SNI: the client sends none and the handshake already failed.
    if state
        .guard()
        .check_name(peer.ip(), &host, QUIC_PORT)
        .is_err()
    {
        connection.close(REJECTED.into(), b"");
        return;
    }
    let tls = ClientTls {
        version: Some("TLSv1_3".to_owned()),
        alpn: Some("h3".to_owned()),
        sni: Some(host.clone()),
        // quinn does not expose the ClientHello, so QUIC flows carry no fingerprint yet.
        ja4: String::new(),
        ja3_hash: String::new(),
        client: None,
    };
    let client = Arc::new(QuicClient::new(host, tls));
    let closed = connection.clone();
    let quic = h3_quinn::Connection::new(connection);
    let Ok(mut h3) = h3::server::builder()
        .max_field_section_size(MAX_HEADERS)
        .build::<_, Bytes>(quic)
        .await
    else {
        return;
    };
    let mut requests = JoinSet::new();
    // A GOAWAY, a closed connection or a protocol error ends it; each request logged its own
    // outcome.
    while let Ok(Some(resolver)) = h3.accept().await {
        while requests.try_join_next().is_some() {}
        requests.spawn(serve_request(
            Arc::clone(&state),
            Arc::clone(&client),
            peer,
            resolver,
        ));
    }
    // After a GOAWAY the requests in flight finish; once the connection is gone they are
    // cancelled, as hyper drops a request's future when its TCP client disconnects.
    tokio::select! {
        () = async { while requests.join_next().await.is_some() {} } => {}
        _ = closed.closed() => requests.shutdown().await,
    }
    // Dropping `h3` closes the connection.
    drop(h3);
}

/// Serves one request stream: the body streams up while the request is forwarded, and the
/// response streams back as it arrives.
async fn serve_request(
    state: Arc<State>,
    client: Arc<QuicClient>,
    peer: SocketAddr,
    resolver: RequestResolver<h3_quinn::Connection, Bytes>,
) {
    let Ok((request, stream)) = resolver.resolve_request().await else {
        return;
    };
    let (down, up) = stream.split();
    let (body_tx, body) = Channel::<Bytes, BoxError>::new(BODY_CHUNKS);
    tokio::spawn(read_body(up, body_tx));
    let (parts, ()) = request.into_parts();
    let response = client
        .forward(&state, peer, Request::from_parts(parts, body))
        .await;
    write_response(down, response).await;
}

/// Copies a request body from the HTTP/3 stream into the forwarded request.
async fn read_body(
    mut stream: RequestStream<h3_quinn::RecvStream, Bytes>,
    mut body: channel::Sender<Bytes, BoxError>,
) {
    loop {
        match stream.recv_data().await {
            Ok(Some(mut chunk)) => {
                let bytes = chunk.copy_to_bytes(chunk.remaining());
                if body.send_data(bytes).await.is_err() {
                    return;
                }
            }
            Ok(None) => break,
            Err(e) => return body.abort(Box::new(e)),
        }
    }
    if let Ok(Some(trailers)) = stream.recv_trailers().await {
        let _ = body.send_trailers(trailers).await;
    }
}

/// Sends the response head, body and trailers on the HTTP/3 stream.
async fn write_response(
    mut stream: RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    response: Response<ProxyBody>,
) {
    let (parts, mut body) = response.into_parts();
    if stream
        .send_response(Response::from_parts(parts, ()))
        .await
        .is_err()
    {
        return;
    }
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else {
            stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
            return;
        };
        let written = match frame.into_data() {
            Ok(data) => stream.send_data(data).await,
            Err(frame) => match frame.into_trailers() {
                Ok(trailers) => stream.send_trailers(trailers).await,
                Err(_) => Ok(()),
            },
        };
        if written.is_err() {
            return;
        }
    }
    let _ = stream.finish().await;
}

/// Leaf certificates for QUIC from the TCP path's cache, by SNI. No SNI, or a passthrough or
/// `--decrypt-only` exclusion: no certificate, so the handshake fails and the client falls
/// back to TCP.
struct Certs(Arc<State>);

impl fmt::Debug for Certs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Certs")
    }
}

impl ResolvesServerCert for Certs {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = hello.server_name()?.to_owned();
        self.0.quic_tls(&sni)?.cert_resolver.resolve(hello)
    }
}

/// quinn's socket: datagrams the loop hands over in, IPv4 packets for the loop out.
#[derive(Debug)]
struct TunnelSocket {
    incoming: Mutex<mpsc::Receiver<Datagram>>,
    inject: mpsc::Sender<Vec<u8>>,
}

impl AsyncUdpSocket for TunnelSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable {
            inject: self.inject.clone(),
            room: Mutex::new(None),
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        // Every connection has a local address: the destination its first datagram named.
        let Some(source) = transmit.src_ip else {
            return Ok(());
        };
        let from = SocketAddr::new(source, QUIC_PORT);
        let size = transmit
            .segment_size
            .unwrap_or(transmit.contents.len())
            .max(1);
        // A full queue pushes back: quinn keeps the datagram and waits for `Writable`.
        if self.inject.capacity() < transmit.contents.len().div_ceil(size) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        for segment in transmit.contents.chunks(size) {
            if let Some(packet) = udp_packet(from, transmit.destination, segment) {
                // Only this endpoint sends with full capacity checked; a DNS answer that took
                // the room meanwhile drops this datagram, and QUIC resends it.
                let _ = self.inject.try_send(packet);
            }
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut incoming = self
            .incoming
            .lock()
            .map_err(|_| io::Error::other("QUIC socket lock poisoned"))?;
        let mut count = 0;
        for (buf, meta) in bufs.iter_mut().zip(meta.iter_mut()) {
            let datagram = if count == 0 {
                match incoming.poll_recv(cx) {
                    Poll::Ready(Some(datagram)) => datagram,
                    Poll::Ready(None) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                match incoming.try_recv() {
                    Ok(datagram) => datagram,
                    Err(_) => break,
                }
            };
            let len = datagram.payload.len().min(buf.len());
            buf[..len].copy_from_slice(&datagram.payload[..len]);
            *meta = RecvMeta {
                addr: datagram.from,
                len,
                stride: len,
                ecn: None,
                dst_ip: Some(IpAddr::V4(datagram.to)),
            };
            count += 1;
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            QUIC_PORT,
        ))
    }
}

/// A wait for room in the loop's packet queue.
type Room = Pin<Box<dyn Future<Output = Result<(), mpsc::error::SendError<()>>> + Send>>;

/// Ready when the loop's packet queue has room again.
struct Writable {
    inject: mpsc::Sender<Vec<u8>>,
    /// The wait in progress; behind a lock only because quinn wants the poller `Sync`.
    room: Mutex<Option<Room>>,
}

impl fmt::Debug for Writable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Writable").finish_non_exhaustive()
    }
}

impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let room = this
            .room
            .get_mut()
            .map_err(|_| io::Error::other("QUIC poller lock poisoned"))?;
        let wait = room.get_or_insert_with(|| {
            let inject = this.inject.clone();
            // The permit is released at once: it only signals that a slot is free.
            Box::pin(async move { inject.reserve_owned().await.map(drop) })
        });
        let ready = wait.as_mut().poll(cx);
        if ready.is_ready() {
            *room = None;
        }
        ready.map(|result| result.map_err(|_| io::ErrorKind::BrokenPipe.into()))
    }
}
