//! HTTP/3 in the WireGuard capture mode: QUIC to UDP port 443 is terminated in process.
//!
//! The loop in [`super::server`] hands each tunneled datagram to [`TunnelSocket`], which quinn
//! reads as if it were a UDP socket bound to every address: a datagram's destination becomes
//! the connection's local address, and replies leave from it. One quinn endpoint serves every
//! destination. The client leg is HTTP/3 (`h3`); each request then goes through the same
//! forwarding path as an intercepted TLS tunnel, so the upstream leg is HTTP/2 or HTTP/1.1
//! over TCP and every interceptor sees the request as usual.

use std::fmt;
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
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use super::server::udp_packet;
use crate::flow::ClientTls;
use crate::idle;
use crate::proxy::{HANDSHAKE_TIMEOUT, ProxyBody, QuicClient, State};

/// The UDP port QUIC is terminated on.
pub(super) const QUIC_PORT: u16 = 443;

/// Datagrams queued for quinn before more are dropped, as a congested link would.
const QUEUE: usize = 256;

/// Request body chunks buffered between the HTTP/3 stream and the forwarding path.
const BODY_CHUNKS: usize = 4;

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
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(idle::IDLE_TIMEOUT.try_into()?));
    config.transport_config(Arc::new(transport));
    let endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    tokio::spawn(accept(endpoint, state));
    Ok(tx)
}

/// Accepts connections until the endpoint closes. Each one takes a client slot, like a
/// connection to the HTTP proxy listener; destinations the guard refuses get no answer.
async fn accept(endpoint: Endpoint, state: Arc<State>) {
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
        let Some(slot) = state.client_slot() else {
            incoming.refuse();
            continue;
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            serve_connection(state, peer, incoming).await;
            drop(slot);
        });
    }
}

/// Completes the handshake and serves the connection's requests, each on its own task;
/// returns when the connection and all its requests are done.
async fn serve_connection(state: Arc<State>, peer: SocketAddr, incoming: Incoming) {
    let Ok(Ok(connection)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming).await else {
        return;
    };
    let Some(host) = (connection.handshake_data())
        .and_then(|data| data.downcast::<HandshakeData>().ok())
        .and_then(|data| data.server_name)
    else {
        return;
    };
    // An SNI naming a refused address (`localhost`, a loopback literal) gets no requests.
    if state
        .guard()
        .check_name(peer.ip(), &host, QUIC_PORT)
        .is_err()
    {
        connection.close(0_u32.into(), b"");
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
    let quic = h3_quinn::Connection::new(connection);
    let Ok(mut h3) = h3::server::Connection::<_, Bytes>::new(quic).await else {
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
    // Dropping `h3` closes the connection: requests still in flight (after a GOAWAY) finish
    // first.
    while requests.join_next().await.is_some() {}
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
        Box::pin(Writable)
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
        for segment in transmit.contents.chunks(size) {
            if let Some(packet) = udp_packet(from, transmit.destination, segment) {
                // A full queue drops the datagram, as a congested link would; QUIC resends.
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

/// Sending never blocks: a full queue drops the datagram instead.
#[derive(Debug)]
struct Writable;

impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
