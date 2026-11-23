//! Deadlines for client connections: request headers, idleness and the HTTP/2 preface.
//!
//! A [`Watch`] follows one connection. Its IO goes through [`Watched`], which notes reads,
//! and every request holds an [`InFlight`] guard until its response body is done. While a
//! request is in flight there is no deadline, however long it takes; the limits apply only
//! to a connection that has nothing to do:
//!
//! - HTTP/1: the first request, and every later one once its first byte arrived, must
//!   finish its head within [`HEADER_TIMEOUT`]; between requests the connection may idle
//!   for [`IDLE_TIMEOUT`].
//! - HTTP/2: the client preface must arrive within [`PREFACE_TIMEOUT`]; a connection with no
//!   open stream may idle for [`IDLE_TIMEOUT`].
//! - Raw relays (non-TLS CONNECT tunnels): closed after [`IDLE_TIMEOUT`] without a byte in
//!   either direction.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::body::{Body, Frame, SizeHint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, OwnedSemaphorePermit};
use tokio::time::Instant;

/// How long an HTTP/1 client may take to send a request head, counted from the connection's
/// start for the first request and from the first byte for later ones.
pub(crate) const HEADER_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a client connection with no request in flight (or a raw tunnel without traffic)
/// stays open.
pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// How long an HTTP/2 client may take to send its connection preface after the TLS handshake.
pub(crate) const PREFACE_TIMEOUT: Duration = Duration::from_secs(10);

/// Interval of the HTTP/2 PINGs that detect a client which vanished without closing.
pub(crate) const H2_PING_INTERVAL: Duration = Duration::from_secs(60);

/// How long an HTTP/2 PING may go unanswered before the connection is closed.
pub(crate) const H2_PING_TIMEOUT: Duration = Duration::from_secs(20);

/// What a [`Watch`] follows, which decides its deadlines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protocol {
    /// HTTP/1 requests.
    Http1,
    /// An HTTP/2 connection.
    Http2,
    /// Bytes copied both ways without parsing.
    Relay,
}

/// The activity of one client connection.
#[derive(Debug)]
pub(crate) struct Watch {
    protocol: Protocol,
    state: Mutex<State>,
    /// Woken when a deadline may have moved earlier.
    wake: Notify,
}

#[derive(Debug)]
struct State {
    in_flight: usize,
    /// When the connection last had nothing to do.
    idle_since: Instant,
    /// HTTP/1: when the pending request head started. HTTP/2: the start, until the preface.
    waiting_since: Option<Instant>,
}

impl Watch {
    /// A watch for a connection that starts now.
    pub(crate) fn new(protocol: Protocol) -> Arc<Self> {
        let now = Instant::now();
        Arc::new(Self {
            protocol,
            state: Mutex::new(State {
                in_flight: 0,
                idle_since: now,
                waiting_since: (protocol != Protocol::Relay).then_some(now),
            }),
            wake: Notify::new(),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("idle watch lock poisoned")
    }

    /// Marks the start of a request; the connection has no deadline until the guard drops.
    pub(crate) fn begin(self: &Arc<Self>) -> InFlight {
        let mut state = self.state();
        state.in_flight += 1;
        state.waiting_since = None;
        InFlight(Arc::clone(self))
    }

    fn on_read(&self) {
        let mut state = self.state();
        match self.protocol {
            Protocol::Http1 => {
                if state.in_flight == 0 && state.waiting_since.is_none() {
                    state.waiting_since = Some(Instant::now());
                    drop(state);
                    self.wake.notify_one();
                }
            }
            Protocol::Http2 => state.waiting_since = None,
            Protocol::Relay => state.idle_since = Instant::now(),
        }
    }

    fn on_write(&self) {
        if self.protocol == Protocol::Relay {
            self.state().idle_since = Instant::now();
        }
    }

    /// When the connection should close, or `None` while a request is in flight.
    fn deadline(&self) -> Option<Instant> {
        let state = self.state();
        if state.in_flight > 0 {
            return None;
        }
        let deadline = match (self.protocol, state.waiting_since) {
            (Protocol::Http1, Some(since)) => since + HEADER_TIMEOUT,
            (Protocol::Http2, Some(since)) => since + PREFACE_TIMEOUT,
            _ => state.idle_since + IDLE_TIMEOUT,
        };
        Some(deadline)
    }

    /// Completes once the connection is past its deadline.
    async fn expired(&self) {
        loop {
            match self.deadline() {
                Some(deadline) if deadline <= Instant::now() => return,
                Some(deadline) => tokio::select! {
                    () = tokio::time::sleep_until(deadline) => {}
                    () = self.wake.notified() => {}
                },
                None => self.wake.notified().await,
            }
        }
    }

    /// Drives `conn` until it ends (`Some`) or the connection is past its deadline (`None`,
    /// and `conn` is dropped, which closes it).
    ///
    /// Boxed so the `Send` check happens here, on concrete types: as a plain `async fn`
    /// inside a spawned task's future it trips rustc's "`Send` is not general enough"
    /// limitation on the task's other borrows.
    pub(crate) fn guard<F>(
        self: &Arc<Self>,
        conn: F,
    ) -> Pin<Box<dyn Future<Output = Option<F::Output>> + Send>>
    where
        F: Future + Send + 'static,
    {
        let watch = Arc::clone(self);
        Box::pin(async move {
            tokio::select! {
                output = conn => Some(output),
                () = watch.expired() => None,
            }
        })
    }
}

/// A request in flight on a watched connection; see [`Watch::begin`].
#[derive(Debug)]
pub(crate) struct InFlight(Arc<Watch>);

impl InFlight {
    /// Keeps this request in flight until `body` is finished or dropped.
    pub(crate) fn hold<B>(self, body: B) -> Held<B> {
        Held {
            body,
            _flight: self,
        }
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        let mut state = self.0.state();
        state.in_flight -= 1;
        if state.in_flight == 0 {
            state.idle_since = Instant::now();
            drop(state);
            self.0.wake.notify_one();
        }
    }
}

/// A response body that keeps its request in flight.
#[derive(Debug)]
pub(crate) struct Held<B> {
    body: B,
    _flight: InFlight,
}

impl<B: Body + Unpin> Body for Held<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.body).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

/// A client stream that reports its traffic to a [`Watch`] and holds the connection's slot
/// under the client cap for as long as it lives.
#[derive(Debug)]
pub(crate) struct Watched<S> {
    io: S,
    watch: Arc<Watch>,
    _slot: Option<OwnedSemaphorePermit>,
}

impl<S> Watched<S> {
    pub(crate) fn new(io: S, watch: Arc<Watch>, slot: Option<OwnedSemaphorePermit>) -> Self {
        Self {
            io,
            watch,
            _slot: slot,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Watched<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.io).poll_read(cx, buf);
        if matches!(poll, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.watch.on_read();
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Watched<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.io).poll_write(cx, buf);
        if matches!(poll, Poll::Ready(Ok(n)) if n > 0) {
            self.watch.on_write();
        }
        poll
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.io).poll_write_vectored(cx, bufs);
        if matches!(poll, Poll::Ready(Ok(n)) if n > 0) {
            self.watch.on_write();
        }
        poll
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_request_in_flight_has_no_deadline_and_idleness_starts_when_it_ends() {
        let watch = Watch::new(Protocol::Http1);
        assert_eq!(watch.deadline(), Some(Instant::now() + HEADER_TIMEOUT));
        let flight = watch.begin();
        assert_eq!(watch.deadline(), None);
        tokio::time::advance(Duration::from_secs(3600)).await;
        drop(flight);
        assert_eq!(watch.deadline(), Some(Instant::now() + IDLE_TIMEOUT));
        watch.on_read();
        assert_eq!(watch.deadline(), Some(Instant::now() + HEADER_TIMEOUT));
    }

    #[tokio::test(start_paused = true)]
    async fn a_relay_deadline_follows_its_traffic() {
        let watch = Watch::new(Protocol::Relay);
        tokio::time::advance(Duration::from_secs(200)).await;
        watch.on_write();
        assert_eq!(watch.deadline(), Some(Instant::now() + IDLE_TIMEOUT));
    }
}
