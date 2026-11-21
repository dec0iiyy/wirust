//! Streaming bodies that keep a bounded copy of what passes through them.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};

/// Trailer fields a [`Capture`] keeps.
const MAX_TRAILERS: usize = 64;

/// Bytes of trailer names and values a [`Capture`] keeps.
const MAX_TRAILER_BYTES: usize = 16 * 1024;

/// The first bytes of a body plus its full size, and its trailers (HTTP/2 or chunked).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capture {
    limit: usize,
    data: Vec<u8>,
    size: u64,
    trailers: Vec<(String, String)>,
}

impl Capture {
    /// An empty capture that keeps at most `limit` bytes.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            data: Vec::new(),
            size: 0,
            trailers: Vec::new(),
        }
    }

    /// Records a trailer block, up to 64 fields and 16 KiB of names and values.
    pub fn push_trailers(&mut self, trailers: &http::HeaderMap) {
        let mut used: usize = self.trailers.iter().map(|(k, v)| k.len() + v.len()).sum();
        for (name, value) in trailers {
            let value = String::from_utf8_lossy(value.as_bytes());
            used += name.as_str().len() + value.len();
            if self.trailers.len() == MAX_TRAILERS || used > MAX_TRAILER_BYTES {
                break;
            }
            self.trailers
                .push((name.as_str().to_owned(), value.into_owned()));
        }
    }

    /// The kept trailers, in the order received.
    #[must_use]
    pub fn trailers(&self) -> &[(String, String)] {
        &self.trailers
    }

    /// Records one chunk: all of it counts toward the size, the part under the limit is kept.
    pub fn push(&mut self, chunk: &[u8]) {
        self.size += chunk.len() as u64;
        let room = self.limit.saturating_sub(self.data.len());
        self.data.extend_from_slice(&chunk[..room.min(chunk.len())]);
    }

    /// The most bytes this capture keeps.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// The kept bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Total bytes seen.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Whether bytes were seen past the limit.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.size > self.data.len() as u64
    }
}

/// A capture shared between the body that fills it and the code that reads it.
pub type SharedCapture = Arc<Mutex<Capture>>;

/// Called once when the body ends: `None` on a clean end, otherwise why it stopped.
pub type OnEnd = Box<dyn FnOnce(Option<String>) + Send>;

/// Wraps a body, copying data frames into a [`Capture`] as they are forwarded.
///
/// The `Body` bound sits on the struct because `Drop` needs it: a body hyper never polls
/// (empty, already at its end) must still report a clean end.
pub struct Tee<B: Body> {
    inner: B,
    capture: SharedCapture,
    on_end: Option<OnEnd>,
}

impl<B: Body> std::fmt::Debug for Tee<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tee").finish_non_exhaustive()
    }
}

impl<B: Body> Tee<B> {
    /// Forwards `inner`, filling `capture`, and calls `on_end` when it ends or is dropped.
    pub fn new(inner: B, capture: SharedCapture, on_end: Option<OnEnd>) -> Self {
        Self {
            inner,
            capture,
            on_end,
        }
    }

    fn finish(&mut self, error: Option<String>) {
        if let Some(on_end) = self.on_end.take() {
            on_end(error);
        }
    }
}

impl<B> Body for Tee<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.capture
                        .lock()
                        .expect("capture lock poisoned")
                        .push(data);
                } else if let Some(trailers) = frame.trailers_ref() {
                    this.capture
                        .lock()
                        .expect("capture lock poisoned")
                        .push_trailers(trailers);
                }
            }
            Poll::Ready(Some(Err(e))) => this.finish(Some(e.to_string())),
            Poll::Ready(None) => this.finish(None),
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<B: Body> Drop for Tee<B> {
    fn drop(&mut self) {
        let error = (!self.inner.is_end_stream())
            .then(|| "the client stopped reading before the body ended".to_owned());
        self.finish(error);
    }
}

/// A body whose first bytes were already read: yields `head`, then the rest of `inner`.
#[derive(Debug)]
pub struct Prepend<B> {
    head: Option<Bytes>,
    inner: B,
}

impl<B> Prepend<B> {
    /// Replays `head` ahead of `inner`.
    pub fn new(head: Bytes, inner: B) -> Self {
        Self {
            head: Some(head).filter(|h| !h.is_empty()),
            inner,
        }
    }
}

impl<B> Body for Prepend<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        let this = self.get_mut();
        if let Some(head) = this.head.take() {
            return Poll::Ready(Some(Ok(Frame::data(head))));
        }
        Pin::new(&mut this.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.head.is_none() && self.inner.is_end_stream()
    }
}

/// A body read into memory, or the reason it was not.
#[derive(Debug)]
pub enum Buffered<B> {
    /// The whole body (trailers are dropped).
    Whole(Bytes),
    /// The body passed the limit; this replays what was read, then streams the rest.
    TooLarge(Prepend<B>),
}

/// Reads `body` into memory if it is at most `limit` bytes.
///
/// # Errors
///
/// Fails when reading the body fails.
pub async fn buffer<B>(mut body: B, limit: usize) -> Result<Buffered<B>, B::Error>
where
    B: Body<Data = Bytes> + Unpin,
{
    use http_body_util::BodyExt as _;
    let mut data = Vec::new();
    while let Some(frame) = body.frame().await {
        if let Some(chunk) = frame?.data_ref() {
            data.extend_from_slice(chunk);
            if data.len() > limit {
                return Ok(Buffered::TooLarge(Prepend::new(Bytes::from(data), body)));
            }
        }
    }
    Ok(Buffered::Whole(Bytes::from(data)))
}

#[cfg(test)]
mod tests {
    use http_body_util::{BodyExt as _, Full};

    use super::*;

    #[test]
    fn keeps_the_head_and_counts_everything() {
        let mut capture = Capture::new(4);
        capture.push(b"abc");
        capture.push(b"defg");
        assert_eq!(capture.data(), b"abcd");
        assert_eq!(capture.size(), 7);
        assert!(capture.truncated());
    }

    #[tokio::test]
    async fn forwards_the_whole_body_and_reports_the_end() {
        let capture = Arc::new(Mutex::new(Capture::new(2)));
        let (tx, rx) = std::sync::mpsc::channel();
        let on_end: OnEnd = Box::new(move |error| tx.send(error).expect("receiver alive"));
        let tee = Tee::new(
            Full::new(Bytes::from_static(b"hello")),
            Arc::clone(&capture),
            Some(on_end),
        );
        let body = tee.collect().await.expect("infallible").to_bytes();
        assert_eq!(&body[..], b"hello");
        assert_eq!(rx.recv().expect("on_end called"), None);
        let capture = capture.lock().expect("lock");
        assert_eq!(capture.data(), b"he");
        assert!(capture.truncated());
    }

    #[tokio::test]
    async fn buffering_stops_at_the_limit_and_loses_nothing() -> Result<(), std::convert::Infallible>
    {
        let small = buffer(Full::new(Bytes::from_static(b"abc")), 3).await?;
        assert!(matches!(small, Buffered::Whole(b) if &b[..] == b"abc"));
        let Buffered::TooLarge(rest) = buffer(Full::new(Bytes::from_static(b"abcd")), 3).await?
        else {
            panic!("4 bytes are over a 3-byte limit");
        };
        assert_eq!(&rest.collect().await?.to_bytes()[..], b"abcd");
        Ok(())
    }
}
