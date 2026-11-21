//! A body wrapper that caps bandwidth and adds latency without buffering the whole body.
//!
//! [`Throttled`] passes each data frame on in chunks of about a tenth of a second's worth of
//! bytes, releasing a chunk only when the bytes sent so far fit the configured rate. Trailers
//! and errors pass through unchanged.

use std::future::Future as _;
use std::num::NonZeroU64;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use tokio::time::{Instant, Sleep};

/// Largest chunk released at once, so a high rate still streams in pieces.
const MAX_CHUNK: u64 = 64 * 1024;

/// A bandwidth cap and a latency for a response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Throttle {
    /// Bytes per second.
    pub rate: NonZeroU64,
    /// Time before the first byte.
    pub latency: Duration,
}

impl Throttle {
    /// Wraps `body` so it streams at this rate after this latency.
    #[must_use]
    pub fn wrap<B>(self, body: B) -> Throttled<B> {
        let chunk = (self.rate.get() / 10).clamp(1, MAX_CHUNK);
        Throttled {
            inner: body,
            throttle: self,
            chunk: usize::try_from(chunk).unwrap_or(usize::MAX),
            start: None,
            sent: 0,
            pending: Bytes::new(),
            sleep: None,
        }
    }

    /// When the stream may have sent `bytes` in total.
    fn due(&self, start: Instant, bytes: u64) -> Instant {
        let nanos = u128::from(bytes) * 1_000_000_000 / u128::from(self.rate.get());
        start + self.latency + Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }
}

/// A body released at a [`Throttle`]'s rate.
#[derive(Debug)]
pub struct Throttled<B> {
    inner: B,
    throttle: Throttle,
    chunk: usize,
    start: Option<Instant>,
    sent: u64,
    pending: Bytes,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl<B> Body for Throttled<B>
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
        let start = *this.start.get_or_insert_with(Instant::now);
        while this.pending.is_empty() {
            match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => this.pending = data,
                    Err(frame) => return Poll::Ready(Some(Ok(frame))),
                },
                other => return Poll::Ready(other),
            }
        }
        let len = this.pending.len().min(this.chunk);
        let due = this.throttle.due(start, this.sent + len as u64);
        if Instant::now() < due {
            let sleep = this
                .sleep
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(due)));
            ready!(sleep.as_mut().poll(cx));
        }
        this.sleep = None;
        this.sent += len as u64;
        Poll::Ready(Some(Ok(Frame::data(this.pending.split_to(len)))))
    }

    fn is_end_stream(&self) -> bool {
        self.pending.is_empty() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let mut hint = self.inner.size_hint();
        let pending = self.pending.len() as u64;
        hint.set_lower(hint.lower() + pending);
        if let Some(upper) = hint.upper() {
            hint.set_upper(upper + pending);
        }
        hint
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::{BodyExt as _, Full};

    use super::*;

    fn throttle(rate: u64, latency_ms: u64) -> Throttle {
        Throttle {
            rate: NonZeroU64::new(rate).expect("non-zero rate"),
            latency: Duration::from_millis(latency_ms),
        }
    }

    #[tokio::test]
    async fn streams_at_roughly_the_configured_rate() {
        // 10 000 bytes at 25 000 B/s after 50 ms: about 450 ms.
        let body = Full::new(Bytes::from(vec![7_u8; 10_000]));
        let started = std::time::Instant::now();
        let mut throttled = throttle(25_000, 50).wrap(body);
        let mut frames = 0;
        let mut total = 0;
        while let Some(frame) = throttled.frame().await {
            let data = frame.expect("infallible").into_data().expect("data");
            total += data.len();
            frames += 1;
        }
        let elapsed = started.elapsed();
        assert_eq!(total, 10_000);
        assert!(frames >= 4, "streams in chunks, got {frames}");
        assert!(
            elapsed >= Duration::from_millis(400) && elapsed < Duration::from_millis(900),
            "took {elapsed:?}"
        );
    }

    /// A body fed by a channel; it ends when the sender is dropped.
    struct ChannelBody(tokio::sync::mpsc::Receiver<Bytes>);

    impl Body for ChannelBody {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            self.get_mut()
                .0
                .poll_recv(cx)
                .map(|chunk| chunk.map(|data| Ok(Frame::data(data))))
        }
    }

    #[tokio::test]
    async fn the_first_chunk_streams_before_the_body_ends() {
        // A body whose second frame never arrives: the first must still come through.
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        sender.send(Bytes::from_static(b"abc")).await.expect("open");
        let mut throttled = throttle(1_000_000, 0).wrap(ChannelBody(receiver));
        let first = tokio::time::timeout(Duration::from_secs(1), throttled.frame())
            .await
            .expect("not buffered until the end")
            .expect("a frame")
            .expect("ok");
        assert_eq!(first.into_data().expect("data"), Bytes::from_static(b"abc"));
        drop(sender);
    }
}
