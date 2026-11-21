//! Reads the client's ClientHello off a tunnel before the TLS handshake and replays it.
//!
//! [`peek`] reads whole TLS records until the ClientHello handshake message is complete and
//! keeps every byte it read; [`Prefixed`] then serves those bytes again ahead of the stream,
//! so the TLS acceptor sees the connection exactly as the client sent it.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, ReadBuf};

/// TLS record content type of a handshake record.
const HANDSHAKE: u8 = 0x16;
/// Handshake message type of a ClientHello.
const CLIENT_HELLO: u8 = 0x01;
/// Upper bound on the bytes read while looking for the ClientHello. Post-quantum key shares
/// make hellos of 2 KiB common; nothing legitimate comes near this.
const MAX_HELLO: usize = 64 * 1024;
/// How long to wait for the client's first byte. A server-speaks-first protocol (SMTP, SSH)
/// sends nothing, so after this the tunnel is passed through untouched.
const FIRST_BYTE_WAIT: Duration = Duration::from_secs(2);

/// What the start of a tunnel holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Peeked {
    /// A TLS ClientHello.
    Tls {
        /// Every byte read, record headers included, to replay to the TLS acceptor.
        raw: Vec<u8>,
        /// The ClientHello handshake message, from its type byte, reassembled from records.
        message: Vec<u8>,
    },
    /// Something else, or nothing within the wait; `raw` holds the bytes read so far.
    Other {
        /// The bytes read before the decision.
        raw: Vec<u8>,
    },
}

/// Reads from `stream` until a complete ClientHello (or something that is not one) is seen.
///
/// # Errors
///
/// Fails on an I/O error of the stream.
pub async fn peek<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Peeked> {
    let mut first = [0_u8; 1];
    match tokio::time::timeout(FIRST_BYTE_WAIT, stream.read(&mut first)).await {
        Err(_) | Ok(Ok(0)) => return Ok(Peeked::Other { raw: Vec::new() }),
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(e),
    }
    let mut raw = first.to_vec();
    if first[0] != HANDSHAKE {
        return Ok(Peeked::Other { raw });
    }
    let mut message = Vec::new();
    let mut record_start = 0;
    loop {
        // Reads may run past the record end; those bytes stay in `raw` for the next record
        // and for the replay.
        while raw.len() < record_start + 5 {
            if !read_more(stream, &mut raw).await? {
                return Ok(Peeked::Other { raw });
            }
        }
        let header = &raw[record_start..record_start + 5];
        if header[0] != HANDSHAKE {
            return Ok(Peeked::Other { raw });
        }
        let body_start = record_start + 5;
        let body_end = body_start + usize::from(u16::from_be_bytes([header[3], header[4]]));
        while raw.len() < body_end {
            if raw.len() > MAX_HELLO || !read_more(stream, &mut raw).await? {
                return Ok(Peeked::Other { raw });
            }
        }
        message.extend_from_slice(&raw[body_start..body_end]);
        if message.first() != Some(&CLIENT_HELLO) {
            return Ok(Peeked::Other { raw });
        }
        if let [_, a, b, c, ..] = message[..] {
            let needed = 4 + (usize::from(a) << 16 | usize::from(b) << 8 | usize::from(c));
            if message.len() >= needed {
                message.truncate(needed);
                return Ok(Peeked::Tls { raw, message });
            }
        }
        if body_end > MAX_HELLO {
            return Ok(Peeked::Other { raw });
        }
        record_start = body_end;
    }
}

/// Reads at most the next chunk into `raw`; `false` at end of stream.
async fn read_more<S: AsyncRead + Unpin>(stream: &mut S, raw: &mut Vec<u8>) -> io::Result<bool> {
    let mut chunk = [0_u8; 4096];
    let n = stream.read(&mut chunk).await?;
    raw.extend_from_slice(&chunk[..n]);
    Ok(n > 0)
}

/// The server name from a parsed ClientHello's `server_name` extension.
#[must_use]
pub fn sni(hello: &fingerprint::ClientHello) -> Option<String> {
    let data = &hello.extensions.iter().find(|e| e.kind == 0)?.data;
    // server_name_list length (2), name_type (1), host_name length (2), host_name.
    let [_, _, 0, hi, lo, rest @ ..] = &data[..] else {
        return None;
    };
    let name = rest.get(..usize::from(u16::from_be_bytes([*hi, *lo])))?;
    std::str::from_utf8(name).ok().map(str::to_owned)
}

/// A stream that yields `prefix` before reading from the inner stream; writes go straight
/// to the inner stream.
#[derive(Debug)]
pub struct Prefixed<S> {
    prefix: Vec<u8>,
    position: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    /// Replays `prefix`, then reads `inner`.
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            position: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let rest = &this.prefix[this.position..];
        if rest.is_empty() {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        let n = rest.len().min(buf.remaining());
        buf.put_slice(&rest[..n]);
        this.position += n;
        if this.position == this.prefix.len() {
            this.prefix = Vec::new();
            this.position = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    /// A ClientHello message with an SNI extension for `host`; the other fields are minimal.
    fn hello_message(host: &str) -> Vec<u8> {
        let name = host.as_bytes();
        let name_len = u16::try_from(name.len()).expect("short test host");
        let mut sni = Vec::new();
        sni.extend_from_slice(&(name_len + 3).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&name_len.to_be_bytes());
        sni.extend_from_slice(name);
        let mut extensions = vec![0, 0];
        extensions.extend_from_slice(&u16::try_from(sni.len()).expect("short").to_be_bytes());
        extensions.extend_from_slice(&sni);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7; 32]); // random
        body.push(0); // session id
        body.extend_from_slice(&[0, 2, 0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[1, 0]); // compression: null
        body.extend_from_slice(
            &u16::try_from(extensions.len())
                .expect("short")
                .to_be_bytes(),
        );
        body.extend_from_slice(&extensions);
        let len = u32::try_from(body.len()).expect("short").to_be_bytes();
        let mut message = vec![CLIENT_HELLO, len[1], len[2], len[3]];
        message.extend_from_slice(&body);
        message
    }

    /// Splits `message` into handshake records of at most `size` bytes each.
    fn records(message: &[u8], size: usize) -> Vec<u8> {
        message
            .chunks(size)
            .flat_map(|chunk| {
                let len = u16::try_from(chunk.len()).expect("short").to_be_bytes();
                [HANDSHAKE, 3, 1, len[0], len[1]]
                    .into_iter()
                    .chain(chunk.iter().copied())
            })
            .collect()
    }

    #[tokio::test]
    async fn reads_a_fragmented_hello_and_replays_every_byte() -> io::Result<()> {
        let message = hello_message("example.com");
        let mut wire = records(&message, 20);
        wire.extend_from_slice(b"after");
        let (mut client, mut server) = tokio::io::duplex(64);
        let sent = wire.clone();
        let writer =
            tokio::spawn(
                async move { tokio::io::AsyncWriteExt::write_all(&mut client, &sent).await },
            );
        let Peeked::Tls { raw, message: got } = peek(&mut server).await? else {
            panic!("expected a ClientHello");
        };
        assert_eq!(got, message);
        assert_eq!(
            sni(&fingerprint::ClientHello::parse(&got)).as_deref(),
            Some("example.com")
        );
        writer.await.expect("writer task")?;
        let mut replayed = Vec::new();
        let mut stream = Prefixed::new(raw, server);
        stream.read_to_end(&mut replayed).await?;
        assert_eq!(replayed, wire, "the acceptor must see the bytes as sent");
        Ok(())
    }

    #[tokio::test]
    async fn passes_other_protocols_through() -> io::Result<()> {
        let mut plain: &[u8] = b"GET / HTTP/1.1\r\n\r\n";
        assert_eq!(
            peek(&mut plain).await?,
            Peeked::Other { raw: b"G".to_vec() }
        );
        Ok(())
    }
}
