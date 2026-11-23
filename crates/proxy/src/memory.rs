//! The byte budget of the [`crate::events::FlowStore`]: `--max-memory` parsing and the
//! estimate of how many heap bytes a held flow or WebSocket message costs.
//!
//! The estimate counts what grows with traffic (bodies, headers, trailers, URLs, message
//! payloads) by allocated capacity, plus a fixed overhead per record for the structs, `Arc`
//! headers and allocator slack. It is computed once, when a record is stored.

use std::fmt;

use crate::events::{Started, StoredFlow};
use crate::flow::{BodyRecord, ClientTls, Event, Exchange};
use crate::ws::WsMessage;

/// Default `--max-memory`: 512 MiB of retained flow data.
pub const DEFAULT_MAX_MEMORY: usize = 512 * 1024 * 1024;

/// Bytes charged per record on top of its strings: the structs, the `Arc`, the ring slot
/// and the allocator's rounding.
const RECORD_OVERHEAD: usize = 512;

/// Bytes charged per string or header pair for its `String` headers and allocator slack.
const FIELD_OVERHEAD: usize = 32;

/// A `--max-memory` value that is not a size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseSizeError(String);

impl fmt::Display for ParseSizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} is not a size: use bytes or a K, M, G, KiB, MiB or GiB suffix",
            self.0
        )
    }
}

impl std::error::Error for ParseSizeError {}

/// Parses a byte size: plain bytes (`1048576`) or a number with a suffix. `K`, `M`, `G` and
/// `KiB`, `MiB`, `GiB` (case-insensitive, an optional `B` after the single letters) are all
/// powers of 1024, as for memory sizes.
///
/// # Errors
///
/// When `text` is not a whole number with one of those suffixes, or overflows `usize`.
pub fn parse_size(text: &str) -> Result<usize, ParseSizeError> {
    let error = || ParseSizeError(text.to_owned());
    let trimmed = text.trim();
    let split = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let (digits, suffix) = trimmed.split_at(split);
    let shift = match suffix.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 0,
        "k" | "kb" | "kib" => 10,
        "m" | "mb" | "mib" => 20,
        "g" | "gb" | "gib" => 30,
        _ => return Err(error()),
    };
    let number: usize = digits.parse().map_err(|_| error())?;
    number.checked_mul(1 << shift).ok_or_else(error)
}

/// The estimated heap bytes `flow` keeps alive while the store holds it.
#[must_use]
pub fn stored_flow(flow: &StoredFlow) -> usize {
    match flow {
        StoredFlow::Pending(started) => self::started(started),
        StoredFlow::Done(flow) => event(&flow.record),
    }
}

/// The estimated heap bytes of one held WebSocket message.
#[must_use]
pub fn ws_message(message: &WsMessage) -> usize {
    RECORD_OVERHEAD
        + text(&message.time)
        + text(&message.data)
        + message.close_reason.as_deref().map_or(0, text)
}

fn started(started: &Started) -> usize {
    RECORD_OVERHEAD
        + text(&started.time)
        + text(&started.method)
        + text(&started.url)
        + text(&started.client_version)
        + headers(&started.request_headers)
        + started.tls.as_ref().map_or(0, tls)
}

fn event(record: &Event) -> usize {
    match record {
        Event::Exchange(exchange) => self::exchange(exchange),
        Event::TlsFailure(failure) => {
            RECORD_OVERHEAD
                + text(&failure.target)
                + text(&failure.reason)
                + failure.sni.as_deref().map_or(0, text)
        }
        Event::Tunnel(tunnel) => {
            RECORD_OVERHEAD + text(&tunnel.target) + tunnel.error.as_deref().map_or(0, text)
        }
    }
}

fn exchange(x: &Exchange) -> usize {
    let optional = [
        x.upstream_version.as_deref(),
        x.reason.as_deref(),
        x.error.as_deref(),
        x.upstream_url.as_deref(),
    ];
    RECORD_OVERHEAD
        + text(&x.time)
        + text(&x.method)
        + text(&x.url)
        + text(&x.client_version)
        + optional.into_iter().flatten().map(text).sum::<usize>()
        + headers(&x.request_headers)
        + headers(&x.response_headers)
        + headers(&x.response_trailers)
        + body(&x.request_body)
        + x.response_body.as_ref().map_or(0, body)
        + x.tls.as_ref().map_or(0, tls)
}

fn body(body: &BodyRecord) -> usize {
    let codings = body.content_encoding.as_ref().map_or(0, |c| {
        c.codings.iter().map(|coding| text(coding)).sum::<usize>()
            + c.reason.as_deref().map_or(0, text)
    });
    FIELD_OVERHEAD + body.data.capacity() + codings
}

fn tls(tls: &ClientTls) -> usize {
    let optional = [
        tls.version.as_deref(),
        tls.alpn.as_deref(),
        tls.sni.as_deref(),
        tls.client.as_deref(),
    ];
    text(&tls.ja4) + text(&tls.ja3_hash) + optional.into_iter().flatten().map(text).sum::<usize>()
}

fn headers(headers: &[(String, String)]) -> usize {
    headers
        .iter()
        .map(|(name, value)| name.len() + value.len() + FIELD_OVERHEAD)
        .sum()
}

fn text(value: &str) -> usize {
    value.len() + FIELD_OVERHEAD
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_take_bytes_and_binary_suffixes() {
        let cases = [
            ("0", 0),
            ("1048576", 1 << 20),
            ("512K", 512 << 10),
            ("128M", 128 << 20),
            ("128m", 128 << 20),
            ("2G", 2 << 30),
            ("64KiB", 64 << 10),
            ("512MiB", 512 << 20),
            ("1GiB", 1 << 30),
            ("1gb", 1 << 30),
            ("100 MiB", 100 << 20),
            ("7B", 7),
        ];
        for (text, want) in cases {
            assert_eq!(parse_size(text), Ok(want), "input {text:?}");
        }
    }

    #[test]
    fn sizes_reject_garbage_fractions_and_overflow() {
        for text in [
            "",
            "M",
            "-1",
            "1.5G",
            "12X",
            "1TiB",
            "99999999999999999999G",
        ] {
            assert!(parse_size(text).is_err(), "input {text:?}");
        }
    }
}
