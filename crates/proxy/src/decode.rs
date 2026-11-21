//! Undoes `Content-Encoding` on a captured copy of a body, with caps against
//! decompression bombs. The bytes forwarded on the wire are never touched here.

use std::fmt;
use std::io::Read;

use crate::body::Capture;
use crate::flow::{BodyRecord, ContentDecoding};

/// The most output one input byte may expand to before decoding stops.
///
/// Text compresses about 5:1 to 20:1 and a page of repeated JSON rarely passes 200:1, while a
/// bomb reaches 1000:1 within its first kilobyte. Raising it lets hostile input allocate more
/// before the body limit cuts it off.
pub const MAX_RATIO: usize = 1000;

/// Output allowed for any input, so tiny bodies of highly repetitive text still decode.
const MIN_OUTPUT: usize = 64 * 1024;

/// Read size while decoding; the output buffer grows by at most this much past what is kept.
const CHUNK: usize = 16 * 1024;

/// One content coding this module can undo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coding {
    /// `gzip` or `x-gzip` (RFC 1952), possibly several members.
    Gzip,
    /// `deflate`: zlib-wrapped (RFC 1950) as specified, or raw deflate as some servers send.
    Deflate,
    /// `br` (RFC 7932).
    Brotli,
    /// `zstd` (RFC 8878).
    Zstd,
}

impl Coding {
    /// The coding a `Content-Encoding` token names; `None` for one this module cannot undo.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token.to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" => Some(Self::Gzip),
            "deflate" => Some(Self::Deflate),
            "br" => Some(Self::Brotli),
            "zstd" => Some(Self::Zstd),
            _ => None,
        }
    }
}

/// The codings listed in every `Content-Encoding` header, lowercase, in the order they were
/// applied; `identity` is left out.
#[must_use]
pub fn codings(headers: &[(String, String)]) -> Vec<String> {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
        .flat_map(|(_, value)| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty() && token != "identity")
        .collect()
}

/// Why decoded output is shorter than the whole decoded body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cut {
    /// The output reached the byte limit.
    Limit,
    /// The output reached [`MAX_RATIO`] times the input.
    Ratio,
    /// The input ended mid-stream because it was itself cut.
    Input,
}

/// Decoded bytes and whether they are the whole body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// The decoded bytes, at most the limit given to [`decode`].
    pub data: Vec<u8>,
    /// Why `data` is not the whole decoded body; `None` when it is.
    pub cut: Option<Cut>,
}

/// Why a body could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// A coding this module does not know.
    Unsupported(String),
    /// The data is not valid for the coding.
    Malformed {
        /// The coding that failed.
        coding: String,
        /// What the decoder reported.
        reason: String,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(coding) => write!(f, "unsupported content coding {coding:?}"),
            Self::Malformed { coding, reason } => write!(f, "invalid {coding} data: {reason}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Undoes `codings` (in the order they were applied) on `data`, keeping at most `limit`
/// output bytes per layer and at most [`MAX_RATIO`] output bytes per input byte.
///
/// `input_cut` says `data` is only the start of the body: a decoder error at its end then
/// means the stream stopped, not that it is invalid, and the output so far is kept.
///
/// # Errors
///
/// [`DecodeError::Unsupported`] for an unknown coding, [`DecodeError::Malformed`] when the
/// data is invalid before its end.
pub fn decode(
    data: &[u8],
    codings: &[String],
    limit: usize,
    input_cut: bool,
) -> Result<Decoded, DecodeError> {
    let parsed: Vec<(Coding, &str)> = codings
        .iter()
        .map(|name| {
            Coding::from_token(name)
                .map(|coding| (coding, name.as_str()))
                .ok_or_else(|| DecodeError::Unsupported(name.clone()))
        })
        .collect::<Result<_, _>>()?;
    let mut current = Decoded {
        data: data.to_vec(),
        cut: input_cut.then_some(Cut::Input),
    };
    for (coding, name) in parsed.into_iter().rev() {
        let next =
            decode_one(coding, &current.data, limit, current.cut.is_some()).map_err(|reason| {
                DecodeError::Malformed {
                    coding: name.to_owned(),
                    reason,
                }
            })?;
        // An inner layer cut short makes every outer layer short too; keep the first reason.
        current = Decoded {
            data: next.data,
            cut: current.cut.or(next.cut),
        };
    }
    Ok(current)
}

fn decode_one(
    coding: Coding,
    data: &[u8],
    limit: usize,
    input_cut: bool,
) -> Result<Decoded, String> {
    match coding {
        Coding::Gzip => drain(
            flate2::read::MultiGzDecoder::new(data),
            data,
            limit,
            input_cut,
        ),
        Coding::Deflate if is_zlib(data) => {
            drain(flate2::read::ZlibDecoder::new(data), data, limit, input_cut)
        }
        Coding::Deflate => drain(
            flate2::read::DeflateDecoder::new(data),
            data,
            limit,
            input_cut,
        ),
        Coding::Brotli => drain(
            brotli_decompressor::Decompressor::new(data, CHUNK),
            data,
            limit,
            input_cut,
        ),
        Coding::Zstd => match ruzstd::decoding::StreamingDecoder::new(data) {
            Ok(decoder) => drain(decoder, data, limit, input_cut),
            Err(_) if input_cut => Ok(Decoded {
                data: Vec::new(),
                cut: Some(Cut::Input),
            }),
            Err(e) => Err(e.to_string()),
        },
    }
}

/// A zlib header (RFC 1950): deflate method and a check value divisible by 31.
fn is_zlib(data: &[u8]) -> bool {
    match data {
        [cmf, flg, ..] => cmf & 0x0f == 8 && (u16::from(*cmf) << 8 | u16::from(*flg)) % 31 == 0,
        _ => false,
    }
}

/// Reads `reader` to its end or to the output cap, whichever comes first.
fn drain(
    mut reader: impl Read,
    input: &[u8],
    limit: usize,
    input_cut: bool,
) -> Result<Decoded, String> {
    let ratio_cap = input.len().saturating_mul(MAX_RATIO).max(MIN_OUTPUT);
    let (cap, cap_cut) = if ratio_cap < limit {
        (ratio_cap, Cut::Ratio)
    } else {
        (limit, Cut::Limit)
    };
    let mut out = Vec::new();
    let mut chunk = vec![0; CHUNK];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => {
                return Ok(Decoded {
                    data: out,
                    cut: input_cut.then_some(Cut::Input),
                });
            }
            Ok(n) => {
                let room = cap - out.len();
                if n > room {
                    out.extend_from_slice(&chunk[..room]);
                    return Ok(Decoded {
                        data: out,
                        cut: Some(cap_cut),
                    });
                }
                out.extend_from_slice(&chunk[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) if input_cut => {
                return Ok(Decoded {
                    data: out,
                    cut: Some(Cut::Input),
                });
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

impl BodyRecord {
    /// The record of a captured body, decoded when `headers` name a `Content-Encoding`.
    ///
    /// A body with no coding (or only `identity`) is recorded as captured. Otherwise the
    /// record holds the decoded bytes and [`BodyRecord::content_encoding`] says what was
    /// undone; when decoding fails it holds the captured bytes and the reason.
    #[must_use]
    pub fn from_capture(capture: &Capture, headers: &[(String, String)]) -> Self {
        let codings = codings(headers);
        if codings.is_empty() || capture.data().is_empty() {
            return Self::from(capture);
        }
        match decode(
            capture.data(),
            &codings,
            capture.limit(),
            capture.truncated(),
        ) {
            Ok(decoded) => {
                let cut = decoded.cut.is_some();
                let mut record = Self::from_bytes(&decoded.data, decoded.data.len() as u64, cut);
                record.content_encoding = Some(ContentDecoding {
                    codings,
                    wire_size: capture.size(),
                    decoded: true,
                    reason: match decoded.cut {
                        Some(Cut::Ratio) => Some(format!(
                            "decoding stopped at the {MAX_RATIO}:1 expansion cap"
                        )),
                        Some(Cut::Limit) => Some("decoded body is over --body-limit".to_owned()),
                        Some(Cut::Input) => {
                            Some("captured bytes were cut by --body-limit".to_owned())
                        }
                        None => None,
                    },
                });
                record
            }
            Err(e) => {
                let mut record = Self::from(capture);
                record.content_encoding = Some(ContentDecoding {
                    codings,
                    wire_size: capture.size(),
                    decoded: false,
                    reason: Some(e.to_string()),
                });
                record
            }
        }
    }

    /// Whether the record holds decoded bytes rather than the bytes on the wire.
    #[must_use]
    pub fn is_decoded(&self) -> bool {
        self.content_encoding.as_ref().is_some_and(|c| c.decoded)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).expect("write to Vec");
        encoder.finish().expect("finish to Vec")
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).expect("write to Vec");
        encoder.finish().expect("finish to Vec")
    }

    fn raw_deflate(data: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).expect("write to Vec");
        encoder.finish().expect("finish to Vec")
    }

    fn brotli(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut writer = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
        writer.write_all(data).expect("write to Vec");
        drop(writer);
        out
    }

    fn zstd(data: &[u8]) -> Vec<u8> {
        ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    const TEXT: &[u8] = b"<html><body>hello, decoded world! hello, decoded world!</body></html>";

    #[test]
    fn every_coding_round_trips() {
        for (name, wire) in [
            ("gzip", gzip(TEXT)),
            ("x-gzip", gzip(TEXT)),
            ("deflate", zlib(TEXT)),
            ("deflate", raw_deflate(TEXT)),
            ("br", brotli(TEXT)),
            ("zstd", zstd(TEXT)),
        ] {
            let decoded = decode(&wire, &names(&[name]), 1 << 20, false).expect(name);
            assert_eq!(decoded.data, TEXT, "{name}");
            assert_eq!(decoded.cut, None, "{name}");
        }
    }

    #[test]
    fn stacked_codings_are_undone_last_first() {
        let wire = brotli(&gzip(TEXT));
        let decoded = decode(&wire, &names(&["gzip", "br"]), 1 << 20, false).expect("decodes");
        assert_eq!(decoded.data, TEXT);
    }

    #[test]
    fn header_lists_are_split_and_identity_dropped() {
        let headers = vec![
            ("Content-Encoding".to_owned(), "identity, GZIP".to_owned()),
            ("content-encoding".to_owned(), " br ".to_owned()),
            ("content-type".to_owned(), "text/html".to_owned()),
        ];
        assert_eq!(codings(&headers), names(&["gzip", "br"]));
    }

    #[test]
    fn unknown_and_malformed_input_is_an_error() {
        assert!(matches!(
            decode(TEXT, &names(&["compress"]), 1 << 20, false),
            Err(DecodeError::Unsupported(c)) if c == "compress"
        ));
        for name in ["gzip", "deflate", "br", "zstd"] {
            let garbage = [0xff_u8; 64];
            assert!(
                matches!(
                    decode(&garbage, &names(&[name]), 1 << 20, false),
                    Err(DecodeError::Malformed { .. })
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn bombs_stop_at_the_caps() {
        let zeros = vec![0_u8; 4 << 20];
        let limit = 256 * 1024;
        for (name, wire) in [
            ("gzip", gzip(&zeros)),
            ("br", brotli(&zeros)),
            ("zstd", zstd(&zeros)),
        ] {
            assert!(
                wire.len() < 64 * 1024,
                "{name} bomb is {} bytes",
                wire.len()
            );
            let decoded = decode(&wire, &names(&[name]), limit, false).expect(name);
            assert!(decoded.data.len() <= limit, "{name}");
            assert!(decoded.cut.is_some(), "{name}");
            // Stacked layers are capped one by one.
            let stacked = gzip(&wire);
            let decoded = decode(&stacked, &names(&[name, "gzip"]), limit, false).expect(name);
            assert!(decoded.data.len() <= limit, "stacked {name}");
        }
        // A tiny input hits the ratio cap long before a generous limit.
        let wire = brotli(&zeros);
        let decoded = decode(&wire, &names(&["br"]), 1 << 30, false).expect("br");
        assert_eq!(decoded.cut, Some(Cut::Ratio));
        assert_eq!(decoded.data.len(), (wire.len() * MAX_RATIO).max(MIN_OUTPUT));
    }

    #[test]
    fn a_cut_stream_decodes_as_far_as_it_goes() {
        let text: Vec<u8> = (0..20_000_u32)
            .flat_map(|i| i.to_string().into_bytes())
            .collect();
        for (name, wire) in [
            ("gzip", gzip(&text)),
            ("br", brotli(&text)),
            ("zstd", zstd(&text)),
        ] {
            let half = &wire[..wire.len() / 2];
            let decoded = decode(half, &names(&[name]), 1 << 20, true).expect(name);
            assert_eq!(decoded.cut, Some(Cut::Input), "{name}");
            assert!(text.starts_with(&decoded.data), "{name} output is a prefix");
        }
    }

    #[test]
    fn records_keep_the_wire_bytes_when_decoding_fails() {
        let headers = vec![("content-encoding".to_owned(), "gzip".to_owned())];
        let mut capture = Capture::new(1024);
        capture.push(b"not gzip at all");
        let record = BodyRecord::from_capture(&capture, &headers);
        assert_eq!(record.data, "not gzip at all");
        let meta = record.content_encoding.expect("metadata");
        assert!(!meta.decoded);
        assert!(meta.reason.is_some());

        let mut capture = Capture::new(1024);
        let wire = gzip(TEXT);
        capture.push(&wire);
        let record = BodyRecord::from_capture(&capture, &headers);
        assert_eq!(record.data.as_bytes(), TEXT);
        assert_eq!(record.size, TEXT.len() as u64);
        assert!(record.is_decoded());
        assert_eq!(
            record.content_encoding.expect("metadata").wire_size,
            wire.len() as u64
        );
    }
}
