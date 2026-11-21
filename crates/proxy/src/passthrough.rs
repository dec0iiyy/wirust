//! TLS passthrough: hosts whose CONNECT tunnels are relayed without decryption.
//!
//! `--passthrough PATTERN` names hosts never to intercept; `--decrypt-only PATTERN`, when
//! given, makes every host that does not match one of its patterns a passthrough host. A
//! passthrough tunnel still has its ClientHello read, so the record keeps the SNI, the
//! offered ALPN, JA4 and JA3; the rest of the bytes are copied both ways untouched.
//! `docs/passthrough.md` describes the flags and the API.

use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};

use crate::clock::Utc;
use crate::flow::{Event, Tunnel, TunnelReason, TunnelTls};
use crate::proxy::State;
use crate::upstream;

/// Most patterns one list may hold.
const MAX_PATTERNS: usize = 1000;

/// One host pattern: `api.example.com`, `*.bank.example` or either with `:PORT`.
///
/// Matching ignores ASCII case and one trailing dot. `*.` is allowed only as the whole
/// left-most label and matches one or more labels in front of the rest, never the rest
/// itself: `*.bank.example` matches `www.bank.example` and `a.b.bank.example`, not
/// `bank.example` or `evilbank.example`. Without a port every port matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    text: String,
    host: HostPattern,
    port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostPattern {
    Exact(String),
    /// The part after `*.`, stored with its leading dot: `.bank.example`.
    Subdomains(String),
}

impl Pattern {
    /// Whether `host` on `port` matches.
    #[must_use]
    pub fn matches(&self, host: &str, port: u16) -> bool {
        if self.port.is_some_and(|p| p != port) {
            return false;
        }
        let host = normalise(host);
        match &self.host {
            HostPattern::Exact(name) => host == *name,
            HostPattern::Subdomains(suffix) => {
                host.len() > suffix.len() && host.ends_with(suffix.as_str())
            }
        }
    }
}

fn normalise(host: &str) -> String {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

impl std::str::FromStr for Pattern {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let bad = |why: &str| format!("invalid pattern {text:?}: {why}");
        let trimmed = text.trim();
        let (host, port) = split_port(trimmed).map_err(|e| bad(&e))?;
        let host = normalise(host);
        if host.is_empty() {
            return Err(bad("empty host"));
        }
        let (wild, rest) = match host.strip_prefix("*.") {
            Some(rest) => (true, rest.to_owned()),
            None => (false, host.clone()),
        };
        let valid = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':');
        if rest.is_empty() || !rest.chars().all(valid) {
            return Err(bad(
                "use host names, IP literals and *. as the left-most label only",
            ));
        }
        if rest.starts_with('.') || rest.ends_with('.') || rest.contains("..") {
            return Err(bad("empty label"));
        }
        let host = if wild {
            HostPattern::Subdomains(format!(".{rest}"))
        } else {
            HostPattern::Exact(rest)
        };
        Ok(Self {
            text: trimmed.to_owned(),
            host,
            port,
        })
    }
}

/// Splits `host:port`, `[v6]:port`, `[v6]` or a bare host (a bare IPv6 keeps its colons).
fn split_port(text: &str) -> Result<(&str, Option<u16>), String> {
    let port = |p: &str| p.parse::<u16>().map_err(|_| format!("bad port {p:?}"));
    if let Some(rest) = text.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or("missing ]")?;
        return match after {
            "" => Ok((host, None)),
            _ => Ok((
                host,
                Some(port(after.strip_prefix(':').ok_or("junk after ]")?)?),
            )),
        };
    }
    match text.split_once(':') {
        Some((host, p)) if !p.contains(':') => Ok((host, Some(port(p)?))),
        _ => Ok((text, None)),
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl Serialize for Pattern {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// The two lists, as the flags and `PUT /api/v1/passthrough` give them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Lists {
    /// Hosts never intercepted.
    pub passthrough: Vec<Pattern>,
    /// When not empty, the only hosts intercepted.
    pub decrypt_only: Vec<Pattern>,
}

/// The JSON body of `PUT /api/v1/passthrough`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListsBody {
    #[serde(default)]
    passthrough: Vec<String>,
    #[serde(default)]
    decrypt_only: Vec<String>,
}

impl ListsBody {
    pub(crate) fn parse(self) -> Result<Lists, String> {
        Lists::parse(&self.passthrough, &self.decrypt_only)
    }
}

impl Lists {
    /// Parses both lists.
    ///
    /// # Errors
    ///
    /// The first invalid pattern, or a list longer than 1000 patterns.
    pub fn parse(passthrough: &[String], decrypt_only: &[String]) -> Result<Self, String> {
        let list = |texts: &[String]| -> Result<Vec<Pattern>, String> {
            if texts.len() > MAX_PATTERNS {
                return Err(format!("at most {MAX_PATTERNS} patterns per list"));
            }
            texts.iter().map(|t| t.parse()).collect()
        };
        Ok(Self {
            passthrough: list(passthrough)?,
            decrypt_only: list(decrypt_only)?,
        })
    }

    /// Whether the tunnel to `host:port`, whose ClientHello named `sni`, is relayed without
    /// decryption. Both names are tried: a match on either counts.
    #[must_use]
    pub fn tunnels(&self, host: &str, port: u16, sni: Option<&str>) -> bool {
        let names: Vec<&str> = std::iter::once(host)
            .chain(sni.filter(|s| !s.eq_ignore_ascii_case(host)))
            .collect();
        let any = |list: &[Pattern]| {
            names
                .iter()
                .any(|name| list.iter().any(|p| p.matches(name, port)))
        };
        any(&self.passthrough) || (!self.decrypt_only.is_empty() && !any(&self.decrypt_only))
    }
}

/// The live lists, shared by the proxy and the control plane. Cloning shares them.
///
/// [`replace`](Self::replace) swaps the whole set at once; a tunnel decides with the set it
/// read when its ClientHello arrived.
#[derive(Debug, Clone, Default)]
pub struct Passthrough(Arc<RwLock<Arc<Lists>>>);

impl Passthrough {
    /// Starts with `lists`.
    #[must_use]
    pub fn new(lists: Lists) -> Self {
        Self(Arc::new(RwLock::new(Arc::new(lists))))
    }

    /// The current lists.
    ///
    /// # Panics
    ///
    /// If the lock is poisoned, which needs a panic while it was held.
    #[must_use]
    pub fn current(&self) -> Arc<Lists> {
        Arc::clone(&self.0.read().expect("passthrough lock poisoned"))
    }

    /// Replaces both lists.
    ///
    /// # Panics
    ///
    /// If the lock is poisoned, which needs a panic while it was held.
    pub fn replace(&self, lists: Lists) {
        *self.0.write().expect("passthrough lock poisoned") = Arc::new(lists);
    }
}

/// Relays a passthrough tunnel: sends the ClientHello already read (`raw`) to the server,
/// copies both ways and publishes a [`Tunnel`] record with the client's TLS facts.
pub(crate) async fn relay<S>(
    state: &State,
    peer: SocketAddr,
    (host, port): (&str, u16),
    tls: TunnelTls,
    raw: Vec<u8>,
    mut io: S,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let start = Instant::now();
    let mut record = Tunnel {
        id: state.next_id(),
        time: String::new(),
        client: peer,
        target: format!("{host}:{port}"),
        bytes_up: raw.len() as u64,
        bytes_down: 0,
        error: None,
        reason: Some(TunnelReason::Passthrough),
        tls: Some(tls),
        duration_ms: None,
    };
    let result = async {
        let mut server = upstream::open_raw(host, port).await?;
        server.write_all(&raw).await?;
        let (up, down) = tokio::io::copy_bidirectional(&mut io, &mut server).await?;
        anyhow::Ok((up, down))
    }
    .await;
    match result {
        Ok((up, down)) => {
            record.bytes_up += up;
            record.bytes_down = down;
        }
        Err(e) => record.error = Some(format!("{e:#}")),
    }
    record.duration_ms = Some(start.elapsed().as_secs_f64() * 1000.0);
    record.time = Utc::now().rfc3339();
    state.emit(Event::Tunnel(record));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(text: &str) -> Pattern {
        text.parse().unwrap_or_else(|e| panic!("{text}: {e}"))
    }

    #[test]
    fn globs_match_by_label_case_and_port() {
        let table = [
            ("api.example.com", "api.example.com", 443, true),
            ("api.example.com", "API.Example.COM.", 8443, true),
            ("api.example.com", "x.api.example.com", 443, false),
            ("api.example.com:443", "api.example.com", 443, true),
            ("api.example.com:443", "api.example.com", 8443, false),
            ("*.bank.example", "www.bank.example", 443, true),
            ("*.bank.example", "a.b.bank.example", 443, true),
            ("*.Bank.Example", "WWW.bank.example", 443, true),
            ("*.bank.example", "bank.example", 443, false),
            ("*.bank.example", "evilbank.example", 443, false),
            ("*.bank.example", "bank.example.evil", 443, false),
            ("*.bank.example:8443", "www.bank.example", 443, false),
            ("[::1]:443", "::1", 443, true),
            ("::1", "[::1]", 9, true),
            ("127.0.0.1", "127.0.0.1", 1, true),
        ];
        for (pat, host, port, want) in table {
            assert_eq!(
                pattern(pat).matches(host, port),
                want,
                "{pat} vs {host}:{port}"
            );
        }
    }

    #[test]
    fn bad_patterns_are_refused() {
        for bad in [
            "",
            "*",
            "*.",
            "a.*.b",
            "*bank.example",
            "**.x",
            "a..b",
            ".a",
            "a b",
            "a:99999",
            "[::1",
            "[::1]x",
            "a/b",
        ] {
            assert!(
                bad.parse::<Pattern>().is_err(),
                "should be refused: {bad:?}"
            );
        }
    }

    #[test]
    fn decrypt_only_tunnels_everything_else_and_sni_counts() -> Result<(), String> {
        let lists = Lists::parse(&["*.bank.example".to_owned()], &[])?;
        assert!(lists.tunnels("www.bank.example", 443, None));
        assert!(lists.tunnels("10.0.0.1", 443, Some("www.bank.example")));
        assert!(!lists.tunnels("example.com", 443, None));
        let lists = Lists::parse(&[], &["api.example.com".to_owned()])?;
        assert!(!lists.tunnels("api.example.com", 443, None));
        assert!(lists.tunnels("other.example", 443, None));
        assert!(!Lists::default().tunnels("any", 443, None));
        Ok(())
    }
}
