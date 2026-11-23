//! Which targets a client may reach through the proxy.
//!
//! [`Guard::check`] is the one decision, made on the address that is really dialled: the
//! control plane and the proxy's own listener are refused for everybody, and a client on
//! another machine (`--allow-remote`, `connect`, WireGuard) may not reach this machine's
//! loopback, unspecified or link-local addresses (`169.254.0.0/16` holds the cloud metadata
//! service, `fe80::/10` its IPv6 counterpart). Clients on this machine keep full access, so
//! `localhost` targets work for local debugging.
//!
//! [`Guard::resolve`] resolves a name once and checks every answer; the caller dials exactly
//! those addresses, so a DNS answer cannot change between the check and the connection.
//! Through an upstream proxy the name is resolved by that proxy, so only what
//! [`Guard::check_name`] can see without DNS is checked: IP literals in every form the
//! system resolver accepts, and `localhost` names.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::Context as _;

/// Why a target was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Denied {
    /// The control plane's address.
    ControlPlane,
    /// The proxy's own listener.
    OwnListener,
    /// A loopback, unspecified or link-local address, for a client on another machine.
    Local,
}

impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = crate::NAME;
        match self {
            Self::ControlPlane => write!(
                f,
                "{name} refuses to proxy requests to its own control plane"
            ),
            Self::OwnListener => write!(f, "{name} refuses to connect to its own listener"),
            Self::Local => write!(
                f,
                "{name} refuses to reach loopback, unspecified or link-local addresses for a \
                 client on another machine"
            ),
        }
    }
}

impl std::error::Error for Denied {}

/// The addresses the proxy refuses to dial.
#[derive(Debug, Clone)]
pub(crate) struct Guard {
    /// The proxy's own listener.
    listen: SocketAddr,
    /// The control plane's addresses.
    refused: Vec<SocketAddr>,
    /// This machine's LAN address, which a wildcard listener also answers on.
    lan: Option<IpAddr>,
}

impl Guard {
    pub(crate) fn new(listen: SocketAddr) -> Self {
        let lan = (listen.ip().is_unspecified())
            .then(crate::mobile::lan_ipv4)
            .and_then(Result::ok)
            .map(IpAddr::V4);
        Self {
            listen,
            refused: Vec::new(),
            lan,
        }
    }

    /// Adds a control plane address.
    pub(crate) fn refuse(&mut self, addr: SocketAddr) {
        self.refused.push(addr);
    }

    /// Whether `peer` may reach `target`.
    ///
    /// # Errors
    ///
    /// Says which rule refused it.
    pub(crate) fn check(&self, peer: IpAddr, target: SocketAddr) -> Result<(), Denied> {
        let ip = target.ip().to_canonical();
        if self
            .refused
            .iter()
            .any(|addr| self.names(*addr, ip, target.port()))
        {
            return Err(Denied::ControlPlane);
        }
        if self.names(self.listen, ip, target.port()) {
            return Err(Denied::OwnListener);
        }
        if !is_local_peer(peer) && (is_here(ip) || is_link_local(ip)) {
            return Err(Denied::Local);
        }
        Ok(())
    }

    /// [`check`](Self::check) for what `host` names without DNS: an IP literal or a
    /// `localhost` name. Other names pass; [`resolve`](Self::resolve) checks them.
    ///
    /// # Errors
    ///
    /// Says which rule refused it.
    pub(crate) fn check_name(&self, peer: IpAddr, host: &str, port: u16) -> Result<(), Denied> {
        literal(host).map_or(Ok(()), |ip| self.check(peer, SocketAddr::new(ip, port)))
    }

    /// Resolves `host:port` and checks every address; the caller dials only these.
    ///
    /// # Errors
    ///
    /// Fails when resolution fails or finds nothing, and with [`Denied`] when any answer is
    /// refused (a name that also resolves to loopback is not dialled at all).
    pub(crate) async fn resolve(
        &self,
        peer: IpAddr,
        host: &str,
        port: u16,
    ) -> anyhow::Result<Vec<SocketAddr>> {
        let host = unbracket(host);
        let addrs: Vec<SocketAddr> = match ip_literal(host) {
            Some(ip) => vec![SocketAddr::new(ip, port)],
            None => tokio::net::lookup_host((host, port))
                .await
                .with_context(|| format!("resolving {host}"))?
                .map(|addr| SocketAddr::new(addr.ip().to_canonical(), addr.port()))
                .collect(),
        };
        anyhow::ensure!(!addrs.is_empty(), "{host} has no address");
        for addr in &addrs {
            self.check(peer, *addr)
                .with_context(|| format!("{host}:{port} is {}", addr.ip()))?;
        }
        Ok(addrs)
    }

    /// Whether `ip:port` reaches the socket bound to `bound`.
    fn names(&self, bound: SocketAddr, ip: IpAddr, port: u16) -> bool {
        let bound_ip = bound.ip().to_canonical();
        port == bound.port()
            && (ip == bound_ip
                || is_here(ip)
                || (bound_ip.is_unspecified() && self.lan == Some(ip)))
    }
}

/// Whether `peer` is this machine. An unspecified peer is the proxy itself (replays carry
/// the listening address), never a real TCP peer.
fn is_local_peer(peer: IpAddr) -> bool {
    is_here(peer.to_canonical())
}

/// Loopback or unspecified: an address that means this machine.
fn is_here(ip: IpAddr) -> bool {
    ip.is_loopback() || ip.is_unspecified()
}

fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unicast_link_local(),
    }
}

/// The address `host` names without DNS: an IP literal in any form the system resolver
/// accepts (`127.1`, `2130706433`, `0x7f.1`, `[::ffff:127.0.0.1]`), canonicalised, or
/// loopback for `localhost`, its subdomains and a trailing-dot spelling.
pub(crate) fn literal(host: &str) -> Option<IpAddr> {
    let host = unbracket(host).trim_end_matches('.');
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") {
        return Some(Ipv4Addr::LOCALHOST.into());
    }
    ip_literal(host)
}

/// An IP literal in any form the system resolver accepts, canonicalised; parsed here so
/// the result is the same on every platform.
fn ip_literal(host: &str) -> Option<IpAddr> {
    let host = unbracket(host).trim_end_matches('.');
    let ip = host
        .parse::<IpAddr>()
        .ok()
        .or_else(|| loose_ipv4(host).map(IpAddr::V4))?;
    Some(ip.to_canonical())
}

/// The classic `inet_aton` forms: one to four dot-separated numbers in decimal, octal
/// (`0` prefix) or hex (`0x` prefix), the last one filling the remaining bytes.
fn loose_ipv4(host: &str) -> Option<Ipv4Addr> {
    let parts: Vec<u32> = host.split('.').map(number).collect::<Option<_>>()?;
    let (last, init) = parts.split_last()?;
    if init.len() > 3 || init.iter().any(|part| *part > 255) {
        return None;
    }
    let bits = 8 * (4 - u32::try_from(init.len()).ok()?);
    if last.checked_shr(bits).unwrap_or(0) != 0 {
        return None;
    }
    let head = init.iter().fold(0_u32, |acc, part| acc << 8 | part);
    Some(Ipv4Addr::from(head.checked_shl(bits).unwrap_or(0) | last))
}

fn number(part: &str) -> Option<u32> {
    if part.is_empty() || !part.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else if let Some(octal) = part.strip_prefix('0').filter(|rest| !rest.is_empty()) {
        u32::from_str_radix(octal, 8).ok()
    } else {
        part.parse().ok()
    }
}

fn unbracket(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAN_PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
    const LOCAL_PEER: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    fn guard() -> Guard {
        let mut guard = Guard::new("127.0.0.1:8899".parse().expect("listen"));
        guard.refuse("127.0.0.1:8898".parse().expect("control"));
        guard
    }

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("socket address")
    }

    #[test]
    fn a_peer_on_another_machine_cannot_reach_this_machine() {
        let guard = guard();
        for target in [
            "127.0.0.1:5432",
            "127.9.9.9:80",
            "[::1]:3000",
            "[::ffff:127.0.0.1]:3000",
            "0.0.0.0:80",
            "[::]:80",
            "169.254.169.254:80",
            "[fe80::1]:80",
        ] {
            assert_eq!(
                guard.check(LAN_PEER, addr(target)),
                Err(Denied::Local),
                "{target}"
            );
        }
        assert_eq!(guard.check(LAN_PEER, addr("93.184.216.34:443")), Ok(()));
        assert_eq!(guard.check(LAN_PEER, addr("192.168.1.30:80")), Ok(()));
    }

    #[test]
    fn a_local_peer_keeps_loopback_but_never_the_control_plane_or_the_listener() {
        let guard = guard();
        let mapped_local = IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
        for peer in [LOCAL_PEER, mapped_local, IpAddr::V4(Ipv4Addr::UNSPECIFIED)] {
            assert_eq!(guard.check(peer, addr("127.0.0.1:5432")), Ok(()), "{peer}");
            assert_eq!(guard.check(peer, addr("[::1]:5432")), Ok(()), "{peer}");
        }
        for peer in [LOCAL_PEER, mapped_local, LAN_PEER] {
            for target in [
                "127.0.0.1:8898",
                "127.0.0.2:8898",
                "[::ffff:127.0.0.1]:8898",
            ] {
                assert_eq!(guard.check(peer, addr(target)), Err(Denied::ControlPlane));
            }
            assert_eq!(
                guard.check(peer, addr("[::]:8899")),
                Err(Denied::OwnListener)
            );
        }
        assert_eq!(guard.check(LOCAL_PEER, addr("93.184.216.34:8898")), Ok(()));
    }

    #[test]
    fn literals_cover_every_spelling_of_loopback() {
        for host in [
            "127.0.0.1",
            "127.1",
            "2130706433",
            "0x7f.1",
            "0177.0.0.1",
            "0x7f000001",
            "[::ffff:127.0.0.1]",
            "localhost",
            "LOCALHOST.",
            "app.localhost",
        ] {
            assert!(literal(host).is_some_and(|ip| ip.is_loopback()), "{host}");
        }
        for host in [
            "example.com",
            "1e100",
            "deadbeef",
            "256.1.1.1",
            "1.2.3.4.5",
            "+1",
            "",
        ] {
            assert!(literal(host).is_none_or(|ip| !ip.is_loopback()), "{host}");
        }
        assert_eq!(
            literal("10.1"),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(
            guard().check_name(LAN_PEER, "127.1", 22),
            Err(Denied::Local)
        );
        assert_eq!(guard().check_name(LAN_PEER, "example.com", 22), Ok(()));
    }

    #[tokio::test]
    async fn resolution_checks_the_address_that_will_be_dialled() -> anyhow::Result<()> {
        let guard = guard();
        let error = (guard.resolve(LAN_PEER, "localhost", 5432).await)
            .expect_err("localhost resolves to loopback");
        assert_eq!(error.downcast_ref::<Denied>(), Some(&Denied::Local));
        let addrs = guard.resolve(LOCAL_PEER, "localhost", 5432).await?;
        assert!(
            addrs.iter().all(|addr| addr.ip().is_loopback()),
            "{addrs:?}"
        );
        let error = (guard.resolve(LOCAL_PEER, "127.1", 8898).await).expect_err("control");
        assert_eq!(error.downcast_ref::<Denied>(), Some(&Denied::ControlPlane));
        Ok(())
    }
}
