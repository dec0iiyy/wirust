//! Experimental WireGuard capture mode (cargo feature `wireguard`): the official WireGuard
//! app on a phone sends all of its traffic here, and every TCP connection becomes a flow as
//! if the app had sent CONNECT to the original destination. No TUN device, no root.
//!
//! [`Store`] keeps the keys and peers, [`Server`] listens; `docs/wireguard.md` describes
//! what happens to each kind of packet and what is out of scope.

mod config;
mod server;

pub use config::{
    DEFAULT_PORT, PREFIX_LEN, Peer, SERVER_ADDR, Store, client_config, decode_key, encode_key,
    generate_key,
};
pub use server::Server;

/// The key types of the noise implementation, so callers name the matching version.
pub use boringtun::x25519::{PublicKey, StaticSecret};

/// The first `nameserver` of `/etc/resolv.conf`, the resolver DNS queries are relayed to.
#[must_use]
pub fn system_resolver() -> Option<std::net::SocketAddr> {
    let text = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    text.lines()
        .filter_map(|line| line.trim().strip_prefix("nameserver"))
        .filter_map(|rest| rest.trim().parse::<std::net::IpAddr>().ok())
        .map(|ip| std::net::SocketAddr::new(ip, 53))
        .next()
}
