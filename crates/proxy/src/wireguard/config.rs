//! Keys, peers and client configurations of the WireGuard capture mode.
//!
//! Everything lives in `<config dir>/wireguard/` (mode 0700): `server.key` holds the
//! server's private key (mode 0600) and `peers` one line per peer, `NAME PUBLIC_KEY ADDRESS`
//! (mode 0600). A peer's private key is printed once by `add-peer` and never stored.

use std::fs;
use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use base64::Engine as _;
use boringtun::x25519::{PublicKey, StaticSecret};

use crate::ca::{create_private_dir, write_private};

/// The server's address inside the tunnel; peers get the following addresses of its /24.
/// A rarely used private range, so it does not collide with the phone's own network.
pub const SERVER_ADDR: Ipv4Addr = Ipv4Addr::new(10, 233, 0, 1);

/// The tunnel's prefix length.
pub const PREFIX_LEN: u8 = 24;

/// The usual WireGuard port, used when `--listen` names none.
pub const DEFAULT_PORT: u16 = 51820;

const DIR: &str = "wireguard";
const SERVER_KEY: &str = "server.key";
const PEERS: &str = "peers";

/// A peer allowed to connect: its public key and its address inside the tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// A label for the operator, without spaces.
    pub name: String,
    /// The peer's public key; only handshakes signed by a configured key are answered.
    pub public_key: [u8; 32],
    /// The only source address the peer may use inside the tunnel.
    pub address: Ipv4Addr,
}

/// The `wireguard` directory under the config dir.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    /// The store under `config_dir`; nothing is created until a key is needed.
    #[must_use]
    pub fn new(config_dir: &Path) -> Self {
        Self {
            dir: config_dir.join(DIR),
        }
    }

    /// The server's private key, created (mode 0600) on first use.
    ///
    /// # Errors
    ///
    /// Fails when the key file cannot be read, written or parsed.
    pub fn server_key(&self) -> anyhow::Result<StaticSecret> {
        let path = self.dir.join(SERVER_KEY);
        if path.exists() {
            let text =
                fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
            return Ok(StaticSecret::from(
                decode_key(text.trim()).with_context(|| format!("parsing {}", path.display()))?,
            ));
        }
        create_private_dir(&self.dir)?;
        let key = generate_key()?;
        write_private(
            &path,
            format!("{}\n", encode_key(&key.to_bytes())).as_bytes(),
        )?;
        Ok(key)
    }

    /// The configured peers; none when the file does not exist yet.
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be read or a line is malformed.
    pub fn peers(&self) -> anyhow::Result<Vec<Peer>> {
        let path = self.dir.join(PEERS);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let lines = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'));
        lines
            .map(|line| parse_peer(line).with_context(|| format!("{}: {line}", path.display())))
            .collect()
    }

    /// Adds a peer named `name` with a fresh key pair and the next free address, and returns
    /// it with its private key, which is not stored anywhere.
    ///
    /// # Errors
    ///
    /// Fails on a bad name, a full subnet or a file error.
    pub fn add_peer(&self, name: &str) -> anyhow::Result<(Peer, StaticSecret)> {
        if name.is_empty() || name.contains(char::is_whitespace) {
            bail!("a peer name needs at least one character and no spaces");
        }
        let peers = self.peers()?;
        if peers.iter().any(|peer| peer.name == name) {
            bail!("a peer named {name} exists already");
        }
        let [a, b, c, _] = SERVER_ADDR.octets();
        let address = (2..=254)
            .map(|d| Ipv4Addr::new(a, b, c, d))
            .find(|address| peers.iter().all(|peer| peer.address != *address))
            .context("every address of the tunnel subnet is taken")?;
        let key = generate_key()?;
        let peer = Peer {
            name: name.to_owned(),
            public_key: PublicKey::from(&key).to_bytes(),
            address,
        };
        create_private_dir(&self.dir)?;
        let path = self.dir.join(PEERS);
        let mut options = fs::OpenOptions::new();
        options.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        writeln!(file, "{name} {} {address}", encode_key(&peer.public_key))
            .with_context(|| format!("writing {}", path.display()))?;
        Ok((peer, key))
    }
}

fn parse_peer(line: &str) -> anyhow::Result<Peer> {
    let [name, key, address] = line.split_whitespace().collect::<Vec<_>>()[..] else {
        bail!("expected NAME PUBLIC_KEY ADDRESS");
    };
    Ok(Peer {
        name: name.to_owned(),
        public_key: decode_key(key)?,
        address: address.parse().context("bad tunnel address")?,
    })
}

/// A new private key from the operating system's random source.
///
/// # Errors
///
/// Fails when the random source does.
pub fn generate_key() -> anyhow::Result<StaticSecret> {
    let mut bytes = [0_u8; 32];
    aws_lc_rs::rand::fill(&mut bytes).map_err(|_| anyhow::anyhow!("no random bytes"))?;
    Ok(StaticSecret::from(bytes))
}

/// A key in WireGuard's text form (standard base64).
#[must_use]
pub fn encode_key(key: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(key)
}

/// Parses a key in WireGuard's text form.
///
/// # Errors
///
/// Fails on bad base64 or a length other than 32 bytes.
pub fn decode_key(text: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text)
        .context("a key is base64")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("a key has 32 bytes"))
}

/// The configuration for the official WireGuard app: every IPv4 and IPv6 route goes
/// through the tunnel and DNS goes to the server's tunnel address.
#[must_use]
pub fn client_config(
    peer: &Peer,
    peer_key: &StaticSecret,
    server: &PublicKey,
    endpoint: SocketAddr,
) -> String {
    format!(
        "[Interface]
PrivateKey = {private}
Address = {address}/32
DNS = {SERVER_ADDR}

[Peer]
PublicKey = {public}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {endpoint}
",
        private = encode_key(&peer_key.to_bytes()),
        address = peer.address,
        public = encode_key(server.as_bytes()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_peers_persist_privately() -> anyhow::Result<()> {
        let dir = std::env::temp_dir().join(format!("wirust-wg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = Store::new(&dir);
        let key = store.server_key()?;
        assert_eq!(store.server_key()?.to_bytes(), key.to_bytes());
        let (first, _) = store.add_peer("phone")?;
        let (second, _) = store.add_peer("tablet")?;
        assert_eq!(first.address, Ipv4Addr::new(10, 233, 0, 2));
        assert_eq!(second.address, Ipv4Addr::new(10, 233, 0, 3));
        assert_eq!(store.peers()?, vec![first, second]);
        assert!(store.add_peer("phone").is_err(), "names are unique");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for file in [SERVER_KEY, PEERS] {
                let mode = fs::metadata(dir.join(DIR).join(file))?.permissions().mode();
                assert_eq!(mode & 0o777, 0o600, "{file}");
            }
        }
        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn the_client_config_routes_everything_through_the_tunnel() -> anyhow::Result<()> {
        let peer_key = generate_key()?;
        let peer = Peer {
            name: "phone".to_owned(),
            public_key: PublicKey::from(&peer_key).to_bytes(),
            address: Ipv4Addr::new(10, 233, 0, 2),
        };
        let server = PublicKey::from(&generate_key()?);
        let text = client_config(&peer, &peer_key, &server, "192.168.1.5:51820".parse()?);
        assert!(text.contains("AllowedIPs = 0.0.0.0/0, ::/0"), "{text}");
        assert!(text.contains("DNS = 10.233.0.1"), "{text}");
        assert!(text.contains("Address = 10.233.0.2/32"), "{text}");
        assert!(text.contains("Endpoint = 192.168.1.5:51820"), "{text}");
        assert!(text.contains(&encode_key(server.as_bytes())), "{text}");
        Ok(())
    }
}
