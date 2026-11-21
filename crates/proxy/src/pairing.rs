//! Device pairing: which source addresses may use a proxy that listens on the LAN.
//!
//! A proxy that signs certificates for every host must not be open to everyone on the same
//! Wi-Fi. With a [`Pairing`] in [`Config::pairing`](crate::Config::pairing), loopback clients
//! are always served, addresses in the `--allow-client` list are served, and every other
//! address is served only after someone at the computer approves it. Until then the device
//! can open the setup page (which asks for approval) and nothing else: its proxy requests
//! are refused by closing the connection.
//!
//! Approval is by source IP and lasts for the session. Requests and rejections reach the
//! terminal as [`Notice`]s on a channel, so tests can approve without a terminal.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use http::{Method, Request};
use tokio::sync::mpsc;

/// How often one rejected address is logged at most.
pub const REJECTION_LOG_INTERVAL: Duration = Duration::from_secs(30);

/// How long a denied device must wait before opening the setup page asks again.
pub const DENY_COOLDOWN: Duration = Duration::from_secs(10);

/// An IP network, such as `192.168.1.0/24`; a bare address means that one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Whether `ip` lies in this network. IPv4 and IPv6 never match each other.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl FromStr for Cidr {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> anyhow::Result<Self> {
        let (addr, prefix) = text.split_once('/').unwrap_or((text, ""));
        let network: IpAddr = addr
            .parse()
            .with_context(|| format!("{text:?} is not an IP address or CIDR"))?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        let prefix = if prefix.is_empty() {
            max
        } else {
            prefix
                .parse()
                .with_context(|| format!("bad prefix length in {text:?}"))?
        };
        if prefix > max {
            bail!("prefix length {prefix} is too long for {network}");
        }
        Ok(Self { network, prefix })
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

/// Where a device stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// It may use the proxy.
    Approved,
    /// Someone at the computer has been asked.
    Waiting,
    /// The last request was refused.
    Denied,
}

impl Status {
    /// The lowercase name the setup page polls for.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Waiting => "waiting",
            Self::Denied => "denied",
        }
    }
}

/// Something the terminal should show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// An unknown device opened the setup page and wants to use the proxy.
    Request {
        /// Its source address.
        ip: IpAddr,
        /// What its User-Agent says it is, such as `iPhone`.
        device: String,
    },
    /// A proxy request from an unapproved address was refused (throttled per address).
    Rejected(IpAddr),
}

/// The approval state of every device, shared by the proxy and the terminal.
///
/// Cloning is cheap; all clones share one state.
#[derive(Debug, Clone)]
pub struct Pairing {
    inner: Arc<Mutex<Inner>>,
    notices: mpsc::UnboundedSender<Notice>,
}

#[derive(Debug)]
struct Inner {
    allow: Vec<Cidr>,
    devices: BTreeMap<IpAddr, Device>,
    rejections: BTreeMap<IpAddr, Instant>,
}

#[derive(Debug)]
struct Device {
    status: Status,
    name: String,
    since: Instant,
    traffic: bool,
    hinted: bool,
}

/// What the proxy does with one request from a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Serve it.
    Serve,
    /// Close the connection without an answer.
    Reject,
}

impl Pairing {
    /// A pairing that pre-approves the networks in `allow`, and the receiver of its notices.
    #[must_use]
    pub fn new(allow: Vec<Cidr>) -> (Self, mpsc::UnboundedReceiver<Notice>) {
        let (notices, receiver) = mpsc::unbounded_channel();
        let inner = Inner {
            allow,
            devices: BTreeMap::new(),
            rejections: BTreeMap::new(),
        };
        let pairing = Self {
            inner: Arc::new(Mutex::new(inner)),
            notices,
        };
        (pairing, receiver)
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("pairing lock poisoned")
    }

    /// Whether `ip` may use the proxy: loopback always, then the allow list, then approvals.
    #[must_use]
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        ip.is_loopback() || self.lock().allows(ip)
    }

    /// Where `ip` stands, without asking anyone.
    #[must_use]
    pub fn status(&self, ip: IpAddr) -> Status {
        if self.is_allowed(ip) {
            return Status::Approved;
        }
        self.lock()
            .devices
            .get(&ip)
            .map_or(Status::Denied, |device| device.status)
    }

    /// Called when `ip` opens the setup page: asks the terminal once, unless the device is
    /// already approved, already waiting, or was denied less than [`DENY_COOLDOWN`] ago.
    #[must_use]
    pub fn ask(&self, ip: IpAddr, device: &str, now: Instant) -> Status {
        if ip.is_loopback() {
            return Status::Approved;
        }
        let mut inner = self.lock();
        if inner.allows(ip) {
            return Status::Approved;
        }
        if let Some(known) = inner.devices.get(&ip) {
            let cooling = now.saturating_duration_since(known.since) < DENY_COOLDOWN;
            if known.status == Status::Waiting || (known.status == Status::Denied && cooling) {
                return known.status;
            }
        }
        inner.devices.insert(
            ip,
            Device {
                status: Status::Waiting,
                name: device.to_owned(),
                since: now,
                traffic: false,
                hinted: false,
            },
        );
        drop(inner);
        let _ = self.notices.send(Notice::Request {
            ip,
            device: device.to_owned(),
        });
        Status::Waiting
    }

    /// Approves `ip` for the rest of the session.
    pub fn approve(&self, ip: IpAddr) {
        self.set(ip, Status::Approved);
    }

    /// Refuses `ip`'s pending request.
    pub fn deny(&self, ip: IpAddr) {
        self.set(ip, Status::Denied);
    }

    fn set(&self, ip: IpAddr, status: Status) {
        let mut inner = self.lock();
        let device = inner.devices.entry(ip).or_insert_with(|| Device {
            status,
            name: String::from("device"),
            since: Instant::now(),
            traffic: false,
            hinted: false,
        });
        device.status = status;
        device.since = Instant::now();
    }

    /// Revokes every approval made in this session (not the `--allow-client` list) and
    /// returns the addresses that lost access.
    #[must_use]
    pub fn revoke_all(&self) -> Vec<IpAddr> {
        let mut inner = self.lock();
        let revoked = inner
            .devices
            .iter()
            .filter(|(_, device)| device.status == Status::Approved)
            .map(|(ip, _)| *ip)
            .collect();
        inner.devices.clear();
        revoked
    }

    /// The approved devices with their names, in address order.
    #[must_use]
    pub fn approved(&self) -> Vec<(IpAddr, String)> {
        self.lock()
            .devices
            .iter()
            .filter(|(_, device)| device.status == Status::Approved)
            .map(|(ip, device)| (*ip, device.name.clone()))
            .collect()
    }

    /// The `--allow-client` list.
    #[must_use]
    pub fn allow_list(&self) -> Vec<Cidr> {
        self.lock().allow.clone()
    }

    /// Decides one request from `ip` and records proxy traffic from approved devices.
    ///
    /// Unapproved clients may still reach the setup page: origin-form requests (a browser
    /// opening `http://IP:PORT/` directly) and plain requests to the magic host. CONNECT and
    /// every other proxied request is rejected, and logged at most once per
    /// [`REJECTION_LOG_INTERVAL`] per address.
    pub fn screen<B>(&self, ip: IpAddr, request: &Request<B>, now: Instant) -> Verdict {
        if ip.is_loopback() {
            return Verdict::Serve;
        }
        let local = is_local(request);
        let mut inner = self.lock();
        if inner.allows(ip) {
            if !local && let Some(device) = inner.devices.get_mut(&ip) {
                device.traffic = true;
            }
            return Verdict::Serve;
        }
        if local {
            return Verdict::Serve;
        }
        let log = inner
            .rejections
            .get(&ip)
            .is_none_or(|last| now.saturating_duration_since(*last) >= REJECTION_LOG_INTERVAL);
        if log {
            inner.rejections.insert(ip, now);
            drop(inner);
            let _ = self.notices.send(Notice::Rejected(ip));
        }
        Verdict::Reject
    }

    /// Approved devices that have sent no proxy traffic for `quiet` since approval; each is
    /// returned once per session.
    #[must_use]
    pub fn silent_devices(&self, now: Instant, quiet: Duration) -> Vec<(IpAddr, String)> {
        let mut inner = self.lock();
        inner
            .devices
            .iter_mut()
            .filter(|(_, d)| {
                d.status == Status::Approved
                    && !d.traffic
                    && !d.hinted
                    && now.saturating_duration_since(d.since) >= quiet
            })
            .map(|(ip, d)| {
                d.hinted = true;
                (*ip, d.name.clone())
            })
            .collect()
    }
}

impl Inner {
    fn allows(&self, ip: IpAddr) -> bool {
        self.allow.iter().any(|net| net.contains(ip))
            || self
                .devices
                .get(&ip)
                .is_some_and(|device| device.status == Status::Approved)
    }
}

/// Whether the proxy answers `request` itself: origin-form, or plain HTTP to the magic host.
fn is_local<B>(request: &Request<B>) -> bool {
    if request.method() == Method::CONNECT {
        return false;
    }
    match request.uri().host() {
        None => true,
        Some(host) => host.eq_ignore_ascii_case(crate::MAGIC_HOST),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("test address")
    }

    fn get(uri: &str) -> Request<()> {
        Request::get(uri).body(()).expect("test request")
    }

    fn connect(authority: &str) -> Request<()> {
        Request::connect(authority).body(()).expect("test request")
    }

    #[test]
    fn cidr_parses_and_matches() -> anyhow::Result<()> {
        let net: Cidr = "192.168.1.0/24".parse()?;
        assert!(net.contains(ip("192.168.1.200")));
        assert!(!net.contains(ip("192.168.2.1")));
        assert!(!net.contains(ip("::1")));
        let one: Cidr = "10.0.0.7".parse()?;
        assert!(one.contains(ip("10.0.0.7")) && !one.contains(ip("10.0.0.8")));
        let all: Cidr = "0.0.0.0/0".parse()?;
        assert!(all.contains(ip("8.8.8.8")));
        let v6: Cidr = "fd00::/8".parse()?;
        assert!(v6.contains(ip("fd12::1")) && !v6.contains(ip("fe80::1")));
        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
        assert!("phone".parse::<Cidr>().is_err());
        assert_eq!(net.to_string(), "192.168.1.0/24");
        Ok(())
    }

    #[test]
    fn unapproved_devices_get_only_the_setup_page() {
        let (pairing, _notices) = Pairing::new(Vec::new());
        let phone = ip("192.168.1.23");
        let now = Instant::now();
        assert_eq!(
            pairing.screen(phone, &connect("example.com:443"), now),
            Verdict::Reject
        );
        assert_eq!(
            pairing.screen(phone, &get("http://example.com/"), now),
            Verdict::Reject
        );
        assert_eq!(pairing.screen(phone, &get("/"), now), Verdict::Serve);
        assert_eq!(
            pairing.screen(phone, &get("http://wirust.test/ca.crt"), now),
            Verdict::Serve
        );
        assert_eq!(
            pairing.screen(phone, &connect("wirust.test:443"), now),
            Verdict::Reject
        );
    }

    #[tokio::test]
    async fn an_approved_device_is_served_and_revoking_ends_it() {
        let (pairing, mut notices) = Pairing::new(Vec::new());
        let phone = ip("192.168.1.23");
        let now = Instant::now();
        assert_eq!(pairing.ask(phone, "iPhone", now), Status::Waiting);
        assert_eq!(
            pairing.ask(phone, "iPhone", now),
            Status::Waiting,
            "asks once"
        );
        assert_eq!(
            notices.recv().await,
            Some(Notice::Request {
                ip: phone,
                device: "iPhone".to_owned()
            })
        );
        assert!(notices.try_recv().is_err(), "no second prompt");
        pairing.approve(phone);
        assert_eq!(pairing.status(phone), Status::Approved);
        assert_eq!(
            pairing.screen(phone, &connect("example.com:443"), now),
            Verdict::Serve
        );
        assert_eq!(pairing.approved(), [(phone, "iPhone".to_owned())]);
        assert_eq!(pairing.revoke_all(), [phone]);
        assert_eq!(
            pairing.screen(phone, &connect("example.com:443"), now),
            Verdict::Reject
        );
    }

    #[test]
    fn the_allow_list_pre_approves_networks() -> anyhow::Result<()> {
        let (pairing, _notices) = Pairing::new(vec!["192.168.1.0/24".parse()?]);
        let now = Instant::now();
        let request = connect("example.com:443");
        assert_eq!(
            pairing.screen(ip("192.168.1.50"), &request, now),
            Verdict::Serve
        );
        assert_eq!(
            pairing.screen(ip("192.168.7.50"), &request, now),
            Verdict::Reject
        );
        assert_eq!(
            pairing.ask(ip("192.168.1.9"), "Android", now),
            Status::Approved
        );
        Ok(())
    }

    #[test]
    fn rejections_are_logged_once_per_interval() {
        let (pairing, mut notices) = Pairing::new(Vec::new());
        let stranger = ip("192.168.1.50");
        let start = Instant::now();
        let request = get("http://example.com/");
        for second in 0..5 {
            let now = start + Duration::from_secs(second);
            assert_eq!(pairing.screen(stranger, &request, now), Verdict::Reject);
        }
        assert_eq!(notices.try_recv(), Ok(Notice::Rejected(stranger)));
        assert!(notices.try_recv().is_err(), "throttled");
        let later = start + REJECTION_LOG_INTERVAL;
        assert_eq!(pairing.screen(stranger, &request, later), Verdict::Reject);
        assert_eq!(notices.try_recv(), Ok(Notice::Rejected(stranger)));
        // Another address has its own budget.
        assert_eq!(
            pairing.screen(ip("192.168.1.51"), &request, later),
            Verdict::Reject
        );
        assert_eq!(notices.try_recv(), Ok(Notice::Rejected(ip("192.168.1.51"))));
    }

    #[test]
    fn loopback_clients_are_never_affected() {
        let (pairing, mut notices) = Pairing::new(Vec::new());
        let now = Instant::now();
        for client in ["127.0.0.1", "127.9.9.9", "::1"] {
            let client = ip(client);
            assert!(pairing.is_allowed(client));
            assert_eq!(pairing.ask(client, "Mac", now), Status::Approved);
            assert_eq!(
                pairing.screen(client, &connect("example.com:443"), now),
                Verdict::Serve
            );
        }
        assert_eq!(pairing.revoke_all(), Vec::<IpAddr>::new());
        assert!(pairing.is_allowed(ip("127.0.0.1")));
        assert!(notices.try_recv().is_err(), "no prompts, no rejections");
    }

    #[test]
    fn a_denied_device_waits_before_asking_again() {
        let (pairing, mut notices) = Pairing::new(Vec::new());
        let phone = ip("192.168.1.23");
        let start = Instant::now();
        assert_eq!(pairing.ask(phone, "Android", start), Status::Waiting);
        pairing.deny(phone);
        let _ = notices.try_recv();
        assert_eq!(pairing.status(phone), Status::Denied);
        let soon = Instant::now() + Duration::from_secs(1);
        assert_eq!(pairing.ask(phone, "Android", soon), Status::Denied);
        assert!(notices.try_recv().is_err());
        let later = Instant::now() + DENY_COOLDOWN;
        assert_eq!(pairing.ask(phone, "Android", later), Status::Waiting);
        assert!(notices.try_recv().is_ok(), "asks again after the cooldown");
    }

    #[test]
    fn silent_devices_are_reported_once() {
        let (pairing, _notices) = Pairing::new(Vec::new());
        let (quiet, busy) = (ip("192.168.1.23"), ip("192.168.1.24"));
        pairing.approve(quiet);
        pairing.approve(busy);
        let now = Instant::now();
        assert_eq!(
            pairing.screen(busy, &connect("example.com:443"), now),
            Verdict::Serve
        );
        let later = now + Duration::from_secs(120);
        let silent = pairing.silent_devices(later, Duration::from_secs(60));
        assert_eq!(silent.len(), 1);
        assert_eq!(silent[0].0, quiet);
        assert_eq!(pairing.silent_devices(later, Duration::from_secs(60)), []);
    }
}
