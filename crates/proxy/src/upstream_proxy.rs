//! Chaining to another proxy (`--upstream-proxy`): the address and its credentials, the
//! bypass list, and small HTTP CONNECT and SOCKS5 clients.
//!
//! Credentials never leave this module in text form: [`UpstreamProxy`] prints as
//! `scheme://user:***@host:port`, and so does every error it produces.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context as _, anyhow, bail};
use base64::Engine as _;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

/// The protocol spoken to the upstream proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// HTTP: `CONNECT` for tunnels, absolute-form requests for plain `http://`.
    Http,
    /// SOCKS5, with host names resolved by this proxy.
    Socks5,
    /// SOCKS5, with host names sent to the upstream proxy to resolve.
    Socks5h,
}

impl Kind {
    fn scheme(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Socks5 => "socks5",
            Self::Socks5h => "socks5h",
        }
    }
}

/// A user name and password for the upstream proxy. `Debug` hides the password.
#[derive(Clone, PartialEq, Eq)]
struct Credentials {
    user: String,
    password: String,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("user", &self.user)
            .field("password", &"***")
            .finish()
    }
}

/// Another proxy every outbound connection goes through, parsed from
/// `http://`, `socks5://` or `socks5h://` URLs with optional `user:pass@`.
///
/// `Display` and `Debug` never show the password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamProxy {
    kind: Kind,
    host: String,
    port: u16,
    credentials: Option<Credentials>,
}

impl UpstreamProxy {
    /// The protocol spoken to it.
    #[must_use]
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// Its host name or IP, without brackets.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Its port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether a user name and password were given.
    #[must_use]
    pub fn has_credentials(&self) -> bool {
        self.credentials.is_some()
    }

    /// Whether the host is a loopback address or `localhost`.
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        is_loopback(&self.host)
    }

    /// The `Proxy-Authorization` value for an HTTP proxy, if credentials were given.
    pub(crate) fn basic_auth(&self) -> Option<String> {
        self.credentials.as_ref().map(|c| {
            let pair = format!("{}:{}", c.user, c.password);
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(pair)
            )
        })
    }
}

impl fmt::Display for UpstreamProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://", self.kind.scheme())?;
        if let Some(credentials) = &self.credentials {
            write!(f, "{}:***@", credentials.user)?;
        }
        write!(f, "{}:{}", bracket(&self.host), self.port)
    }
}

impl FromStr for UpstreamProxy {
    type Err = anyhow::Error;

    /// Parses `scheme://[user:pass@]host[:port]`. Errors never repeat the input, which may
    /// hold a password. The port defaults to 8080 for `http` and 1080 for SOCKS.
    fn from_str(url: &str) -> anyhow::Result<Self> {
        let (scheme, rest) = url
            .split_once("://")
            .context("the upstream proxy needs a scheme: http://, socks5:// or socks5h://")?;
        let kind = match scheme.to_ascii_lowercase().as_str() {
            "http" => Kind::Http,
            "socks5" => Kind::Socks5,
            "socks5h" => Kind::Socks5h,
            _ => bail!("unsupported upstream proxy scheme; use http://, socks5:// or socks5h://"),
        };
        let rest = rest.trim_end_matches('/');
        if rest.contains('/') {
            bail!("the upstream proxy URL takes no path");
        }
        let (userinfo, address) = match rest.rsplit_once('@') {
            Some((userinfo, address)) => (Some(userinfo), address),
            None => (None, rest),
        };
        let credentials = userinfo.map(parse_userinfo).transpose()?;
        let default_port = if kind == Kind::Http { 8080 } else { 1080 };
        let (host, port) = split_host_port(address, default_port)?;
        Ok(Self {
            kind,
            host,
            port,
            credentials,
        })
    }
}

fn parse_userinfo(userinfo: &str) -> anyhow::Result<Credentials> {
    let (user, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    let credentials = Credentials {
        user: percent_decode(user).context("invalid %-escape in the upstream proxy user")?,
        password: percent_decode(password)
            .context("invalid %-escape in the upstream proxy password")?,
    };
    if credentials.user.is_empty() {
        bail!("the upstream proxy user name is empty");
    }
    if credentials.user.len() > 255 || credentials.password.len() > 255 {
        bail!("the upstream proxy user name and password are limited to 255 bytes each");
    }
    Ok(credentials)
}

fn percent_decode(text: &str) -> anyhow::Result<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3).context("truncated escape")?;
            let hex = std::str::from_utf8(hex)?;
            out.push(u8::from_str_radix(hex, 16)?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(String::from_utf8(out)?)
}

fn split_host_port(address: &str, default_port: u16) -> anyhow::Result<(String, u16)> {
    let (host, port) = if let Some(rest) = address.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .context("unclosed [ in the upstream proxy address")?;
        (host, after.strip_prefix(':'))
    } else {
        match address.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (address, None),
        }
    };
    if host.is_empty() {
        bail!("the upstream proxy URL has no host");
    }
    let port = match port {
        Some(port) => port.parse().context("invalid upstream proxy port")?,
        None => default_port,
    };
    Ok((host.to_ascii_lowercase(), port))
}

/// Destinations that skip the upstream proxy (`--upstream-bypass`): exact host names,
/// `*.domain` (the domain and its subdomains), IP addresses and CIDR ranges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bypass {
    entries: Vec<Entry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    Host(String),
    Domain(String),
    Net(IpAddr, u8),
}

impl Bypass {
    /// Whether `host` (a name or an IP, brackets allowed) is on the list.
    #[must_use]
    pub fn matches(&self, host: &str) -> bool {
        let host = unbracket(host).trim_end_matches('.').to_ascii_lowercase();
        let ip: Option<IpAddr> = host.parse().ok();
        self.entries.iter().any(|entry| match entry {
            Entry::Host(name) => *name == host,
            Entry::Domain(domain) => {
                host == *domain
                    || host
                        .strip_suffix(domain.as_str())
                        .is_some_and(|rest| rest.ends_with('.'))
            }
            Entry::Net(net, prefix) => ip.is_some_and(|ip| in_net(ip, *net, *prefix)),
        })
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Adds the entries of a comma-separated list.
    ///
    /// # Errors
    ///
    /// Fails on an invalid IP or CIDR prefix.
    pub fn extend_from(&mut self, list: &str) -> anyhow::Result<()> {
        for item in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            self.entries.push(parse_entry(item)?);
        }
        Ok(())
    }
}

impl FromStr for Bypass {
    type Err = anyhow::Error;

    fn from_str(list: &str) -> anyhow::Result<Self> {
        let mut bypass = Self::default();
        bypass.extend_from(list)?;
        Ok(bypass)
    }
}

fn parse_entry(item: &str) -> anyhow::Result<Entry> {
    let item = item.to_ascii_lowercase();
    if let Some((net, prefix)) = item.split_once('/') {
        let net: IpAddr = unbracket(net)
            .parse()
            .with_context(|| format!("invalid network in bypass entry {item}"))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let prefix: u8 = prefix
            .parse()
            .ok()
            .filter(|p| *p <= max)
            .with_context(|| format!("invalid prefix length in bypass entry {item}"))?;
        return Ok(Entry::Net(net, prefix));
    }
    if let Ok(ip) = unbracket(&item).parse::<IpAddr>() {
        return Ok(Entry::Net(ip, if ip.is_ipv4() { 32 } else { 128 }));
    }
    match item.strip_prefix("*.").or_else(|| item.strip_prefix('.')) {
        Some(domain) => Ok(Entry::Domain(domain.to_owned())),
        None => Ok(Entry::Host(item)),
    }
}

fn in_net(ip: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            u32::from(ip) & mask == u32::from(net) & mask
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            u128::from(ip) & mask == u128::from(net) & mask
        }
        _ => false,
    }
}

/// Which connections go through the upstream proxy.
#[derive(Debug, Clone, Default)]
pub(crate) struct Route {
    proxy: Option<UpstreamProxy>,
    bypass: Bypass,
}

impl Route {
    pub(crate) fn new(proxy: Option<UpstreamProxy>, bypass: Bypass) -> Self {
        Self { proxy, bypass }
    }

    /// The proxy to reach `host` through, or `None` to connect directly. Loopback,
    /// `localhost` and the proxy's own setup host always go direct.
    pub(crate) fn via(&self, host: &str) -> Option<&UpstreamProxy> {
        let proxy = self.proxy.as_ref()?;
        let direct = is_loopback(host)
            || unbracket(host).eq_ignore_ascii_case(crate::MAGIC_HOST)
            || self.bypass.matches(host);
        (!direct).then_some(proxy)
    }
}

fn is_loopback(host: &str) -> bool {
    let host = unbracket(host).trim_end_matches('.');
    let lower = host.to_ascii_lowercase();
    lower == "localhost"
        || lower.ends_with(".localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified())
}

fn unbracket(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

fn bracket(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

/// Upper bound on the response head of an HTTP proxy's answer to `CONNECT`.
const MAX_HEAD: usize = 16 * 1024;

/// Opens a TCP connection to `proxy` and asks it for a tunnel to `host:port`, all within
/// `timeout`. Errors name the proxy, redacted.
pub(crate) async fn tunnel(
    proxy: &UpstreamProxy,
    host: &str,
    port: u16,
    timeout: Duration,
) -> anyhow::Result<TcpStream> {
    let host = unbracket(host);
    let attempt = async {
        let mut stream = connect(proxy).await?;
        match proxy.kind {
            Kind::Http => http_connect(&mut stream, proxy, host, port).await?,
            Kind::Socks5 | Kind::Socks5h => socks5_connect(&mut stream, proxy, host, port).await?,
        }
        anyhow::Ok(stream)
    };
    tokio::time::timeout(timeout, attempt)
        .await
        .map_err(|_| anyhow!("upstream proxy {proxy}: tunnel to {host}:{port} timed out"))?
        .with_context(|| format!("upstream proxy {proxy}: tunnel to {host}:{port}"))
}

/// Opens a plain TCP connection to `proxy`, for absolute-form HTTP requests, within
/// `timeout`.
pub(crate) async fn connect_forward(
    proxy: &UpstreamProxy,
    timeout: Duration,
) -> anyhow::Result<TcpStream> {
    tokio::time::timeout(timeout, connect(proxy))
        .await
        .map_err(|_| anyhow!("upstream proxy {proxy}: connecting timed out"))?
        .with_context(|| format!("upstream proxy {proxy}"))
}

async fn connect(proxy: &UpstreamProxy) -> anyhow::Result<TcpStream> {
    let stream = TcpStream::connect((proxy.host.as_str(), proxy.port))
        .await
        .context("connecting")?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

async fn http_connect(
    stream: &mut TcpStream,
    proxy: &UpstreamProxy,
    host: &str,
    port: u16,
) -> anyhow::Result<()> {
    let authority = format!("{}:{port}", bracket(host));
    let auth = proxy
        .basic_auth()
        .map(|auth| format!("Proxy-Authorization: {auth}\r\n"))
        .unwrap_or_default();
    let head = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{auth}\r\n");
    stream.write_all(head.as_bytes()).await?;
    let response = read_head(stream).await?;
    let status = status_code(&response).context("invalid answer to CONNECT")?;
    match status {
        200..=299 => Ok(()),
        407 if proxy.has_credentials() => {
            bail!("the credentials were rejected (407 Proxy Authentication Required)")
        }
        407 => bail!("authentication required (407 Proxy Authentication Required)"),
        _ => bail!("CONNECT refused with status {status}"),
    }
}

/// Reads up to and including the blank line, one byte at a time so no tunnel data is
/// consumed.
async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> anyhow::Result<Vec<u8>> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEAD {
            bail!("the answer to CONNECT is over {MAX_HEAD} bytes");
        }
        let byte = stream
            .read_u8()
            .await
            .context("the connection closed before the answer to CONNECT ended")?;
        head.push(byte);
    }
    Ok(head)
}

fn status_code(head: &[u8]) -> Option<u16> {
    let line = head.split(|b| *b == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?;
    let mut words = line.split_whitespace();
    words.next().filter(|v| v.starts_with("HTTP/"))?;
    words.next()?.parse().ok()
}

/// SOCKS5 authentication methods (RFC 1928 section 3).
const NO_AUTH: u8 = 0x00;
const USER_PASS: u8 = 0x02;
const NO_ACCEPTABLE: u8 = 0xFF;

async fn socks5_connect(
    stream: &mut TcpStream,
    proxy: &UpstreamProxy,
    host: &str,
    port: u16,
) -> anyhow::Result<()> {
    let greeting: &[u8] = if proxy.credentials.is_some() {
        &[5, 2, NO_AUTH, USER_PASS]
    } else {
        &[5, 1, NO_AUTH]
    };
    stream.write_all(greeting).await?;
    let mut choice = [0u8; 2];
    stream
        .read_exact(&mut choice)
        .await
        .context("no SOCKS5 greeting")?;
    if choice[0] != 5 {
        bail!("not a SOCKS5 server (version byte {})", choice[0]);
    }
    match (choice[1], &proxy.credentials) {
        (NO_AUTH, _) => {}
        (USER_PASS, Some(credentials)) => socks5_login(stream, credentials).await?,
        (USER_PASS, None) => bail!("SOCKS5 authentication required"),
        (NO_ACCEPTABLE, _) => bail!("SOCKS5 server accepts none of the offered auth methods"),
        (other, _) => bail!("SOCKS5 server chose unknown auth method {other}"),
    }
    let mut request = vec![5, 1, 0];
    let ip = match host.parse::<IpAddr>() {
        Ok(ip) => Some(ip),
        Err(_) if proxy.kind == Kind::Socks5 => Some(resolve(host, port).await?),
        Err(_) => None,
    };
    match ip {
        Some(IpAddr::V4(ip)) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        Some(IpAddr::V6(ip)) => {
            request.push(4);
            request.extend_from_slice(&ip.octets());
        }
        None => {
            let len = u8::try_from(host.len()).context("host name over 255 bytes")?;
            request.push(3);
            request.push(len);
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 4];
    stream
        .read_exact(&mut reply)
        .await
        .context("no SOCKS5 reply")?;
    if reply[1] != 0 {
        bail!("SOCKS5 reply {}: {}", reply[1], reply_text(reply[1]));
    }
    let address_len = match reply[3] {
        1 => 4,
        4 => 16,
        3 => usize::from(stream.read_u8().await?),
        other => bail!("SOCKS5 reply with unknown address type {other}"),
    };
    let mut bound = vec![0u8; address_len + 2];
    stream.read_exact(&mut bound).await?;
    Ok(())
}

async fn socks5_login(stream: &mut TcpStream, credentials: &Credentials) -> anyhow::Result<()> {
    // Lengths were checked to fit a byte when the URL was parsed.
    let user_len = u8::try_from(credentials.user.len())?;
    let password_len = u8::try_from(credentials.password.len())?;
    let mut login = vec![1, user_len];
    login.extend_from_slice(credentials.user.as_bytes());
    login.push(password_len);
    login.extend_from_slice(credentials.password.as_bytes());
    stream.write_all(&login).await?;
    let mut status = [0u8; 2];
    stream
        .read_exact(&mut status)
        .await
        .context("no SOCKS5 login reply")?;
    if status[1] != 0 {
        bail!("SOCKS5 server rejected the credentials");
    }
    Ok(())
}

async fn resolve(host: &str, port: u16) -> anyhow::Result<IpAddr> {
    let mut addrs = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolving {host}"))?;
    addrs
        .next()
        .map(|addr: SocketAddr| addr.ip())
        .with_context(|| format!("{host} has no address"))
}

/// The meaning of a SOCKS5 reply code (RFC 1928 section 6).
fn reply_text(code: u8) -> &'static str {
    match code {
        1 => "general failure",
        2 => "connection not allowed by ruleset",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "TTL expired",
        7 => "command not supported",
        8 => "address type not supported",
        _ => "unknown error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_redacts() -> anyhow::Result<()> {
        let proxy: UpstreamProxy = "socks5h://alice:s%40cret@Proxy.example:1081".parse()?;
        assert_eq!(proxy.kind(), Kind::Socks5h);
        assert_eq!(proxy.host(), "proxy.example");
        assert_eq!(proxy.port(), 1081);
        assert_eq!(proxy.to_string(), "socks5h://alice:***@proxy.example:1081");
        assert!(!format!("{proxy:?}").contains("cret"));
        assert_eq!(
            proxy.basic_auth().as_deref(),
            Some("Basic YWxpY2U6c0BjcmV0")
        );
        Ok(())
    }

    #[test]
    fn defaults_and_ipv6() -> anyhow::Result<()> {
        let http: UpstreamProxy = "http://10.0.0.1".parse()?;
        assert_eq!(http.to_string(), "http://10.0.0.1:8080");
        let socks: UpstreamProxy = "socks5://[::1]/".parse()?;
        assert_eq!(socks.to_string(), "socks5://[::1]:1080");
        assert!(socks.is_loopback());
        Ok(())
    }

    #[test]
    fn errors_do_not_echo_the_url() {
        for url in [
            "ftp://u:hunter2@h:1",
            "http://u:hunter2@h:notaport",
            "u:hunter2@h:1",
            "http://u:hunter2%zz@h",
        ] {
            let error = url.parse::<UpstreamProxy>().err().map(|e| format!("{e:#}"));
            let error = error.unwrap_or_default();
            assert!(!error.is_empty(), "{url} should fail");
            assert!(!error.contains("hunter2"), "{error}");
        }
    }

    #[test]
    fn bypass_matches_hosts_domains_and_networks() -> anyhow::Result<()> {
        let bypass: Bypass = "intranet, *.corp.example, 10.0.0.0/8, fd00::/8, 192.0.2.7".parse()?;
        assert!(bypass.matches("INTRANET"));
        assert!(bypass.matches("corp.example"));
        assert!(bypass.matches("a.b.corp.example"));
        assert!(!bypass.matches("evilcorp.example"));
        assert!(bypass.matches("10.200.1.1"));
        assert!(bypass.matches("[fd12::1]"));
        assert!(bypass.matches("192.0.2.7"));
        assert!(!bypass.matches("192.0.2.8"));
        assert!(!bypass.matches("example.org"));
        assert!("10.0.0.0/33".parse::<Bypass>().is_err());
        Ok(())
    }

    #[test]
    fn loopback_and_magic_host_always_go_direct() -> anyhow::Result<()> {
        let route = Route::new(Some("http://10.0.0.1:3128".parse()?), "*.direct".parse()?);
        for host in [
            "localhost",
            "127.0.0.5",
            "[::1]",
            "app.localhost",
            crate::MAGIC_HOST,
        ] {
            assert!(route.via(host).is_none(), "{host}");
        }
        assert!(route.via("x.direct").is_none());
        assert!(route.via("example.com").is_some());
        assert!(Route::default().via("example.com").is_none());
        Ok(())
    }
}
