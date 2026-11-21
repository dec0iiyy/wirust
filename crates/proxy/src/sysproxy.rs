//! Points this computer's system proxy at wirust and puts the previous settings back.
//!
//! Before anything changes, the current settings are saved to `system-proxy.json` (mode
//! `0600`) in the config directory. Restoring reads that file, so `wirust system-proxy off`
//! also repairs the settings after a crash, and a leftover file is detected at the next start.
//!
//! - macOS: `networksetup` web and secure web proxy of every enabled network service.
//! - Windows: `ProxyEnable`, `ProxyServer` and `ProxyOverride` under the `HKCU` Internet
//!   Settings key, then a `WinINet` refresh so running programs see the change.
//! - Linux: `gsettings` (`org.gnome.system.proxy`) when GNOME is present, otherwise the
//!   environment variables to set by hand.

use std::fmt::Write as _;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

use crate::NAME;
use crate::oscmd::{CommandRunner, Platform, args};

/// The state file in the config directory.
const STATE_FILE: &str = "system-proxy.json";

/// Hosts and networks that keep going direct: this machine and the local network.
const BYPASS: &[&str] = &[
    "localhost",
    "127.0.0.1",
    "::1",
    "*.local",
    "169.254.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
];

const NETWORKSETUP: &str = "networksetup";
const REG_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const REG_VALUES: [&str; 3] = ["ProxyEnable", "ProxyServer", "ProxyOverride"];
/// Tells `WinINet` (and so Edge, Chrome and most programs) to reread the proxy settings:
/// `INTERNET_OPTION_SETTINGS_CHANGED` (39), then `INTERNET_OPTION_REFRESH` (37).
const WININET_REFRESH: &str = "$t=Add-Type -PassThru -Name WinInet -Namespace Wirust \
     -MemberDefinition '[DllImport(\"wininet.dll\")] public static extern bool \
     InternetSetOption(IntPtr h, int o, IntPtr b, int l);'; \
     [void]$t::InternetSetOption(0,39,0,0); [void]$t::InternetSetOption(0,37,0,0)";
const GNOME_KEYS: [(&str, &str); 6] = [
    ("org.gnome.system.proxy", "mode"),
    ("org.gnome.system.proxy", "ignore-hosts"),
    ("org.gnome.system.proxy.http", "host"),
    ("org.gnome.system.proxy.http", "port"),
    ("org.gnome.system.proxy.https", "host"),
    ("org.gnome.system.proxy.https", "port"),
];

/// One `networksetup` proxy (web or secure web) of one service.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacProxy {
    /// Whether the proxy is on.
    pub enabled: bool,
    /// The proxy host; empty when none was ever set.
    pub server: String,
    /// The proxy port; 0 when none was ever set.
    pub port: u16,
}

/// The saved proxy settings of one macOS network service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacService {
    /// The service name, such as `Wi-Fi`.
    pub name: String,
    /// The web (HTTP) proxy.
    pub web: MacProxy,
    /// The secure web (HTTPS) proxy.
    pub secure: MacProxy,
    /// The bypass domains.
    pub bypass: Vec<String>,
}

/// One saved registry value; `None` when it did not exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegValue {
    /// The value name, such as `ProxyEnable`.
    pub name: String,
    /// The type (`REG_DWORD`, `REG_SZ`) and data as `reg query` printed them.
    pub value: Option<(String, String)>,
}

/// One saved `gsettings` key, as `GVariant` text that `gsettings set` takes back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GnomeKey {
    /// The schema, such as `org.gnome.system.proxy.http`.
    pub schema: String,
    /// The key, such as `host`.
    pub key: String,
    /// The value, such as `'127.0.0.1'`.
    pub value: String,
}

/// The settings saved before wirust changed them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case")]
pub enum Saved {
    /// Every enabled macOS network service.
    MacOs {
        /// The services, in `networksetup` order.
        services: Vec<MacService>,
    },
    /// The three Internet Settings registry values.
    Windows {
        /// The values.
        values: Vec<RegValue>,
    },
    /// The GNOME proxy keys.
    Gnome {
        /// The keys.
        keys: Vec<GnomeKey>,
    },
}

/// What turning the system proxy on did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enabled {
    /// The settings were changed; the text says which.
    Changed(String),
    /// Nothing could be changed automatically; the text says what to set by hand.
    Manual(String),
}

/// The system proxy settings of one machine, read and written through a [`CommandRunner`].
#[derive(Debug)]
pub struct SystemProxy<R: CommandRunner> {
    runner: R,
    platform: Platform,
    state_path: PathBuf,
}

impl<R: CommandRunner> SystemProxy<R> {
    /// Settings of `platform`, saved to a state file in `dir`.
    pub fn new(runner: R, platform: Platform, dir: &Path) -> Self {
        Self {
            runner,
            platform,
            state_path: dir.join(STATE_FILE),
        }
    }

    /// The runner, for tests that inspect the recorded commands.
    pub fn runner(&self) -> &R {
        &self.runner
    }

    /// Where the previous settings are saved while the system proxy is on.
    #[must_use]
    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    /// Whether a state file exists, that is the settings have not been restored yet.
    #[must_use]
    pub fn has_saved_state(&self) -> bool {
        self.state_path.exists()
    }

    /// Saves the current settings, then points the system proxy at `listen`.
    ///
    /// When a change fails halfway, the saved settings are put back before returning.
    ///
    /// # Errors
    ///
    /// Fails when a state file from an earlier run still exists (restore it first with
    /// [`SystemProxy::restore`]), when the settings cannot be read or saved, or when a
    /// change fails.
    pub fn enable(&self, listen: SocketAddr) -> anyhow::Result<Enabled> {
        anyhow::ensure!(
            !self.has_saved_state(),
            "{} exists: an earlier run did not restore the system proxy; run `{NAME} \
             system-proxy off` first",
            self.state_path.display()
        );
        let target = Target::from_listen(listen);
        let Some(saved) = self.capture()? else {
            return Ok(Enabled::Manual(env_instructions(target)));
        };
        if let Some(dir) = self.state_path.parent() {
            crate::ca::create_private_dir(dir)?;
        }
        let json = serde_json::to_vec_pretty(&saved).context("encoding the saved settings")?;
        crate::ca::write_private(&self.state_path, &json)?;
        let commands = apply_commands(&saved, target);
        if let Err(e) = self.run_all(&commands) {
            let undo = self.restore();
            return Err(match undo {
                Ok(_) => e.context("changing the system proxy (the old settings are back)"),
                Err(undo) => e.context(format!(
                    "changing the system proxy; restoring also failed ({undo:#}); run `{NAME} \
                     system-proxy off`"
                )),
            });
        }
        self.refresh();
        Ok(Enabled::Changed(describe(&saved, target)))
    }

    /// Puts back the settings saved by [`SystemProxy::enable`] and deletes the state file.
    /// Returns `false` when there was nothing to restore.
    ///
    /// # Errors
    ///
    /// Fails when the state file cannot be read or a command fails; the state file is then
    /// kept so a later `off` can retry.
    pub fn restore(&self) -> anyhow::Result<bool> {
        let json = match fs::read(&self.state_path) {
            Ok(json) => json,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => {
                return Err(e).with_context(|| format!("reading {}", self.state_path.display()));
            }
        };
        let saved: Saved = serde_json::from_slice(&json)
            .with_context(|| format!("parsing {}", self.state_path.display()))?;
        self.run_all(&restore_commands(&saved))?;
        self.refresh();
        fs::remove_file(&self.state_path)
            .with_context(|| format!("removing {}", self.state_path.display()))?;
        Ok(true)
    }

    /// The current settings, as readable text.
    ///
    /// # Errors
    ///
    /// Fails when the settings cannot be read.
    pub fn status(&self) -> anyhow::Result<String> {
        let mut out = match self.capture()? {
            Some(saved) => describe_saved(&saved),
            None => "no system proxy settings this program can read (no GNOME gsettings); \
                     programs use the http_proxy and https_proxy environment variables\n"
                .to_owned(),
        };
        if self.has_saved_state() {
            let _ = writeln!(
                out,
                "{} holds the settings from before {NAME} changed them; `{NAME} system-proxy \
                 off` puts them back",
                self.state_path.display()
            );
        }
        Ok(out)
    }

    /// Reads the current settings; `None` on Linux without GNOME.
    fn capture(&self) -> anyhow::Result<Option<Saved>> {
        match self.platform {
            Platform::MacOs => self.capture_mac().map(Some),
            Platform::Windows => self.capture_windows().map(Some),
            Platform::Linux => self.capture_gnome(),
        }
    }

    fn capture_mac(&self) -> anyhow::Result<Saved> {
        let list = self
            .runner
            .run_ok(NETWORKSETUP, &args(&["-listallnetworkservices"]))?;
        let services = parse_services(&list)
            .into_iter()
            .map(|name| {
                let get = |flag: &str| self.runner.run_ok(NETWORKSETUP, &args(&[flag, &name]));
                Ok(MacService {
                    web: parse_proxy(&get("-getwebproxy")?),
                    secure: parse_proxy(&get("-getsecurewebproxy")?),
                    bypass: parse_bypass(&get("-getproxybypassdomains")?),
                    name,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Saved::MacOs { services })
    }

    fn capture_windows(&self) -> anyhow::Result<Saved> {
        let values = REG_VALUES
            .iter()
            .map(|&name| {
                let output = self
                    .runner
                    .run("reg", &args(&["query", REG_KEY, "/v", name]))?;
                Ok(RegValue {
                    name: name.to_owned(),
                    value: output
                        .success
                        .then(|| parse_reg_value(&output.stdout, name))
                        .flatten(),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Saved::Windows { values })
    }

    fn capture_gnome(&self) -> anyhow::Result<Option<Saved>> {
        let mut keys = Vec::with_capacity(GNOME_KEYS.len());
        for (schema, key) in GNOME_KEYS {
            let output = self.runner.run("gsettings", &args(&["get", schema, key]));
            match output {
                Ok(output) if output.success => keys.push(GnomeKey {
                    schema: schema.to_owned(),
                    key: key.to_owned(),
                    value: output.stdout.trim().to_owned(),
                }),
                // No gsettings, or no GNOME proxy schema: not a GNOME desktop.
                _ if keys.is_empty() => return Ok(None),
                Ok(output) => anyhow::bail!(
                    "`gsettings get {schema} {key}` failed: {}",
                    output.stderr.trim()
                ),
                Err(e) => return Err(e),
            }
        }
        Ok(Some(Saved::Gnome { keys }))
    }

    fn run_all(&self, commands: &[(&'static str, Vec<String>)]) -> anyhow::Result<()> {
        for (program, arguments) in commands {
            self.runner.run_ok(program, arguments)?;
        }
        Ok(())
    }

    /// Makes running Windows programs reread the registry; best effort, since the registry
    /// change itself already took effect for new connections.
    fn refresh(&self) {
        if self.platform == Platform::Windows {
            let refresh = args(&["-NoProfile", "-NonInteractive", "-Command", WININET_REFRESH]);
            if let Err(e) = self.runner.run_ok("powershell", &refresh) {
                eprintln!("{NAME}: could not notify programs of the proxy change ({e:#})");
            }
        }
    }
}

/// Restores the system proxy when dropped, so an early return or a panic in the caller
/// still puts the old settings back. Call [`Guard::restore`] to see the result instead.
#[derive(Debug)]
pub struct Guard<R: CommandRunner> {
    proxy: Option<SystemProxy<R>>,
}

impl<R: CommandRunner> Guard<R> {
    /// Takes charge of restoring `proxy`, which [`SystemProxy::enable`] changed.
    pub fn new(proxy: SystemProxy<R>) -> Self {
        Self { proxy: Some(proxy) }
    }

    /// Restores the settings now.
    ///
    /// # Errors
    ///
    /// Fails like [`SystemProxy::restore`].
    pub fn restore(mut self) -> anyhow::Result<bool> {
        self.proxy.take().map_or(Ok(false), |proxy| proxy.restore())
    }
}

impl<R: CommandRunner> Drop for Guard<R> {
    fn drop(&mut self) {
        if let Some(proxy) = self.proxy.take()
            && let Err(e) = proxy.restore()
        {
            eprintln!(
                "{NAME}: could not restore the system proxy ({e:#}); run `{NAME} system-proxy off`"
            );
        }
    }
}

/// Waits for Ctrl-C, or on Unix also for SIGTERM or SIGHUP, so the caller can clean up
/// before exiting.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let (Ok(mut term), Ok(mut hup)) = (
            signal(SignalKind::terminate()),
            signal(SignalKind::hangup()),
        ) else {
            let _ = tokio::signal::ctrl_c().await;
            return;
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
            _ = hup.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Where the system proxy points: the proxy's address, with an unspecified listen address
/// (`0.0.0.0`) replaced by loopback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Target {
    ip: IpAddr,
    port: u16,
}

impl Target {
    fn from_listen(listen: SocketAddr) -> Self {
        let ip = if listen.ip().is_unspecified() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            listen.ip()
        };
        Self {
            ip,
            port: listen.port(),
        }
    }

    /// `HOST:PORT`, with brackets around an IPv6 host.
    fn authority(self) -> String {
        SocketAddr::new(self.ip, self.port).to_string()
    }
}

/// The commands that point every saved service or key at `target`.
fn apply_commands(saved: &Saved, target: Target) -> Vec<(&'static str, Vec<String>)> {
    let host = target.ip.to_string();
    let port = target.port.to_string();
    match saved {
        Saved::MacOs { services } => services
            .iter()
            .flat_map(|service| {
                let name = service.name.as_str();
                let mut bypass = args(&["-setproxybypassdomains", name]);
                bypass.extend(BYPASS.iter().map(|&host| host.to_owned()));
                [
                    (NETWORKSETUP, args(&["-setwebproxy", name, &host, &port])),
                    (
                        NETWORKSETUP,
                        args(&["-setsecurewebproxy", name, &host, &port]),
                    ),
                    (NETWORKSETUP, bypass),
                ]
            })
            .collect(),
        Saved::Windows { .. } => {
            let server = target.authority();
            let bypass = windows_bypass();
            vec![
                reg_add("ProxyEnable", "REG_DWORD", "1"),
                reg_add("ProxyServer", "REG_SZ", &server),
                reg_add("ProxyOverride", "REG_SZ", &bypass),
            ]
        }
        Saved::Gnome { .. } => {
            let host = format!("'{host}'");
            let ignore = BYPASS
                .iter()
                .map(|host| format!("'{host}'"))
                .collect::<Vec<_>>()
                .join(", ");
            let set = |schema: &str, key: &str, value: &str| {
                ("gsettings", args(&["set", schema, key, value]))
            };
            vec![
                set("org.gnome.system.proxy.http", "host", &host),
                set("org.gnome.system.proxy.http", "port", &port),
                set("org.gnome.system.proxy.https", "host", &host),
                set("org.gnome.system.proxy.https", "port", &port),
                set(
                    "org.gnome.system.proxy",
                    "ignore-hosts",
                    &format!("[{ignore}]"),
                ),
                set("org.gnome.system.proxy", "mode", "'manual'"),
            ]
        }
    }
}

/// The commands that put `saved` back.
fn restore_commands(saved: &Saved) -> Vec<(&'static str, Vec<String>)> {
    match saved {
        Saved::MacOs { services } => services
            .iter()
            .flat_map(|service| {
                let name = service.name.as_str();
                let mut commands = Vec::with_capacity(5);
                for (set, state, proxy) in [
                    ("-setwebproxy", "-setwebproxystate", &service.web),
                    (
                        "-setsecurewebproxy",
                        "-setsecurewebproxystate",
                        &service.secure,
                    ),
                ] {
                    if !proxy.server.is_empty() {
                        let port = proxy.port.to_string();
                        commands.push((NETWORKSETUP, args(&[set, name, &proxy.server, &port])));
                    }
                    let on = if proxy.enabled { "on" } else { "off" };
                    commands.push((NETWORKSETUP, args(&[state, name, on])));
                }
                let mut bypass = args(&["-setproxybypassdomains", name]);
                if service.bypass.is_empty() {
                    bypass.push("Empty".to_owned());
                } else {
                    bypass.extend(service.bypass.iter().cloned());
                }
                commands.push((NETWORKSETUP, bypass));
                commands
            })
            .collect(),
        Saved::Windows { values } => values
            .iter()
            .map(|value| match &value.value {
                Some((kind, data)) => reg_add(&value.name, kind, data),
                None => ("reg", args(&["delete", REG_KEY, "/v", &value.name, "/f"])),
            })
            .collect(),
        // `mode` was saved first, so it is set back first: the proxy is off before the
        // host and port change.
        Saved::Gnome { keys } => keys
            .iter()
            .map(|key| {
                (
                    "gsettings",
                    args(&["set", &key.schema, &key.key, &key.value]),
                )
            })
            .collect(),
    }
}

fn reg_add(name: &str, kind: &str, data: &str) -> (&'static str, Vec<String>) {
    (
        "reg",
        args(&["add", REG_KEY, "/v", name, "/t", kind, "/d", data, "/f"]),
    )
}

/// `ProxyOverride`: `WinINet` takes `*` wildcards, not CIDR, and `<local>` for dotless names.
fn windows_bypass() -> String {
    let private_172 = (16..=31).map(|octet| format!("172.{octet}.*"));
    [
        "localhost",
        "127.*",
        "[::1]",
        "*.local",
        "169.254.*",
        "10.*",
    ]
    .into_iter()
    .map(str::to_owned)
    .chain(private_172)
    .chain(["192.168.*".to_owned(), "<local>".to_owned()])
    .collect::<Vec<_>>()
    .join(";")
}

/// What to set by hand when no settings tool is available.
fn env_instructions(target: Target) -> String {
    let url = format!("http://{}", target.authority());
    let no_proxy = "localhost,127.0.0.1,::1,.local";
    format!(
        "No GNOME proxy settings found, so nothing was changed. Point programs at the proxy \
         with environment variables in the shell that starts them:\n\
         \n  export http_proxy={url} https_proxy={url} HTTP_PROXY={url} HTTPS_PROXY={url}\
         \n  export no_proxy={no_proxy} NO_PROXY={no_proxy}\n\
         \nKDE: System Settings > Network > Settings > Proxy > Use manually specified proxy, \
         HTTP and HTTPS {}.\n",
        target.authority()
    )
}

fn describe(saved: &Saved, target: Target) -> String {
    let at = target.authority();
    match saved {
        Saved::MacOs { services } => {
            let names: Vec<&str> = services.iter().map(|s| s.name.as_str()).collect();
            format!(
                "system proxy (web and secure web) of {} set to {at}",
                names.join(", ")
            )
        }
        Saved::Windows { .. } => format!("Windows proxy (current user) set to {at}"),
        Saved::Gnome { .. } => format!("GNOME proxy set to {at}"),
    }
}

fn describe_saved(saved: &Saved) -> String {
    let mut out = String::new();
    match saved {
        Saved::MacOs { services } => {
            for service in services {
                let show = |proxy: &MacProxy| {
                    let state = if proxy.enabled { "on" } else { "off" };
                    if proxy.server.is_empty() {
                        state.to_owned()
                    } else {
                        format!("{state} ({}:{})", proxy.server, proxy.port)
                    }
                };
                let _ = writeln!(
                    out,
                    "{}: web proxy {}, secure web proxy {}",
                    service.name,
                    show(&service.web),
                    show(&service.secure)
                );
            }
        }
        Saved::Windows { values } => {
            for value in values {
                let data = value
                    .value
                    .as_ref()
                    .map_or("(not set)", |(_, data)| data.as_str());
                let _ = writeln!(out, "{}: {data}", value.name);
            }
        }
        Saved::Gnome { keys } => {
            for key in keys {
                let _ = writeln!(out, "{} {}: {}", key.schema, key.key, key.value);
            }
        }
    }
    out
}

/// The enabled services of `networksetup -listallnetworkservices`: the first line is a
/// legend and disabled services start with `*`.
fn parse_services(output: &str) -> Vec<String> {
    output
        .lines()
        .filter(|line| !line.starts_with("An asterisk"))
        .map(str::trim_end)
        .filter(|line| !line.is_empty() && !line.starts_with('*'))
        .map(str::to_owned)
        .collect()
}

/// `networksetup -getwebproxy` or `-getsecurewebproxy` output.
fn parse_proxy(output: &str) -> MacProxy {
    let mut proxy = MacProxy::default();
    for line in output.lines() {
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match field.trim() {
            "Enabled" => proxy.enabled = value.eq_ignore_ascii_case("yes"),
            "Server" => value.clone_into(&mut proxy.server),
            "Port" => proxy.port = value.parse().unwrap_or(0),
            _ => {}
        }
    }
    proxy
}

/// `networksetup -getproxybypassdomains` output: one domain per line, or a sentence when
/// there are none.
fn parse_bypass(output: &str) -> Vec<String> {
    if output.contains("There aren't any bypass domains") {
        return Vec::new();
    }
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The type and data of `name` in `reg query` output, such as `REG_DWORD` and `0x1`.
fn parse_reg_value(output: &str, name: &str) -> Option<(String, String)> {
    output.lines().find_map(|line| {
        let rest = line.trim().strip_prefix(name)?;
        let rest = rest.strip_prefix(char::is_whitespace)?.trim_start();
        let (kind, data) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        kind.starts_with("REG_")
            .then(|| (kind.to_owned(), data.trim().to_owned()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oscmd::Output;
    use crate::oscmd::fake::FakeRunner;

    const SERVICES: &str = "An asterisk (*) denotes that a network service is disabled.\n\
                            USB 10/100/1000 LAN\n*Thunderbolt Bridge\nWi-Fi\n";
    const WEB_OFF: &str = "Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n";
    const WEB_ON: &str =
        "Enabled: Yes\nServer: proxy.corp.test\nPort: 3128\nAuthenticated Proxy Enabled: 0\n";
    const NO_BYPASS: &str = "There aren't any bypass domains set on Wi-Fi.\n";

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("{NAME}-sysproxy-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn mac_runner() -> FakeRunner {
        FakeRunner::default()
            .reply("networksetup -listallnetworkservices", Output::ok(SERVICES))
            .reply(
                "networksetup -getwebproxy USB 10/100/1000 LAN",
                Output::ok(WEB_ON),
            )
            .reply("networksetup -getwebproxy", Output::ok(WEB_OFF))
            .reply("networksetup -getsecurewebproxy", Output::ok(WEB_OFF))
            .reply(
                "networksetup -getproxybypassdomains USB",
                Output::ok("*.corp.test\n10.0.0.0/8\n"),
            )
            .reply("networksetup -getproxybypassdomains", Output::ok(NO_BYPASS))
    }

    fn listen() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 8080))
    }

    #[test]
    fn parses_networksetup_output() {
        assert_eq!(parse_services(SERVICES), ["USB 10/100/1000 LAN", "Wi-Fi"]);
        assert_eq!(
            parse_proxy(WEB_ON),
            MacProxy {
                enabled: true,
                server: "proxy.corp.test".to_owned(),
                port: 3128
            }
        );
        assert_eq!(parse_proxy(WEB_OFF), MacProxy::default());
        assert_eq!(parse_bypass(NO_BYPASS), Vec::<String>::new());
        assert_eq!(
            parse_bypass("*.local\n169.254/16\n"),
            ["*.local", "169.254/16"]
        );
    }

    #[test]
    fn parses_reg_query_output() {
        let out = "\r\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet \
                   Settings\r\n    ProxyEnable    REG_DWORD    0x1\r\n\r\n";
        assert_eq!(
            parse_reg_value(out, "ProxyEnable"),
            Some(("REG_DWORD".to_owned(), "0x1".to_owned()))
        );
        let out = "    ProxyOverride    REG_SZ    localhost;<local>\r\n";
        assert_eq!(
            parse_reg_value(out, "ProxyOverride"),
            Some(("REG_SZ".to_owned(), "localhost;<local>".to_owned()))
        );
        assert_eq!(parse_reg_value(out, "ProxyServer"), None);
    }

    #[test]
    fn mac_enable_saves_state_first_and_restore_puts_everything_back() -> anyhow::Result<()> {
        let dir = TempDir::new("mac");
        let proxy = SystemProxy::new(mac_runner(), Platform::MacOs, &dir.0);
        let Enabled::Changed(text) = proxy.enable(listen())? else {
            panic!("expected a change");
        };
        assert!(text.contains("USB 10/100/1000 LAN, Wi-Fi"), "{text}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(proxy.state_path())?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let bypass = BYPASS.join(" ");
        assert_eq!(
            proxy.runner().writes(),
            [
                "networksetup -setwebproxy USB 10/100/1000 LAN 127.0.0.1 8080".to_owned(),
                "networksetup -setsecurewebproxy USB 10/100/1000 LAN 127.0.0.1 8080".to_owned(),
                format!("networksetup -setproxybypassdomains USB 10/100/1000 LAN {bypass}"),
                "networksetup -setwebproxy Wi-Fi 127.0.0.1 8080".to_owned(),
                "networksetup -setsecurewebproxy Wi-Fi 127.0.0.1 8080".to_owned(),
                format!("networksetup -setproxybypassdomains Wi-Fi {bypass}"),
            ]
        );
        // A second enable refuses while the state file exists.
        assert!(proxy.enable(listen()).is_err());

        let restorer = SystemProxy::new(mac_runner(), Platform::MacOs, &dir.0);
        assert!(restorer.restore()?);
        assert_eq!(
            restorer.runner().writes(),
            [
                "networksetup -setwebproxy USB 10/100/1000 LAN proxy.corp.test 3128",
                "networksetup -setwebproxystate USB 10/100/1000 LAN on",
                "networksetup -setsecurewebproxystate USB 10/100/1000 LAN off",
                "networksetup -setproxybypassdomains USB 10/100/1000 LAN *.corp.test 10.0.0.0/8",
                "networksetup -setwebproxystate Wi-Fi off",
                "networksetup -setsecurewebproxystate Wi-Fi off",
                "networksetup -setproxybypassdomains Wi-Fi Empty",
            ]
        );
        assert!(!restorer.has_saved_state());
        assert!(!restorer.restore()?, "nothing left to restore");
        Ok(())
    }

    #[test]
    fn failed_change_restores_and_removes_the_state_file() {
        let dir = TempDir::new("fail");
        let runner = mac_runner().reply(
            "networksetup -setsecurewebproxy Wi-Fi 127",
            Output::failed("boom"),
        );
        let proxy = SystemProxy::new(runner, Platform::MacOs, &dir.0);
        let err = proxy.enable(listen()).expect_err("the change fails");
        assert!(
            format!("{err:#}").contains("old settings are back"),
            "{err:#}"
        );
        assert!(!proxy.has_saved_state());
        let writes = proxy.runner().writes();
        assert_eq!(
            writes.last().map(String::as_str),
            Some("networksetup -setproxybypassdomains Wi-Fi Empty")
        );
    }

    #[test]
    fn guard_restores_on_drop() -> anyhow::Result<()> {
        let dir = TempDir::new("guard");
        let proxy = SystemProxy::new(mac_runner(), Platform::MacOs, &dir.0);
        proxy.enable(listen())?;
        let state = proxy.state_path().to_owned();
        drop(Guard::new(proxy));
        assert!(!state.exists());
        Ok(())
    }

    #[test]
    fn windows_sets_and_restores_registry_values() -> anyhow::Result<()> {
        let dir = TempDir::new("win");
        let runner = || {
            FakeRunner::default()
                .reply(
                    "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet \
                     Settings /v ProxyEnable",
                    Output::ok("    ProxyEnable    REG_DWORD    0x0\r\n"),
                )
                .reply("reg query", Output::failed("ERROR: unable to find"))
        };
        let proxy = SystemProxy::new(runner(), Platform::Windows, &dir.0);
        proxy.enable(SocketAddr::from(([0, 0, 0, 0], 9090)))?;
        let writes = proxy.runner().writes();
        assert_eq!(writes.len(), 4, "{writes:#?}");
        assert!(writes[0].ends_with("/v ProxyEnable /t REG_DWORD /d 1 /f"));
        assert!(writes[1].ends_with("/v ProxyServer /t REG_SZ /d 127.0.0.1:9090 /f"));
        assert!(writes[2].contains("localhost;127.*;"), "{}", writes[2]);
        assert!(writes[2].contains("172.31.*;192.168.*;<local> /f"));
        assert!(writes[3].starts_with("powershell -NoProfile"));

        let restorer = SystemProxy::new(runner(), Platform::Windows, &dir.0);
        restorer.restore()?;
        let writes = restorer.runner().writes();
        assert!(writes[0].ends_with("/v ProxyEnable /t REG_DWORD /d 0x0 /f"));
        assert!(writes[1].starts_with("reg delete") && writes[1].ends_with("/v ProxyServer /f"));
        assert!(writes[2].starts_with("reg delete") && writes[2].ends_with("/v ProxyOverride /f"));
        Ok(())
    }

    #[test]
    fn gnome_round_trips_raw_values() -> anyhow::Result<()> {
        let dir = TempDir::new("gnome");
        let runner = || {
            FakeRunner::default()
                .reply(
                    "gsettings get org.gnome.system.proxy mode",
                    Output::ok("'none'\n"),
                )
                .reply(
                    "gsettings get org.gnome.system.proxy ignore-hosts",
                    Output::ok("['localhost', '127.0.0.0/8', '::1']\n"),
                )
                .reply(
                    "gsettings get org.gnome.system.proxy.http host",
                    Output::ok("''\n"),
                )
                .reply("gsettings get", Output::ok("0\n"))
        };
        let proxy = SystemProxy::new(runner(), Platform::Linux, &dir.0);
        proxy.enable(listen())?;
        let writes = proxy.runner().writes();
        assert_eq!(
            writes.last().map(String::as_str),
            Some("gsettings set org.gnome.system.proxy mode 'manual'")
        );
        assert!(
            writes
                .contains(&"gsettings set org.gnome.system.proxy.http host '127.0.0.1'".to_owned())
        );

        let restorer = SystemProxy::new(runner(), Platform::Linux, &dir.0);
        restorer.restore()?;
        let writes = restorer.runner().writes();
        assert_eq!(
            writes[0],
            "gsettings set org.gnome.system.proxy mode 'none'"
        );
        assert_eq!(
            writes[1],
            "gsettings set org.gnome.system.proxy ignore-hosts ['localhost', '127.0.0.0/8', '::1']"
        );
        Ok(())
    }

    #[test]
    fn linux_without_gnome_prints_env_vars_and_changes_nothing() -> anyhow::Result<()> {
        let dir = TempDir::new("env");
        let runner = FakeRunner::default().reply("gsettings", Output::failed("No such schema"));
        let proxy = SystemProxy::new(runner, Platform::Linux, &dir.0);
        let Enabled::Manual(text) = proxy.enable(listen())? else {
            panic!("expected instructions");
        };
        assert!(text.contains("https_proxy=http://127.0.0.1:8080"), "{text}");
        assert_eq!(proxy.runner().writes(), Vec::<String>::new());
        assert!(!proxy.has_saved_state());
        Ok(())
    }
}
