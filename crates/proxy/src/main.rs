//! Command-line entry point.

use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use http::{HeaderName, HeaderValue, StatusCode};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc::UnboundedReceiver;
use wirust::adb::{self, Adb};
use wirust::ca::Ca;
use wirust::control::ControlPlane;
use wirust::events::{DEFAULT_MAX_FLOWS, FlowEvent};
use wirust::flow::Event;
use wirust::intercept::{BlockHost, DEFAULT_PAUSE_TIMEOUT, HeaderRules};
use wirust::logfold::Folder;
use wirust::oscmd::{Platform, SystemRunner};
use wirust::pairing::{Cidr, Notice, Pairing};
use wirust::passthrough::{Lists, Passthrough};
use wirust::rules::Rules;
use wirust::script::Scripts;
use wirust::session;
use wirust::sysproxy::{self, Enabled, SystemProxy};
use wirust::trust::{self, CaTrust, TrustStatus};
use wirust::upstream_proxy::{Bypass, Kind as UpstreamProxyKind, UpstreamProxy};
use wirust::ws::{self, DEFAULT_WS_BODY_LIMIT, DEFAULT_WS_MAX_MESSAGES, WsLimits};
use wirust::{Config, DEFAULT_BODY_LIMIT, MAGIC_HOST, NAME, Proxy, RemoteAccess, UpstreamTls};
use wirust::{mobile, qr};

/// Parsed command line.
#[derive(Debug)]
enum Command {
    Run(RunArgs, MobileArgs),
    Connect(RunArgs, MobileArgs),
    AndroidSetup(Option<PathBuf>, MobileArgs),
    AndroidReset(MobileArgs),
    CaPath(Option<PathBuf>),
    CaShow(Option<PathBuf>),
    CaInstallHelp(Option<PathBuf>),
    /// `ca install|uninstall|status [--yes]`
    CaTrust(CaTrustCommand, Option<PathBuf>, Confirm),
    /// `system-proxy on|off|status [--listen ADDR | --port P]`
    SystemProxy(SystemProxyCommand, Option<PathBuf>),
    /// `export --har OUT [--session FILE] [--filter Q]`
    Export {
        har: PathBuf,
        session: Option<PathBuf>,
        filter: Option<String>,
    },
    /// `import --har IN --session OUT`
    Import {
        har: PathBuf,
        session: PathBuf,
    },
    /// `view --session FILE [--filter Q]`
    View {
        session: PathBuf,
        filter: Option<String>,
    },
    /// `replay --session FILE --id N [edits] [--via ADDR]`
    Replay {
        session: PathBuf,
        config_dir: Option<PathBuf>,
        args: ReplayArgs,
    },
    /// `wireguard add-peer NAME [--lan-ip IP] [--port P]` (experimental)
    #[cfg(feature = "wireguard")]
    WireguardAddPeer {
        name: String,
        config_dir: Option<PathBuf>,
        mobile: MobileArgs,
    },
    /// `--help`, with the command words given before or after it (none: the main help).
    Help(Vec<String>),
    Version,
}

#[derive(Debug)]
struct RunArgs {
    listen: SocketAddr,
    json: bool,
    body_limit: usize,
    upstream_insecure: bool,
    allow_remote: bool,
    config_dir: Option<PathBuf>,
    max_flows: usize,
    pause_timeout: Duration,
    ui: Option<SocketAddr>,
    add_headers: Vec<(HeaderName, HeaderValue)>,
    remove_headers: Vec<HeaderName>,
    block_hosts: Vec<String>,
    session: Option<PathBuf>,
    filter: Option<String>,
    har: Option<PathBuf>,
    rules: Option<PathBuf>,
    schemas: wirust::schema::Sources,
    scripts: Vec<PathBuf>,
    passthrough: Vec<String>,
    decrypt_only: Vec<String>,
    replay: ReplayArgs,
    ws: WsLimits,
    ws_log: WsLog,
    upstream_proxy: Option<UpstreamProxy>,
    upstream_bypass: Bypass,
    system_proxy: SystemProxyFlag,
    confirm: Confirm,
    /// `wireguard`: the UDP address of the WireGuard capture mode (experimental).
    #[cfg(feature = "wireguard")]
    wireguard: Option<SocketAddr>,
}

/// `ca install|uninstall|status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaTrustCommand {
    Install,
    Uninstall,
    Status,
}

/// `system-proxy on|off|status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SystemProxyCommand {
    /// Point the system proxy at the proxy listening on this address.
    On(SocketAddr),
    Off,
    Status,
}

/// Whether the run points the system proxy at itself (`--system-proxy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SystemProxyFlag {
    Off,
    On,
}

/// Whether trust-store changes still ask (`--yes` skips the question).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Confirm {
    Ask,
    Assumed,
}

/// Flags of `replay`.
#[derive(Debug, Default)]
struct ReplayArgs {
    id: Option<u64>,
    edits: wirust::replay::CliEdits,
    via: Option<SocketAddr>,
}

/// Whether the console prints WebSocket messages (`--ws-log`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WsLog {
    Off,
    Lines,
}

/// Flags of `connect` and `android`, and `--android-cleanup`.
#[derive(Debug, Default)]
struct MobileArgs {
    port: Option<u16>,
    lan_ip: Option<Ipv4Addr>,
    allow_clients: Vec<Cidr>,
    serial: Option<String>,
    android_cleanup: bool,
}

impl MobileArgs {
    fn port(&self) -> u16 {
        self.port.unwrap_or(DEFAULT_PORT)
    }
}

/// The proxy port `connect` and `android` use unless `--port` says otherwise.
const DEFAULT_PORT: u16 = 8080;

#[expect(
    clippy::too_many_lines,
    reason = "one help text; splitting it would only move the lines"
)]
fn usage() -> String {
    format!(
        "{NAME} {version}: an HTTPS debugging proxy

Usage:
  {NAME} [--listen ADDR] [--json] [--body-limit BYTES] [--upstream-insecure]
         [--upstream-proxy URL] [--upstream-bypass LIST] [--system-proxy]
         [--allow-remote] [--config-dir DIR] [--max-flows N] [--pause-timeout SECS]
         [--ui ADDR] [--add-header 'NAME: VALUE']... [--remove-header NAME]...
         [--block-host HOST]... [--rules FILE] [--script FILE]... [--session FILE]
         [--proto PATH]... [--proto-include DIR]... [--proto-message TYPE]
         [--passthrough PATTERN]... [--decrypt-only PATTERN]...
         [--ws-body-limit BYTES] [--ws-max-messages N] [--ws-log]
         [--ws-strip-compression]
         [--android-cleanup [--serial S]]
  {NAME} connect [--port P] [--lan-ip IP] [--allow-client IP|CIDR]... [run options]
  {NAME} android setup|reset [--serial S] [--port P] [--config-dir DIR]
  {NAME} ca path|show|install-help [--config-dir DIR]
  {NAME} ca install|uninstall|status [--yes] [--config-dir DIR]
  {NAME} system-proxy on|off|status [--listen ADDR | --port P] [--allow-remote] [--config-dir DIR]
  {NAME} export --har OUT.har [--session FILE] [--filter QUERY]   (no --session: JSON Lines on stdin)
  {NAME} import --har IN.har --session OUT.jsonl
  {NAME} view --session FILE [--filter QUERY]
  {NAME} replay --session FILE --id N [--set-header 'N: V']... [--method M] [--url U]
         [--via http://127.0.0.1:8080] [--config-dir DIR]
  {NAME} wireguard [--listen UDP_ADDR] [--allow-remote] [run options]       (experimental)
  {NAME} wireguard add-peer NAME [--lan-ip IP] [--port P] [--config-dir DIR] (experimental)
  {NAME} COMMAND --help      the options of one command

Commands:
  connect               listen on this computer's LAN address, show a QR code of the setup
                        page and ask before each phone may use the proxy (see docs/mobile.md)
  android setup         over adb: reverse the port, set the device's proxy to 127.0.0.1:P,
                        copy the CA to its Download folder
  android reset         over adb: clear the device's proxy and the port reversal
  ca install            trust the CA for the current user only (macOS login keychain, Windows
                        user Root store; Linux: prints the commands); asks for `yes` first
  ca uninstall          remove exactly that certificate, matched by its SHA-256 fingerprint
  ca status             say whether the CA is trusted
  system-proxy on       point this computer's system proxy at the proxy's address (--listen,
                        or 127.0.0.1:P), saving the old settings first; `off` restores them,
                        `status` shows them
  replay                send flow N of a session file again through a running proxy (--via),
                        as an ordinary client, and print the status line; see docs/replay.md
  wireguard             experimental, only in builds with the cargo feature `wireguard`:
                        capture a phone's TCP traffic through the official WireGuard app
                        (docs/wireguard.md); `add-peer` prints a client config and QR code

Options:
  -h, --help            print this help; after a command, such as `{NAME} ca --help`, the
                        help of that command
  -V, --version         print the version
  --listen ADDR         address to listen on (default 127.0.0.1:8080); for `system-proxy on`,
                        the address of the running proxy
  --json                print one JSON object per line instead of text
  --body-limit BYTES    body bytes kept per request and response (default {DEFAULT_BODY_LIMIT})
  --upstream-insecure   do not verify server certificates (dangerous)
  --upstream-proxy URL  send every outbound connection through another proxy:
                        http://, socks5:// or socks5h:// (remote DNS), optional USER:PASS@
  --upstream-bypass LIST  comma-separated hosts, *.domains, IPs and CIDRs that go direct
                        (repeatable); loopback and localhost always go direct
  --allow-remote        allow a non-loopback --listen address (dangerous), also for `system-proxy on`
  --config-dir DIR      where the CA is kept (default: the platform config dir)
  --max-flows N         flows kept in memory for the UI and API (default {DEFAULT_MAX_FLOWS})
  --pause-timeout SECS  how long a breakpoint waits before the exchange goes on (default {pause})
  --ui ADDR             serve the web UI and API on ADDR, such as 127.0.0.1:8081 (off by default)
  --add-header 'N: V'   set this header on every request sent to servers (repeatable)
  --remove-header NAME  remove this header from every request sent to servers (repeatable)
  --block-host HOST     answer requests to HOST and its subdomains with 403 (repeatable)
  --android-cleanup     on exit, clear the adb device's proxy setting (android reset)
  --system-proxy        point the system proxy at this proxy while it runs; restored on exit
                        (Ctrl-C, SIGTERM, SIGHUP); after a crash, `system-proxy off` restores
  --yes                 ca install/uninstall: do not ask for confirmation
  --port P              proxy port for connect, android and system-proxy on (default {DEFAULT_PORT})
  --lan-ip IP           connect: the address to listen on, instead of the detected one
  --allow-client NET    connect: pre-approve this IP or CIDR (repeatable)
  --serial S            android: the adb device to use when several are connected
  --session FILE        append every finished flow to FILE as JSON Lines (mode 0600; it holds
                        tokens, cookies and passwords from the traffic)
  --filter QUERY        search query for export and view, such as 'host:example.com status:5xx'
  --har FILE            HAR file to write (export) or read (import)
  --rules FILE          TOML rules (block, map-local, map-remote, rewrite, throttle, breakpoints);
                        reloaded when it changes; see docs/rules.md
  --script FILE         sandboxed Rhai script with on_request/on_response hooks (repeatable);
                        reloaded when it changes; see docs/scripting.md
  --proto PATH          .proto file, or directory scanned for them, to decode gRPC messages
                        with field names (repeatable); reloaded on change; see docs/grpc.md
  --proto-include DIR   import root for --proto files (repeatable)
  --proto-message TYPE  message type for bare application/x-protobuf bodies, such as pkg.Msg
  --passthrough PATTERN relay this host's TLS undecrypted, such as '*.bank.example' or
                        'api.example.com:443' (repeatable); see docs/passthrough.md
  --decrypt-only PATTERN  decrypt only matching hosts and relay all others (repeatable)
  --id N                replay: the flow id in the session file
  --set-header 'N: V'   replay: set this header (repeatable)
  --method M            replay: send with this method
  --url U               replay: send to this path or absolute http(s) URL
  --via URL             replay: the proxy to go through (default http://127.0.0.1:8080)
  --ws-body-limit BYTES WebSocket bytes kept per message (default {ws_body})
  --ws-max-messages N   WebSocket messages kept per connection (default {ws_max})
  --ws-log              print one line per WebSocket message (see docs/websocket.md)
  --ws-strip-compression  remove the client's WebSocket extension offer, so peers whose
                        permessage-deflate misbehaves send plain frames

Requests to http://{MAGIC_HOST}/ through the proxy get a page with the CA download.
",
        version = env!("CARGO_PKG_VERSION"),
        pause = DEFAULT_PAUSE_TIMEOUT.as_secs(),
        ws_body = DEFAULT_WS_BODY_LIMIT,
        ws_max = DEFAULT_WS_MAX_MESSAGES
    )
}

/// The help of one command (`{NAME} COMMAND --help`); `None` for words that name no command,
/// which get the main help. A parent word (`android`, `ca`) describes its sub-commands.
#[expect(
    clippy::too_many_lines,
    reason = "one page per command; splitting it would only move the pages"
)]
fn command_help(words: &[&str]) -> Option<String> {
    let page = match words {
        ["connect"] => format!(
            "{NAME} connect: set up a phone through this computer's LAN address

Usage:
  {NAME} connect [--port P] [--lan-ip IP] [--allow-client IP|CIDR]... [run options]

Listens on this computer's LAN address, shows a QR code of the setup page and asks
before each phone may use the proxy (see docs/mobile.md).

Options:
  --port P              proxy port (default {DEFAULT_PORT})
  --lan-ip IP           the address to listen on, instead of the detected one
  --allow-client NET    pre-approve this IP or CIDR (repeatable)

The options of a plain run work too, such as --ui, --rules and --passthrough; --listen
is replaced by --port and --lan-ip. See `{NAME} --help`.
"
        ),
        ["android"] => format!(
            "{NAME} android: point an Android device at the proxy over adb

Usage:
  {NAME} android setup [--serial S] [--port P] [--config-dir DIR]
  {NAME} android reset [--serial S] [--port P]

  setup   reverse the port, set the device's proxy to 127.0.0.1:P and copy the CA to
          its Download folder
  reset   clear the device's proxy and the port reversal

See `{NAME} android setup --help` and docs/mobile.md.
"
        ),
        ["android", "setup"] => format!(
            "{NAME} android setup: point an Android device at the proxy over adb

Usage:
  {NAME} android setup [--serial S] [--port P] [--config-dir DIR]

Reverses the port over adb, sets the device's proxy to 127.0.0.1:P and copies the CA to
the device's Download folder. While the proxy is not running the device has no working
HTTP proxy; `{NAME} android reset` undoes it. See docs/mobile.md.

Options:
  --serial S            the adb device to use when several are connected
  --port P              proxy port (default {DEFAULT_PORT})
  --config-dir DIR      where the CA is kept (default: the platform config dir)
"
        ),
        ["android", "reset"] => format!(
            "{NAME} android reset: clear the proxy setting of an Android device

Usage:
  {NAME} android reset [--serial S] [--port P]

Clears the device's proxy and the reversal of the proxy port, over adb.

Options:
  --serial S            the adb device to use when several are connected
  --port P              proxy port whose reversal is removed (default {DEFAULT_PORT})
"
        ),
        ["ca"] => format!(
            "{NAME} ca: the local certificate authority

Usage:
  {NAME} ca path|show|install-help [--config-dir DIR]
  {NAME} ca install|uninstall|status [--yes] [--config-dir DIR]

  path           print where the CA certificate file is
  show           print the CA certificate (PEM)
  install-help   how to trust the CA on macOS, Linux and Windows
  install        trust the CA for the current user only
  uninstall      remove exactly that certificate from the user's trust store
  status         say whether the CA is trusted

The CA is created on first use. See `{NAME} ca path --help`.
"
        ),
        ["ca", "install"] => format!(
            "{NAME} ca install: trust the CA for the current user

Usage:
  {NAME} ca install [--yes] [--config-dir DIR]

Adds the CA to the current user's trust store: the login keychain on macOS, the user Root
store on Windows. On Linux it prints the commands instead. It shows the plan and the CA's
SHA-256 fingerprint and waits for `yes`; it never uses sudo and never touches the system
store. See docs/desktop.md.

Options:
  --yes                 do not ask for confirmation
  --config-dir DIR      where the CA is kept (default: the platform config dir)
"
        ),
        ["ca", "uninstall"] => format!(
            "{NAME} ca uninstall: remove the CA from the user's trust store

Usage:
  {NAME} ca uninstall [--yes] [--config-dir DIR]

Removes exactly the certificate whose fingerprint matches this CA, and nothing else.
Asks for `yes` first.

Options:
  --yes                 do not ask for confirmation
  --config-dir DIR      where the CA is kept (default: the platform config dir)
"
        ),
        ["ca", "status"] => format!(
            "{NAME} ca status: say whether the CA is trusted

Usage:
  {NAME} ca status [--config-dir DIR]

Prints whether the user's trust store has this CA, with its SHA-256 fingerprint.

Options:
  --config-dir DIR      where the CA is kept (default: the platform config dir)
"
        ),
        ["system-proxy"] => format!(
            "{NAME} system-proxy: point this computer's system proxy at wirust

Usage:
  {NAME} system-proxy on|off|status [--listen ADDR | --port P] [--allow-remote] [--config-dir DIR]

  on       save the current settings, then set the web and secure web proxy to the address of
           the running proxy: --listen ADDR, or 127.0.0.1:P
  off      restore the saved settings
  status   show the current settings and whether wirust changed them

A plain run does the same while it lives with --system-proxy, using the address it really
listens on, and restores on exit. After a crash, `{NAME} system-proxy off` restores the old
settings. See docs/desktop.md.

Options:
  --listen ADDR         on: the address the proxy listens on, such as 127.0.0.1:9090; a
                        wildcard such as 0.0.0.0:9090 points at 127.0.0.1
  --port P              on: shorthand for --listen 127.0.0.1:P (default {DEFAULT_PORT}); given
                        together with --listen, both must name the same port
  --allow-remote        on: accept a --listen address that is not loopback, a wildcard included
  --config-dir DIR      where the saved settings are kept (default: the platform config dir)
"
        ),
        ["ca", "path"] => format!(
            "{NAME} ca path: print where the CA certificate file is

Usage:
  {NAME} ca path [--config-dir DIR]

Creates the CA when there is none yet.

Options:
  --config-dir DIR      where the CA is kept (default: the platform config dir)
"
        ),
        ["ca", "show"] => format!(
            "{NAME} ca show: print the CA certificate

Usage:
  {NAME} ca show [--config-dir DIR]

Prints the certificate as PEM; the private key is never printed. Creates the CA when
there is none yet.

Options:
  --config-dir DIR      where the CA is kept (default: the platform config dir)
"
        ),
        ["ca", "install-help"] => format!(
            "{NAME} ca install-help: how to trust the CA

Usage:
  {NAME} ca install-help [--config-dir DIR]

Prints the commands that trust the CA on macOS, Linux and Windows, and how to pass it to
single tools. Creates the CA when there is none yet.

Options:
  --config-dir DIR      where the CA is kept (default: the platform config dir)
"
        ),
        ["export"] => format!(
            "{NAME} export: write flows as a HAR file

Usage:
  {NAME} export --har OUT.har [--session FILE] [--filter QUERY]

Reads a session file, or JSON Lines on stdin without --session, and writes the matching
flows as HAR 1.2 (see docs/interchange.md).

Options:
  --har FILE            the HAR file to write (- for stdout)
  --session FILE        the session file to read (default: JSON Lines on stdin)
  --filter QUERY        keep only flows matching this search, such as 'host:example.com status:5xx'
"
        ),
        ["import"] => format!(
            "{NAME} import: turn a HAR file into a session file

Usage:
  {NAME} import --har IN.har --session OUT.jsonl

Writes the entries of a HAR file as JSON Lines flows, which `{NAME} view`, `{NAME} export`
and `{NAME} replay` read (see docs/interchange.md).

Options:
  --har FILE            the HAR file to read
  --session FILE        the session file to write
"
        ),
        ["view"] => format!(
            "{NAME} view: print the flows of a session file

Usage:
  {NAME} view --session FILE [--filter QUERY]

Prints one line per flow, as the proxy prints them while it runs.

Options:
  --session FILE        the session file to read
  --filter QUERY        keep only flows matching this search, such as 'host:example.com status:5xx'
"
        ),
        ["replay"] => format!(
            "{NAME} replay: send a recorded flow again

Usage:
  {NAME} replay --session FILE --id N [--set-header 'N: V']... [--method M] [--url U]
         [--via http://127.0.0.1:{DEFAULT_PORT}] [--config-dir DIR]

Sends flow N of a session file through a running proxy, as an ordinary client, and prints
the status line (see docs/replay.md).

Options:
  --session FILE        the session file to read
  --id N                the flow id in the session file
  --set-header 'N: V'   set this header (repeatable)
  --method M            send with this method
  --url U               send to this path or absolute http(s) URL
  --via URL             the proxy to go through (default http://127.0.0.1:{DEFAULT_PORT})
  --config-dir DIR      where the CA is kept (default: the platform config dir)
"
        ),
        ["wireguard"] => format!(
            "{NAME} wireguard: capture a phone's traffic through the WireGuard app (experimental)

Usage:
  {NAME} wireguard [--listen UDP_ADDR] [--allow-remote] [run options]
  {NAME} wireguard add-peer NAME [--lan-ip IP] [--port P] [--config-dir DIR]

Only in builds with the cargo feature `wireguard`; release builds do not have it.
Listens for WireGuard on UDP_ADDR and turns every TCP connection of the configured
peers into flows, as if the phone had sent CONNECT. DNS is relayed to this computer's
resolver; QUIC (UDP/443) and other UDP are dropped, so apps fall back to TCP. The HTTP
proxy listener moves to a free loopback port. Peers are read at start. See
docs/wireguard.md.

Options:
  --listen UDP_ADDR     the WireGuard address (default 127.0.0.1:51820); a phone needs a
                        LAN address, which also needs --allow-remote
  --allow-remote        allow a non-loopback --listen address; only configured peer keys
                        get an answer

The options of a plain run work too, such as --ui, --rules and --passthrough.
"
        ),
        ["wireguard", "add-peer"] => format!(
            "{NAME} wireguard add-peer: add a phone to the WireGuard capture mode (experimental)

Usage:
  {NAME} wireguard add-peer NAME [--lan-ip IP] [--port P] [--config-dir DIR]

Creates a key pair for the peer, stores its public key and tunnel address, and prints
a configuration for the official WireGuard app as text and as a QR code. The peer's
private key is shown once and not stored. Restart `{NAME} wireguard` to load the peer.

Options:
  --lan-ip IP           the address the phone reaches this computer on (default: detected)
  --port P              the WireGuard port in the configuration (default 51820)
  --config-dir DIR      where the keys are kept (default: the platform config dir)
"
        ),
        _ => return None,
    };
    Some(page)
}

#[expect(
    clippy::too_many_lines,
    reason = "one match arm per command-line flag; splitting it would only move the arms"
)]
fn parse(args: &[String]) -> anyhow::Result<Command> {
    let mut run = RunArgs {
        listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
        json: false,
        body_limit: DEFAULT_BODY_LIMIT,
        upstream_insecure: false,
        allow_remote: false,
        config_dir: None,
        max_flows: DEFAULT_MAX_FLOWS,
        pause_timeout: DEFAULT_PAUSE_TIMEOUT,
        ui: None,
        add_headers: Vec::new(),
        remove_headers: Vec::new(),
        block_hosts: Vec::new(),
        session: None,
        filter: None,
        har: None,
        rules: None,
        schemas: wirust::schema::Sources::default(),
        scripts: Vec::new(),
        passthrough: Vec::new(),
        decrypt_only: Vec::new(),
        replay: ReplayArgs::default(),
        ws: WsLimits::default(),
        ws_log: WsLog::Off,
        upstream_proxy: None,
        upstream_bypass: Bypass::default(),
        system_proxy: SystemProxyFlag::Off,
        confirm: Confirm::Ask,
        #[cfg(feature = "wireguard")]
        wireguard: None,
    };
    let mut mobile = MobileArgs::default();
    let mut words = Vec::new();
    let mut help = false;
    let mut listen_given = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let mut value = |flag: &str| {
            args.next()
                .cloned()
                .with_context(|| format!("{flag} needs a value"))
        };
        match arg.as_str() {
            "-h" | "--help" => help = true,
            "-V" | "--version" => return Ok(Command::Version),
            "--listen" => {
                run.listen = value(arg)?
                    .parse()
                    .context("--listen takes IP:PORT, such as 127.0.0.1:8080")?;
                listen_given = true;
            }
            "--json" => run.json = true,
            "--body-limit" => {
                run.body_limit = value(arg)?
                    .parse()
                    .context("--body-limit takes a byte count")?;
            }
            "--upstream-insecure" => run.upstream_insecure = true,
            "--upstream-proxy" => {
                run.upstream_proxy = Some(value(arg)?.parse().context("--upstream-proxy")?);
            }
            "--upstream-bypass" => run
                .upstream_bypass
                .extend_from(&value(arg)?)
                .context("--upstream-bypass")?,
            "--allow-remote" => run.allow_remote = true,
            "--config-dir" => run.config_dir = Some(PathBuf::from(value(arg)?)),
            "--max-flows" => {
                run.max_flows = value(arg)?.parse().context("--max-flows takes a count")?;
            }
            "--pause-timeout" => {
                let secs = value(arg)?
                    .parse()
                    .context("--pause-timeout takes seconds")?;
                run.pause_timeout = Duration::from_secs(secs);
            }
            "--ui" => {
                run.ui = Some(
                    value(arg)?
                        .parse()
                        .context("--ui takes IP:PORT, such as 127.0.0.1:8081")?,
                );
            }
            "--add-header" => run
                .add_headers
                .push(HeaderRules::parse_header(&value(arg)?).context("--add-header")?),
            "--remove-header" => run.remove_headers.push(
                HeaderName::from_bytes(value(arg)?.trim().as_bytes())
                    .context("--remove-header takes a header name")?,
            ),
            "--block-host" => run.block_hosts.push(value(arg)?),
            "--android-cleanup" => mobile.android_cleanup = true,
            "--port" => mobile.port = Some(value(arg)?.parse().context("--port takes a port")?),
            "--lan-ip" => {
                mobile.lan_ip = Some(value(arg)?.parse().context("--lan-ip takes an IPv4")?);
            }
            "--allow-client" => mobile.allow_clients.push(value(arg)?.parse()?),
            "--serial" => mobile.serial = Some(value(arg)?),
            "--session" => run.session = Some(PathBuf::from(value(arg)?)),
            "--filter" => run.filter = Some(value(arg)?),
            "--har" => run.har = Some(PathBuf::from(value(arg)?)),
            "--rules" => run.rules = Some(PathBuf::from(value(arg)?)),
            "--script" => run.scripts.push(PathBuf::from(value(arg)?)),
            "--proto" => run.schemas.protos.push(PathBuf::from(value(arg)?)),
            "--proto-include" => run.schemas.includes.push(PathBuf::from(value(arg)?)),
            "--proto-message" => run.schemas.message = Some(value(arg)?),
            "--passthrough" => run.passthrough.push(value(arg)?),
            "--decrypt-only" => run.decrypt_only.push(value(arg)?),
            "--id" => run.replay.id = Some(value(arg)?.parse().context("--id takes a flow id")?),
            "--set-header" => run
                .replay
                .edits
                .set_headers
                .push(HeaderRules::parse_header(&value(arg)?).context("--set-header")?),
            "--method" => {
                run.replay.edits.method =
                    Some(http::Method::from_bytes(value(arg)?.as_bytes()).context("--method")?);
            }
            "--url" => run.replay.edits.url = Some(value(arg)?),
            "--via" => {
                let via = value(arg)?;
                let addr = via
                    .strip_prefix("http://")
                    .unwrap_or(&via)
                    .trim_end_matches('/');
                run.replay.via = Some(
                    addr.parse()
                        .context("--via takes http://IP:PORT, such as http://127.0.0.1:8080")?,
                );
            }
            "--ws-body-limit" => {
                run.ws.body_limit = value(arg)?
                    .parse()
                    .context("--ws-body-limit takes a byte count")?;
            }
            "--ws-max-messages" => {
                run.ws.max_messages = value(arg)?
                    .parse()
                    .context("--ws-max-messages takes a count")?;
            }
            "--ws-log" => run.ws_log = WsLog::Lines,
            "--ws-strip-compression" => run.ws.strip_compression = true,
            "--system-proxy" => run.system_proxy = SystemProxyFlag::On,
            "--yes" => run.confirm = Confirm::Assumed,
            flag if flag.starts_with('-') => bail!("unknown option {flag}; see --help"),
            word => words.push(word.to_owned()),
        }
    }
    if help {
        return Ok(Command::Help(words));
    }
    let dir = run.config_dir.clone();
    match words.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        [] => Ok(Command::Run(run, mobile)),
        ["connect"] => Ok(Command::Connect(run, mobile)),
        ["android", "setup"] => Ok(Command::AndroidSetup(dir, mobile)),
        ["android", "reset"] => Ok(Command::AndroidReset(mobile)),
        ["ca", "path"] => Ok(Command::CaPath(dir)),
        ["ca", "show"] => Ok(Command::CaShow(dir)),
        ["ca", "install-help"] => Ok(Command::CaInstallHelp(dir)),
        ["ca", "install"] => Ok(Command::CaTrust(CaTrustCommand::Install, dir, run.confirm)),
        ["ca", "uninstall"] => Ok(Command::CaTrust(
            CaTrustCommand::Uninstall,
            dir,
            run.confirm,
        )),
        ["ca", "status"] => Ok(Command::CaTrust(CaTrustCommand::Status, dir, run.confirm)),
        ["system-proxy", action] => {
            let action = match action {
                "on" => SystemProxyCommand::On(system_proxy_target(
                    listen_given.then_some(run.listen),
                    mobile.port,
                    run.allow_remote,
                )?),
                "off" => SystemProxyCommand::Off,
                "status" => SystemProxyCommand::Status,
                _ => bail!("system-proxy takes on, off or status"),
            };
            Ok(Command::SystemProxy(action, dir))
        }
        ["export"] => Ok(Command::Export {
            har: run.har.context("export needs --har OUT.har")?,
            session: run.session,
            filter: run.filter,
        }),
        ["import"] => Ok(Command::Import {
            har: run.har.context("import needs --har IN.har")?,
            session: run.session.context("import needs --session OUT.jsonl")?,
        }),
        ["view"] => Ok(Command::View {
            session: run.session.context("view needs --session FILE")?,
            filter: run.filter,
        }),
        ["replay"] => {
            anyhow::ensure!(run.replay.id.is_some(), "replay needs --id N");
            Ok(Command::Replay {
                session: run.session.context("replay needs --session FILE")?,
                config_dir: dir,
                args: run.replay,
            })
        }
        #[cfg(feature = "wireguard")]
        ["wireguard"] => {
            let default = SocketAddr::from(([127, 0, 0, 1], wirust::wireguard::DEFAULT_PORT));
            run.wireguard = Some(if listen_given { run.listen } else { default });
            // The HTTP proxy listener stays on loopback, on a free port.
            run.listen = SocketAddr::from(([127, 0, 0, 1], 0));
            Ok(Command::Run(run, mobile))
        }
        #[cfg(feature = "wireguard")]
        ["wireguard", "add-peer", name] => Ok(Command::WireguardAddPeer {
            name: name.to_owned(),
            config_dir: dir,
            mobile,
        }),
        #[cfg(not(feature = "wireguard"))]
        ["wireguard", ..] => {
            let _ = listen_given;
            bail!(
                "this build has no WireGuard capture mode; it needs the cargo feature `wireguard`"
            )
        }
        _ => bail!("unknown command {}; see --help", words.join(" ")),
    }
}

fn config_dir(dir: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    dir.map_or_else(Ca::default_dir, Ok)
}

/// The address `system-proxy on` points at: `--listen`, or `--port` on loopback (default
/// port 8080). Both must agree on the port. A non-loopback address, a wildcard included, needs
/// `--allow-remote`, as it does for the proxy itself; a wildcard then points at loopback.
fn system_proxy_target(
    listen: Option<SocketAddr>,
    port: Option<u16>,
    allow_remote: bool,
) -> anyhow::Result<SocketAddr> {
    let addr = match (listen, port) {
        (Some(listen), Some(port)) => {
            anyhow::ensure!(
                listen.port() == port,
                "--listen {listen} and --port {port} name different ports; give one of them"
            );
            listen
        }
        (Some(listen), None) => listen,
        (None, port) => SocketAddr::from(([127, 0, 0, 1], port.unwrap_or(DEFAULT_PORT))),
    };
    anyhow::ensure!(
        addr.ip().is_loopback() || allow_remote,
        "system-proxy on {addr}: this is not a loopback address, so the system proxy would send \
         this computer's web traffic to another host or to an open port; pass --allow-remote if \
         that is intended"
    );
    Ok(addr)
}

fn install_help(path: &std::path::Path) -> String {
    let path = path.display();
    format!(
        "Trust the {NAME} CA ({path}). Only do this on machines you control; remove it when
you stop using the proxy. Anyone with the CA key ({NAME} keeps it next to the certificate)
can impersonate any site to this machine.

macOS (system keychain, asks for your password):
  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \"{path}\"
  remove: sudo security remove-trusted-cert -d \"{path}\"

Linux, Debian/Ubuntu:
  sudo cp \"{path}\" /usr/local/share/ca-certificates/{NAME}.crt && sudo update-ca-certificates
Linux, Fedora/RHEL/Arch:
  sudo trust anchor --store \"{path}\"
Firefox keeps its own store: Settings > Privacy & Security > Certificates > View Certificates >
Authorities > Import. Chrome and Chromium on Linux use the NSS store (~/.pki/nssdb).

Windows (current user, no admin needed):
  certutil -addstore -user Root \"{path}\"

Single tools, without trusting it system-wide:
  curl --cacert \"{path}\" -x http://127.0.0.1:8080 https://example.com/
  NODE_EXTRA_CA_CERTS=\"{path}\"   SSL_CERT_FILE=\"{path}\"   REQUESTS_CA_BUNDLE=\"{path}\"

Android and iOS: see docs/mobile.md in the source tree. Apps on Android 7+ ignore
user-installed CAs unless they opt in, and pinned apps reject any CA.
"
    )
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse(&args).and_then(execute) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{NAME}: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn execute(command: Command) -> anyhow::Result<()> {
    match command {
        Command::Help(words) => {
            let words: Vec<&str> = words.iter().map(String::as_str).collect();
            print!("{}", command_help(&words).unwrap_or_else(usage));
        }
        Command::Version => println!("{NAME} {}", env!("CARGO_PKG_VERSION")),
        Command::CaPath(dir) => {
            let dir = config_dir(dir)?;
            Ca::load_or_create(&dir)?;
            println!("{}", Ca::cert_path(&dir).display());
        }
        Command::CaShow(dir) => print!("{}", Ca::load_or_create(&config_dir(dir)?)?.cert_pem()),
        Command::CaInstallHelp(dir) => {
            let dir = config_dir(dir)?;
            Ca::load_or_create(&dir)?;
            print!("{}", install_help(&Ca::cert_path(&dir)));
        }
        Command::CaTrust(action, dir, confirm) => ca_trust(action, &config_dir(dir)?, confirm)?,
        Command::SystemProxy(action, dir) => system_proxy(action, &config_dir(dir)?)?,
        Command::Run(args, mobile) => run(args, &mobile, None)?,
        Command::Connect(mut args, mobile) => {
            let ip = match mobile.lan_ip {
                Some(ip) => ip,
                None => wirust::mobile::lan_ipv4()?,
            };
            args.listen = SocketAddr::new(ip.into(), mobile.port());
            // Running `connect` is the consent to listen beyond loopback; pairing guards it.
            args.allow_remote = true;
            let pairing = Pairing::new(mobile.allow_clients.clone());
            run(args, &mobile, Some(pairing))?;
        }
        Command::AndroidSetup(dir, mobile) => android_setup(dir, &mobile)?,
        Command::AndroidReset(mobile) => {
            let adb = Adb::open(mobile.serial.clone())?;
            adb.run_all(&adb::reset_commands(adb.serial(), mobile.port()))?;
            println!(
                "cleared the device's proxy and the reverse mapping of port {}",
                mobile.port()
            );
        }
        Command::Export {
            har,
            session,
            filter,
        } => {
            let entries = session::export_har(session.as_deref(), filter.as_deref(), &har)?;
            eprintln!("{NAME}: wrote {entries} entries to {}", har.display());
        }
        Command::Import { har, session } => {
            let flows = session::import_har(&har, &session)?;
            eprintln!("{NAME}: wrote {flows} flows to {}", session.display());
        }
        Command::View { session, filter } => {
            session::view(&session, filter.as_deref(), &mut std::io::stdout().lock())?;
        }
        Command::Replay {
            session,
            config_dir: dir,
            args,
        } => replay(&session, &config_dir(dir)?, args)?,
        #[cfg(feature = "wireguard")]
        Command::WireguardAddPeer {
            name,
            config_dir: dir,
            mobile,
        } => wireguard_add_peer(&name, &config_dir(dir)?, &mobile)?,
    }
    Ok(())
}

/// `wireguard add-peer NAME`: a new peer, printed as a client config and a QR code.
#[cfg(feature = "wireguard")]
fn wireguard_add_peer(
    name: &str,
    dir: &std::path::Path,
    mobile: &MobileArgs,
) -> anyhow::Result<()> {
    use wirust::wireguard::{DEFAULT_PORT, PublicKey, Store, client_config};
    let store = Store::new(dir);
    let server = PublicKey::from(&store.server_key()?);
    let ip = match mobile.lan_ip {
        Some(ip) => ip,
        None => wirust::mobile::lan_ipv4()?,
    };
    let endpoint = SocketAddr::new(ip.into(), mobile.port.unwrap_or(DEFAULT_PORT));
    let (peer, key) = store.add_peer(name)?;
    let config = client_config(&peer, &key, &server, endpoint);
    println!("{config}\n{}", qr::terminal(&config)?);
    eprintln!(
        "{NAME}: added peer {name} ({}); this private key is not stored anywhere. Start or \
         restart `{NAME} wireguard --listen {endpoint} --allow-remote` to accept it \
         (experimental, see docs/wireguard.md).",
        peer.address
    );
    Ok(())
}

/// Stops the WireGuard listener task when dropped.
#[cfg(feature = "wireguard")]
struct AbortOnDrop(tokio::task::JoinHandle<anyhow::Result<()>>);

#[cfg(feature = "wireguard")]
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Starts the WireGuard capture mode for `proxy` when `listen` is set; it runs until the
/// result is dropped.
#[cfg(feature = "wireguard")]
async fn start_wireguard(
    listen: Option<SocketAddr>,
    remote: RemoteAccess,
    dir: &std::path::Path,
    proxy: &Proxy,
) -> anyhow::Result<Option<AbortOnDrop>> {
    use wirust::wireguard::{Server, Store, system_resolver};
    let Some(listen) = listen else {
        return Ok(None);
    };
    let store = Store::new(dir);
    let peers = store.peers()?;
    let resolver = system_resolver();
    let count = peers.len();
    let server = Server::bind(proxy, listen, remote, store.server_key()?, peers, resolver).await?;
    let dns = resolver.map_or_else(
        || "dropped (no resolver found)".to_owned(),
        |r| r.to_string(),
    );
    eprintln!(
        "{NAME} WireGuard capture mode (experimental) on UDP {}: {count} peer(s), DNS to {dns}",
        server.local_addr()?
    );
    if count == 0 {
        eprintln!("{NAME}: no peers yet; add one with `{NAME} wireguard add-peer NAME`");
    }
    Ok(Some(AbortOnDrop(tokio::spawn(server.run()))))
}

/// `ca install|uninstall|status`: the CA in the current user's trust store.
fn ca_trust(action: CaTrustCommand, dir: &std::path::Path, confirm: Confirm) -> anyhow::Result<()> {
    let ca = Ca::load_or_create(dir)?;
    let home = dirs::home_dir().context("the platform reports no home directory")?;
    let trust = CaTrust::new(
        SystemRunner,
        Platform::current(),
        (ca.path(), ca.cert_pem(), ca.cert_der()?),
        &home,
    );
    let change = match action {
        CaTrustCommand::Install => trust::Action::Install,
        CaTrustCommand::Uninstall => trust::Action::Uninstall,
        CaTrustCommand::Status => {
            let status = match trust.status()? {
                TrustStatus::Trusted => "trusted",
                TrustStatus::NotTrusted => "not trusted",
                TrustStatus::Unknown => "unknown (check your distribution's trust store)",
            };
            println!(
                "{NAME} CA: {status}\nSHA-256 fingerprint: {}",
                trust.fingerprint()
            );
            return Ok(());
        }
    };
    let plan = trust.plan(change);
    let confirmed = match confirm {
        Confirm::Assumed => {
            eprint!("{plan}");
            true
        }
        Confirm::Ask => {
            trust::confirm(&plan, &mut std::io::stdin().lock(), &mut std::io::stderr())?
        }
    };
    anyhow::ensure!(confirmed, "cancelled; nothing changed");
    let done = match change {
        trust::Action::Install => trust.install()?,
        trust::Action::Uninstall => trust.uninstall()?,
    };
    println!("{done}");
    Ok(())
}

/// `system-proxy on|off|status`.
fn system_proxy(action: SystemProxyCommand, dir: &std::path::Path) -> anyhow::Result<()> {
    let proxy = SystemProxy::new(SystemRunner, Platform::current(), dir);
    match action {
        SystemProxyCommand::On(listen) => match proxy.enable(listen)? {
            Enabled::Changed(text) => println!(
                "{text}\nUndo with `{NAME} system-proxy off`; until then programs need the \
                     proxy running on port {}.",
                listen.port()
            ),
            Enabled::Manual(text) => print!("{text}"),
        },
        SystemProxyCommand::Off => {
            if proxy.restore()? {
                println!("restored the system proxy settings from before {NAME} changed them");
            } else {
                println!("nothing to restore: {NAME} has not changed the system proxy");
            }
        }
        SystemProxyCommand::Status => print!("{}", proxy.status()?),
    }
    Ok(())
}

/// Puts the system proxy settings back on the way out and says so (or how to do it by hand).
fn restore_system_proxy(guard: Option<sysproxy::Guard<SystemRunner>>) {
    let Some(guard) = guard else { return };
    match guard.restore() {
        Ok(_) => eprintln!("{NAME}: restored the system proxy settings"),
        Err(e) => eprintln!(
            "{NAME}: could not restore the system proxy ({e:#}); run `{NAME} system-proxy off`"
        ),
    }
}

/// For `--system-proxy`: restores what a crashed run left, then points the system proxy at
/// `listen`. Without the flag, only warns about a leftover state file.
fn start_system_proxy(
    flag: SystemProxyFlag,
    dir: &std::path::Path,
    listen: SocketAddr,
) -> anyhow::Result<Option<sysproxy::Guard<SystemRunner>>> {
    let proxy = SystemProxy::new(SystemRunner, Platform::current(), dir);
    if flag == SystemProxyFlag::Off {
        if proxy.has_saved_state() {
            eprintln!(
                "{NAME}: an earlier run left the system proxy pointing at it ({}); run `{NAME} \
                 system-proxy off` to restore the old settings",
                proxy.state_path().display()
            );
        }
        return Ok(None);
    }
    if proxy.restore()? {
        eprintln!("{NAME}: restored the system proxy settings an earlier run left behind");
    }
    match proxy.enable(listen)? {
        Enabled::Changed(text) => {
            eprintln!("{NAME}: {text}; restored on exit");
            Ok(Some(sysproxy::Guard::new(proxy)))
        }
        Enabled::Manual(text) => {
            eprint!("{text}");
            Ok(None)
        }
    }
}

/// The `replay` command: one flow of a session file, through a running proxy.
fn replay(
    session: &std::path::Path,
    dir: &std::path::Path,
    args: ReplayArgs,
) -> anyhow::Result<()> {
    let id = args.id.context("replay needs --id N")?;
    let flows = session::read(session)?.flows;
    let flow = flows
        .iter()
        .find(|flow| flow.id() == id)
        .with_context(|| format!("no flow {id} in {}", session.display()))?;
    let wirust::flow::Event::Exchange(exchange) = &flow.record else {
        bail!("flow {id} is not an HTTP exchange");
    };
    let via = args
        .via
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], DEFAULT_PORT)));
    let runtime = tokio::runtime::Runtime::new().context("starting the async runtime")?;
    let status = runtime.block_on(wirust::replay::send_via(exchange, args.edits, via, dir))?;
    println!("{status}");
    Ok(())
}

fn android_setup(dir: Option<PathBuf>, mobile: &MobileArgs) -> anyhow::Result<()> {
    let dir = config_dir(dir)?;
    let ca = Ca::load_or_create(&dir)?;
    let port = mobile.port();
    let adb = Adb::open(mobile.serial.clone())?;
    // Push DER: the Android certificate installer reads it as a CA certificate.
    let der_file = dir.join(format!("{NAME}-ca.crt"));
    std::fs::write(&der_file, ca.cert_der()?)
        .with_context(|| format!("writing {}", der_file.display()))?;
    adb.run_all(&adb::setup_commands(adb.serial(), port, &der_file))?;
    let reset = adb::reset_hint(adb.serial(), port);
    println!(
        "The device now sends HTTP traffic to 127.0.0.1:{port}, which adb reverse maps to this
computer. Start the proxy:   {NAME} --listen 127.0.0.1:{port} --android-cleanup

Then on the device: Settings > Security & privacy > More security & privacy > Encryption &
credentials > Install a certificate > CA certificate, and pick Download/{NAME}-ca.crt
(menu names vary by vendor; Android asks for a screen lock first). Chrome and other browsers
trust the certificate; most apps do not unless they opt in with debug-overrides (your own
debug builds). See docs/mobile.md.

IMPORTANT: while the proxy is not running the device has no working HTTP proxy. Undo with:
  {reset}"
    );
    Ok(())
}

/// Runs `android reset` for `--android-cleanup`, reporting instead of failing.
fn android_cleanup(mobile: &MobileArgs, port: u16) {
    let result = Adb::open(mobile.serial.clone())
        .and_then(|adb| adb.run_all(&adb::reset_commands(adb.serial(), port)));
    match result {
        Ok(()) => eprintln!("{NAME}: cleared the Android device's proxy setting"),
        Err(e) => eprintln!(
            "{NAME}: could not clear the Android proxy ({e:#}); run: {}",
            adb::reset_hint(mobile.serial.as_deref(), port)
        ),
    }
}

/// The lists `--passthrough` and `--decrypt-only` give.
fn passthrough(args: &RunArgs) -> anyhow::Result<Passthrough> {
    let lists = Lists::parse(&args.passthrough, &args.decrypt_only)
        .map_err(anyhow::Error::msg)
        .context("--passthrough/--decrypt-only")?;
    Ok(Passthrough::new(lists))
}

/// Puts the built-in interceptors (`--block-host`, `--add-header`, `--remove-header`) and then
/// the rules engine on the chain, with the `--script` stages after the rule actions and before
/// the rule breakpoints. With `--ui` the rules engine is on, empty, even without `--rules`, so
/// the API can manage it. Returns the engine when it is on.
fn register_interceptors(
    config: &mut Config,
    block_hosts: Vec<String>,
    (add_headers, remove_headers): (Vec<(HeaderName, HeaderValue)>, Vec<HeaderName>),
    (rules_file, ui): (Option<&std::path::Path>, bool),
    scripts: Option<&Scripts>,
) -> anyhow::Result<Option<Rules>> {
    if !block_hosts.is_empty() {
        config
            .interceptors
            .push(Arc::new(BlockHost::new(block_hosts, StatusCode::FORBIDDEN)));
    }
    if !add_headers.is_empty() || !remove_headers.is_empty() {
        config
            .interceptors
            .push(Arc::new(HeaderRules::new(add_headers, remove_headers)));
    }
    let rules = match (rules_file, ui) {
        (Some(path), _) => Some(Rules::from_file(path).context("--rules")?),
        (None, true) => Some(Rules::new()),
        (None, false) => None,
    };
    let mut stages = (rules.as_ref()).map_or_else(Vec::new, |r| r.interceptors(&config.pauses));
    // The last rules stage holds the breakpoints: they see what the scripts made.
    let breakpoints = stages.pop();
    stages.extend(scripts.map_or_else(Vec::new, Scripts::interceptors));
    stages.extend(breakpoints);
    for stage in stages {
        config.interceptors.push(stage);
    }
    Ok(rules)
}

/// Starts the phone console of `connect` (the setup banner, then the approval prompts);
/// without pairing there is none.
fn start_console(
    pairing: Option<(Pairing, UnboundedReceiver<Notice>)>,
    proxy: &Proxy,
    local: SocketAddr,
) -> anyhow::Result<Option<tokio::task::JoinHandle<()>>> {
    let Some((pairing, notices)) = pairing else {
        return Ok(None);
    };
    let url = format!("http://{local}/");
    eprintln!("{}", mobile::banner(local, &qr::terminal(&url)?, &pairing));
    let events = proxy.subscribe();
    let input = mobile::stdin_lines();
    Ok(Some(tokio::spawn(mobile::console(
        pairing, notices, events, input, local,
    ))))
}

fn run(
    mut args: RunArgs,
    mobile: &MobileArgs,
    pairing: Option<(Pairing, UnboundedReceiver<Notice>)>,
) -> anyhow::Result<()> {
    let remote = if args.allow_remote {
        RemoteAccess::Allow
    } else {
        RemoteAccess::LoopbackOnly
    };
    let mut config = Config {
        listen: args.listen,
        remote,
        body_limit: args.body_limit,
        upstream: if args.upstream_insecure {
            UpstreamTls::Insecure
        } else {
            UpstreamTls::default()
        },
        max_flows: args.max_flows,
        pause_timeout: args.pause_timeout,
        pairing: pairing.as_ref().map(|(pairing, _)| pairing.clone()),
        passthrough: passthrough(&args)?,
        ws: args.ws,
        upstream_proxy: args.upstream_proxy.take(),
        upstream_bypass: std::mem::take(&mut args.upstream_bypass),
        ..Config::new(config_dir(args.config_dir.clone())?)
    };
    let dir = config_dir(args.config_dir.clone())?;
    let scripts = load_scripts(&args)?;
    let rules = register_interceptors(
        &mut config,
        std::mem::take(&mut args.block_hosts),
        (
            std::mem::take(&mut args.add_headers),
            std::mem::take(&mut args.remove_headers),
        ),
        (args.rules.as_deref(), args.ui.is_some()),
        scripts.as_ref(),
    )?;
    warn_about_risky_options(
        config.listen,
        args.ui,
        args.allow_remote,
        args.upstream_insecure,
    );
    if let Some(proxy) = &config.upstream_proxy {
        announce_upstream_proxy(proxy);
    }
    let schemas = load_schemas(std::mem::take(&mut args.schemas))?;
    let runtime = tokio::runtime::Runtime::new().context("starting the async runtime")?;
    runtime.block_on(async {
        let mut proxy = Proxy::bind(config).await?;
        let control = match args.ui {
            Some(addr) => Some(ControlPlane::bind(addr, remote, &mut proxy).await?),
            None => None,
        };
        // After the control plane, which adds the refused targets the listener shares.
        #[cfg(feature = "wireguard")]
        let _wireguard = start_wireguard(args.wireguard, remote, &dir, &proxy).await?;
        eprintln!(
            "{NAME} listening on {}  CA: {}",
            proxy.local_addr()?,
            proxy.ca().path().display()
        );
        if let Some(control) = &control {
            eprintln!("{NAME} UI (keep this link private): {}", control.url());
            control.set_session_file(args.session.clone());
        }
        let local = proxy.local_addr()?;
        // Dropped on every way out of this block, so an early error also restores it.
        let system_proxy = start_system_proxy(args.system_proxy, &dir, local)?;
        let console = start_console(pairing, &proxy, local)?;
        if let Some(path) = &args.session {
            start_session(path, proxy.subscribe())?;
        }
        if let Some(rules) = &rules {
            start_rules(rules, control.as_ref(), args.rules.is_some());
        }
        start_schemas(schemas, control.as_ref());
        start_scripts(scripts.as_ref(), control.as_ref());
        let printer = tokio::spawn(print_flows(proxy.subscribe(), args.json, args.ws_log));
        let control = control.map(|control| tokio::spawn(control.run()));
        let result = tokio::select! {
            result = proxy.run() => result,
            () = sysproxy::shutdown_signal() => Ok(()),
        };
        restore_system_proxy(system_proxy);
        printer.abort();
        if let Some(control) = control {
            control.abort();
        }
        if let Some(console) = console {
            console.abort();
        }
        if mobile.android_cleanup {
            android_cleanup(mobile, local.port());
        }
        result
    })
}

/// Prints a warning for each option that makes the proxy reachable by others or stops it
/// verifying servers.
fn warn_about_risky_options(
    listen: SocketAddr,
    ui: Option<SocketAddr>,
    allow_remote: bool,
    upstream_insecure: bool,
) {
    for addr in std::iter::once(listen).chain(ui) {
        if !addr.ip().is_loopback() && allow_remote {
            eprintln!(
                "WARNING: listening on {addr}: anyone who can reach this port can use the proxy, \
                 and the CA key signs certificates for every host. Firewall it."
            );
        }
    }
    if upstream_insecure {
        eprintln!(
            "WARNING: --upstream-insecure: server certificates are NOT verified; anyone on the \
             path to a server can read and change the traffic."
        );
    }
}

/// Prints the upstream proxy (password redacted) and warns once when its credentials would
/// cross the network in clear text.
fn announce_upstream_proxy(proxy: &UpstreamProxy) {
    eprintln!("{NAME}: outbound connections go through the upstream proxy {proxy}");
    if proxy.kind() == UpstreamProxyKind::Http && proxy.has_credentials() && !proxy.is_loopback() {
        eprintln!(
            "WARNING: --upstream-proxy: the credentials go to {proxy} over plain http://; anyone \
             on the path can read them."
        );
    }
}

/// Appends every finished flow to `path` as JSON Lines, from now on.
fn start_session(
    path: &std::path::Path,
    events: tokio::sync::broadcast::Receiver<FlowEvent>,
) -> anyhow::Result<()> {
    let writer = session::SessionWriter::create(path, session::Existing::Append)
        .with_context(|| format!("opening the session file {}", path.display()))?;
    drop(writer.follow(events));
    eprintln!(
        "{NAME}: saving sessions to {} (contains request data)",
        path.display()
    );
    Ok(())
}

/// Hands the rules to the control plane's API and, when they came from a file, starts watching
/// that file for changes.
/// Loads the `--script` files; `None` without any.
fn load_scripts(args: &RunArgs) -> anyhow::Result<Option<Scripts>> {
    if args.scripts.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        Scripts::load(&args.scripts, args.body_limit).context("--script")?,
    ))
}

/// Shows the scripts in the API and reloads them when their files change.
fn start_scripts(scripts: Option<&Scripts>, control: Option<&ControlPlane>) {
    let Some(scripts) = scripts else {
        return;
    };
    if let Some(control) = control {
        control.set_scripts(scripts.clone());
    }
    drop(scripts.watch(Duration::from_secs(1)));
}

fn start_rules(rules: &Rules, control: Option<&ControlPlane>, watch_file: bool) {
    if let Some(control) = control {
        control.set_rules(rules.clone());
    }
    if watch_file {
        drop(rules.watch(Duration::from_secs(1)));
    }
}

/// Compiles the `--proto` schemas, refusing to start on a bad one; `None` without `--proto`.
fn load_schemas(
    sources: wirust::schema::Sources,
) -> anyhow::Result<Option<wirust::schema::Schemas>> {
    if sources.protos.is_empty() {
        anyhow::ensure!(
            sources.includes.is_empty() && sources.message.is_none(),
            "--proto-include and --proto-message need --proto"
        );
        return Ok(None);
    }
    let schemas =
        wirust::schema::Schemas::load(sources).map_err(|e| anyhow::anyhow!("--proto: {e}"))?;
    let report = schemas.report();
    eprintln!(
        "{NAME}: loaded {} schema file(s), {} service(s)",
        report.files.len(),
        report.services.len()
    );
    Ok(Some(schemas))
}

/// Hands the schemas to the control plane's API and watches their files for changes.
fn start_schemas(schemas: Option<wirust::schema::Schemas>, control: Option<&ControlPlane>) {
    let Some(schemas) = schemas else {
        return;
    };
    drop(schemas.watch(Duration::from_secs(2)));
    if let Some(control) = control {
        control.set_schemas(schemas);
    }
}

/// Prints every finished flow, as text or as JSON Lines of the stored flow schema.
/// With `ws_log`, also one short line per WebSocket message.
///
/// In text mode, repeated TLS failures of one host and error are folded into a summary line
/// (see [`Folder`]); the summary of a window that closes is printed on time even when no
/// other event arrives. JSON output has one object per event and is never folded.
async fn print_flows(
    mut events: tokio::sync::broadcast::Receiver<FlowEvent>,
    json: bool,
    ws_log: WsLog,
) {
    let mut stdout = std::io::stdout();
    let mut folder = Folder::new();
    loop {
        let received = match folder.next_deadline() {
            Some(deadline) => tokio::select! {
                received = events.recv() => received,
                () = tokio::time::sleep_until(deadline.into()) => {
                    if print_lines(&mut stdout, &folder.expire(Instant::now())).is_err() {
                        break;
                    }
                    continue;
                }
            },
            None => events.recv().await,
        };
        let lines = match received {
            Ok(event) => console_lines(&event, json, ws_log, &mut folder),
            Err(RecvError::Lagged(missed)) => {
                eprintln!("{NAME}: the log fell behind and skipped {missed} events");
                continue;
            }
            Err(RecvError::Closed) => break,
        };
        if print_lines(&mut stdout, &lines).is_err() {
            break;
        }
    }
}

/// The console lines `event` turns into: none for events the console does not show.
fn console_lines(event: &FlowEvent, json: bool, ws_log: WsLog, folder: &mut Folder) -> Vec<String> {
    let now = Instant::now();
    match event.flow() {
        Some(flow) if json => vec![
            serde_json::to_string(&**flow).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}")),
        ],
        Some(flow) => {
            let failure = match &flow.record {
                Event::TlsFailure(failure) => Some(failure),
                _ => None,
            };
            folder.lines(now, failure, flow.record.to_string())
        }
        None => match event {
            FlowEvent::WsMessage(message) if ws_log == WsLog::Lines => {
                folder.lines(now, None, ws::log_line(message))
            }
            _ => Vec::new(),
        },
    }
}

/// Writes each line and flushes, so a pipe sees them at once.
fn print_lines(out: &mut std::io::Stdout, lines: &[String]) -> std::io::Result<()> {
    for line in lines {
        writeln!(out, "{line}")?;
    }
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn parses_run_flags_and_ca_commands() -> anyhow::Result<()> {
        let Command::Run(run, _) = parse(&args("--listen 127.0.0.1:9 --json --body-limit 10"))?
        else {
            panic!("expected run");
        };
        assert_eq!((run.listen.port(), run.json, run.body_limit), (9, true, 10));
        assert!(matches!(
            parse(&args("ca path --config-dir /x"))?,
            Command::CaPath(Some(_))
        ));
        let Command::Run(run, _) = parse(&args(
            "--ui 127.0.0.1:0 --block-host a.test --block-host b.test --add-header x-a:1 \
             --remove-header cookie --max-flows 7 --pause-timeout 3",
        ))?
        else {
            panic!("expected run");
        };
        assert_eq!(run.block_hosts, ["a.test", "b.test"]);
        assert_eq!((run.add_headers.len(), run.remove_headers.len()), (1, 1));
        assert_eq!((run.max_flows, run.pause_timeout.as_secs()), (7, 3));
        assert!(run.ui.is_some());
        assert!(parse(&args("--bogus")).is_err());
        assert!(parse(&args("ca nope")).is_err());
        assert!(matches!(
            parse(&args("export --har o.har --filter status:5xx"))?,
            Command::Export {
                session: None,
                filter: Some(_),
                ..
            }
        ));
        assert!(matches!(
            parse(&args("import --har i.har --session s.jsonl"))?,
            Command::Import { .. }
        ));
        assert!(parse(&args("import --har i.har")).is_err());
        assert!(parse(&args("view")).is_err());
        let Command::Run(run, _) = parse(&args("--session s.jsonl"))? else {
            panic!("expected run");
        };
        assert!(run.session.is_some());
        Ok(())
    }

    #[test]
    fn parses_trust_and_system_proxy_commands() -> anyhow::Result<()> {
        assert!(matches!(
            parse(&args("ca install --yes"))?,
            Command::CaTrust(CaTrustCommand::Install, None, Confirm::Assumed)
        ));
        assert!(matches!(
            parse(&args("ca uninstall"))?,
            Command::CaTrust(CaTrustCommand::Uninstall, None, Confirm::Ask)
        ));
        assert!(matches!(
            parse(&args("system-proxy status"))?,
            Command::SystemProxy(SystemProxyCommand::Status, None)
        ));
        assert!(parse(&args("system-proxy maybe")).is_err());
        let Command::Run(run, _) = parse(&args("--system-proxy"))? else {
            panic!("expected run");
        };
        assert_eq!(run.system_proxy, SystemProxyFlag::On);
        Ok(())
    }

    /// The address `system-proxy on` points at for a command line, or the error text.
    fn system_proxy_on(line: &str) -> Result<SocketAddr, String> {
        match parse(&args(line)) {
            Ok(Command::SystemProxy(SystemProxyCommand::On(addr), _)) => Ok(addr),
            Ok(other) => panic!("expected system-proxy on, got {other:?}"),
            Err(e) => Err(format!("{e:#}")),
        }
    }

    #[test]
    fn system_proxy_on_takes_the_port_from_port_or_listen() {
        let on = |line: &str| system_proxy_on(line).map(|addr| addr.to_string());
        assert_eq!(on("system-proxy on"), Ok("127.0.0.1:8080".to_owned()));
        assert_eq!(
            on("system-proxy on --port 9000"),
            Ok("127.0.0.1:9000".to_owned())
        );
        assert_eq!(
            on("system-proxy on --listen 127.0.0.1:9001"),
            Ok("127.0.0.1:9001".to_owned())
        );
        // The host of --listen is kept, not only its port.
        assert_eq!(
            on("system-proxy on --listen [::1]:9002"),
            Ok("[::1]:9002".to_owned())
        );
        assert_eq!(
            on("system-proxy on --listen 127.0.0.2:9003 --port 9003"),
            Ok("127.0.0.2:9003".to_owned())
        );
        assert_eq!(
            on("system-proxy on --port 9004 --listen 127.0.0.1:9004"),
            Ok("127.0.0.1:9004".to_owned())
        );
    }

    #[test]
    fn system_proxy_on_refuses_disagreeing_ports() {
        let err = system_proxy_on("system-proxy on --listen 127.0.0.1:9001 --port 9002")
            .expect_err("two ports");
        assert!(err.contains("9001") && err.contains("9002"), "{err}");
        assert!(system_proxy_on("system-proxy on --port 9002 --listen 127.0.0.1:9001").is_err());
        // --allow-remote does not make them agree, and 8080 is no exception to the rule.
        assert!(
            system_proxy_on("system-proxy on --allow-remote --listen 10.0.0.2:9001 --port 9002")
                .is_err()
        );
        assert!(system_proxy_on("system-proxy on --listen 127.0.0.1:9001 --port 8080").is_err());
    }

    #[test]
    fn system_proxy_on_refuses_remote_and_wildcard_addresses_without_allow_remote() {
        for listen in [
            "0.0.0.0:8080",
            "[::]:8080",
            "192.168.1.5:8080",
            "[fe80::1]:8080",
        ] {
            let line = format!("system-proxy on --listen {listen}");
            let err = system_proxy_on(&line).expect_err(&line);
            assert!(err.contains("--allow-remote"), "{line}: {err}");
            let allowed = system_proxy_on(&format!("{line} --allow-remote"));
            assert_eq!(
                allowed.map(|a| a.to_string()),
                Ok(listen.to_owned()),
                "{line}"
            );
        }
        // Loopback is fine without it, and `off` and `status` never look at the address.
        assert!(system_proxy_on("system-proxy on --listen 127.9.9.9:80").is_ok());
        assert!(matches!(
            parse(&args("system-proxy off --listen 0.0.0.0:1 --port 2")),
            Ok(Command::SystemProxy(SystemProxyCommand::Off, None))
        ));
    }

    #[test]
    fn the_system_proxy_help_describes_its_address_flags() {
        let page = command_help(&["system-proxy"]).expect("a page");
        for flag in ["--listen ADDR", "--port P", "--allow-remote"] {
            assert!(page.contains(flag), "{flag} missing from: {page}");
        }
        assert!(usage().contains("system-proxy on|off|status [--listen ADDR | --port P]"));
    }

    #[test]
    fn parses_connect_and_android_commands() -> anyhow::Result<()> {
        let Command::Connect(_, mobile) = parse(&args(
            "connect --port 9090 --lan-ip 192.168.1.10 --allow-client 192.168.1.23 \
             --allow-client 10.0.0.0/8",
        ))?
        else {
            panic!("expected connect");
        };
        assert_eq!(mobile.port(), 9090);
        assert_eq!(mobile.lan_ip, Some(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(mobile.allow_clients.len(), 2);
        let Command::AndroidSetup(_, mobile) =
            parse(&args("android setup --serial emulator-5554"))?
        else {
            panic!("expected android setup");
        };
        assert_eq!(
            (mobile.serial.as_deref(), mobile.port()),
            (Some("emulator-5554"), DEFAULT_PORT)
        );
        assert!(matches!(
            parse(&args("android reset"))?,
            Command::AndroidReset(_)
        ));
        let Command::Run(_, mobile) = parse(&args("--android-cleanup"))? else {
            panic!("expected run");
        };
        assert!(mobile.android_cleanup);
        assert!(parse(&args("connect --allow-client phone")).is_err());
        assert!(parse(&args("android nope")).is_err());
        Ok(())
    }

    /// The text of `fn parse`, the one place that knows the flags and commands.
    fn parser_source() -> &'static str {
        const SOURCE: &str = include_str!("main.rs");
        let start = SOURCE.find("\nfn parse(").expect("main.rs has fn parse");
        let end = SOURCE[start..]
            .find("\nfn config_dir")
            .expect("fn config_dir follows fn parse");
        &SOURCE[start..start + end]
    }

    /// The string literals before the `=>` of an arm line.
    fn arm_literals(line: &str) -> Vec<&str> {
        let pattern = line.split("=>").next().unwrap_or_default();
        pattern.split('"').skip(1).step_by(2).collect()
    }

    /// Every flag the parser accepts, read from its match arms.
    fn parser_flags() -> Vec<&'static str> {
        let flags: Vec<&str> = (parser_source().lines())
            .map(str::trim)
            .filter(|line| line.starts_with("\"-") && line.contains("=>"))
            .flat_map(arm_literals)
            .collect();
        assert!(
            flags.len() > 30,
            "found too few flags in the parser: {flags:?}"
        );
        flags
    }

    /// Every command the parser accepts, such as `["android", "setup"]`.
    fn parser_commands() -> Vec<Vec<&'static str>> {
        let commands: Vec<Vec<&str>> = (parser_source().lines())
            .map(str::trim)
            .filter(|line| line.starts_with('[') && line.contains("=>"))
            .map(arm_literals)
            .filter(|words| !words.is_empty())
            .collect();
        assert!(commands.len() >= 9, "found too few commands: {commands:?}");
        commands
    }

    /// The `--flag` words in `text`.
    fn flags_in(text: &str) -> Vec<&str> {
        text.match_indices("--")
            .filter(|(at, _)| !text[..*at].ends_with(|c: char| c.is_ascii_alphanumeric()))
            .map(|(at, _)| {
                let rest = &text[at..];
                let len = rest
                    .find(|c: char| !(c == '-' || c.is_ascii_lowercase()))
                    .unwrap_or(rest.len());
                &rest[..len]
            })
            .filter(|flag| flag.len() > 2)
            .collect()
    }

    #[test]
    fn the_help_lists_every_flag_the_parser_accepts() {
        let help = usage();
        let (synopsis, rest) = help
            .split_once("\nCommands:")
            .expect("usage has a Commands section");
        let (_, options) = rest
            .split_once("\nOptions:")
            .expect("usage has an Options section");
        for flag in parser_flags() {
            assert!(options.contains(flag), "Options lacks {flag}");
            // The help flags have a line in Options only.
            if !matches!(flag, "-h" | "--help" | "-V" | "--version") {
                assert!(synopsis.contains(flag), "the Usage lines lack {flag}");
            }
        }
    }

    #[test]
    fn the_help_names_no_flag_the_parser_refuses() {
        let known = parser_flags();
        let mut texts = vec![usage()];
        texts.extend(
            parser_commands()
                .iter()
                .filter_map(|words| command_help(words)),
        );
        for text in &texts {
            for flag in flags_in(text) {
                assert!(
                    known.contains(&flag),
                    "help mentions {flag}, which is not parsed"
                );
            }
        }
    }

    #[test]
    fn every_command_has_its_own_help_page() -> anyhow::Result<()> {
        let mut commands = parser_commands();
        // The parents of the two-word commands have a page of their own.
        commands.extend([vec!["android"], vec!["ca"]]);
        for words in commands {
            let page = command_help(&words)
                .with_context(|| format!("no help page for {}", words.join(" ")))?;
            assert_ne!(page, usage(), "{words:?} shows the main help");
            assert!(
                page.starts_with(&format!("{NAME} {}", words.join(" "))),
                "{words:?}: {page}"
            );
            for position in [0, words.len()] {
                let mut line = words.clone();
                line.insert(position, "--help");
                let Command::Help(given) = parse(&args(&line.join(" ")))? else {
                    panic!("{line:?} must ask for help");
                };
                assert_eq!(given, words, "{line:?}");
            }
        }
        assert!(command_help(&["nope"]).is_none());
        let Command::Help(given) = parse(&args("--help"))? else {
            panic!("--help must ask for help");
        };
        assert!(given.is_empty(), "{given:?}");
        assert!(matches!(parse(&args("-h"))?, Command::Help(_)));
        assert!(matches!(parse(&args("-V"))?, Command::Version));
        Ok(())
    }

    #[test]
    fn the_plain_run_usage_names_the_passthrough_flags() {
        let help = usage();
        let (run_usage, _) = help
            .split_once(&format!("\n  {NAME} connect"))
            .expect("the connect usage line follows the plain run");
        for flag in ["--passthrough PATTERN", "--decrypt-only PATTERN"] {
            assert!(run_usage.contains(flag), "{flag} missing from: {run_usage}");
        }
    }
}
