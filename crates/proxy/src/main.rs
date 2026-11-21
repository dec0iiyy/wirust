//! Command-line entry point.

use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, bail};
use http::{HeaderName, HeaderValue, StatusCode};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc::UnboundedReceiver;
use wirust::adb::{self, Adb};
use wirust::ca::Ca;
use wirust::control::ControlPlane;
use wirust::events::{DEFAULT_MAX_FLOWS, FlowEvent};
use wirust::intercept::{BlockHost, DEFAULT_PAUSE_TIMEOUT, HeaderRules};
use wirust::oscmd::{Platform, SystemRunner};
use wirust::pairing::{Cidr, Notice, Pairing};
use wirust::passthrough::{Lists, Passthrough};
use wirust::rules::Rules;
use wirust::session;
use wirust::sysproxy::{self, Enabled, SystemProxy};
use wirust::trust::{self, CaTrust, TrustStatus};
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
    /// `system-proxy on|off|status [--port P]`
    SystemProxy(SystemProxyCommand, Option<PathBuf>, u16),
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
    Help,
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
    passthrough: Vec<String>,
    decrypt_only: Vec<String>,
    replay: ReplayArgs,
    ws: WsLimits,
    ws_log: WsLog,
    system_proxy: SystemProxyFlag,
    confirm: Confirm,
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
    On,
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

fn usage() -> String {
    format!(
        "{NAME} {version}: an HTTPS debugging proxy

Usage:
  {NAME} [--listen ADDR] [--json] [--body-limit BYTES] [--upstream-insecure]
         [--allow-remote] [--config-dir DIR] [--max-flows N] [--pause-timeout SECS]
         [--ui ADDR] [--add-header 'NAME: VALUE']... [--remove-header NAME]...
         [--block-host HOST]... [--rules FILE] [--session FILE]
         [--ws-body-limit BYTES] [--ws-max-messages N] [--ws-log]
         [--android-cleanup [--serial S]]
  {NAME} connect [--port P] [--lan-ip IP] [--allow-client IP|CIDR]... [run options]
  {NAME} android setup|reset [--serial S] [--port P] [--config-dir DIR]
  {NAME} ca path|show|install-help [--config-dir DIR]
  {NAME} ca install|uninstall|status [--yes] [--config-dir DIR]
  {NAME} system-proxy on|off|status [--port P] [--config-dir DIR]
  {NAME} export --har OUT.har [--session FILE] [--filter QUERY]   (no --session: JSON Lines on stdin)
  {NAME} import --har IN.har --session OUT.jsonl
  {NAME} view --session FILE [--filter QUERY]
  {NAME} replay --session FILE --id N [--set-header 'N: V']... [--method M] [--url U]
         [--via http://127.0.0.1:8080] [--config-dir DIR]

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
  system-proxy on       point this computer's system proxy at 127.0.0.1:P, saving the old
                        settings first; `off` restores them, `status` shows them
  replay                send flow N of a session file again through a running proxy (--via),
                        as an ordinary client, and print the status line; see docs/replay.md

Options:
  --listen ADDR         address to listen on (default 127.0.0.1:8080)
  --json                print one JSON object per line instead of text
  --body-limit BYTES    body bytes kept per request and response (default {DEFAULT_BODY_LIMIT})
  --upstream-insecure   do not verify server certificates (dangerous)
  --allow-remote        allow a non-loopback --listen address (dangerous)
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
  --port P              proxy port for connect and android (default {DEFAULT_PORT})
  --lan-ip IP           connect: the address to listen on, instead of the detected one
  --allow-client NET    connect: pre-approve this IP or CIDR (repeatable)
  --serial S            android: the adb device to use when several are connected
  --session FILE        append every finished flow to FILE as JSON Lines (mode 0600; it holds
                        tokens, cookies and passwords from the traffic)
  --filter QUERY        search query for export and view, such as 'host:example.com status:5xx'
  --har FILE            HAR file to write (export) or read (import)
  --rules FILE          TOML rules (block, map-local, map-remote, rewrite, throttle, breakpoints);
                        reloaded when it changes; see docs/rules.md
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

Requests to http://{MAGIC_HOST}/ through the proxy get a page with the CA download.
",
        version = env!("CARGO_PKG_VERSION"),
        pause = DEFAULT_PAUSE_TIMEOUT.as_secs(),
        ws_body = DEFAULT_WS_BODY_LIMIT,
        ws_max = DEFAULT_WS_MAX_MESSAGES
    )
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
        passthrough: Vec::new(),
        decrypt_only: Vec::new(),
        replay: ReplayArgs::default(),
        ws: WsLimits::default(),
        ws_log: WsLog::Off,
        system_proxy: SystemProxyFlag::Off,
        confirm: Confirm::Ask,
    };
    let mut mobile = MobileArgs::default();
    let mut words = Vec::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let mut value = |flag: &str| {
            args.next()
                .cloned()
                .with_context(|| format!("{flag} needs a value"))
        };
        match arg.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "-V" | "--version" => return Ok(Command::Version),
            "--listen" => {
                run.listen = value(arg)?
                    .parse()
                    .context("--listen takes IP:PORT, such as 127.0.0.1:8080")?;
            }
            "--json" => run.json = true,
            "--body-limit" => {
                run.body_limit = value(arg)?
                    .parse()
                    .context("--body-limit takes a byte count")?;
            }
            "--upstream-insecure" => run.upstream_insecure = true,
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
            "--system-proxy" => run.system_proxy = SystemProxyFlag::On,
            "--yes" => run.confirm = Confirm::Assumed,
            flag if flag.starts_with('-') => bail!("unknown option {flag}; see --help"),
            word => words.push(word.to_owned()),
        }
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
                "on" => SystemProxyCommand::On,
                "off" => SystemProxyCommand::Off,
                "status" => SystemProxyCommand::Status,
                _ => bail!("system-proxy takes on, off or status"),
            };
            Ok(Command::SystemProxy(action, dir, mobile.port()))
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
        _ => bail!("unknown command {}; see --help", words.join(" ")),
    }
}

fn config_dir(dir: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    dir.map_or_else(Ca::default_dir, Ok)
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
        Command::Help => print!("{}", usage()),
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
        Command::SystemProxy(action, dir, port) => system_proxy(action, &config_dir(dir)?, port)?,
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
    }
    Ok(())
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
fn system_proxy(
    action: SystemProxyCommand,
    dir: &std::path::Path,
    port: u16,
) -> anyhow::Result<()> {
    let proxy = SystemProxy::new(SystemRunner, Platform::current(), dir);
    match action {
        SystemProxyCommand::On => {
            let listen = SocketAddr::from(([127, 0, 0, 1], port));
            match proxy.enable(listen)? {
                Enabled::Changed(text) => println!(
                    "{text}\nUndo with `{NAME} system-proxy off`; until then programs need the \
                     proxy running on port {port}."
                ),
                Enabled::Manual(text) => print!("{text}"),
            }
        }
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

Then on the device: Settings > Security & privacy > More security settings > Encryption &
credentials > Install a certificate > CA certificate, and pick Download/{NAME}-ca.crt
(menu names vary by vendor). Only your own debug builds that opt in with debug-overrides
trust it; see docs/mobile.md.

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
/// the rules engine on the chain. With `--ui` the rules engine is on, empty, even without
/// `--rules`, so the API can manage it. Returns the engine when it is on.
fn register_interceptors(
    config: &mut Config,
    block_hosts: Vec<String>,
    (add_headers, remove_headers): (Vec<(HeaderName, HeaderValue)>, Vec<HeaderName>),
    (rules_file, ui): (Option<&std::path::Path>, bool),
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
    if let Some(rules) = &rules {
        for stage in rules.interceptors(&config.pauses) {
            config.interceptors.push(stage);
        }
    }
    Ok(rules)
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
        ..Config::new(config_dir(args.config_dir.clone())?)
    };
    let dir = config_dir(args.config_dir.clone())?;
    let rules = register_interceptors(
        &mut config,
        std::mem::take(&mut args.block_hosts),
        (
            std::mem::take(&mut args.add_headers),
            std::mem::take(&mut args.remove_headers),
        ),
        (args.rules.as_deref(), args.ui.is_some()),
    )?;
    warn_about_risky_options(
        config.listen,
        args.ui,
        args.allow_remote,
        args.upstream_insecure,
    );
    let runtime = tokio::runtime::Runtime::new().context("starting the async runtime")?;
    runtime.block_on(async {
        let mut proxy = Proxy::bind(config).await?;
        let control = match args.ui {
            Some(addr) => Some(ControlPlane::bind(addr, remote, &mut proxy).await?),
            None => None,
        };
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
        let console = match pairing {
            Some((pairing, notices)) => {
                let url = format!("http://{local}/");
                eprintln!("{}", mobile::banner(local, &qr::terminal(&url)?, &pairing));
                let events = proxy.subscribe();
                let input = mobile::stdin_lines();
                Some(tokio::spawn(mobile::console(
                    pairing, notices, events, input, local,
                )))
            }
            None => None,
        };
        if let Some(path) = &args.session {
            start_session(path, proxy.subscribe())?;
        }
        if let Some(rules) = &rules {
            start_rules(rules, control.as_ref(), args.rules.is_some());
        }
        let printer = tokio::spawn(print_flows(proxy.subscribe(), args.json, args.ws_log));
        let control = control.map(|control| tokio::spawn(control.run()));
        let result = tokio::select! {
            result = proxy.run() => result,
            () = sysproxy::shutdown_signal() => Ok(()),
        };
        if let Some(guard) = system_proxy {
            match guard.restore() {
                Ok(_) => eprintln!("{NAME}: restored the system proxy settings"),
                Err(e) => eprintln!(
                    "{NAME}: could not restore the system proxy ({e:#}); run `{NAME} \
                     system-proxy off`"
                ),
            }
        }
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
fn start_rules(rules: &Rules, control: Option<&ControlPlane>, watch_file: bool) {
    if let Some(control) = control {
        control.set_rules(rules.clone());
    }
    if watch_file {
        drop(rules.watch(Duration::from_secs(1)));
    }
}

/// Prints every finished flow, as text or as JSON Lines of the stored flow schema.
/// With `ws_log`, also one short line per WebSocket message.
async fn print_flows(
    mut events: tokio::sync::broadcast::Receiver<FlowEvent>,
    json: bool,
    ws_log: WsLog,
) {
    let mut stdout = std::io::stdout();
    loop {
        let flow = match events.recv().await {
            Ok(event) => match event.flow() {
                Some(flow) => Arc::clone(flow),
                None => match &event {
                    FlowEvent::WsMessage(message) if ws_log == WsLog::Lines => {
                        if writeln!(stdout, "{}", ws::log_line(message)).is_err() {
                            break;
                        }
                        continue;
                    }
                    _ => continue,
                },
            },
            Err(RecvError::Lagged(missed)) => {
                eprintln!("{NAME}: the log fell behind and skipped {missed} events");
                continue;
            }
            Err(RecvError::Closed) => break,
        };
        let line = if json {
            serde_json::to_string(&*flow).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
        } else {
            flow.record.to_string()
        };
        if writeln!(stdout, "{line}")
            .and_then(|()| stdout.flush())
            .is_err()
        {
            break;
        }
    }
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
            parse(&args("system-proxy on --port 9000"))?,
            Command::SystemProxy(SystemProxyCommand::On, None, 9000)
        ));
        assert!(matches!(
            parse(&args("system-proxy status"))?,
            Command::SystemProxy(SystemProxyCommand::Status, None, DEFAULT_PORT)
        ));
        assert!(parse(&args("system-proxy maybe")).is_err());
        let Command::Run(run, _) = parse(&args("--system-proxy"))? else {
            panic!("expected run");
        };
        assert_eq!(run.system_proxy, SystemProxyFlag::On);
        Ok(())
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
}
