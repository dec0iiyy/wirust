//! Connecting phones: the setup page, the `connect` screen, the approval console and the
//! hints printed when a device's traffic does not arrive or its TLS handshakes fail.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::{self, BufRead as _, IsTerminal as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, mpsc};

use crate::events::FlowEvent;
use crate::flow::Event;
use crate::pairing::{Notice, Pairing, Status};

/// How long an approved device may stay silent before the console suggests causes.
pub const SILENT_AFTER: Duration = Duration::from_secs(60);

/// The device family a User-Agent names; the setup page shows only its steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// iPhone, iPad or iPod touch.
    Ios,
    /// Any Android device.
    Android,
    /// Anything else, including no User-Agent.
    Other,
}

impl Platform {
    /// Reads the platform from a User-Agent header.
    #[must_use]
    pub fn from_user_agent(user_agent: &str) -> Self {
        if user_agent.contains("Android") {
            Self::Android
        } else if ["iPhone", "iPad", "iPod"]
            .iter()
            .any(|d| user_agent.contains(d))
        {
            Self::Ios
        } else {
            Self::Other
        }
    }
}

/// A short device name for the approval prompt, such as `iPhone` or `Android`.
#[must_use]
pub fn device_name(user_agent: &str) -> &'static str {
    [
        "iPhone",
        "iPad",
        "iPod",
        "Android",
        "Macintosh",
        "Windows",
        "Linux",
    ]
    .into_iter()
    .find(|name| user_agent.contains(name))
    .unwrap_or("unknown device")
}

/// The computer's LAN IPv4 address: the source address the OS picks for a route to the
/// internet. A UDP `connect` sends nothing; it only asks the routing table.
///
/// # Errors
///
/// Fails when there is no route, or the address found is loopback or unspecified.
pub fn lan_ipv4() -> io::Result<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect((Ipv4Addr::new(1, 1, 1, 1), 53))?;
    match socket.local_addr()?.ip() {
        IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_unspecified() => Ok(ip),
        other => Err(io::Error::other(format!(
            "no LAN address found (the route to the internet uses {other}); pass --lan-ip"
        ))),
    }
}

/// The text `connect` prints: addresses, the QR code of the setup URL, one line of steps
/// per platform, and the pairing rules.
#[must_use]
pub fn banner(proxy: SocketAddr, qr: &str, pairing: &Pairing) -> String {
    let name = crate::NAME;
    let url = format!("http://{proxy}/");
    let (host, port) = (proxy.ip(), proxy.port());
    let mut allowed = vec![String::from("loopback")];
    allowed.extend(pairing.allow_list().iter().map(ToString::to_string));
    allowed.extend(
        pairing
            .approved()
            .iter()
            .map(|(ip, d)| format!("{ip} ({d})")),
    );
    let allowed = allowed.join(", ");
    format!(
        "{name} connect

  Proxy    {proxy}   (set it as the phone's Wi-Fi proxy: Manual, host {host}, port {port})
  Setup    {url}   (scan, or type it in the phone's browser)

{qr}
  Android  open the setup URL > install ca.crt as a CA certificate > Wi-Fi proxy Manual {host}:{port}
  iOS      open the setup URL in Safari > install the profile, then enable full trust in
           Settings > General > About > Certificate Trust Settings > Wi-Fi proxy Manual {host}:{port}

  Pairing  only approved devices may use the proxy; answer y/N here when one asks.
           Type r and Enter to revoke all approvals; Ctrl-C quits.
  Allowed  {allowed}
  Note     most Android apps ignore user CAs (only debug builds with debug-overrides opt in);
           HTTP/3 (QUIC) does not go through an HTTP proxy; pinned apps fail by design.
           Help: {url}mobile-help
"
    )
}

/// Lines typed on stdin, or `None` when stdin is not a terminal (every request is denied).
#[must_use]
pub fn stdin_lines() -> Option<mpsc::UnboundedReceiver<String>> {
    if !io::stdin().is_terminal() {
        return None;
    }
    let (sender, receiver) = mpsc::unbounded_channel();
    // A blocking reader thread: stdin has no portable async API. It ends with stdin.
    std::thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    Some(receiver)
}

/// Whether a typed answer approves.
#[must_use]
pub fn approves(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Runs the approval console until the notice channel closes: prompts for each device that
/// asks, answers from `input` (or denies every request when `input` is `None`), revokes on
/// `r`, logs rejections and prints hints. `proxy` is the address devices should use.
pub async fn console(
    pairing: Pairing,
    mut notices: mpsc::UnboundedReceiver<Notice>,
    mut events: broadcast::Receiver<FlowEvent>,
    mut input: Option<mpsc::UnboundedReceiver<String>>,
    proxy: SocketAddr,
) {
    let mut queue: Vec<(IpAddr, String)> = Vec::new();
    let mut tls_hinted: BTreeSet<IpAddr> = BTreeSet::new();
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    loop {
        tokio::select! {
            notice = notices.recv() => match notice {
                None => return,
                Some(Notice::Rejected(ip)) => eprintln!("rejected {ip}: not paired"),
                Some(Notice::Request { ip, device }) => {
                    if input.is_none() {
                        pairing.deny(ip);
                        eprintln!(
                            "device {ip} ({device}) wants to use the proxy: denied (stdin is \
                             not interactive; pre-approve with --allow-client {ip})"
                        );
                    } else {
                        queue.push((ip, device));
                        if queue.len() == 1 {
                            prompt(&queue[0]);
                        }
                    }
                }
            },
            line = recv_line(&mut input) => {
                let Some(line) = line else {
                    // stdin closed: deny what is pending and stop reading.
                    for (ip, _) in queue.drain(..) {
                        pairing.deny(ip);
                    }
                    input = None;
                    continue;
                };
                if !queue.is_empty() {
                    let (ip, device) = queue.remove(0);
                    if approves(&line) {
                        pairing.approve(ip);
                        eprintln!("approved {ip} ({device}) for this session; r revokes");
                    } else {
                        pairing.deny(ip);
                        eprintln!("denied {ip}");
                    }
                    if let Some(next) = queue.first() {
                        prompt(next);
                    }
                } else if line.trim().eq_ignore_ascii_case("r") {
                    let revoked = pairing.revoke_all();
                    eprintln!("revoked {} approval(s); devices must ask again", revoked.len());
                } else if !line.trim().is_empty() {
                    eprintln!("keys: r + Enter revokes all approvals, Ctrl-C quits");
                }
            },
            event = events.recv() => match event {
                Ok(FlowEvent::TlsFailed(flow)) => {
                    if let Event::TlsFailure(failure) = &flow.record
                        && tls_hinted.insert(failure.client.ip())
                    {
                        eprintln!("{}", tls_hint(failure.client.ip(), &failure.target, &failure.reason));
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return,
                _ => {}
            },
            _ = tick.tick() => {
                for (ip, device) in pairing.silent_devices(Instant::now(), SILENT_AFTER) {
                    eprintln!("{}", silent_hint(ip, &device, proxy));
                }
            },
        }
    }
}

async fn recv_line(input: &mut Option<mpsc::UnboundedReceiver<String>>) -> Option<String> {
    match input {
        Some(lines) => lines.recv().await,
        None => std::future::pending().await,
    }
}

fn prompt((ip, device): &(IpAddr, String)) {
    eprintln!("device {ip} ({device}) wants to use the proxy: allow? [y/N]");
}

/// The hint printed once per device after its first failed client-leg TLS handshake.
#[must_use]
pub fn tls_hint(ip: IpAddr, target: &str, reason: &str) -> String {
    format!(
        "hint: {ip} refused the proxy's certificate for {target} ({reason}). Likely causes: the \
         CA is not trusted (iOS: enable it in Certificate Trust Settings; Android: apps trust \
         user CAs only in debug builds with debug-overrides), or the app pins its certificates."
    )
}

/// The hint printed once when an approved device sends no proxy traffic.
#[must_use]
pub fn silent_hint(ip: IpAddr, device: &str, proxy: SocketAddr) -> String {
    format!(
        "hint: {ip} ({device}) is approved but has sent no proxy traffic for {}s. Check its \
         Wi-Fi proxy is Manual {} port {}; Android 17 apps targeting API 37 may need \
         ACCESS_LOCAL_NETWORK to reach a LAN proxy (USB avoids it: {} android setup); \
         HTTP/3 (QUIC) traffic does not use the proxy.",
        SILENT_AFTER.as_secs(),
        proxy.ip(),
        proxy.port(),
        crate::NAME
    )
}

/// Everything the setup page shows that depends on the request.
#[derive(Debug, Clone)]
pub(crate) struct PageInput<'a> {
    /// The proxy address devices should configure.
    pub(crate) proxy_host: String,
    pub(crate) proxy_port: u16,
    pub(crate) user_agent: &'a str,
    /// The device's pairing status, or `None` when pairing is off or the client is local.
    pub(crate) pairing: Option<Status>,
}

/// The setup page: only the steps for the device's platform.
pub(crate) fn setup_page(input: &PageInput<'_>) -> String {
    let name = escape(crate::NAME);
    let host = escape(&input.proxy_host);
    let port = input.proxy_port;
    let platform = Platform::from_user_agent(input.user_agent);
    let mut body = String::new();
    if let Some(status) = input.pairing {
        let message = match status {
            Status::Approved => "This device is approved: it may use the proxy.",
            Status::Waiting => {
                "Waiting for approval on the computer: answer the prompt in the terminal \
                 running the proxy. This page updates by itself."
            }
            Status::Denied => {
                "The computer refused this device. Reload this page in a few seconds to ask \
                 again."
            }
        };
        let _ = writeln!(
            body,
            "<p id=\"pairing\" class=\"box {status}\" data-status=\"{status}\">{message}</p>",
            status = status.as_str()
        );
    }
    let wifi_android = format!(
        "<li>Settings &gt; Network &amp; internet &gt; Wi-Fi &gt; this network &gt; Edit (pencil) &gt; \
         Proxy: <b>Manual</b>, host <code>{host}</code>, port <code>{port}</code>. The menu \
         names vary by vendor.</li>"
    );
    let android = format!(
        "<h2>Android</h2>
<ol>
<li>Download the certificate: <a href=\"/ca.crt\">ca.crt</a>.</li>
<li>Settings &gt; Security &amp; privacy &gt; More security settings &gt; Encryption &amp;
credentials &gt; Install a certificate &gt; <b>CA certificate</b>, then pick
<code>ca.crt</code> (Pixel wording; other vendors differ). Check it under Trusted credentials
&gt; User.</li>
{wifi_android}
</ol>
<div class=\"box warn\"><p><b>Most apps ignore this certificate.</b> Since Android 7 apps trust
user-installed CAs only if they target API 23 or lower or opt in. Your own debug build can opt
in with <code>&lt;debug-overrides&gt;</code> in its network security config. Chrome trusts user
CAs, so a working browser does not mean apps will work.</p></div>
<div class=\"box warn\"><p><b>Android 17:</b> apps that target API 37 may need the
<code>ACCESS_LOCAL_NETWORK</code> permission to reach a proxy on the LAN. Over USB,
<code>{name} android setup</code> uses <code>127.0.0.1</code> and avoids it.</p></div>
"
    );
    let ios = format!(
        "<h2>iPhone and iPad</h2>
<ol>
<li>In Safari, download the profile: <a href=\"/ca.mobileconfig\">ca.mobileconfig</a>, then
Settings &gt; Profile Downloaded &gt; Install.</li>
<li>Settings &gt; General &gt; About &gt; Certificate Trust Settings: turn on full trust for
<b>{name} CA</b>. Without this step iOS installs the CA but does not trust it for HTTPS.</li>
<li>Settings &gt; Wi-Fi &gt; (i) next to this network &gt; Configure Proxy &gt; <b>Manual</b>:
server <code>{host}</code>, port <code>{port}</code>, authentication off.</li>
</ol>
<p>Remove the profile when you are done: Settings &gt; General &gt; VPN &amp; Device
Management.</p>
"
    );
    match platform {
        Platform::Android => body.push_str(&android),
        Platform::Ios => body.push_str(&ios),
        Platform::Other => {
            let _ = write!(
                body,
                "<p>Proxy: <code>{host}:{port}</code>. Certificate: <a href=\"/ca.crt\">ca.crt</a> \
                 (DER, Android and Windows), <a href=\"/ca.pem\">ca.pem</a> (PEM, macOS and \
                 Linux), <a href=\"/ca.mobileconfig\">ca.mobileconfig</a> (iOS profile).</p>\n\
                 {android}{ios}"
            );
        }
    }
    let _ = write!(
        body,
        "<div class=\"box warn\"><p><b>What cannot be seen:</b> apps that use HTTP/3 (QUIC) or
ignore the proxy setting bypass the proxy; apps that pin their certificates fail by design.</p>
</div>
<p><a href=\"/mobile-help\">Full guide and troubleshooting</a></p>
<p class=\"small\">Served by {name} itself; it never reaches the internet. Remove the
certificate when you stop using the proxy.</p>
"
    );
    html_page(&format!("{name} setup"), &body)
}

/// The mobile guide (`docs/mobile.md`) as a static page.
pub(crate) fn help_page() -> String {
    html_page(
        &format!("{} mobile guide", escape(crate::NAME)),
        &markdown(include_str!("../../../docs/mobile.md")),
    )
}

/// Polls the pairing state and reloads when it changes. Served as a file so the CSP can
/// forbid inline scripts.
pub(crate) const SETUP_JS: &str = r#""use strict";
(function () {
  var box = document.getElementById("pairing");
  if (!box || box.dataset.status === "approved") { return; }
  function poll() {
    fetch("/pairing-status", { cache: "no-store" })
      .then(function (r) { return r.text(); })
      .then(function (s) {
        if (s.trim() !== box.dataset.status) { location.reload(); return; }
        setTimeout(poll, 2000);
      })
      .catch(function () { setTimeout(poll, 5000); });
  }
  setTimeout(poll, 2000);
})();
"#;

/// The page style, also a file because of the CSP.
pub(crate) const SETUP_CSS: &str = "body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;\
margin:0 auto;padding:0 16px}code,pre{font-family:ui-monospace,monospace}pre{overflow-x:auto;\
background:#f4f4f4;padding:8px}.box{border-left:4px solid #888;padding:4px 12px;\
background:#f6f6f6}.warn{border-color:#c80}.waiting{border-color:#06c}.approved{border-color:#080}\
.denied{border-color:#c00}.small{font-size:14px;color:#555}@media (prefers-color-scheme:dark){\
body{background:#111;color:#ddd}a{color:#8af}.box,pre{background:#222}.small{color:#aaa}}\n";

fn html_page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html>
<html lang=\"en\">
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>{title}</title>
<link rel=\"stylesheet\" href=\"/setup.css\">
<script src=\"/setup.js\" defer></script>
<h1>{title}</h1>
{body}</html>
"
    )
}

/// Escapes text for HTML element content and quoted attributes.
pub(crate) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// A small Markdown subset for the guide: headings, paragraphs, lists, fenced code and
/// tables (kept as preformatted text), with inline code. Everything is escaped.
fn markdown(md: &str) -> String {
    #[derive(PartialEq)]
    enum Block {
        None,
        Paragraph,
        List(&'static str),
        Code,
        Table,
    }
    fn close(out: &mut String, block: &mut Block) {
        out.push_str(match block {
            Block::None => "",
            Block::Paragraph => "</p>\n",
            Block::List(tag) => {
                if *tag == "ol" {
                    "</li></ol>\n"
                } else {
                    "</li></ul>\n"
                }
            }
            Block::Code => "</code></pre>\n",
            Block::Table => "</pre>\n",
        });
        *block = Block::None;
    }
    let mut out = String::new();
    let mut block = Block::None;
    for line in md.lines() {
        if line.starts_with("```") {
            if block == Block::Code {
                close(&mut out, &mut block);
            } else {
                close(&mut out, &mut block);
                out.push_str("<pre><code>");
                block = Block::Code;
            }
            continue;
        }
        if block == Block::Code {
            let _ = writeln!(out, "{}", escape(line));
            continue;
        }
        let trimmed = line.trim();
        if trimmed.starts_with('|') {
            if block != Block::Table {
                close(&mut out, &mut block);
                out.push_str("<pre>");
                block = Block::Table;
            }
            let _ = writeln!(out, "{}", escape(line));
            continue;
        }
        let level = line.chars().take_while(|c| *c == '#').count();
        let item = line
            .strip_prefix("- ")
            .map(|rest| ("ul", rest))
            .or_else(|| ordered_item(line).map(|rest| ("ol", rest)));
        if (1..=4).contains(&level) && line[level..].starts_with(' ') {
            close(&mut out, &mut block);
            let _ = writeln!(out, "<h{level}>{}</h{level}>", inline(line[level..].trim()));
        } else if let Some((tag, rest)) = item {
            if block == Block::List(tag) {
                out.push_str("</li>\n<li>");
            } else {
                close(&mut out, &mut block);
                let _ = write!(out, "<{tag}>\n<li>");
                block = Block::List(tag);
            }
            out.push_str(&inline(rest));
        } else if trimmed.is_empty() {
            close(&mut out, &mut block);
        } else {
            match block {
                Block::Paragraph | Block::List(_) => out.push(' '),
                _ => {
                    close(&mut out, &mut block);
                    out.push_str("<p>");
                    block = Block::Paragraph;
                }
            }
            out.push_str(&inline(trimmed));
        }
    }
    close(&mut out, &mut block);
    out
}

/// The text of a `1. item` line.
fn ordered_item(line: &str) -> Option<&str> {
    let digits = line.chars().take_while(char::is_ascii_digit).count();
    (digits > 0)
        .then(|| line[digits..].strip_prefix(". "))
        .flatten()
}

/// Escapes a line and turns `code` spans into `<code>`.
fn inline(text: &str) -> String {
    text.split('`')
        .enumerate()
        .map(|(i, part)| {
            if i % 2 == 1 {
                format!("<code>{}</code>", escape(part))
            } else {
                escape(part)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const IPHONE: &str =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 27_0 like Mac OS X) AppleWebKit/605.1.15";
    const PIXEL: &str = "Mozilla/5.0 (Linux; Android 17; Pixel 10) AppleWebKit/537.36 Chrome/142.0";

    fn page(user_agent: &str, pairing: Option<Status>) -> String {
        setup_page(&PageInput {
            proxy_host: "192.168.1.10".to_owned(),
            proxy_port: 8080,
            user_agent,
            pairing,
        })
    }

    #[test]
    fn detects_the_platform_and_device() {
        assert_eq!(Platform::from_user_agent(IPHONE), Platform::Ios);
        assert_eq!(Platform::from_user_agent(PIXEL), Platform::Android);
        assert_eq!(Platform::from_user_agent("curl/8.9"), Platform::Other);
        assert_eq!(device_name(IPHONE), "iPhone");
        assert_eq!(device_name(PIXEL), "Android");
        assert_eq!(device_name(""), "unknown device");
    }

    #[test]
    fn each_platform_sees_only_its_steps() {
        let ios = page(IPHONE, None);
        assert!(ios.contains("/ca.mobileconfig") && ios.contains("Certificate Trust Settings"));
        assert!(!ios.contains("debug-overrides"));
        let android = page(PIXEL, None);
        assert!(android.contains("/ca.crt") && android.contains("CA certificate"));
        assert!(android.contains("debug-overrides") && android.contains("ACCESS_LOCAL_NETWORK"));
        assert!(!android.contains("Certificate Trust Settings"));
        for page in [&ios, &android] {
            assert!(page.contains("192.168.1.10") && page.contains("8080"));
            assert!(page.contains("QUIC") && page.contains("/mobile-help"));
            assert!(!page.contains("id=\"pairing\""));
        }
        let other = page("", None);
        assert!(other.contains("/ca.crt") && other.contains("/ca.mobileconfig"));
    }

    #[test]
    fn the_page_shows_the_pairing_state_and_has_no_inline_script() {
        let waiting = page(IPHONE, Some(Status::Waiting));
        assert!(waiting.contains("data-status=\"waiting\""));
        assert!(waiting.contains("Waiting for approval on the computer"));
        assert!(waiting.contains("<script src=\"/setup.js\" defer></script>"));
        assert_eq!(waiting.matches("<script").count(), 1);
        assert!(!waiting.contains("onclick=") && !waiting.contains("onload="));
        assert!(page(IPHONE, Some(Status::Denied)).contains("refused"));
    }

    #[test]
    fn dynamic_text_is_escaped() {
        let hostile = setup_page(&PageInput {
            proxy_host: "<script>alert(1)</script>".to_owned(),
            proxy_port: 1,
            user_agent: "Android <img src=x onerror=alert(1)>",
            pairing: None,
        });
        assert!(!hostile.contains("<script>alert"));
        assert!(hostile.contains("&lt;script&gt;"));
        assert!(!hostile.contains("<img"));
        assert_eq!(escape("a\"b'c&"), "a&quot;b&#39;c&amp;");
    }

    #[test]
    fn renders_the_guide_markdown() {
        let html = markdown(
            "# Title\n\nSome `code` <here>.\nmore\n\n- one\n- two\n  cont\n\n1. first\n2. second\n\n\
             | a | b |\n|---|---|\n\n```\nadb <x>\n```\n",
        );
        assert!(html.contains("<h1>Title</h1>"));
        assert!(html.contains("<p>Some <code>code</code> &lt;here&gt;. more</p>"));
        assert!(html.contains("<ul>\n<li>one</li>\n<li>two cont</li></ul>"));
        assert!(html.contains("<ol>\n<li>first</li>\n<li>second</li></ol>"));
        assert!(html.contains("<pre>| a | b |\n|---|---|\n</pre>"));
        assert!(html.contains("<pre><code>adb &lt;x&gt;\n</code></pre>"));
        assert!(help_page().contains("<h1>"));
    }

    #[test]
    fn the_banner_shows_addresses_steps_and_approvals() {
        let (pairing, _notices) = Pairing::new(vec!["10.0.0.0/8".parse().expect("cidr")]);
        pairing.approve("192.168.1.23".parse().expect("ip"));
        let text = banner("192.168.1.10:8080".parse().expect("addr"), "QR\n", &pairing);
        assert!(text.contains("http://192.168.1.10:8080/"));
        assert!(text.contains("\n  Android  ") && text.contains("\n  iOS      "));
        assert!(text.contains("loopback, 10.0.0.0/8, 192.168.1.23 (device)"));
        assert!(text.contains("QR\n"));
    }

    #[test]
    fn answers_and_hints() {
        assert!(approves("y") && approves(" YES "));
        assert!(!approves("") && !approves("n") && !approves("yep"));
        let ip: IpAddr = "192.168.1.23".parse().expect("ip");
        let tls = tls_hint(ip, "api.example.com:443", "received fatal alert: UnknownCA");
        assert!(tls.contains("not trusted") && tls.contains("pins"));
        let silent = silent_hint(ip, "Android", "192.168.1.10:8080".parse().expect("addr"));
        assert!(silent.contains("ACCESS_LOCAL_NETWORK") && silent.contains("QUIC"));
    }

    #[tokio::test]
    async fn a_non_interactive_console_denies_every_request() {
        let (pairing, notices) = Pairing::new(Vec::new());
        let (bus, events) = broadcast::channel(4);
        let phone: IpAddr = "192.168.1.23".parse().expect("ip");
        let task = tokio::spawn(console(
            pairing.clone(),
            notices,
            events,
            None,
            "127.0.0.1:8080".parse().expect("addr"),
        ));
        assert_eq!(
            pairing.ask(phone, "iPhone", Instant::now()),
            Status::Waiting
        );
        wait_for(&pairing, phone, Status::Denied).await;
        drop(bus);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    #[tokio::test]
    async fn typing_y_approves_and_r_revokes() {
        let (pairing, notices) = Pairing::new(Vec::new());
        let (_bus, events) = broadcast::channel(4);
        let (keys, lines) = mpsc::unbounded_channel();
        let phone: IpAddr = "192.168.1.23".parse().expect("ip");
        let task = tokio::spawn(console(
            pairing.clone(),
            notices,
            events,
            Some(lines),
            "127.0.0.1:8080".parse().expect("addr"),
        ));
        assert_eq!(
            pairing.ask(phone, "Android", Instant::now()),
            Status::Waiting
        );
        // The prompt and the key travel on different channels: a `y` that arrives before the
        // console has seen the prompt is ignored, so repeat it until the device is approved.
        // A `y` with no prompt pending does nothing.
        for _ in 0..200 {
            keys.send("y".to_owned()).expect("console running");
            tokio::time::sleep(Duration::from_millis(10)).await;
            if pairing.status(phone) == Status::Approved {
                break;
            }
        }
        wait_for(&pairing, phone, Status::Approved).await;
        keys.send("r".to_owned()).expect("console running");
        wait_for(&pairing, phone, Status::Denied).await;
        task.abort();
    }

    async fn wait_for(pairing: &Pairing, ip: IpAddr, want: Status) {
        for _ in 0..200 {
            if pairing.status(ip) == want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "{ip} never reached {want:?}; it is {:?}",
            pairing.status(ip)
        );
    }
}
