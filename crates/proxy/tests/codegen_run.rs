//! Runs the generated Python, JavaScript and Swift against a local server and checks that the
//! server saw the method, target, headers and body of the captured request. A language whose
//! tool is missing is skipped with a note on stderr: `python3` needs the `requests` package
//! (point `WIRUST_TEST_PYTHON` at an interpreter that has it), `node` needs `fetch` (18+), and
//! `swiftc` stands for Swift.

mod codegen_cases;
mod common;

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use base64::Engine as _;
use codegen_cases::{Case, cases};
use common::{TestResult, temp_dir};
use wirust::codegen::{Lang, generate};

/// A request as the server read it.
#[derive(Debug)]
struct Seen {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Serves one connection at a time on loopback, answers `200 ok` and reports what it read.
fn serve() -> TestResult2<(SocketAddr, mpsc::Receiver<Seen>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let Some(seen) = read_request(&mut stream) else {
                continue;
            };
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
            if tx.send(seen).is_err() {
                break;
            }
        }
    });
    Ok((addr, rx))
}

type TestResult2<T> = anyhow::Result<T>;

fn read_request(stream: &mut std::net::TcpStream) -> Option<Seen> {
    let mut reader = BufReader::new(stream);
    let mut line = Vec::new();
    reader.read_until(b'\n', &mut line).ok()?;
    let start = String::from_utf8_lossy(&line).trim_end().to_owned();
    let mut parts = start.split(' ');
    let (method, target) = (parts.next()?.to_owned(), parts.next()?.to_owned());
    let mut headers = Vec::new();
    loop {
        line.clear();
        reader.read_until(b'\n', &mut line).ok()?;
        let text = String::from_utf8_lossy(&line).trim_end().to_owned();
        if text.is_empty() {
            break;
        }
        let (name, value) = text.split_once(':')?;
        headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
    }
    let length = headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    Some(Seen {
        method,
        target,
        headers,
        body,
    })
}

/// What the captured request carries that the generated code must reproduce: its headers
/// without those a library sets itself, and its body bytes.
fn expected(case: &Case) -> (Vec<(String, String)>, Vec<u8>) {
    let x = &case.exchange;
    let skipped = [
        ":authority",
        "host",
        "accept-encoding",
        "connection",
        "content-length",
        "content-encoding",
    ];
    let mut headers: Vec<(String, String)> = Vec::new();
    for (name, value) in &x.request_headers {
        if skipped.contains(&name.as_str()) {
            continue;
        }
        match headers.iter_mut().find(|(n, _)| n == name) {
            Some((_, joined)) => {
                joined.push_str(if name == "cookie" { "; " } else { ", " });
                joined.push_str(value);
            }
            None => headers.push((name.clone(), value.clone())),
        }
    }
    let body = &x.request_body;
    let bytes = if body.encoding == "base64" {
        base64::engine::general_purpose::STANDARD
            .decode(&body.data)
            .expect("valid base64")
    } else {
        body.data.clone().into_bytes()
    };
    (headers, bytes)
}

fn target(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    rest.find('/').map_or("/", |at| &rest[at..])
}

fn check(case: &Case, seen: &Seen, what: &str) {
    let (headers, body) = expected(case);
    assert_eq!(seen.method, case.exchange.method, "{what}: method");
    assert_eq!(seen.target, target(&case.exchange.url), "{what}: target");
    for (name, value) in headers {
        let got = seen
            .headers
            .iter()
            .find(|(n, _)| *n == name)
            .unwrap_or_else(|| panic!("{what}: the server saw no {name}; saw {:?}", seen.headers));
        assert_eq!(got.1, value, "{what}: header {name}");
    }
    assert_eq!(seen.body, body, "{what}: body");
}

/// Runs `command` and fails with its output unless it succeeds.
fn run(mut command: Command, what: &str) -> TestResult2<()> {
    let output = command.stdin(Stdio::null()).output()?;
    anyhow::ensure!(
        output.status.success(),
        "{what} failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn have(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Generates the code of `lang` for every case, runs each with `launch(script path, dir)` and
/// checks what the server saw.
fn exercise(
    lang: Lang,
    extension: &str,
    only: &[&str],
    launch: impl Fn(&Path, &Path) -> Command,
) -> TestResult {
    let (addr, seen) = serve()?;
    let dir = temp_dir();
    std::fs::create_dir_all(&dir)?;
    for case in cases(&format!("http://{addr}")) {
        if !only.is_empty() && !only.contains(&case.name) {
            continue;
        }
        let what = format!("{} / {}", lang.id(), case.name);
        let script = dir.join(format!("{}.{extension}", case.name));
        std::fs::write(&script, generate(lang, &case.exchange))?;
        run(launch(&script, &dir), &what)?;
        let request = seen.recv_timeout(Duration::from_secs(10))?;
        check(&case, &request, &what);
        eprintln!("ran {what}");
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn generated_python_sends_what_was_captured() -> TestResult {
    let python = std::env::var("WIRUST_TEST_PYTHON").unwrap_or_else(|_| "python3".to_owned());
    if !have(&python, &["-c", "import requests"]) {
        eprintln!("skipped: {python} with the requests package is not available");
        return Ok(());
    }
    exercise(Lang::Python, "py", &[], |script, _| {
        let mut command = Command::new(&python);
        command.arg("-I").arg(script);
        command
    })
}

#[test]
fn generated_javascript_sends_what_was_captured() -> TestResult {
    if !have(
        "node",
        &["-e", "if (typeof fetch !== 'function') process.exit(1)"],
    ) {
        eprintln!("skipped: node with fetch is not available");
        return Ok(());
    }
    exercise(Lang::Fetch, "js", &[], |script, _| {
        let mut command = Command::new("node");
        command.arg(script);
        command
    })
}

#[test]
fn generated_swift_sends_what_was_captured() -> TestResult {
    if !have("swiftc", &["--version"]) {
        eprintln!("skipped: swiftc is not available");
        return Ok(());
    }
    // Compiling takes seconds per snippet: a few cases that cover text, JSON and binary.
    let only = ["get", "post_json", "binary", "headers_quotes_unicode"];
    exercise(Lang::UrlSession, "swift", &only, |script, dir| {
        let program = script.with_extension("bin");
        let compiled = Command::new("swiftc")
            .arg("-o")
            .arg(&program)
            .arg(script)
            .current_dir(dir)
            .stdin(Stdio::null())
            .output()
            .expect("swiftc starts");
        assert!(
            compiled.status.success(),
            "swiftc failed: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        Command::new(program)
    })
}
