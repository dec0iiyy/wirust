//! Rebuilds a recorded request as a cURL command line that is safe to paste into `sh`.
//!
//! Every argument that is not plain is single-quoted (a `'` inside becomes `'\''`), so
//! `$`, backticks, newlines and non-ASCII text reach cURL unchanged. Bodies that cURL would
//! misread as an argument (binary data, text starting with `@`) are piped in on stdin.

use std::fmt::Write as _;

use crate::flow::Exchange;

/// Request headers cURL must not repeat: hop-by-hop headers and those it computes itself.
pub(crate) const SKIPPED: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "content-length",
];

/// How the body reaches cURL when it cannot be an argument.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Input {
    /// Text, sent with `printf '%s'`.
    Text(String),
    /// Base64, decoded with `base64 -d`.
    Base64(String),
}

/// The pieces of the command before quoting.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Plan {
    note: Option<String>,
    input: Option<Input>,
    args: Vec<String>,
}

/// The cURL command for `exchange`, possibly over several lines joined with `\`.
#[must_use]
pub fn command(exchange: &Exchange) -> String {
    render(&plan(exchange), "curl")
}

fn plan(x: &Exchange) -> Plan {
    let mut args = Vec::new();
    match x.client_version.as_str() {
        "h2" => args.push("--http2".to_owned()),
        "http/1.1" => args.push("--http1.1".to_owned()),
        "http/1.0" => args.push("--http1.0".to_owned()),
        _ => {}
    }
    let body = &x.request_body;
    let has_body = !body.data.is_empty();
    match x.method.as_str() {
        "HEAD" => args.push("--head".to_owned()),
        "GET" if !has_body => {}
        "POST" if has_body => {}
        method => args.extend(["-X".to_owned(), method.to_owned()]),
    }
    let authority = x.url.split_once("://").map_or("", |(_, rest)| {
        rest.split(['/', '?', '#']).next().unwrap_or_default()
    });
    let mut compressed = false;
    for (name, value) in &x.request_headers {
        let lower = name.to_ascii_lowercase();
        if lower.starts_with(':') || SKIPPED.contains(&lower.as_str()) {
            continue;
        }
        // The stored body is decoded, so the command sends it as identity.
        if lower == "content-encoding" && body.is_decoded() {
            continue;
        }
        if lower == "accept-encoding" {
            compressed = true;
            continue;
        }
        if lower == "host" && value.eq_ignore_ascii_case(authority) {
            continue;
        }
        args.push("-H".to_owned());
        // cURL drops `Name:` with an empty value; `Name;` sends it empty.
        args.push(if value.is_empty() {
            format!("{name};")
        } else {
            format!("{name}: {value}")
        });
    }
    if compressed {
        args.push("--compressed".to_owned());
    }
    let mut input = None;
    if has_body {
        args.push("--data-binary".to_owned());
        if body.encoding == "base64" {
            input = Some(Input::Base64(body.data.clone()));
            args.push("@-".to_owned());
        } else if body.data.starts_with('@') {
            input = Some(Input::Text(body.data.clone()));
            args.push("@-".to_owned());
        } else {
            args.push(body.data.clone());
        }
    }
    if x.url.contains(['[', ']', '{', '}']) {
        args.push("--globoff".to_owned());
    }
    args.push(x.url.clone());
    let note = body.truncated.then(|| {
        format!(
            "# the request body was cut to its first part by the body limit; it had {} bytes",
            body.size
        )
    });
    Plan { note, input, args }
}

fn render(plan: &Plan, program: &str) -> String {
    let mut out = String::new();
    if let Some(note) = &plan.note {
        out.push_str(note);
        out.push('\n');
    }
    match &plan.input {
        Some(Input::Text(text)) => {
            let _ = write!(out, "printf '%s' {} | ", quote(text));
        }
        Some(Input::Base64(data)) => {
            let _ = write!(out, "printf '%s' {} | base64 -d | ", quote(data));
        }
        None => {}
    }
    out.push_str(program);
    let mut args = plan.args.iter().peekable();
    while let Some(arg) = args.next() {
        // Keep an option and its value on one line.
        let value = arg.starts_with('-')
            && arg != "--compressed"
            && arg != "--globoff"
            && !arg.starts_with("--http")
            && arg != "--head";
        out.push_str(" \\\n  ");
        out.push_str(&quote(arg));
        if value && let Some(next) = args.next() {
            out.push(' ');
            out.push_str(&quote(next));
        }
    }
    out
}

/// `text` as one `sh` word.
pub(crate) fn quote(text: &str) -> String {
    let plain = !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./:=@%+,".contains(&b));
    if plain {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', r"'\''"))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::process::Command;

    use super::*;
    use crate::flow::BodyRecord;
    use crate::query::tests::exchange;

    const NASTY: &str = "it's $HOME `id` $(id)\nline 2 \u{fc}n\u{ef}c\u{f6}d\u{e9} \\ \"q\" '' !*?";

    /// Runs the rendered command in `sh` with a stand-in that prints each argument followed
    /// by a NUL byte, then byte 1, then its stdin.
    fn run(plan: &Plan) -> (Vec<u8>, Vec<String>) {
        let script = format!(
            "f() {{ printf '%s\\0' \"$@\"; printf '\\001'; cat; }}\n{}",
            render(plan, "f")
        );
        let output = Command::new("sh")
            .arg("-c")
            .arg(&script)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("sh runs");
        assert!(output.status.success(), "{script}\n{output:?}");
        let split = output
            .stdout
            .iter()
            .position(|b| *b == 1)
            .expect("the marker byte");
        let (args, stdin) = output.stdout.split_at(split);
        let args = args
            .split(|b| *b == 0)
            .filter(|p| !p.is_empty())
            .map(|p| String::from_utf8(p.to_vec()).expect("utf-8 argument"))
            .collect();
        (stdin[1..].to_vec(), args)
    }

    #[test]
    fn nasty_text_round_trips_through_sh() {
        let mut x = exchange(1, "PUT", "https://a.test/p?q='x'&y=$z", 200);
        x.request_headers = vec![
            (":authority".to_owned(), "a.test".to_owned()),
            ("host".to_owned(), "a.test".to_owned()),
            ("connection".to_owned(), "keep-alive".to_owned()),
            ("accept-encoding".to_owned(), "gzip, br".to_owned()),
            ("x-nasty".to_owned(), NASTY.to_owned()),
            ("x-empty".to_owned(), String::new()),
            ("content-length".to_owned(), "99".to_owned()),
        ];
        x.request_body = BodyRecord {
            size: 99,
            truncated: false,
            encoding: "utf8",
            data: NASTY.to_owned(),
            content_encoding: None,
        };
        let plan = plan(&x);
        let (stdin, args) = run(&plan);
        assert_eq!(String::from_utf8_lossy(&stdin), "");
        assert_eq!(args, plan.args);
        assert_eq!(
            args,
            [
                "--http2",
                "-X",
                "PUT",
                "-H",
                &format!("x-nasty: {NASTY}"),
                "-H",
                "x-empty;",
                "--compressed",
                "--data-binary",
                NASTY,
                "https://a.test/p?q='x'&y=$z",
            ]
        );
        assert!(command(&x).starts_with("curl \\\n  --http2"));
    }

    #[test]
    fn binary_and_at_sign_bodies_go_through_stdin() {
        let mut x = exchange(2, "POST", "http://a.test/[1]", 200);
        x.client_version = "http/1.1".to_owned();
        x.request_headers.clear();
        x.request_body = BodyRecord {
            size: 10,
            truncated: true,
            encoding: "base64",
            data: "/wBh".to_owned(), // ff 00 61
            content_encoding: None,
        };
        let plan = plan(&x);
        let (stdin, args) = run(&plan);
        assert_eq!(stdin, [0xff, 0x00, b'a']);
        assert_eq!(
            args,
            [
                "--http1.1",
                "--data-binary",
                "@-",
                "--globoff",
                "http://a.test/[1]"
            ]
        );
        assert!(render(&plan, "curl").starts_with("# the request body was cut"));
        x.request_body = BodyRecord {
            size: 6,
            truncated: false,
            encoding: "utf8",
            data: "@/etc/passwd 'x'".to_owned(),
            content_encoding: None,
        };
        let (stdin, args) = run(&super::plan(&x));
        assert_eq!(stdin, b"@/etc/passwd 'x'");
        assert_eq!(args[1..3], ["--data-binary", "@-"]);
    }

    #[test]
    fn get_and_head_need_no_method_flag() {
        let x = exchange(3, "GET", "https://a.test/", 200);
        assert!(!plan(&x).args.contains(&"-X".to_owned()));
        let x = exchange(3, "HEAD", "https://a.test/", 200);
        assert!(plan(&x).args.contains(&"--head".to_owned()));
    }
}
