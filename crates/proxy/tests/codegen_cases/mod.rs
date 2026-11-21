//! The captured requests the code generators are tested with, shared by the golden-file test
//! (`codegen.rs`) and the test that runs the generated code (`codegen_run.rs`).

#![allow(
    dead_code,
    reason = "each test crate uses a different part of the cases"
)]

use serde_json::{Value, json};
use wirust::flow::Exchange;

/// One captured request: a name for the golden files and the exchange.
pub struct Case {
    pub name: &'static str,
    pub exchange: Exchange,
}

/// The authority of an origin such as `https://api.test`.
fn authority(origin: &str) -> &str {
    origin.split_once("://").map_or(origin, |(_, rest)| rest)
}

fn text(data: &str) -> Value {
    json!({ "size": data.len(), "truncated": false, "encoding": "utf8", "data": data })
}

fn exchange(method: &str, url: &str, headers: &[(&str, &str)], body: Value) -> Exchange {
    let mut record = json!({
        "id": 1, "time": "2026-01-02T03:04:05Z", "client": "127.0.0.1:1", "method": method,
        "url": url, "client_version": "h2", "upstream_version": "h2",
        "status": 200, "reason": "OK", "request_headers": headers,
        "response_headers": [], "response_body": null,
        "timing": {"total_ms": 1.0}, "tls": null, "error": null,
    });
    record["request_body"] = body;
    serde_json::from_value(record).expect("a valid exchange")
}

/// The cases, with every URL under `origin`.
#[expect(clippy::too_many_lines, reason = "one entry per case")]
pub fn cases(origin: &str) -> Vec<Case> {
    let host = authority(origin);
    let url = |path: &str| format!("{origin}{path}");
    let common = |extra: &[(&'static str, &'static str)]| -> Vec<(&str, &str)> {
        let mut headers = vec![
            (":authority", host),
            ("host", host),
            ("accept-encoding", "gzip, br"),
            ("connection", "keep-alive"),
            ("user-agent", "wirust-test/1.0"),
        ];
        headers.extend_from_slice(extra);
        headers
    };
    let pretty = "{\n  \"name\": \"Zo\u{eb}\",\n  \"tags\": [\"a\", \"b\"],\n  \"nested\": {\n    \"ok\": true\n  }\n}";
    vec![
        Case {
            name: "get",
            exchange: exchange(
                "GET",
                &url("/users/42"),
                &common(&[("accept", "application/json")]),
                text(""),
            ),
        },
        Case {
            name: "post_json",
            exchange: exchange(
                "POST",
                &url("/items"),
                &common(&[
                    ("content-type", "application/json"),
                    ("content-length", "44"),
                ]),
                text(r#"{"user":"zoe","price":"$5","say":"a \"b\"\n"}"#),
            ),
        },
        Case {
            name: "post_json_pretty",
            exchange: exchange(
                "PUT",
                &url("/items/7"),
                &common(&[("content-type", "application/json")]),
                text(pretty),
            ),
        },
        Case {
            name: "form",
            exchange: exchange(
                "POST",
                &url("/login"),
                &common(&[
                    ("content-type", "application/x-www-form-urlencoded"),
                    ("content-length", "28"),
                ]),
                text("a=1&b=hello+world&c=%7B%7D"),
            ),
        },
        Case {
            name: "binary",
            exchange: exchange(
                "PUT",
                &url("/blob"),
                &common(&[("content-type", "application/octet-stream")]),
                json!({ "size": 5, "truncated": false, "encoding": "base64", "data": "/wBhAP8=" }),
            ),
        },
        Case {
            name: "headers_quotes_unicode",
            exchange: exchange(
                "GET",
                &url("/h"),
                &common(&[
                    ("x-quote", "say \"hi\" it's"),
                    ("x-name", "Zo\u{eb} \u{f1} \u{65e5}\u{672c}"),
                    ("x-back", r"C:\dir\new"),
                    ("x-dollar", "$HOME ${x} `id`"),
                    ("cookie", "a=1"),
                    ("cookie", "b=2"),
                ]),
                text(""),
            ),
        },
        Case {
            name: "query_empty_body",
            exchange: exchange(
                "POST",
                &url("/search?q=a%20b&x=1&y=%7B%7D"),
                &common(&[("content-length", "0")]),
                text(""),
            ),
        },
        Case {
            name: "gzip_body_decoded",
            exchange: exchange(
                "POST",
                &url("/upload"),
                &common(&[
                    ("content-type", "text/plain; charset=utf-8"),
                    ("content-encoding", "gzip"),
                    ("content-length", "40"),
                ]),
                json!({
                    "size": 12, "truncated": false, "encoding": "utf8", "data": "caf\u{e9}\ttab\nok",
                    "content_encoding": {"codings": ["gzip"], "wire_size": 40, "decoded": true},
                }),
            ),
        },
    ]
}
