//! Content-Encoding through the real proxy: the client gets the wire bytes unchanged, the
//! flow holds the decoded body, and search and HAR see the decoded text.

mod common;

use std::io::Write as _;
use std::sync::Arc;

use bytes::Bytes;
use common::{TestResult, next_bus_event, start_proxy, upstream_certs};
use http::{Request, Response};
use http_body_util::{BodyExt as _, Full};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use wirust::events::Flow;
use wirust::flow::{Event, Exchange};
use wirust::query::Query;

const TEXT: &str = "<html><body>a decoded page, a decoded page, a decoded page</body></html>";

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).expect("write to Vec");
    encoder.finish().expect("finish to Vec")
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).expect("write to Vec");
    encoder.finish().expect("finish to Vec")
}

fn brotli(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut writer = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
    writer.write_all(data).expect("write to Vec");
    drop(writer);
    out
}

fn zstd(data: &[u8]) -> Vec<u8> {
    ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)
}

/// Long text whose compressed form is far over a small body limit.
fn long_text() -> Vec<u8> {
    (0..40_000_u32)
        .flat_map(|i| format!("{i},").into_bytes())
        .collect()
}

/// The body and `Content-Encoding` served at `path`.
fn served(path: &str) -> (Vec<u8>, &'static str) {
    match path {
        "/gzip" => (gzip(TEXT.as_bytes()), "gzip"),
        "/x-gzip" => (gzip(TEXT.as_bytes()), "x-gzip"),
        "/deflate" => (zlib(TEXT.as_bytes()), "deflate"),
        "/br" => (brotli(TEXT.as_bytes()), "br"),
        "/zstd" => (zstd(TEXT.as_bytes()), "zstd"),
        "/identity" => (TEXT.as_bytes().to_vec(), "identity"),
        "/stacked" => (brotli(&gzip(TEXT.as_bytes())), "gzip, br"),
        "/unknown" => (TEXT.as_bytes().to_vec(), "compress"),
        "/bad" => (b"\x1f\x8b\x08\x00garbage".to_vec(), "gzip"),
        "/bomb" => (gzip(&vec![0; 8 << 20]), "gzip"),
        "/cut" => (gzip(&long_text()), "gzip"),
        _ => (Vec::new(), "identity"),
    }
}

async fn encoding_server() -> anyhow::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let service = service_fn(|request: Request<hyper::body::Incoming>| async move {
                let (body, coding) = served(request.uri().path());
                Response::builder()
                    .header("content-type", "text/html")
                    .header("content-encoding", coding)
                    .body(Full::new(Bytes::from(body)))
            });
            tokio::spawn(
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), service),
            );
        }
    });
    Ok(port)
}

/// Fetches `path` through the proxy; returns what the client received and the flow.
async fn fetch(
    proxy: &mut common::Running,
    port: u16,
    path: &str,
) -> anyhow::Result<(Bytes, Option<String>, Arc<Flow>)> {
    let tcp = TcpStream::connect(proxy.addr).await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(connection);
    let request = Request::get(format!("http://127.0.0.1:{port}{path}"))
        .header("host", format!("127.0.0.1:{port}"))
        .header("accept-encoding", "gzip, deflate, br, zstd")
        .body(Full::new(Bytes::new()))?;
    let response = sender.send_request(request).await?;
    let coding = response
        .headers()
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = response.into_body().collect().await?.to_bytes();
    loop {
        if let Some(flow) = next_bus_event(&mut proxy.events).await?.flow() {
            return Ok((body, coding, Arc::clone(flow)));
        }
    }
}

fn exchange(flow: &Flow) -> &Exchange {
    match &flow.record {
        Event::Exchange(x) => x,
        other => panic!("expected an exchange, got {other}"),
    }
}

#[tokio::test]
async fn every_coding_is_decoded_in_the_flow_and_untouched_on_the_wire() -> TestResult {
    let certs = upstream_certs()?;
    let port = encoding_server().await?;
    let mut proxy = start_proxy(&certs.ca, 64 * 1024).await?;
    for (path, codings) in [
        ("/gzip", vec!["gzip"]),
        ("/x-gzip", vec!["x-gzip"]),
        ("/deflate", vec!["deflate"]),
        ("/br", vec!["br"]),
        ("/zstd", vec!["zstd"]),
        ("/stacked", vec!["gzip", "br"]),
    ] {
        let (wire, _) = served(path);
        let (received, coding, flow) = fetch(&mut proxy, port, path).await?;
        assert_eq!(
            &received[..],
            &wire[..],
            "{path}: the client gets the wire bytes"
        );
        assert!(
            coding.is_some(),
            "{path}: content-encoding reaches the client"
        );
        let body = exchange(&flow)
            .response_body
            .clone()
            .expect("response body");
        assert_eq!(body.data, TEXT, "{path}");
        assert_eq!(body.size, TEXT.len() as u64, "{path}");
        assert!(!body.truncated, "{path}");
        let meta = body.content_encoding.clone().expect("metadata");
        assert!(meta.decoded, "{path}");
        assert_eq!(meta.codings, codings, "{path}");
        assert_eq!(meta.wire_size, wire.len() as u64, "{path}");

        // The flow API serialises the same record.
        let json = serde_json::to_value(exchange(&flow))?;
        assert_eq!(json["response_body"]["data"], TEXT, "{path}");
        assert_eq!(
            json["response_body"]["content_encoding"]["decoded"], true,
            "{path}"
        );

        // Body search sees the decoded text.
        assert!(
            Query::parse("body:\"decoded page\"")?.matches_flow(&flow),
            "{path}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn identity_unknown_and_malformed_bodies_stay_as_sent() -> TestResult {
    let certs = upstream_certs()?;
    let port = encoding_server().await?;
    let mut proxy = start_proxy(&certs.ca, 64 * 1024).await?;

    let (_, _, flow) = fetch(&mut proxy, port, "/identity").await?;
    let body = exchange(&flow).response_body.clone().expect("body");
    assert_eq!(body.data, TEXT);
    assert_eq!(body.content_encoding, None);

    let (_, _, flow) = fetch(&mut proxy, port, "/unknown").await?;
    let body = exchange(&flow).response_body.clone().expect("body");
    assert_eq!(body.data, TEXT);
    let meta = body.content_encoding.expect("metadata");
    assert!(!meta.decoded);
    assert!(meta.reason.expect("reason").contains("compress"));

    let (wire, _) = served("/bad");
    let (received, _, flow) = fetch(&mut proxy, port, "/bad").await?;
    assert_eq!(&received[..], &wire[..]);
    let body = exchange(&flow).response_body.clone().expect("body");
    assert_eq!(body.size, wire.len() as u64, "the wire bytes are kept");
    let meta = body.content_encoding.expect("metadata");
    assert!(!meta.decoded);
    assert!(meta.reason.is_some());
    Ok(())
}

#[tokio::test]
async fn bombs_and_cut_streams_stop_at_the_body_limit() -> TestResult {
    let certs = upstream_certs()?;
    let port = encoding_server().await?;
    let limit = 4096;
    let mut proxy = start_proxy(&certs.ca, limit).await?;

    let (wire, _) = served("/bomb");
    let (received, _, flow) = fetch(&mut proxy, port, "/bomb").await?;
    assert_eq!(
        &received[..],
        &wire[..],
        "the bomb reaches the client untouched"
    );
    let body = exchange(&flow).response_body.clone().expect("body");
    assert!(body.truncated);
    assert!(body.size <= limit as u64);
    assert!(body.content_encoding.expect("metadata").decoded);

    let (wire, _) = served("/cut");
    assert!(wire.len() > limit, "the compressed body is over the limit");
    let (received, _, flow) = fetch(&mut proxy, port, "/cut").await?;
    assert_eq!(&received[..], &wire[..]);
    let body = exchange(&flow).response_body.clone().expect("body");
    assert!(body.truncated);
    assert!(!body.data.is_empty(), "the kept start decodes");
    assert!(long_text().starts_with(body.data.as_bytes()));
    let meta = body.content_encoding.expect("metadata");
    assert!(meta.decoded);
    assert_eq!(meta.wire_size, wire.len() as u64);
    Ok(())
}

#[tokio::test]
async fn har_export_writes_decoded_text_and_imports_back() -> TestResult {
    let certs = upstream_certs()?;
    let port = encoding_server().await?;
    let mut proxy = start_proxy(&certs.ca, 64 * 1024).await?;
    let (wire, _) = served("/br");
    let (_, _, flow) = fetch(&mut proxy, port, "/br").await?;

    let har = serde_json::to_value(wirust::har::to_har([flow.as_ref()]))?;
    let response = &har["log"]["entries"][0]["response"];
    assert_eq!(response["content"]["text"], TEXT);
    assert_eq!(response["content"]["size"], TEXT.len());
    let saved = i64::try_from(TEXT.len())? - i64::try_from(wire.len())?;
    assert_eq!(response["content"]["compression"], saved);
    assert_eq!(response["bodySize"], wire.len());
    let headers = response["headers"].as_array().expect("headers");
    assert!(
        headers
            .iter()
            .any(|h| h["name"] == "content-encoding" && h["value"] == "br")
    );

    let imported = wirust::har::from_har(&serde_json::to_vec(&har)?)?;
    let body = exchange(&imported[0]).response_body.clone().expect("body");
    assert_eq!(body.data, TEXT);
    let meta = body.content_encoding.expect("metadata");
    assert!(meta.decoded);
    assert_eq!(meta.wire_size, wire.len() as u64);
    Ok(())
}

#[test]
fn sessions_without_decoding_metadata_still_load() -> TestResult {
    let old = r#"{"size":3,"truncated":false,"encoding":"utf8","data":"abc"}"#;
    let body: wirust::flow::BodyRecord = serde_json::from_str(old)?;
    assert_eq!(body.data, "abc");
    assert_eq!(body.content_encoding, None);
    assert!(!serde_json::to_string(&body)?.contains("content_encoding"));
    Ok(())
}
