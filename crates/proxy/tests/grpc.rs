//! End to end: a gRPC-style h2 server that answers with framed messages and trailers, a
//! client that calls it through the proxy, and `GET /api/v1/flows/{id}/grpc` decoding both
//! directions with the status from the trailers.

mod common;

use std::collections::VecDeque;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use common::*;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body::{Body, Frame};
use http_body_util::{BodyExt as _, Full};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use wirust::Proxy;
use wirust::control::ControlPlane;
use wirust::flow::Exchange;

/// A body that yields fixed frames: data, then trailers.
struct Frames(VecDeque<Frame<Bytes>>);

impl Body for Frames {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.get_mut().0.pop_front().map(Ok))
    }
}

fn grpc_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0];
    out.extend_from_slice(&u32::try_from(payload.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// `HelloReply { message: "hi", count: 3 }`, then a second message `{ 1: "bye" }`.
async fn greeter(_: Request<hyper::body::Incoming>) -> Result<Response<Frames>, Infallible> {
    let mut data = grpc_frame(&[0x0a, 0x02, b'h', b'i', 0x10, 0x03]);
    data.extend(grpc_frame(&[0x0a, 0x03, b'b', b'y', b'e']));
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from_static("7"));
    trailers.insert("grpc-message", HeaderValue::from_static("not%20allowed"));
    let body = Frames(VecDeque::from([
        Frame::data(Bytes::from(data)),
        Frame::trailers(trailers),
    ]));
    let mut response = Response::new(body);
    response.headers_mut().insert(
        "content-type",
        HeaderValue::from_static("application/grpc+proto"),
    );
    Ok(response)
}

async fn grpc_server(certs: &UpstreamCerts) -> anyhow::Result<u16> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certs.leaf.clone()], certs.key.clone_key())?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), service_fn(greeter))
                    .await;
            });
        }
    });
    Ok(port)
}

async fn api_get(
    addr: std::net::SocketAddr,
    token: &str,
    path: &str,
) -> anyhow::Result<(StatusCode, Bytes)> {
    let tcp = TcpStream::connect(addr).await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
    tokio::spawn(connection);
    let request = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header("host", addr.to_string())
        .header("authorization", format!("Bearer {token}"))
        .body(Full::new(Bytes::new()))?;
    let response = sender.send_request(request).await?;
    let status = response.status();
    Ok((status, response.into_body().collect().await?.to_bytes()))
}

#[tokio::test]
async fn grpc_messages_and_trailers_are_decoded_through_the_api() -> TestResult {
    let certs = upstream_certs()?;
    let port = grpc_server(&certs).await?;
    let config = test_config(&certs.ca, 1 << 16)?;
    let dir = config.config_dir.clone();
    let mut proxy = Proxy::bind(config).await?;
    let control = ControlPlane::bind(
        "127.0.0.1:0".parse()?,
        wirust::RemoteAccess::LoopbackOnly,
        &mut proxy,
    )
    .await?;
    let (addr, token) = (control.local_addr(), control.token().to_owned());
    tokio::spawn(control.run());
    let mut running = spawn(proxy, dir);

    // The client: h2 through a CONNECT tunnel, one `HelloRequest { name: "world" }`.
    let ca = CertificateDer::from_pem_slice(running.ca_pem.as_bytes())?;
    let tls = tunnel(running.addr, port, &[ca], b"h2").await?;
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls)).await?;
    tokio::spawn(connection);
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "https://localhost:{port}/helloworld.Greeter/SayHello"
        ))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(Full::new(Bytes::from(grpc_frame(&[
            0x0a, 0x05, b'w', b'o', b'r', b'l', b'd',
        ]))))?;
    let response = sender.send_request(request).await?;
    let collected = response.into_body().collect().await?;
    let client_trailers = collected.trailers().cloned().unwrap_or_default();
    assert_eq!(
        client_trailers
            .get("grpc-status")
            .map(HeaderValue::as_bytes),
        Some(&b"7"[..]),
        "the client still gets the trailers"
    );

    let record: Exchange = next_exchange(&mut running.events).await?;
    assert!(
        record
            .response_trailers
            .contains(&("grpc-status".to_owned(), "7".to_owned())),
        "trailers in the record: {:?}",
        record.response_trailers
    );

    // The store applies bus events on its own task: wait until it holds the finished flow.
    let path = format!("/api/v1/flows/{}/grpc", record.id);
    let (status, body) = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let answer = api_get(addr, &token, &path).await?;
            if answer.0 == StatusCode::OK {
                return anyhow::Ok(answer);
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    assert_eq!(status, StatusCode::OK);
    let call: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(call["kind"], "grpc");
    assert_eq!(call["service"], "helloworld.Greeter");
    assert_eq!(call["method"], "SayHello");
    assert_eq!(call["status"], 7);
    assert_eq!(call["status_name"], "PERMISSION_DENIED");
    assert_eq!(call["message"], "not allowed");
    assert_eq!(call["truncated"], false);
    let name = &call["request"]["messages"][0]["decoded"]["fields"][0];
    assert_eq!(
        (&name["type"], &name["value"]),
        (&"string".into(), &"world".into())
    );
    let replies = call["response"]["messages"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(replies.len(), 2);
    let count = &replies[0]["decoded"]["fields"][1];
    assert_eq!(
        (&count["field"], &count["wire"], &count["value"]),
        (&2.into(), &"varint".into(), &"3".into())
    );
    assert_eq!(replies[1]["decoded"]["fields"][0]["value"], "bye");
    Ok(())
}
