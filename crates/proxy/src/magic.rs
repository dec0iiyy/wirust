//! The magic host [`MAGIC_HOST`](crate::MAGIC_HOST): requests to it are answered by the
//! proxy itself, over plain HTTP or through CONNECT with a leaf from the CA. It serves the
//! CA to devices that are being set up, so they need no other way to fetch it.

use std::net::IpAddr;
use std::time::Instant;

use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderValue};
use http::{Method, Response, StatusCode};

use crate::pairing::Status;
use crate::proxy::State;
use crate::{mobile, mobileconfig};

/// Answers one request to the magic host, or an origin-form request to the proxy port:
/// `/` (the setup page for the device's platform), `/ca.pem`, `/ca.crt`,
/// `/ca.mobileconfig`, `/mobile-help`, `/pairing-status` and the page's script and style.
pub(crate) fn respond(
    state: &State,
    peer: IpAddr,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
) -> Response<Bytes> {
    if method != Method::GET && method != Method::HEAD {
        return reply(
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain; charset=utf-8",
            "GET only\n",
        );
    }
    let ca = state.ca();
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let pairing = state.pairing.as_ref().filter(|_| !peer.is_loopback());
    match path {
        "/" => {
            let status =
                pairing.map(|p| p.ask(peer, mobile::device_name(user_agent), Instant::now()));
            let (proxy_host, proxy_port) = proxy_address(state, headers);
            let page = mobile::setup_page(&mobile::PageInput {
                proxy_host,
                proxy_port,
                user_agent,
                pairing: status,
            });
            reply(StatusCode::OK, "text/html; charset=utf-8", page)
        }
        "/pairing-status" => {
            let status = pairing.map_or(Status::Approved, |p| p.status(peer));
            reply(
                StatusCode::OK,
                "text/plain; charset=utf-8",
                format!("{}\n", status.as_str()),
            )
        }
        "/setup.js" => reply(
            StatusCode::OK,
            "text/javascript; charset=utf-8",
            mobile::SETUP_JS,
        ),
        "/setup.css" => reply(StatusCode::OK, "text/css; charset=utf-8", mobile::SETUP_CSS),
        "/mobile-help" => reply(
            StatusCode::OK,
            "text/html; charset=utf-8",
            mobile::help_page(),
        ),
        "/ca.mobileconfig" => match ca.cert_der().and_then(|der| mobileconfig::profile(&der)) {
            Ok(profile) => {
                let mut response = reply(StatusCode::OK, mobileconfig::CONTENT_TYPE, profile);
                response.headers_mut().insert(
                    header::CONTENT_DISPOSITION,
                    HeaderValue::from_static("attachment; filename=\"ca.mobileconfig\""),
                );
                response
            }
            Err(e) => reply(
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain; charset=utf-8",
                format!("{e:#}\n"),
            ),
        },
        "/ca.pem" => reply(
            StatusCode::OK,
            "application/x-pem-file",
            ca.cert_pem().to_owned(),
        ),
        "/ca.crt" => match ca.cert_der() {
            Ok(der) => {
                let mut response = reply(StatusCode::OK, "application/x-x509-ca-cert", der);
                response.headers_mut().insert(
                    header::CONTENT_DISPOSITION,
                    HeaderValue::from_static("attachment; filename=\"ca.crt\""),
                );
                response
            }
            Err(e) => reply(
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain; charset=utf-8",
                format!("{e:#}\n"),
            ),
        },
        _ => reply(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            "not found\n",
        ),
    }
}

/// The proxy address a device should configure: the listening address, or, when that is
/// unspecified (`0.0.0.0`), the host the request named.
fn proxy_address(state: &State, headers: &HeaderMap) -> (String, u16) {
    let listen = state.listen;
    if !listen.ip().is_unspecified() {
        return (listen.ip().to_string(), listen.port());
    }
    let named = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .and_then(|host| host.parse::<http::uri::Authority>().ok())
        .filter(|authority| !authority.host().eq_ignore_ascii_case(crate::MAGIC_HOST));
    match named {
        Some(authority) => (authority.host().to_owned(), listen.port()),
        None => ("this computer's address".to_owned(), listen.port()),
    }
}

fn reply(
    status: StatusCode,
    content_type: &'static str,
    body: impl Into<Bytes>,
) -> Response<Bytes> {
    let mut response = Response::new(body.into());
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
             base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}
