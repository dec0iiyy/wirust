//! An HTTPS debugging proxy: it decrypts TLS with a local certificate authority, forwards
//! every request upstream and reports each exchange on an event bus.
//!
//! [`Proxy::bind`] opens the listener, [`Proxy::run`] serves it. Each exchange publishes
//! [`events::FlowEvent`]s, which the [`events::FlowStore`] keeps; the
//! [`intercept::Interceptors`] chain can change or answer requests; the optional
//! [`control::ControlPlane`] serves the API and web UI. The CA lives in [`ca::Ca`]; the
//! first TLS record of each tunnel is read by [`hello`] so the client's ClientHello can be
//! fingerprinted before the handshake. `docs/architecture.md` maps the modules.

pub mod adb;
pub mod body;
pub mod ca;
pub mod certs;
mod clock;
pub mod control;
pub mod curl;
pub mod decode;
pub mod events;
pub mod flow;
pub mod grpc;
mod grpc_api;
pub mod har;
mod har_api;
pub mod hello;
pub mod intercept;
mod magic;
pub mod mobile;
pub mod mobileconfig;
pub mod oscmd;
pub mod pairing;
pub mod passthrough;
pub mod protobuf;
mod proxy;
pub mod qr;
pub mod query;
pub mod replay;
mod replay_api;
pub mod rules;
mod rules_api;
pub mod schema;
pub mod session;
pub mod sysproxy;
pub mod throttle;
pub mod trust;
mod upstream;
pub mod upstream_proxy;
pub mod ws;
mod ws_api;

pub use proxy::{Config, Proxy, RemoteAccess, UpstreamTls, check_listen};

/// The program name. Config directories and certificate names derive from it, so a rename
/// changes this constant, the Cargo package and binary names, and the README title.
pub const NAME: &str = "wirust";

/// The host name the proxy answers itself (CA download and setup page) instead of
/// forwarding. Not a real domain, so it never reaches the internet.
pub const MAGIC_HOST: &str = "wirust.test";

/// Default number of body bytes kept per request and per response for the log.
pub const DEFAULT_BODY_LIMIT: usize = 1024 * 1024;
