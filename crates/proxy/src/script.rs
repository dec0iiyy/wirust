//! Scripting: `--script FILE` runs sandboxed [Rhai](https://rhai.rs) hooks on each exchange.
//!
//! A script defines `on_request(req)` and/or `on_response(req, resp)`. Each file becomes one
//! [`Interceptor`] in the chain; [`Scripts::interceptors`] returns them in file order. The
//! engine has no file, network, process, `eval` or module access, and every call runs under
//! limits on operations, call depth, data sizes and wall-clock time. A script that fails is
//! skipped for that exchange (fail open): the error is logged once per distinct message and
//! the flow gets the `script_error` flag. Files are reloaded when they change; a broken file
//! keeps the previous working version. `docs/scripting.md` documents the API.

use std::cell::RefCell;
use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use base64::Engine as _;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode};
use rhai::{AST, Blob, CallFnOptions, Dynamic, Engine, EvalAltResult, ImmutableString, Map, Scope};
use serde::Serialize;

use crate::flow::Flag;
use crate::intercept::{Action, ClientInfo, Interceptor, RequestCtx, ResponseCtx, plain};
use crate::rules::file_name;

/// Most operations one hook call may run.
pub const MAX_OPERATIONS: u64 = 1_000_000;

/// Longest one hook call (or the top level of a file at load) may run.
pub const CALL_TIMEOUT: Duration = Duration::from_millis(250);

/// Deepest function call nesting.
pub const MAX_CALL_LEVELS: usize = 32;

/// Smallest string limit; the limit is twice the body limit when that is larger.
const MIN_STRING_SIZE: usize = 4 << 20;

/// Smallest array and blob limit (elements); the body limit when that is larger.
const MIN_ARRAY_SIZE: usize = 1 << 20;

/// Most entries in one object map.
const MAX_MAP_SIZE: usize = 100_000;

/// Most entries the log ring keeps.
const LOG_CAPACITY: usize = 500;

/// Most `log()` lines one call keeps; longer lines are cut to [`MAX_LOG_LINE`] bytes.
const MAX_LOGS_PER_CALL: usize = 100;

/// Longest kept log line, in bytes.
const MAX_LOG_LINE: usize = 4096;

/// Longest name `flag()` accepts.
const MAX_FLAG_NAME: usize = 64;

/// Distinct error messages remembered per file to log each only once.
const MAX_SEEN_ERRORS: usize = 1000;

/// Most decoded bytes a script sees of a body; a body that decodes to more is not shown.
const SCRIPT_DECODE_LIMIT: usize = 64 << 20;

/// Largest compiled program of one regex used by the regex helpers.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// Longest delay one hook call may ask for.
const MAX_DELAY: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------------------
// Per-call state: what the helpers asked for. Hooks run synchronously on one thread.
// ---------------------------------------------------------------------------------------

#[derive(Default)]
struct CallState {
    deadline: Option<Instant>,
    respond: Option<Response<Bytes>>,
    delay: Duration,
    logs: Vec<String>,
    flags: Vec<String>,
}

thread_local! {
    static CALL: RefCell<CallState> = RefCell::new(CallState::default());
}

/// Starts a call with a fresh state and a deadline.
fn begin_call() {
    CALL.with_borrow_mut(|call| {
        *call = CallState {
            deadline: Some(Instant::now() + CALL_TIMEOUT),
            ..CallState::default()
        };
    });
}

/// Ends a call and returns what the helpers asked for.
fn end_call() -> CallState {
    CALL.with_borrow_mut(std::mem::take)
}

fn push_log(text: &str) {
    let mut line = text.to_owned();
    if line.len() > MAX_LOG_LINE {
        let mut end = MAX_LOG_LINE;
        while !line.is_char_boundary(end) {
            end -= 1;
        }
        line.truncate(end);
    }
    CALL.with_borrow_mut(|call| {
        if call.logs.len() < MAX_LOGS_PER_CALL {
            call.logs.push(line);
        }
    });
}

type Fallible<T> = Result<T, Box<EvalAltResult>>;

#[expect(
    clippy::unnecessary_box_returns,
    reason = "rhai's functions return their error boxed"
)]
fn script_error(message: impl Into<String>) -> Box<EvalAltResult> {
    message.into().into()
}

// ---------------------------------------------------------------------------------------
// The objects scripts see.
// ---------------------------------------------------------------------------------------

/// Message headers, shared with the request or response they belong to.
#[derive(Debug, Clone, Default)]
struct Headers(Arc<Mutex<HeaderMap>>);

impl Headers {
    fn new(map: HeaderMap) -> Self {
        Self(Arc::new(Mutex::new(map)))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HeaderMap> {
        self.0.lock().expect("script headers lock poisoned")
    }

    fn get(&mut self, name: &str) -> Dynamic {
        self.lock()
            .get(name.to_ascii_lowercase().as_str())
            .map_or(Dynamic::UNIT, |v| {
                String::from_utf8_lossy(v.as_bytes()).into_owned().into()
            })
    }

    fn has(&mut self, name: &str) -> bool {
        self.lock().contains_key(name.to_ascii_lowercase().as_str())
    }

    fn set(&mut self, name: &str, value: &str) -> Fallible<()> {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| script_error(format!("invalid header name {name:?}")))?;
        let value = HeaderValue::from_str(value)
            .map_err(|_| script_error(format!("invalid value for header {name}")))?;
        self.lock().insert(name, value);
        Ok(())
    }

    fn remove(&mut self, name: &str) {
        self.lock().remove(name.to_ascii_lowercase().as_str());
    }

    fn names(&mut self) -> rhai::Array {
        self.lock()
            .keys()
            .map(|name| Dynamic::from(name.as_str().to_owned()))
            .collect()
    }
}

/// A body as scripts see it: decoded, and whether the script replaced it.
#[derive(Debug, Clone, Default)]
struct Body {
    bytes: Option<Bytes>,
    changed: bool,
}

impl Body {
    /// The decoded form of `wire` sent with `headers`; `None` without a buffered body or
    /// when it cannot be decoded whole.
    fn of(wire: Option<&Bytes>, headers: &HeaderMap) -> Self {
        Self {
            bytes: wire.and_then(|wire| decoded(wire, headers)),
            changed: false,
        }
    }

    fn text(&self) -> String {
        self.bytes
            .as_deref()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default()
    }

    fn blob(&self) -> Blob {
        self.bytes
            .as_deref()
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
    }

    fn replace(&mut self, bytes: Vec<u8>) {
        self.bytes = Some(Bytes::from(bytes));
        self.changed = true;
    }

    /// Writes a changed body back: it goes on as identity, so `Content-Encoding` is removed
    /// (the proxy sets `Content-Length`).
    fn write_back(self, target: &mut Option<Bytes>, headers: &mut HeaderMap) {
        if self.changed {
            headers.remove(http::header::CONTENT_ENCODING);
            *target = self.bytes;
        }
    }
}

/// `wire` decoded by its `Content-Encoding`, as body rewrite rules do.
fn decoded(wire: &Bytes, headers: &HeaderMap) -> Option<Bytes> {
    let listed: Vec<(String, String)> = headers
        .get_all(http::header::CONTENT_ENCODING)
        .iter()
        .map(|v| {
            (
                "content-encoding".to_owned(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let codings = crate::decode::codings(&listed);
    if codings.is_empty() || wire.is_empty() {
        return Some(wire.clone());
    }
    let decoded = crate::decode::decode(wire, &codings, SCRIPT_DECODE_LIMIT, false).ok()?;
    decoded.cut.is_none().then(|| Bytes::from(decoded.data))
}

#[derive(Debug)]
struct RequestData {
    method: String,
    scheme: &'static str,
    host: String,
    port: u16,
    path: String,
    query: Option<String>,
    headers: Headers,
    body: Body,
    client: Map,
}

/// The request object (`req`). Clones share the same data.
#[derive(Debug, Clone)]
struct ScriptRequest(Arc<Mutex<RequestData>>);

impl ScriptRequest {
    fn of(ctx: &RequestCtx) -> Self {
        let (path, query) = match ctx.path.split_once('?') {
            Some((path, query)) => (path.to_owned(), Some(query.to_owned())),
            None => (ctx.path.clone(), None),
        };
        let mut client = Map::new();
        client.insert("address".into(), ctx.client.to_string().into());
        let info = ctx.extensions.get::<ClientInfo>();
        client.insert(
            "ja4".into(),
            info.map_or(Dynamic::UNIT, |i| i.ja4.clone().into()),
        );
        client.insert(
            "name".into(),
            info.and_then(|i| i.known_client.clone())
                .map_or(Dynamic::UNIT, Dynamic::from),
        );
        Self(Arc::new(Mutex::new(RequestData {
            method: ctx.method.to_string(),
            scheme: ctx.scheme,
            host: ctx.host.clone(),
            port: ctx.port,
            path,
            query,
            headers: Headers::new(ctx.headers.clone()),
            body: Body::of(ctx.body.as_ref(), &ctx.headers),
            client,
        })))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RequestData> {
        self.0.lock().expect("script request lock poisoned")
    }

    fn url(&mut self) -> String {
        let data = self.lock();
        let host = if data.host.contains(':') {
            format!("[{}]", data.host)
        } else {
            data.host.clone()
        };
        let default_port = if data.scheme == "https" { 443 } else { 80 };
        let authority = if data.port == default_port {
            host
        } else {
            format!("{host}:{}", data.port)
        };
        let query = data
            .query
            .as_ref()
            .map(|q| format!("?{q}"))
            .unwrap_or_default();
        format!("{}://{authority}{}{query}", data.scheme, data.path)
    }

    /// Writes the script's changes back to `ctx`.
    fn write_back(self, ctx: &mut RequestCtx) -> Fallible<()> {
        let data = self.lock();
        ctx.method = Method::from_bytes(data.method.as_bytes())
            .map_err(|_| script_error(format!("invalid method {:?}", data.method)))?;
        ctx.path = match &data.query {
            Some(query) => format!("{}?{query}", data.path),
            None => data.path.clone(),
        };
        if !ctx.path.starts_with('/') {
            return Err(script_error(format!(
                "path {:?} must start with /",
                ctx.path
            )));
        }
        ctx.headers = data.headers.lock().clone();
        data.body
            .clone()
            .write_back(&mut ctx.body, &mut ctx.headers);
        Ok(())
    }
}

#[derive(Debug)]
struct ResponseData {
    status: StatusCode,
    headers: Headers,
    body: Body,
}

/// The response object (`resp`). Clones share the same data.
#[derive(Debug, Clone)]
struct ScriptResponse(Arc<Mutex<ResponseData>>);

impl ScriptResponse {
    fn of(ctx: &ResponseCtx) -> Self {
        Self(Arc::new(Mutex::new(ResponseData {
            status: ctx.status,
            headers: Headers::new(ctx.headers.clone()),
            body: Body::of(ctx.body.as_ref(), &ctx.headers),
        })))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ResponseData> {
        self.0.lock().expect("script response lock poisoned")
    }

    fn write_back(self, ctx: &mut ResponseCtx) {
        let data = self.lock();
        ctx.status = data.status;
        ctx.headers = data.headers.lock().clone();
        data.body
            .clone()
            .write_back(&mut ctx.body, &mut ctx.headers);
    }
}

fn status_code(code: i64) -> Fallible<StatusCode> {
    u16::try_from(code)
        .ok()
        .and_then(|code| StatusCode::from_u16(code).ok())
        .ok_or_else(|| script_error(format!("invalid status {code}")))
}

/// Text or bytes for a body: a string, a blob, or anything else as its JSON text.
fn body_bytes(value: &Dynamic) -> Fallible<Vec<u8>> {
    if let Some(text) = value.read_lock::<ImmutableString>() {
        return Ok(text.as_bytes().to_vec());
    }
    if let Some(blob) = value.read_lock::<Blob>() {
        return Ok(blob.clone());
    }
    serde_json::to_vec(value).map_err(|e| script_error(format!("body: {e}")))
}

// ---------------------------------------------------------------------------------------
// The engine.
// ---------------------------------------------------------------------------------------

/// The sandboxed engine every script runs on.
fn engine(body_limit: usize) -> Engine {
    let mut engine = Engine::new();
    engine.set_max_operations(MAX_OPERATIONS);
    engine.set_max_call_levels(MAX_CALL_LEVELS);
    engine.set_max_expr_depths(64, 32);
    engine.set_max_string_size(MIN_STRING_SIZE.max(body_limit.saturating_mul(2)));
    engine.set_max_array_size(MIN_ARRAY_SIZE.max(body_limit));
    engine.set_max_map_size(MAX_MAP_SIZE);
    engine.disable_symbol("eval");
    engine.on_progress(|operations| {
        if operations % 256 != 0 {
            return None;
        }
        let late = CALL.with_borrow(|call| call.deadline.is_some_and(|d| Instant::now() > d));
        late.then(|| Dynamic::from("the call ran out of time".to_owned()))
    });
    engine.on_print(push_log);
    engine.on_debug(|text, _, _| push_log(text));
    register_headers(&mut engine);
    register_request(&mut engine);
    register_response(&mut engine);
    register_actions(&mut engine);
    register_helpers(&mut engine);
    engine
}

fn register_headers(engine: &mut Engine) {
    engine
        .register_type_with_name::<Headers>("Headers")
        .register_fn("get", Headers::get)
        .register_fn("has", Headers::has)
        .register_fn("set", Headers::set)
        .register_fn("remove", Headers::remove)
        .register_fn("names", Headers::names);
}

fn register_request(engine: &mut Engine) {
    engine
        .register_type_with_name::<ScriptRequest>("Request")
        .register_get_set(
            "method",
            |r: &mut ScriptRequest| r.lock().method.clone(),
            |r: &mut ScriptRequest, v: String| r.lock().method = v,
        )
        .register_get_set(
            "path",
            |r: &mut ScriptRequest| r.lock().path.clone(),
            |r: &mut ScriptRequest, v: String| r.lock().path = v,
        )
        .register_get_set(
            "query",
            |r: &mut ScriptRequest| r.lock().query.clone().unwrap_or_default(),
            |r: &mut ScriptRequest, v: String| {
                r.lock().query = (!v.is_empty()).then_some(v);
            },
        )
        .register_get("url", ScriptRequest::url)
        .register_get("host", |r: &mut ScriptRequest| r.lock().host.clone())
        .register_get("port", |r: &mut ScriptRequest| i64::from(r.lock().port))
        .register_get("scheme", |r: &mut ScriptRequest| r.lock().scheme.to_owned())
        .register_get("client", |r: &mut ScriptRequest| r.lock().client.clone())
        .register_get("headers", |r: &mut ScriptRequest| r.lock().headers.clone())
        .register_get("body", |r: &mut ScriptRequest| r.lock().body.text())
        .register_set(
            "body",
            |r: &mut ScriptRequest, v: Dynamic| -> Fallible<()> {
                let bytes = body_bytes(&v)?;
                r.lock().body.replace(bytes);
                Ok(())
            },
        )
        .register_get_set(
            "body_bytes",
            |r: &mut ScriptRequest| r.lock().body.blob(),
            |r: &mut ScriptRequest, v: Blob| r.lock().body.replace(v),
        )
        .register_get("has_body", |r: &mut ScriptRequest| {
            r.lock().body.bytes.is_some()
        });
}

fn register_response(engine: &mut Engine) {
    engine
        .register_type_with_name::<ScriptResponse>("Response")
        .register_get_set(
            "status",
            |r: &mut ScriptResponse| i64::from(r.lock().status.as_u16()),
            |r: &mut ScriptResponse, v: i64| -> Fallible<()> {
                r.lock().status = status_code(v)?;
                Ok(())
            },
        )
        .register_get("headers", |r: &mut ScriptResponse| r.lock().headers.clone())
        .register_get("body", |r: &mut ScriptResponse| r.lock().body.text())
        .register_set(
            "body",
            |r: &mut ScriptResponse, v: Dynamic| -> Fallible<()> {
                let bytes = body_bytes(&v)?;
                r.lock().body.replace(bytes);
                Ok(())
            },
        )
        .register_get_set(
            "body_bytes",
            |r: &mut ScriptResponse| r.lock().body.blob(),
            |r: &mut ScriptResponse, v: Blob| r.lock().body.replace(v),
        )
        .register_get("has_body", |r: &mut ScriptResponse| {
            r.lock().body.bytes.is_some()
        });
}

/// `respond`, `block`, `delay`, `log` and `flag`.
fn register_actions(engine: &mut Engine) {
    engine
        .register_fn(
            "respond",
            |status: i64, headers: Map, body: Dynamic| -> Fallible<()> {
                let mut response = Response::new(Bytes::from(body_bytes(&body)?));
                *response.status_mut() = status_code(status)?;
                for (name, value) in headers {
                    let name = HeaderName::from_bytes(name.as_bytes())
                        .map_err(|_| script_error(format!("invalid header name {name:?}")))?;
                    let value = HeaderValue::from_str(&value.to_string())
                        .map_err(|_| script_error(format!("invalid value for header {name}")))?;
                    response.headers_mut().append(name, value);
                }
                CALL.with_borrow_mut(|call| call.respond = Some(response));
                Ok(())
            },
        )
        .register_fn("block", |status: i64| -> Fallible<()> {
            let response = plain(status_code(status)?, "blocked by a script\n");
            CALL.with_borrow_mut(|call| call.respond = Some(response));
            Ok(())
        })
        .register_fn("delay", |ms: i64| -> Fallible<()> {
            let ms = u64::try_from(ms).map_err(|_| script_error("delay: negative time"))?;
            CALL.with_borrow_mut(|call| {
                call.delay = (call.delay + Duration::from_millis(ms)).min(MAX_DELAY);
            });
            Ok(())
        })
        .register_fn("log", |text: Dynamic| push_log(&text.to_string()))
        .register_fn("flag", |name: &str| -> Fallible<()> {
            let valid = !name.is_empty()
                && name.len() <= MAX_FLAG_NAME
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
            if !valid {
                return Err(script_error(format!(
                    "flag: {name:?} is not 1 to {MAX_FLAG_NAME} letters, digits, - _ ."
                )));
            }
            CALL.with_borrow_mut(|call| {
                if !call.flags.iter().any(|f| f == name) {
                    call.flags.push(name.to_owned());
                }
            });
            Ok(())
        });
}

fn regex(pattern: &str) -> Fallible<regex::Regex> {
    regex::RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| script_error(format!("regex: {e}")))
}

/// JSON, regex, base64 and time helpers.
fn register_helpers(engine: &mut Engine) {
    engine
        .register_fn("json_parse", |text: &str| -> Fallible<Dynamic> {
            serde_json::from_str::<Dynamic>(text)
                .map_err(|e| script_error(format!("json_parse: {e}")))
        })
        .register_fn("json_stringify", |value: Dynamic| -> Fallible<String> {
            serde_json::to_string(&value).map_err(|e| script_error(format!("json_stringify: {e}")))
        })
        .register_fn(
            "regex_match",
            |text: &str, pattern: &str| -> Fallible<bool> { Ok(regex(pattern)?.is_match(text)) },
        )
        .register_fn(
            "regex_replace",
            |text: &str, pattern: &str, with: &str| -> Fallible<String> {
                Ok(regex(pattern)?.replace_all(text, with).into_owned())
            },
        )
        .register_fn(
            "regex_captures",
            |text: &str, pattern: &str| -> Fallible<rhai::Array> {
                Ok(regex(pattern)?
                    .captures(text)
                    .map(|caps| {
                        caps.iter()
                            .map(|m| m.map_or(Dynamic::UNIT, |m| m.as_str().to_owned().into()))
                            .collect()
                    })
                    .unwrap_or_default())
            },
        )
        .register_fn("base64_encode", |text: &str| {
            base64::engine::general_purpose::STANDARD.encode(text)
        })
        .register_fn("base64_encode", |blob: Blob| {
            base64::engine::general_purpose::STANDARD.encode(blob)
        })
        .register_fn("base64_decode", |text: &str| -> Fallible<String> {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(text.trim())
                .map_err(|e| script_error(format!("base64_decode: {e}")))?;
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        })
        .register_fn("base64_decode_bytes", |text: &str| -> Fallible<Blob> {
            base64::engine::general_purpose::STANDARD
                .decode(text.trim())
                .map_err(|e| script_error(format!("base64_decode_bytes: {e}")))
        })
        .register_fn("now", || {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        });
}

// ---------------------------------------------------------------------------------------
// Files, reloads, the log.
// ---------------------------------------------------------------------------------------

/// One hook of a script, as `GET /api/v1/script` shows it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Hook {
    /// Whether the script defines it (`on_request(req)`, `on_response(req, resp)`).
    pub defined: bool,
    /// Whether `WANTS_BODY` asks for the body of this half of the exchange.
    pub body: bool,
}

/// One compiled script.
#[derive(Debug)]
struct Compiled {
    ast: AST,
    request: Hook,
    response: Hook,
}

/// One `--script` file.
#[derive(Debug)]
struct ScriptFile {
    path: PathBuf,
    name: String,
    compiled: RwLock<Arc<Compiled>>,
    state: Mutex<FileState>,
}

#[derive(Debug, Default)]
struct FileState {
    modified: Option<SystemTime>,
    error: Option<String>,
    seen_errors: HashSet<String>,
}

impl ScriptFile {
    fn current(&self) -> Arc<Compiled> {
        Arc::clone(&self.compiled.read().expect("script lock poisoned"))
    }

    fn state(&self) -> std::sync::MutexGuard<'_, FileState> {
        self.state.lock().expect("script state lock poisoned")
    }
}

/// One entry of the script log: a `log()` line or an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogEntry {
    /// Increasing number, for `?after=`.
    pub seq: u64,
    /// When, RFC 3339 UTC.
    pub time: String,
    /// The script's file name (never its directory).
    pub file: String,
    /// `log` or `error`.
    pub level: &'static str,
    /// The text.
    pub text: String,
}

#[derive(Debug, Default)]
struct LogRing {
    next: u64,
    entries: VecDeque<LogEntry>,
}

/// What `GET /api/v1/script` shows of one file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileReport {
    /// The file name, without its directory.
    pub file: String,
    /// Whether a working version is loaded.
    pub loaded: bool,
    /// `on_request`.
    pub request: Hook,
    /// `on_response`.
    pub response: Hook,
    /// The last load or run error.
    pub error: Option<String>,
}

#[derive(Debug)]
struct Inner {
    engine: Engine,
    files: Vec<ScriptFile>,
    log: Mutex<LogRing>,
}

/// The loaded scripts. Cloning is cheap; all clones share the same files and log.
#[derive(Debug, Clone)]
pub struct Scripts {
    inner: Arc<Inner>,
}

impl Scripts {
    /// Loads and compiles every file; `body_limit` sizes the string and array limits.
    ///
    /// # Errors
    ///
    /// Fails, naming the file (without its directory), when a file cannot be read, has a
    /// syntax error, or its top level fails.
    pub fn load(paths: &[PathBuf], body_limit: usize) -> anyhow::Result<Self> {
        let engine = engine(body_limit);
        let mut files = Vec::with_capacity(paths.len());
        for path in paths {
            let name = file_name(path);
            let modified = modified(path);
            let compiled = compile(&engine, path).map_err(|e| anyhow::anyhow!("{name}: {e}"))?;
            files.push(ScriptFile {
                path: path.clone(),
                name,
                compiled: RwLock::new(Arc::new(compiled)),
                state: Mutex::new(FileState {
                    modified,
                    ..FileState::default()
                }),
            });
        }
        Ok(Self {
            inner: Arc::new(Inner {
                engine,
                files,
                log: Mutex::default(),
            }),
        })
    }

    /// One chain stage per file, in file order.
    #[must_use]
    pub fn interceptors(&self) -> Vec<Arc<dyn Interceptor>> {
        (0..self.inner.files.len())
            .map(|index| {
                Arc::new(ScriptStage {
                    scripts: self.clone(),
                    index,
                    name: format!("script:{}", self.inner.files[index].name),
                }) as Arc<dyn Interceptor>
            })
            .collect()
    }

    /// What `GET /api/v1/script` shows.
    #[must_use]
    pub fn report(&self) -> Vec<FileReport> {
        self.inner
            .files
            .iter()
            .map(|file| {
                let compiled = file.current();
                FileReport {
                    file: file.name.clone(),
                    loaded: true,
                    request: compiled.request,
                    response: compiled.response,
                    error: file.state().error.clone(),
                }
            })
            .collect()
    }

    /// The log entries after `after` (0 for all kept), oldest first.
    ///
    /// # Panics
    ///
    /// When a thread panicked while holding the log (lock poisoning).
    #[must_use]
    pub fn log_after(&self, after: u64) -> Vec<LogEntry> {
        let ring = self.inner.log.lock().expect("script log lock poisoned");
        ring.entries
            .iter()
            .filter(|e| e.seq > after)
            .cloned()
            .collect()
    }

    /// Reloads every file whose modification time changed. A broken file keeps the previous
    /// version; the error goes to the report, the log and stderr. Returns how many files
    /// got a new version.
    ///
    /// # Panics
    ///
    /// When a thread panicked while holding a script's lock (lock poisoning).
    #[expect(
        clippy::must_use_candidate,
        reason = "the watcher calls it for the side effect"
    )]
    pub fn reload_if_changed(&self) -> usize {
        let mut reloaded = 0;
        for file in &self.inner.files {
            let modified = modified(&file.path);
            if modified == file.state().modified {
                continue;
            }
            let result = compile(&self.inner.engine, &file.path);
            let mut state = file.state();
            state.modified = modified;
            match result {
                Ok(compiled) => {
                    state.error = None;
                    state.seen_errors.clear();
                    drop(state);
                    *file.compiled.write().expect("script lock poisoned") = Arc::new(compiled);
                    self.push(&file.name, "log", "reloaded".to_owned());
                    reloaded += 1;
                }
                Err(e) => {
                    let text = format!("{e}; keeping the previous version");
                    eprintln!("{}: script {}: {text}", crate::NAME, file.name);
                    state.error = Some(text.clone());
                    drop(state);
                    self.push(&file.name, "error", text);
                }
            }
        }
        reloaded
    }

    /// Polls the files every `interval` and reloads changed ones. The task ends when every
    /// other clone of this handle is gone.
    #[must_use = "dropping the handle detaches the task; it keeps running"]
    pub fn watch(&self, interval: Duration) -> tokio::task::JoinHandle<()> {
        let weak = Arc::downgrade(&self.inner);
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval(interval);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticks.tick().await;
                let Some(inner) = weak.upgrade() else {
                    return;
                };
                Self { inner }.reload_if_changed();
            }
        })
    }

    fn push(&self, file: &str, level: &'static str, text: String) {
        let mut ring = self.inner.log.lock().expect("script log lock poisoned");
        ring.next += 1;
        let entry = LogEntry {
            seq: ring.next,
            time: crate::clock::Utc::now().rfc3339(),
            file: file.to_owned(),
            level,
            text,
        };
        if ring.entries.len() == LOG_CAPACITY {
            ring.entries.pop_front();
        }
        ring.entries.push_back(entry);
    }

    /// Records a run error of `file`: always as the last error, and in the log and on
    /// stderr only the first time this message is seen.
    fn fail(&self, file: &ScriptFile, hook: &str, error: &EvalAltResult) {
        let text = format!("{hook}: {error}");
        let mut state = file.state();
        state.error = Some(text.clone());
        let first =
            state.seen_errors.len() < MAX_SEEN_ERRORS && state.seen_errors.insert(text.clone());
        drop(state);
        if first {
            eprintln!("{}: script {}: {text}", crate::NAME, file.name);
            self.push(&file.name, "error", text);
        }
    }

    /// Runs `hook` of file `index` with `args`, collecting the helper calls. `None` when the
    /// call failed (already recorded).
    fn call(
        &self,
        index: usize,
        compiled: &Compiled,
        hook: &str,
        args: impl rhai::FuncArgs,
    ) -> Option<CallState> {
        let file = &self.inner.files[index];
        begin_call();
        let options = CallFnOptions::new().eval_ast(false).rewind_scope(true);
        let result = self.inner.engine.call_fn_with_options::<Dynamic>(
            options,
            &mut Scope::new(),
            &compiled.ast,
            hook,
            args,
        );
        let state = end_call();
        for line in &state.logs {
            self.push(&file.name, "log", line.clone());
        }
        match result {
            Ok(_) => Some(state),
            Err(error) => {
                self.fail(file, hook, &error);
                None
            }
        }
    }
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Reads, compiles and runs the top level of `path` once, to read `WANTS_BODY`.
fn compile(engine: &Engine, path: &Path) -> Result<Compiled, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let ast = engine.compile(&text).map_err(|e| e.to_string())?;
    let mut scope = Scope::new();
    begin_call();
    let result = engine.run_ast_with_scope(&mut scope, &ast);
    end_call();
    result.map_err(|e| e.to_string())?;
    let wants = scope.get_value::<Map>("WANTS_BODY").unwrap_or_default();
    let wants = |key: &str| wants.get(key).and_then(|v| v.as_bool().ok()) == Some(true);
    let defines = |name: &str, params: usize| {
        ast.iter_functions()
            .any(|f| f.name == name && f.params.len() == params)
    };
    Ok(Compiled {
        request: Hook {
            defined: defines("on_request", 1),
            body: wants("request"),
        },
        response: Hook {
            defined: defines("on_response", 2),
            body: wants("response"),
        },
        ast,
    })
}

/// Marks the files whose `on_request` failed, so their `on_response` is skipped.
#[derive(Debug, Clone, Default)]
struct Failed(HashSet<usize>);

/// One file in the chain.
struct ScriptStage {
    scripts: Scripts,
    index: usize,
    name: String,
}

impl ScriptStage {
    fn file(&self) -> &ScriptFile {
        &self.scripts.inner.files[self.index]
    }

    fn flags(state: &CallState) -> impl Iterator<Item = Flag> + '_ {
        state.flags.iter().map(|name| Flag::Script(name.clone()))
    }
}

impl Interceptor for ScriptStage {
    fn name(&self) -> &str {
        &self.name
    }

    fn needs_request_body(&self) -> bool {
        let compiled = self.file().current();
        compiled.request.defined && compiled.request.body
    }

    fn needs_response_body(&self) -> bool {
        let compiled = self.file().current();
        compiled.response.defined && compiled.response.body
    }

    fn on_request(&self, request: &mut RequestCtx) -> Action {
        let compiled = self.file().current();
        if !compiled.request.defined {
            return Action::Continue;
        }
        let req = ScriptRequest::of(request);
        let Some(state) = self
            .scripts
            .call(self.index, &compiled, "on_request", (req.clone(),))
        else {
            return self.failed(request);
        };
        if let Err(error) = req.write_back(request) {
            self.scripts.fail(self.file(), "on_request", &error);
            return self.failed(request);
        }
        request.flags.extend(Self::flags(&state));
        match (state.respond, state.delay) {
            (Some(response), _) => Action::Respond(response),
            (None, delay) if !delay.is_zero() => Action::Delay(delay),
            (None, _) => Action::Continue,
        }
    }

    fn on_response(&self, request: &RequestCtx, response: &mut ResponseCtx) -> Action {
        let compiled = self.file().current();
        let failed = request
            .extensions
            .get::<Failed>()
            .is_some_and(|f| f.0.contains(&self.index));
        if !compiled.response.defined || failed {
            return Action::Continue;
        }
        let req = ScriptRequest::of(request);
        let resp = ScriptResponse::of(response);
        let Some(state) =
            self.scripts
                .call(self.index, &compiled, "on_response", (req, resp.clone()))
        else {
            if !response.flags.contains(&Flag::ScriptError) {
                response.flags.push(Flag::ScriptError);
            }
            return Action::Continue;
        };
        resp.write_back(response);
        response.flags.extend(Self::flags(&state));
        match (state.respond, state.delay) {
            (Some(answer), _) => Action::Respond(answer),
            (None, delay) if !delay.is_zero() => Action::Delay(delay),
            (None, _) => Action::Continue,
        }
    }
}

impl ScriptStage {
    fn failed(&self, request: &mut RequestCtx) -> Action {
        if !request.flags.contains(&Flag::ScriptError) {
            request.flags.push(Flag::ScriptError);
        }
        let mut failed = request.extensions.remove::<Failed>().unwrap_or_default();
        failed.0.insert(self.index);
        request.extensions.insert(failed);
        Action::Continue
    }
}
