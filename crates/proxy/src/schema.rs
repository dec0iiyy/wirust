//! `.proto` schemas for the gRPC view: `--proto` files and directories compiled with `protox`
//! (no `protoc` binary) into a descriptor pool, reloaded when they change, and a decoder that
//! turns a message into the same tree as the schema-less [`protobuf`](crate::protobuf)
//! decoder, with field names, declared types and enum names added.
//!
//! Schema files are local, but reading them is still bounded: at most [`MAX_SCHEMA_BYTES`]
//! in all, [`MAX_SCHEMA_FILES`] files and [`MAX_SCAN_DEPTH`] directory levels. Errors name
//! files by their name relative to the include root, never by an absolute path. Decoding
//! keeps the caps of the schema-less decoder: [`protobuf::MAX_DEPTH`] levels, a shared
//! budget of field visits and [`protobuf::MAX_BYTES_SHOWN`] bytes per opaque field.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use prost_reflect::prost::Message as _;
use prost_reflect::{
    DescriptorPool, DynamicMessage, FieldDescriptor, Kind as FieldKind, MessageDescriptor,
    ReflectMessage as _, Value as Dyn,
};
use protox::file::{ChainFileResolver, File, FileResolver, GoogleFileResolver};
use serde::Serialize;

use crate::clock::Utc;
use crate::protobuf::{self, Decoded, Field, Value};

/// Bytes of `.proto` source read per compile, imports included.
pub const MAX_SCHEMA_BYTES: usize = 8 << 20;

/// Schema files read per compile, imports included.
pub const MAX_SCHEMA_FILES: usize = 1000;

/// Directory levels scanned below a `--proto` directory.
pub const MAX_SCAN_DEPTH: usize = 16;

/// Where the schemas come from: `--proto`, `--proto-include` and `--proto-message`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sources {
    /// `.proto` files, or directories scanned recursively for them.
    pub protos: Vec<PathBuf>,
    /// Import roots.
    pub includes: Vec<PathBuf>,
    /// The message type for bare `application/x-protobuf` bodies.
    pub message: Option<String>,
}

/// One compile of the schemas.
#[derive(Debug)]
pub struct Compiled {
    pool: DescriptorPool,
    files: Vec<String>,
    stamps: Vec<Stamp>,
    opened: Vec<PathBuf>,
}

/// What a file looked like when it was read: its path, modification time and length.
type Stamp = (PathBuf, Option<SystemTime>, u64);

impl Compiled {
    /// The request and response types of `/service/method`.
    #[must_use]
    pub fn method(
        &self,
        service: &str,
        method: &str,
    ) -> Option<(MessageDescriptor, MessageDescriptor)> {
        let service = self.pool.get_service_by_name(service)?;
        let method = service.methods().find(|m| m.name() == method)?;
        Some((method.input(), method.output()))
    }

    /// The message type named `name` (`pkg.Message`).
    #[must_use]
    pub fn message(&self, name: &str) -> Option<MessageDescriptor> {
        self.pool.get_message_by_name(name.trim_start_matches('.'))
    }
}

/// The loaded schemas, shared by the API and the reload watcher; cheap to clone.
#[derive(Debug, Clone, Default)]
pub struct Schemas {
    inner: Arc<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    sources: Sources,
    current: RwLock<Option<Arc<Compiled>>>,
    status: Mutex<Status>,
}

#[derive(Debug, Default)]
struct Status {
    error: Option<String>,
    seen: Vec<Stamp>,
}

/// What `GET /api/v1/proto` answers.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Report {
    /// The compiled files, by name relative to their root (no absolute paths).
    pub files: Vec<String>,
    /// The services, sorted by name.
    pub services: Vec<ServiceReport>,
    /// The `--proto-message` type, if one was given.
    pub message: Option<String>,
    /// Why the last reload failed; the previous schemas stay in force.
    pub error: Option<String>,
}

/// A service and its methods.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ServiceReport {
    /// `pkg.Service`.
    pub name: String,
    /// Its methods, in declaration order.
    pub methods: Vec<MethodReport>,
}

/// One method of a service.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MethodReport {
    /// `Method`.
    pub name: String,
    /// The request type, `pkg.Request`.
    pub input: String,
    /// The response type.
    pub output: String,
    /// Whether the client sends a stream.
    pub client_streaming: bool,
    /// Whether the server sends a stream.
    pub server_streaming: bool,
}

impl Schemas {
    /// Compiles `sources`; [`Schemas::watch`] recompiles them when they change.
    ///
    /// # Errors
    ///
    /// The compile error, naming the file, when a schema cannot be read or compiled, or
    /// when `--proto-message` names no type in them.
    pub fn load(sources: Sources) -> Result<Self, String> {
        let compiled = compile(&sources)?;
        if let Some(name) = &sources.message
            && compiled.message(name).is_none()
        {
            return Err(format!(
                "--proto-message {name}: no such message type in the schemas"
            ));
        }
        let seen = compiled.stamps.clone();
        Ok(Self {
            inner: Arc::new(Inner {
                sources,
                current: RwLock::new(Some(Arc::new(compiled))),
                status: Mutex::new(Status { error: None, seen }),
            }),
        })
    }

    /// The current compile, if any.
    ///
    /// # Panics
    ///
    /// When a thread panicked while swapping it (lock poisoning).
    #[must_use]
    pub fn current(&self) -> Option<Arc<Compiled>> {
        self.inner
            .current
            .read()
            .expect("schemas lock poisoned")
            .clone()
    }

    /// The `--proto-message` type.
    #[must_use]
    pub fn message_hint(&self) -> Option<&str> {
        self.inner.sources.message.as_deref()
    }

    /// What `GET /api/v1/proto` shows.
    #[must_use]
    pub fn report(&self) -> Report {
        let current = self.current();
        let mut services: Vec<ServiceReport> = current
            .iter()
            .flat_map(|c| c.pool.services())
            .map(|s| ServiceReport {
                name: s.full_name().to_owned(),
                methods: s
                    .methods()
                    .map(|m| MethodReport {
                        name: m.name().to_owned(),
                        input: m.input().full_name().to_owned(),
                        output: m.output().full_name().to_owned(),
                        client_streaming: m.is_client_streaming(),
                        server_streaming: m.is_server_streaming(),
                    })
                    .collect(),
            })
            .collect();
        services.sort_by(|a, b| a.name.cmp(&b.name));
        Report {
            files: current.map(|c| c.files.clone()).unwrap_or_default(),
            services,
            message: self.inner.sources.message.clone(),
            error: self.status().error.clone(),
        }
    }

    /// Recompiles when a schema file was added, removed or changed. A broken schema keeps
    /// the previous pool; the error goes to [`Report::error`] and stderr. Returns whether a
    /// new pool was installed.
    ///
    /// # Panics
    ///
    /// When a thread panicked while swapping the pool (lock poisoning).
    #[expect(
        clippy::must_use_candidate,
        reason = "the watcher calls it for the side effect"
    )]
    pub fn reload_if_changed(&self) -> bool {
        let opened = self.current().map(|c| c.opened.clone()).unwrap_or_default();
        let Ok(found) = scan(&self.inner.sources) else {
            return self.record_failure(Vec::new(), "a --proto path is gone".to_owned());
        };
        let stamps = stamps(found.iter().map(|(path, _)| path.clone()).chain(opened));
        if stamps == self.status().seen {
            return false;
        }
        match compile(&self.inner.sources) {
            Ok(compiled) => {
                let mut status = self.status();
                status.error = None;
                status.seen = stamps;
                drop(status);
                *self.inner.current.write().expect("schemas lock poisoned") =
                    Some(Arc::new(compiled));
                true
            }
            Err(e) => self.record_failure(stamps, e),
        }
    }

    fn record_failure(&self, stamps: Vec<Stamp>, error: String) -> bool {
        eprintln!(
            "{}: --proto: {error}; keeping the previous schemas",
            crate::NAME
        );
        let mut status = self.status();
        status.error = Some(error);
        status.seen = stamps;
        false
    }

    /// Polls the schema files every `interval` and recompiles them when they change. The
    /// task ends when every other clone of this handle is gone.
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
                let schemas = Self { inner };
                // Compiling reads files: keep it off the async workers.
                let _ = tokio::task::spawn_blocking(move || schemas.reload_if_changed()).await;
            }
        })
    }

    fn status(&self) -> std::sync::MutexGuard<'_, Status> {
        self.inner
            .status
            .lock()
            .expect("schemas status lock poisoned")
    }
}

fn stamps(paths: impl IntoIterator<Item = PathBuf>) -> Vec<Stamp> {
    let unique: BTreeSet<PathBuf> = paths.into_iter().collect();
    unique
        .into_iter()
        .map(|path| {
            let meta = std::fs::metadata(&path).ok();
            let modified = meta.as_ref().and_then(|m| m.modified().ok());
            let len = meta.map_or(0, |m| m.len());
            (path, modified, len)
        })
        .collect()
}

/// The `.proto` files the sources name: each with its path and its import name.
fn scan(sources: &Sources) -> Result<Vec<(PathBuf, String)>, String> {
    let includes: Vec<PathBuf> = sources.includes.iter().map(|p| canonical(p)).collect();
    let mut found = Vec::new();
    for root in &sources.protos {
        let shown = crate::rules::file_name(root);
        let meta = std::fs::metadata(root).map_err(|e| format!("{shown}: {e}"))?;
        if meta.is_dir() {
            walk(&canonical(root), &canonical(root), 0, &includes, &mut found)?;
        } else {
            let path = canonical(root);
            let base = path.parent().map(Path::to_owned).unwrap_or_default();
            found.push((path.clone(), import_name(&path, &base, &includes)));
        }
        if found.len() > MAX_SCHEMA_FILES {
            return Err(format!("more than {MAX_SCHEMA_FILES} schema files"));
        }
    }
    Ok(found)
}

fn walk(
    dir: &Path,
    base: &Path,
    depth: usize,
    includes: &[PathBuf],
    found: &mut Vec<(PathBuf, String)>,
) -> Result<(), String> {
    if depth > MAX_SCAN_DEPTH {
        return Ok(());
    }
    let shown = crate::rules::file_name(dir);
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{shown}: {e}"))?;
    let mut paths: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
    paths.sort();
    for path in paths {
        let Ok(kind) = std::fs::symlink_metadata(&path).map(|m| m.file_type()) else {
            continue;
        };
        if kind.is_dir() {
            walk(&path, base, depth + 1, includes, found)?;
        } else if kind.is_file() && path.extension().is_some_and(|e| e == "proto") {
            found.push((path.clone(), import_name(&path, base, includes)));
            if found.len() > MAX_SCHEMA_FILES {
                return Err(format!("more than {MAX_SCHEMA_FILES} schema files"));
            }
        }
    }
    Ok(())
}

fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned())
}

/// The name `path` is imported by: relative to the first include root holding it, else to
/// `base`, with `/` separators.
fn import_name(path: &Path, base: &Path, includes: &[PathBuf]) -> String {
    let relative = includes
        .iter()
        .find_map(|root| path.strip_prefix(root).ok())
        .or_else(|| path.strip_prefix(base).ok())
        .unwrap_or(path);
    relative
        .components()
        .filter_map(|c| match c {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// What the resolver read, shared with [`compile`] after the compiler took the resolver.
#[derive(Debug, Default)]
struct Reads {
    bytes: Cell<usize>,
    opened: RefCell<Vec<PathBuf>>,
}

/// Opens imports from the include roots, then the scan roots, within the caps.
struct Limited {
    roots: Vec<PathBuf>,
    reads: Rc<Reads>,
}

impl FileResolver for Limited {
    fn open_file(&self, name: &str) -> Result<File, protox::Error> {
        let relative = Path::new(name);
        let safe = relative
            .components()
            .all(|c| matches!(c, Component::Normal(_)));
        if !safe {
            return Err(protox::Error::file_not_found(name));
        }
        let Some(path) = self
            .roots
            .iter()
            .map(|root| root.join(relative))
            .find(|path| path.is_file())
        else {
            return Err(protox::Error::file_not_found(name));
        };
        let cap = |what: String| protox::Error::new(std::io::Error::other(what));
        if self.reads.opened.borrow().len() >= MAX_SCHEMA_FILES {
            return Err(cap(format!(
                "{name}: more than {MAX_SCHEMA_FILES} schema files"
            )));
        }
        let len = std::fs::metadata(&path).map_or(0, |m| m.len());
        let total = self
            .reads
            .bytes
            .get()
            .saturating_add(usize::try_from(len).unwrap_or(usize::MAX));
        if total > MAX_SCHEMA_BYTES {
            return Err(cap(format!(
                "{name}: the schemas exceed {} MiB",
                MAX_SCHEMA_BYTES >> 20
            )));
        }
        let source = std::fs::read_to_string(&path).map_err(|e| cap(format!("{name}: {e}")))?;
        self.reads.bytes.set(total);
        self.reads.opened.borrow_mut().push(path);
        File::from_source(name, &source)
    }
}

/// Compiles the schemas `sources` name.
fn compile(sources: &Sources) -> Result<Compiled, String> {
    if sources.protos.is_empty() {
        return Err("no --proto files".to_owned());
    }
    let found = scan(sources)?;
    if found.is_empty() {
        return Err("no .proto files found".to_owned());
    }
    let mut roots: Vec<PathBuf> = sources.includes.iter().map(|p| canonical(p)).collect();
    for root in &sources.protos {
        let root = canonical(root);
        let root = if root.is_dir() {
            root
        } else {
            root.parent().map(Path::to_owned).unwrap_or_default()
        };
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    let reads = Rc::new(Reads::default());
    let mut chain = ChainFileResolver::new();
    chain.add(Limited {
        roots,
        reads: Rc::clone(&reads),
    });
    chain.add(GoogleFileResolver::new());
    let mut compiler = protox::Compiler::with_file_resolver(chain);
    compiler.include_imports(true);
    for (_, name) in &found {
        compiler.open_file(name).map_err(|e| compile_error(&e))?;
    }
    let files = compiler
        .files()
        .map(|f| f.name().to_owned())
        .filter(|name| !name.starts_with("google/protobuf/"))
        .collect();
    let opened = reads.opened.borrow().clone();
    let stamps = stamps(
        found
            .into_iter()
            .map(|(path, _)| path)
            .chain(opened.clone()),
    );
    Ok(Compiled {
        pool: compiler.descriptor_pool(),
        files,
        stamps,
        opened,
    })
}

/// A compile error with the file it is in, by import name.
fn compile_error(error: &protox::Error) -> String {
    let text = error.to_string();
    match error.file() {
        Some(file) if !text.contains(file) => format!("{file}: {text}"),
        _ => text,
    }
}

/// Field visits left for one call, and whether a cap cut the tree short.
struct Walk<'p> {
    budget: &'p mut usize,
    truncated: bool,
}

/// Decodes `data` as a `desc` message, spending field visits from `budget`.
///
/// # Errors
///
/// The decoder's error when `data` is not a valid `desc` message.
pub fn decode(
    desc: &MessageDescriptor,
    data: &[u8],
    budget: &mut usize,
) -> Result<Decoded, String> {
    let message = DynamicMessage::decode(desc.clone(), data).map_err(|e| e.to_string())?;
    let mut walk = Walk {
        budget,
        truncated: false,
    };
    let fields = message_fields(&message, 0, &mut walk);
    Ok(Decoded {
        fields,
        error: None,
        truncated: walk.truncated,
    })
}

fn message_fields(message: &DynamicMessage, depth: usize, walk: &mut Walk<'_>) -> Vec<Field> {
    let mut out = Vec::new();
    for (desc, value) in message.fields() {
        match value {
            Dyn::List(items) => {
                for item in items {
                    if let Some(field) = field(&desc, item, depth, walk) {
                        out.push(field);
                    }
                }
            }
            Dyn::Map(map) => {
                let mut entries: Vec<_> = map.iter().collect();
                entries.sort_by(|a, b| a.0.cmp(b.0));
                for (key, item) in entries {
                    if let Some(field) = map_entry(&desc, key, item, depth, walk) {
                        out.push(field);
                    }
                }
            }
            single => {
                if let Some(field) = field(&desc, single, depth, walk) {
                    out.push(field);
                }
            }
        }
    }
    for unknown in message.unknown_fields() {
        let mut raw = Vec::new();
        unknown.encode(&mut raw);
        let decoded = protobuf::decode_within(&raw, walk.budget);
        walk.truncated |= decoded.truncated;
        out.extend(decoded.fields);
    }
    out
}

/// Takes one field visit; `None` when the budget ran out.
fn spend(walk: &mut Walk<'_>) -> Option<()> {
    if *walk.budget == 0 {
        walk.truncated = true;
        return None;
    }
    *walk.budget -= 1;
    Some(())
}

fn field(desc: &FieldDescriptor, value: &Dyn, depth: usize, walk: &mut Walk<'_>) -> Option<Field> {
    spend(walk)?;
    let kind = desc.kind();
    let label = if desc.is_list() {
        format!("repeated {}", kind_name(&kind))
    } else {
        kind_name(&kind)
    };
    Some(Field {
        field: desc.number(),
        wire: wire_name(&kind),
        name: Some(desc.name().to_owned()),
        proto: Some(label),
        oneof: desc.containing_oneof().map(|o| o.name().to_owned()),
        value: convert(value, &kind, depth, walk),
    })
}

fn map_entry(
    desc: &FieldDescriptor,
    key: &prost_reflect::MapKey,
    value: &Dyn,
    depth: usize,
    walk: &mut Walk<'_>,
) -> Option<Field> {
    spend(walk)?;
    let entry = desc.kind().as_message()?.clone();
    let (key_desc, value_desc) = (entry.map_entry_key_field(), entry.map_entry_value_field());
    let key_value: Dyn = key.clone().into();
    let fields = [(key_desc, &key_value), (value_desc, value)]
        .into_iter()
        .filter_map(|(d, v)| field(&d, v, depth + 1, walk))
        .collect();
    Some(Field {
        field: desc.number(),
        wire: "len",
        name: Some(desc.name().to_owned()),
        proto: Some(format!(
            "map<{}, {}>",
            kind_name(&entry.map_entry_key_field().kind()),
            kind_name(&entry.map_entry_value_field().kind())
        )),
        oneof: None,
        value: Value::Message { fields },
    })
}

fn kind_name(kind: &FieldKind) -> String {
    match kind {
        FieldKind::Double => "double".to_owned(),
        FieldKind::Float => "float".to_owned(),
        FieldKind::Int32 => "int32".to_owned(),
        FieldKind::Int64 => "int64".to_owned(),
        FieldKind::Uint32 => "uint32".to_owned(),
        FieldKind::Uint64 => "uint64".to_owned(),
        FieldKind::Sint32 => "sint32".to_owned(),
        FieldKind::Sint64 => "sint64".to_owned(),
        FieldKind::Fixed32 => "fixed32".to_owned(),
        FieldKind::Fixed64 => "fixed64".to_owned(),
        FieldKind::Sfixed32 => "sfixed32".to_owned(),
        FieldKind::Sfixed64 => "sfixed64".to_owned(),
        FieldKind::Bool => "bool".to_owned(),
        FieldKind::String => "string".to_owned(),
        FieldKind::Bytes => "bytes".to_owned(),
        FieldKind::Message(m) => m.full_name().to_owned(),
        FieldKind::Enum(e) => e.full_name().to_owned(),
    }
}

fn wire_name(kind: &FieldKind) -> &'static str {
    match kind {
        FieldKind::Double | FieldKind::Fixed64 | FieldKind::Sfixed64 => "i64",
        FieldKind::Float | FieldKind::Fixed32 | FieldKind::Sfixed32 => "i32",
        FieldKind::String | FieldKind::Bytes | FieldKind::Message(_) => "len",
        _ => "varint",
    }
}

fn convert(value: &Dyn, kind: &FieldKind, depth: usize, walk: &mut Walk<'_>) -> Value {
    let number = |value: String| Value::Number { value };
    match value {
        Dyn::Bool(v) => Value::Bool { value: *v },
        Dyn::I32(v) => number(v.to_string()),
        Dyn::I64(v) => number(v.to_string()),
        Dyn::U32(v) => number(v.to_string()),
        Dyn::U64(v) => number(v.to_string()),
        Dyn::F32(v) => number(v.to_string()),
        Dyn::F64(v) => number(v.to_string()),
        Dyn::String(v) => Value::String { value: v.clone() },
        Dyn::Bytes(v) => protobuf::bytes_value(v),
        Dyn::EnumNumber(n) => Value::Enum {
            value: *n,
            symbol: kind
                .as_enum()
                .and_then(|e| e.get_value(*n))
                .map(|v| v.name().to_owned()),
        },
        Dyn::Message(m) => message_value(m, depth, walk),
        Dyn::List(_) | Dyn::Map(_) => Value::String {
            value: "(nested collection)".to_owned(),
        },
    }
}

fn message_value(message: &DynamicMessage, depth: usize, walk: &mut Walk<'_>) -> Value {
    if depth + 1 >= protobuf::MAX_DEPTH {
        walk.truncated = true;
        return protobuf::bytes_value(&message.encode_to_vec());
    }
    if let Some(value) = well_known(message, depth, walk) {
        return value;
    }
    Value::Message {
        fields: message_fields(message, depth + 1, walk),
    }
}

/// `Timestamp`, `Duration`, the wrappers, `Struct`, `Value`, `ListValue` and `Any`, shown by
/// meaning.
fn well_known(message: &DynamicMessage, depth: usize, walk: &mut Walk<'_>) -> Option<Value> {
    let desc = message.descriptor();
    let get = |name: &str| {
        message
            .get_field_by_name(name)
            .map(std::borrow::Cow::into_owned)
    };
    let int = |name: &str| get(name).and_then(|v| v.as_i64().or_else(|| v.as_i32().map(i64::from)));
    match desc.full_name() {
        "google.protobuf.Timestamp" => {
            let (seconds, nanos) = (int("seconds")?, int("nanos")?);
            let utc = Utc::from_unix(seconds, 0).rfc3339();
            let base = utc.trim_end_matches(".000Z");
            let text = if nanos == 0 {
                format!("{base}Z")
            } else {
                format!("{base}.{nanos:09}Z")
            };
            Some(Value::String { value: text })
        }
        "google.protobuf.Duration" => {
            let (seconds, nanos) = (int("seconds")?, int("nanos")?);
            let sign = if seconds < 0 || nanos < 0 { "-" } else { "" };
            let (seconds, nanos) = (seconds.unsigned_abs(), nanos.unsigned_abs());
            let text = if nanos == 0 {
                format!("{sign}{seconds}s")
            } else {
                let fraction = format!("{nanos:09}");
                format!("{sign}{seconds}.{}s", fraction.trim_end_matches('0'))
            };
            Some(Value::String { value: text })
        }
        "google.protobuf.DoubleValue"
        | "google.protobuf.FloatValue"
        | "google.protobuf.Int64Value"
        | "google.protobuf.UInt64Value"
        | "google.protobuf.Int32Value"
        | "google.protobuf.UInt32Value"
        | "google.protobuf.BoolValue"
        | "google.protobuf.StringValue"
        | "google.protobuf.BytesValue" => {
            let field = desc.get_field_by_name("value")?;
            let value = message.get_field(&field);
            Some(convert(&value, &field.kind(), depth, walk))
        }
        "google.protobuf.Struct" | "google.protobuf.Value" | "google.protobuf.ListValue" => {
            Some(Value::Json {
                value: json(message, depth, walk),
            })
        }
        "google.protobuf.Any" => any(message, depth, walk),
        _ => None,
    }
}

/// `google.protobuf.Any`: the packed message decoded when its type is in the pool.
fn any(message: &DynamicMessage, depth: usize, walk: &mut Walk<'_>) -> Option<Value> {
    let url = message.get_field_by_name("type_url")?;
    let url = url.as_str()?.to_owned();
    let bytes = message.get_field_by_name("value")?;
    let bytes = bytes.as_bytes()?.clone();
    let name = url.rsplit('/').next().unwrap_or_default().to_owned();
    let desc = message
        .descriptor()
        .parent_pool()
        .get_message_by_name(&name)?;
    let inner = DynamicMessage::decode(desc, bytes).ok()?;
    spend(walk)?;
    let type_url = Field {
        field: 1,
        wire: "len",
        name: Some("type_url".to_owned()),
        proto: Some("string".to_owned()),
        oneof: None,
        value: Value::String { value: url },
    };
    let value = Field {
        field: 2,
        wire: "len",
        name: Some("value".to_owned()),
        proto: Some(name),
        oneof: None,
        value: message_value(&inner, depth + 1, walk),
    };
    Some(Value::Message {
        fields: vec![type_url, value],
    })
}

/// `Struct`, `Value` and `ListValue` as the JSON they stand for.
fn json(message: &DynamicMessage, depth: usize, walk: &mut Walk<'_>) -> serde_json::Value {
    use serde_json::Value as J;
    if depth + 1 >= protobuf::MAX_DEPTH || spend(walk).is_none() {
        walk.truncated = true;
        return J::Null;
    }
    let nested = |value: &Dyn, walk: &mut Walk<'_>| match value {
        Dyn::Message(m) => json(m, depth + 1, walk),
        _ => J::Null,
    };
    match message.descriptor().full_name() {
        "google.protobuf.Struct" => {
            let Some(fields) = message.get_field_by_name("fields") else {
                return J::Null;
            };
            let mut object = serde_json::Map::new();
            if let Some(map) = fields.as_map() {
                let mut entries: Vec<_> = map.iter().collect();
                entries.sort_by(|a, b| a.0.cmp(b.0));
                for (key, value) in entries {
                    let key = key.as_str().unwrap_or_default().to_owned();
                    object.insert(key, nested(value, walk));
                }
            }
            J::Object(object)
        }
        "google.protobuf.ListValue" => {
            let values = message.get_field_by_name("values");
            let items = values.as_deref().and_then(Dyn::as_list).unwrap_or_default();
            J::Array(items.iter().map(|v| nested(v, walk)).collect())
        }
        _ => {
            let Some((field, value)) = message.fields().next() else {
                return J::Null;
            };
            match (field.name(), value) {
                ("number_value", Dyn::F64(n)) => {
                    serde_json::Number::from_f64(*n).map_or(J::Null, J::Number)
                }
                ("string_value", Dyn::String(s)) => J::String(s.clone()),
                ("bool_value", Dyn::Bool(b)) => J::Bool(*b),
                ("struct_value" | "list_value", v) => nested(v, walk),
                _ => J::Null,
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A schema with nested messages, an enum, a map, a oneof, repeated fields and a
    /// Timestamp.
    pub(crate) const SHOP: &str = r#"
syntax = "proto3";
package shop;
import "google/protobuf/timestamp.proto";
import "google/protobuf/duration.proto";
import "google/protobuf/wrappers.proto";
import "google/protobuf/struct.proto";

enum Color { COLOR_UNSPECIFIED = 0; RED = 1; GREEN = 2; }

message Item {
  string sku = 1;
  int32 count = 2;
}

message Order {
  int64 id = 1;
  repeated Item items = 2;
  map<string, int32> tags = 3;
  Color color = 4;
  oneof payment { string card = 5; bool cash = 6; }
  google.protobuf.Timestamp created = 7;
  google.protobuf.Duration ttl = 8;
  google.protobuf.StringValue note = 9;
  google.protobuf.Struct extra = 10;
  repeated sint32 deltas = 11;
}

message Reply { bool ok = 1; }

service Orders {
  rpc Place(Order) returns (Reply);
  rpc Watch(Reply) returns (stream Order);
}
"#;

    pub(crate) fn write_shop(dir: &Path) -> PathBuf {
        let path = dir.join("shop.proto");
        std::fs::write(&path, SHOP).expect("write the schema");
        path
    }

    pub(crate) fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wirust-schema-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create a temp dir");
        dir
    }

    /// An `Order` with every kind of field set, encoded with prost-reflect.
    pub(crate) fn order_bytes(schemas: &Schemas) -> Vec<u8> {
        let compiled = schemas.current().expect("compiled");
        let order = compiled.message("shop.Order").expect("Order");
        let item = compiled.message("shop.Item").expect("Item");
        let mut msg = DynamicMessage::new(order.clone());
        msg.set_field_by_name("id", Dyn::I64(42));
        let mut first = DynamicMessage::new(item.clone());
        first.set_field_by_name("sku", Dyn::String("A-1".to_owned()));
        first.set_field_by_name("count", Dyn::I32(2));
        let mut second = DynamicMessage::new(item);
        second.set_field_by_name("sku", Dyn::String("B-2".to_owned()));
        msg.set_field_by_name(
            "items",
            Dyn::List(vec![Dyn::Message(first), Dyn::Message(second)]),
        );
        let mut tags = std::collections::HashMap::new();
        tags.insert(
            prost_reflect::MapKey::String("gift".to_owned()),
            Dyn::I32(1),
        );
        msg.set_field_by_name("tags", Dyn::Map(tags));
        msg.set_field_by_name("color", Dyn::EnumNumber(2));
        msg.set_field_by_name("card", Dyn::String("visa".to_owned()));
        let ts = compiled
            .message("google.protobuf.Timestamp")
            .expect("Timestamp");
        let mut created = DynamicMessage::new(ts);
        created.set_field_by_name("seconds", Dyn::I64(1_700_000_000));
        created.set_field_by_name("nanos", Dyn::I32(5));
        msg.set_field_by_name("created", Dyn::Message(created));
        let duration = compiled
            .message("google.protobuf.Duration")
            .expect("Duration");
        let mut ttl = DynamicMessage::new(duration);
        ttl.set_field_by_name("seconds", Dyn::I64(90));
        ttl.set_field_by_name("nanos", Dyn::I32(500_000_000));
        msg.set_field_by_name("ttl", Dyn::Message(ttl));
        let wrapper = compiled
            .message("google.protobuf.StringValue")
            .expect("StringValue");
        let mut note = DynamicMessage::new(wrapper);
        note.set_field_by_name("value", Dyn::String("fragile".to_owned()));
        msg.set_field_by_name("note", Dyn::Message(note));
        msg.set_field_by_name("deltas", Dyn::List(vec![Dyn::I32(-1), Dyn::I32(3)]));
        let mut bytes = msg.encode_to_vec();
        // An unknown field 99 = 7 stays visible by number.
        bytes.extend_from_slice(&[0x98, 0x06, 0x07]);
        bytes
    }

    fn named<'f>(fields: &'f [Field], name: &str) -> Vec<&'f Field> {
        fields
            .iter()
            .filter(|f| f.name.as_deref() == Some(name))
            .collect()
    }

    #[test]
    fn decodes_every_kind_of_field_with_names_and_types() {
        let dir = temp_dir("kinds");
        let path = write_shop(&dir);
        let schemas = Schemas::load(Sources {
            protos: vec![path],
            ..Sources::default()
        })
        .expect("the schema compiles");
        let order = schemas
            .current()
            .and_then(|c| c.message("shop.Order"))
            .expect("Order");
        let mut budget = protobuf::MAX_STEPS;
        let decoded = decode(&order, &order_bytes(&schemas), &mut budget).expect("decodes");
        let f = &decoded.fields;
        assert_eq!(
            named(f, "id")[0].value,
            Value::Number {
                value: "42".to_owned()
            }
        );
        assert_eq!(named(f, "id")[0].proto.as_deref(), Some("int64"));
        let items = named(f, "items");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].proto.as_deref(), Some("repeated shop.Item"));
        let Value::Message { fields } = &items[0].value else {
            panic!("item is a message: {:?}", items[0].value);
        };
        assert_eq!(
            named(fields, "sku")[0].value,
            Value::String {
                value: "A-1".to_owned()
            }
        );
        let tags = named(f, "tags");
        assert_eq!(tags[0].proto.as_deref(), Some("map<string, int32>"));
        assert_eq!(
            named(f, "color")[0].value,
            Value::Enum {
                value: 2,
                symbol: Some("GREEN".to_owned())
            }
        );
        assert_eq!(named(f, "card")[0].oneof.as_deref(), Some("payment"));
        assert_eq!(
            named(f, "created")[0].value,
            Value::String {
                value: "2023-11-14T22:13:20.000000005Z".to_owned()
            }
        );
        assert_eq!(
            named(f, "ttl")[0].value,
            Value::String {
                value: "90.5s".to_owned()
            }
        );
        assert_eq!(
            named(f, "note")[0].value,
            Value::String {
                value: "fragile".to_owned()
            }
        );
        let deltas: Vec<_> = named(f, "deltas").iter().map(|d| d.value.clone()).collect();
        assert_eq!(
            deltas,
            vec![
                Value::Number {
                    value: "-1".to_owned()
                },
                Value::Number {
                    value: "3".to_owned()
                }
            ]
        );
        let unknown = f
            .iter()
            .find(|x| x.field == 99)
            .expect("unknown field kept");
        assert!(unknown.name.is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn struct_values_become_json() {
        let dir = temp_dir("struct");
        let schemas = Schemas::load(Sources {
            protos: vec![write_shop(&dir)],
            ..Sources::default()
        })
        .expect("compiles");
        let compiled = schemas.current().expect("compiled");
        let order = compiled.message("shop.Order").expect("Order");
        // `extra: { a: 1.5 }`.
        let value_desc = compiled.message("google.protobuf.Value").expect("Value");
        let struct_desc = compiled.message("google.protobuf.Struct").expect("Struct");
        let mut a = DynamicMessage::new(value_desc.clone());
        a.set_field_by_name("number_value", Dyn::F64(1.5));
        let mut fields = std::collections::HashMap::new();
        fields.insert(
            prost_reflect::MapKey::String("a".to_owned()),
            Dyn::Message(a),
        );
        let mut extra = DynamicMessage::new(struct_desc);
        extra.set_field_by_name("fields", Dyn::Map(fields));
        let mut msg = DynamicMessage::new(order.clone());
        msg.set_field_by_name("extra", Dyn::Message(extra));
        let mut budget = protobuf::MAX_STEPS;
        let decoded = decode(&order, &msg.encode_to_vec(), &mut budget).expect("decodes");
        assert_eq!(
            decoded.fields[0].value,
            Value::Json {
                value: serde_json::json!({"a": 1.5})
            }
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn malformed_bytes_fail_without_panicking() {
        let dir = temp_dir("malformed");
        let schemas = Schemas::load(Sources {
            protos: vec![write_shop(&dir)],
            ..Sources::default()
        })
        .expect("compiles");
        let order = schemas
            .current()
            .and_then(|c| c.message("shop.Order"))
            .expect("Order");
        let good = order_bytes(&schemas);
        let mut state: u64 = 11;
        for round in 0..5_000 {
            let mut data = good.clone();
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let at = usize::try_from(state).unwrap_or(0) % data.len();
            data[at] = state.to_le_bytes()[1];
            let cut = usize::try_from(state >> 8).unwrap_or(0) % (data.len() + 1);
            let mut budget = protobuf::MAX_STEPS;
            if let Ok(d) = decode(&order, &data[..cut], &mut budget) {
                assert!(serde_json::to_vec(&d).is_ok(), "round {round}");
            }
        }
        let mut budget = protobuf::MAX_STEPS;
        assert!(decode(&order, &[0x0a, 0x10, b'a'], &mut budget).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn bad_schemas_name_the_file_and_reload_keeps_the_previous_pool() {
        let dir = temp_dir("reload");
        let path = write_shop(&dir);
        std::fs::write(dir.join("broken.txt"), "ignored").expect("write");
        let schemas = Schemas::load(Sources {
            protos: vec![dir.clone()],
            ..Sources::default()
        })
        .expect("compiles");
        assert_eq!(schemas.report().files, vec!["shop.proto".to_owned()]);
        assert!(!schemas.reload_if_changed(), "nothing changed");

        std::fs::write(&path, "syntax = \"proto3\";\nmessage {").expect("write");
        bump(&path, 10);
        assert!(!schemas.reload_if_changed());
        let report = schemas.report();
        let error = report.error.expect("the reload error is kept");
        assert!(error.contains("shop.proto"), "{error}");
        assert!(
            !error.contains(&*dir.to_string_lossy()),
            "no absolute path: {error}"
        );
        assert_eq!(report.services[0].name, "shop.Orders", "previous pool kept");
        assert!(
            !schemas.reload_if_changed(),
            "the broken file is not retried"
        );

        std::fs::write(
            &path,
            SHOP.replace(
                "Reply { bool ok = 1; }",
                "Reply { bool ok = 1; string why = 2; }",
            ),
        )
        .expect("write");
        bump(&path, 20);
        assert!(schemas.reload_if_changed());
        let report = schemas.report();
        assert_eq!(report.error, None);
        assert_eq!(report.services[0].methods[1].name, "Watch");
        assert!(report.services[0].methods[1].server_streaming);

        let error = Schemas::load(Sources {
            protos: vec![dir.join("missing.proto")],
            ..Sources::default()
        })
        .expect_err("a missing file refuses to load");
        assert!(error.starts_with("missing.proto:"), "{error}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn imports_resolve_from_include_roots_and_escapes_are_refused() {
        let dir = temp_dir("include");
        std::fs::create_dir_all(dir.join("lib/common")).expect("mkdir");
        std::fs::create_dir_all(dir.join("api")).expect("mkdir");
        std::fs::write(
            dir.join("lib/common/money.proto"),
            "syntax = \"proto3\"; package common; message Money { int64 units = 1; }",
        )
        .expect("write");
        std::fs::write(
            dir.join("api/pay.proto"),
            "syntax = \"proto3\"; package pay; import \"common/money.proto\";\n\
             message Pay { common.Money amount = 1; }",
        )
        .expect("write");
        let schemas = Schemas::load(Sources {
            protos: vec![dir.join("api")],
            includes: vec![dir.join("lib")],
            message: Some("pay.Pay".to_owned()),
        })
        .expect("compiles with the include root");
        assert!(
            schemas
                .report()
                .files
                .contains(&"common/money.proto".to_owned())
        );
        assert_eq!(schemas.message_hint(), Some("pay.Pay"));

        std::fs::write(
            dir.join("api/pay.proto"),
            "syntax = \"proto3\"; import \"../lib/common/money.proto\";",
        )
        .expect("write");
        let error = Schemas::load(Sources {
            protos: vec![dir.join("api")],
            ..Sources::default()
        })
        .expect_err("a .. import is refused");
        assert!(error.contains("pay.proto"), "{error}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Moves the modification time `secs` seconds forward, so a rewrite is seen even on file
    /// systems with coarse timestamps.
    fn bump(path: &Path, secs: u64) {
        let file = std::fs::File::options()
            .write(true)
            .open(path)
            .expect("open");
        let at = SystemTime::now() + Duration::from_secs(secs);
        file.set_modified(at).expect("set mtime");
    }
}
