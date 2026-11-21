//! The rules engine: an ordered list of match-and-act rules from a TOML file or the API.
//!
//! [`Rules`] holds the current [`RuleSet`] behind an atomic swap. Each exchange takes the set
//! that is current when its request arrives and keeps it until its response is done, so a
//! reload never changes an exchange half-way. [`Rules::interceptors`] returns the three
//! chain stages (delay, main, breakpoint) to register; `docs/rules.md` documents the file.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::num::NonZeroU64;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::flow::Flag;
use crate::intercept::{
    Action, Interceptor, Paused, Pauses, Phase, RequestCtx, ResponseCtx, plain,
};
use crate::throttle::Throttle;

/// Largest compiled program of one regex, in bytes; bigger patterns are a rule error.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// Longest regex or glob source accepted, in bytes.
const MAX_PATTERN_LEN: usize = 4096;

/// Largest file `map_local` serves; larger files answer `413`.
const MAX_LOCAL_FILE: u64 = 64 * 1024 * 1024;

/// Longest rule name.
const MAX_NAME_LEN: usize = 64;

// ---------------------------------------------------------------------------------------
// The configuration, as written in the file and sent to the API.
// ---------------------------------------------------------------------------------------

/// A rules file: `[[rules]]` tables in order. The API uses the same shape in JSON.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesFile {
    /// The rules, first match first.
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

/// One rule: a name, a matcher and one action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    /// Unique name: ASCII letters, digits, `.`, `_`, `-`; at most 64 characters.
    pub name: String,
    /// Whether the rule runs.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Which exchanges the rule applies to; empty matches every exchange.
    #[serde(default, rename = "match")]
    pub matcher: MatchConfig,
    /// What the rule does.
    pub action: ActionConfig,
}

fn yes() -> bool {
    true
}

/// Which exchanges a rule applies to. Every field given must match.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchConfig {
    /// `http` or `https`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// Host glob (`*` any run of characters, `?` one), case-insensitive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Server port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Path glob, matched against the whole path without the query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Regex searched in the path and query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_regex: Option<String>,
    /// Methods; any of them matches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub method: Vec<String>,
    /// A header that must be present, optionally with a value matching a regex. Request
    /// headers for request-phase actions, response headers for response-phase ones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<HeaderMatch>,
    /// Response status; only for response-phase actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
}

/// A header condition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderMatch {
    /// Header name.
    pub name: String,
    /// Regex searched in each value; absent means any value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// Request or response, for actions that can do either.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RulePhase {
    /// Before the request goes to the server.
    #[default]
    Request,
    /// Before the response goes to the client.
    Response,
}

/// What a rule does, tagged by `type`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionConfig {
    /// Answer the request with `status` and `body`; the server is not contacted.
    Block {
        /// Status code (default 403).
        #[serde(default = "forbidden")]
        status: u16,
        /// Body text.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        body: Option<String>,
    },
    /// Replace the status of the response.
    Status {
        /// The new status code.
        status: u16,
    },
    /// Answer from a local file or directory; the server is not contacted.
    MapLocal {
        /// File, or directory served by request path (`index.html` for directories).
        /// Relative paths are relative to the rules file's directory.
        path: PathBuf,
        /// Prefix removed from the request path before it is looked up in a directory.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        strip_prefix: Option<String>,
    },
    /// Send the request to another server; the client still sees its own URL.
    MapRemote {
        /// New scheme, `http` or `https`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scheme: Option<String>,
        /// New host.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
        /// New port.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
        /// Path prefix to replace...
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path_from: Option<String>,
        /// ...with this one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path_to: Option<String>,
    },
    /// Change headers.
    RewriteHeaders {
        /// Request (default) or response headers.
        #[serde(default)]
        phase: RulePhase,
        /// Headers to set, replacing existing values.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        set: BTreeMap<String, String>,
        /// Headers to add next to existing values.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        add: BTreeMap<String, String>,
        /// Headers to remove.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        remove: Vec<String>,
        /// Regex replacements in the values of a header.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        replace: Vec<HeaderReplace>,
    },
    /// Change the body (buffered up to `--body-limit`).
    RewriteBody {
        /// Request (default) or response body.
        #[serde(default)]
        phase: RulePhase,
        /// Regex replacements, in order.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        replace: Vec<BodyReplace>,
        /// Values set at dotted key paths of a JSON body.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        json_set: Vec<JsonSet>,
    },
    /// Wait before the request goes on.
    Delay {
        /// Milliseconds.
        ms: u64,
    },
    /// Stream the response body at a bandwidth cap after a latency.
    Throttle {
        /// Bytes per second, at least 1.
        bytes_per_second: u64,
        /// Milliseconds before the first body byte.
        #[serde(default)]
        latency_ms: u64,
    },
    /// Hold the exchange until resumed, edited or aborted over the API.
    Breakpoint {
        /// Pause before the request goes to the server (default true).
        #[serde(default = "yes")]
        request: bool,
        /// Pause before the response goes to the client.
        #[serde(default)]
        response: bool,
    },
}

fn forbidden() -> u16 {
    403
}

/// A regex replacement in the values of one header.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderReplace {
    /// Header name.
    pub name: String,
    /// Regex.
    pub regex: String,
    /// Replacement; `$1` and `${name}` refer to groups.
    pub with: String,
}

/// A regex replacement in a body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BodyReplace {
    /// Regex, searched in the raw bytes.
    pub regex: String,
    /// Replacement; `$1` and `${name}` refer to groups.
    pub with: String,
}

/// A JSON value set at a key path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonSet {
    /// Dotted path such as `user.roles.0`; numbers index arrays. Missing objects are made.
    pub path: String,
    /// The value.
    pub value: serde_json::Value,
}

// ---------------------------------------------------------------------------------------
// Compiled rules.
// ---------------------------------------------------------------------------------------

/// A validated, compiled set of rules. Cheap to share; never changes once built.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
    needs_request_body: bool,
    needs_response_body: bool,
}

#[derive(Debug, Clone)]
struct Rule {
    config: RuleConfig,
    matcher: Matcher,
    action: Act,
}

#[derive(Debug, Clone, Default)]
struct Matcher {
    scheme: Option<String>,
    host: Option<Regex>,
    port: Option<u16>,
    path: Option<Regex>,
    path_regex: Option<Regex>,
    methods: Vec<Method>,
    header: Option<(HeaderName, Option<Regex>)>,
    status: Option<StatusCode>,
}

#[derive(Debug, Clone)]
enum Act {
    Block(StatusCode, Bytes),
    Status(StatusCode),
    MapLocal(MapLocal),
    MapRemote(MapRemote),
    Headers(RulePhase, HeaderEdits),
    Body(RulePhase, BodyEdits),
    Delay(Duration),
    Throttle(Throttle),
    Breakpoint { request: bool, response: bool },
}

#[derive(Debug, Clone)]
struct MapLocal {
    /// Canonical file or directory.
    root: PathBuf,
    is_dir: bool,
    strip_prefix: Option<String>,
}

#[derive(Debug, Clone)]
struct MapRemote {
    scheme: Option<&'static str>,
    host: Option<String>,
    port: Option<u16>,
    path: Option<(String, String)>,
}

#[derive(Debug, Clone, Default)]
struct HeaderEdits {
    set: Vec<(HeaderName, HeaderValue)>,
    add: Vec<(HeaderName, HeaderValue)>,
    remove: Vec<HeaderName>,
    replace: Vec<(HeaderName, Regex, String)>,
}

#[derive(Debug, Clone, Default)]
struct BodyEdits {
    replace: Vec<(regex::bytes::Regex, Vec<u8>)>,
    json_set: Vec<(Vec<String>, serde_json::Value)>,
}

impl RuleSet {
    /// Validates and compiles `file`. Relative `map_local` paths resolve against `base`
    /// (the rules file's directory), else the working directory.
    ///
    /// # Errors
    ///
    /// Fails with every rule error found, one per line: duplicate or invalid names, invalid
    /// regexes, globs, headers, status codes, phases or `map_local` paths.
    pub fn compile(file: &RulesFile, base: Option<&Path>) -> Result<Self, String> {
        let mut errors = String::new();
        let mut names = HashSet::new();
        let mut rules = Vec::with_capacity(file.rules.len());
        for (index, config) in file.rules.iter().enumerate() {
            if !names.insert(config.name.as_str()) {
                let _ = writeln!(
                    errors,
                    "rule {}: duplicate name {:?}",
                    index + 1,
                    config.name
                );
                continue;
            }
            match Rule::compile(config, base) {
                Ok(rule) => rules.push(rule),
                Err(e) => {
                    let _ = writeln!(errors, "rule {} ({:?}): {e}", index + 1, config.name);
                }
            }
        }
        if !errors.is_empty() {
            return Err(errors.trim_end().to_owned());
        }
        Ok(Self::from_rules(rules))
    }

    fn from_rules(rules: Vec<Rule>) -> Self {
        // Body rewrites need the body; so do breakpoints, so the pause shows it for editing.
        fn wants(rules: &[Rule], phase: RulePhase) -> bool {
            rules
                .iter()
                .filter(|r| r.config.enabled)
                .any(|r| match r.action {
                    Act::Body(p, _) => p == phase,
                    Act::Breakpoint { request, response } => match phase {
                        RulePhase::Request => request,
                        RulePhase::Response => response,
                    },
                    _ => false,
                })
        }
        let needs_request_body = wants(&rules, RulePhase::Request);
        let needs_response_body = wants(&rules, RulePhase::Response);
        Self {
            rules,
            needs_request_body,
            needs_response_body,
        }
    }

    /// The configuration of every rule, in order.
    #[must_use]
    pub fn configs(&self) -> RulesFile {
        RulesFile {
            rules: self.rules.iter().map(|r| r.config.clone()).collect(),
        }
    }

    /// Whether the set holds no rules.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The number of rules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    fn enabled(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().filter(|r| r.config.enabled)
    }
}

impl Rule {
    fn compile(config: &RuleConfig, base: Option<&Path>) -> Result<Self, String> {
        let name = &config.name;
        if name.is_empty()
            || name.len() > MAX_NAME_LEN
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(format!(
                "names are 1 to {MAX_NAME_LEN} of A-Z a-z 0-9 . _ -"
            ));
        }
        let matcher = Matcher::compile(&config.matcher)?;
        let action = Act::compile(&config.action, base)?;
        if matcher.status.is_some() && action.phases().0 {
            return Err("`status` in `match` needs a response-phase action".to_owned());
        }
        Ok(Self {
            config: config.clone(),
            matcher,
            action,
        })
    }

    fn flag(&self) -> Flag {
        Flag::Rule(self.config.name.clone())
    }
}

fn regex(pattern: &str) -> Result<Regex, String> {
    if pattern.len() > MAX_PATTERN_LEN {
        return Err(format!("pattern longer than {MAX_PATTERN_LEN} bytes"));
    }
    regex::RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| format!("regex {pattern:?}: {e}"))
}

fn bytes_regex(pattern: &str) -> Result<regex::bytes::Regex, String> {
    if pattern.len() > MAX_PATTERN_LEN {
        return Err(format!("pattern longer than {MAX_PATTERN_LEN} bytes"));
    }
    regex::bytes::RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| format!("regex {pattern:?}: {e}"))
}

/// Compiles a glob (`*` any run of characters, `?` one character) to an anchored regex.
fn glob(pattern: &str, case_insensitive: bool) -> Result<Regex, String> {
    if pattern.len() > MAX_PATTERN_LEN {
        return Err(format!("glob longer than {MAX_PATTERN_LEN} bytes"));
    }
    let mut source = String::from("^");
    let mut buf = [0_u8; 4];
    for c in pattern.chars() {
        match c {
            '*' => source.push_str(".*"),
            '?' => source.push('.'),
            c => source.push_str(&regex::escape(c.encode_utf8(&mut buf))),
        }
    }
    source.push('$');
    regex::RegexBuilder::new(&source)
        .case_insensitive(case_insensitive)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| format!("glob {pattern:?}: {e}"))
}

fn status(code: u16) -> Result<StatusCode, String> {
    if (100..=599).contains(&code) {
        StatusCode::from_u16(code).map_err(|e| e.to_string())
    } else {
        Err(format!("status {code} is not in 100..=599"))
    }
}

fn header_name(name: &str) -> Result<HeaderName, String> {
    HeaderName::from_bytes(name.as_bytes()).map_err(|_| format!("invalid header name {name:?}"))
}

fn header_pair(name: &str, value: &str) -> Result<(HeaderName, HeaderValue), String> {
    let value =
        HeaderValue::from_str(value).map_err(|_| format!("invalid value for header {name:?}"))?;
    Ok((header_name(name)?, value))
}

fn scheme(text: &str) -> Result<&'static str, String> {
    match text.to_ascii_lowercase().as_str() {
        "http" => Ok("http"),
        "https" => Ok("https"),
        _ => Err(format!("scheme {text:?} is not http or https")),
    }
}

impl Matcher {
    fn compile(config: &MatchConfig) -> Result<Self, String> {
        Ok(Self {
            scheme: config
                .scheme
                .as_deref()
                .map(|s| scheme(s).map(str::to_owned))
                .transpose()?,
            host: config.host.as_deref().map(|h| glob(h, true)).transpose()?,
            port: config.port,
            path: config.path.as_deref().map(|p| glob(p, false)).transpose()?,
            path_regex: config.path_regex.as_deref().map(regex).transpose()?,
            methods: config
                .method
                .iter()
                .map(|m| {
                    Method::from_bytes(m.to_ascii_uppercase().as_bytes())
                        .map_err(|_| format!("invalid method {m:?}"))
                })
                .collect::<Result<_, _>>()?,
            header: config
                .header
                .as_ref()
                .map(|h| {
                    Ok::<_, String>((
                        header_name(&h.name)?,
                        h.value.as_deref().map(regex).transpose()?,
                    ))
                })
                .transpose()?,
            status: config.status.map(status).transpose()?,
        })
    }

    /// Whether the exchange matches. `headers` are the request headers in the request
    /// phase and the response headers in the response phase; `status` is `None` in the
    /// request phase.
    fn matches(&self, seen: &Seen, headers: &HeaderMap, status: Option<StatusCode>) -> bool {
        let path_only = seen
            .path
            .split_once('?')
            .map_or(seen.path.as_str(), |(p, _)| p);
        self.scheme.as_deref().is_none_or(|s| s == seen.scheme)
            && self
                .host
                .as_ref()
                .is_none_or(|h| h.is_match(seen.host.trim_end_matches('.')))
            && self.port.is_none_or(|p| p == seen.port)
            && self.path.as_ref().is_none_or(|p| p.is_match(path_only))
            && self
                .path_regex
                .as_ref()
                .is_none_or(|r| r.is_match(&seen.path))
            && (self.methods.is_empty() || self.methods.contains(&seen.method))
            && self.header.as_ref().is_none_or(|(name, value)| {
                headers.get_all(name).iter().any(|v| {
                    value
                        .as_ref()
                        .is_none_or(|r| v.to_str().is_ok_and(|v| r.is_match(v)))
                })
            })
            && self.status.is_none_or(|s| Some(s) == status)
    }
}

impl Act {
    #[expect(clippy::too_many_lines, reason = "one arm per action kind")]
    fn compile(config: &ActionConfig, base: Option<&Path>) -> Result<Self, String> {
        Ok(match config {
            ActionConfig::Block { status: code, body } => Self::Block(
                status(*code)?,
                Bytes::from(body.clone().unwrap_or_default()),
            ),
            ActionConfig::Status { status: code } => Self::Status(status(*code)?),
            ActionConfig::MapLocal { path, strip_prefix } => {
                let path = match base {
                    Some(base) if path.is_relative() => base.join(path),
                    _ => path.clone(),
                };
                let root = path
                    .canonicalize()
                    .map_err(|e| format!("map_local path {}: {e}", path.display()))?;
                Self::MapLocal(MapLocal {
                    is_dir: root.is_dir(),
                    root,
                    strip_prefix: strip_prefix.clone(),
                })
            }
            ActionConfig::MapRemote {
                scheme: new_scheme,
                host,
                port,
                path_from,
                path_to,
            } => {
                if let Some(host) = host
                    && (host.is_empty()
                        || host.len() > 253
                        || !host.bytes().all(|b| {
                            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'_')
                        }))
                {
                    return Err(format!("invalid map_remote host {host:?}"));
                }
                let path = match (path_from, path_to) {
                    (None, None) => None,
                    (Some(from), Some(to)) if from.starts_with('/') && to.starts_with('/') => {
                        Some((from.clone(), to.clone()))
                    }
                    _ => {
                        return Err(
                            "map_remote needs both path_from and path_to, each starting with /"
                                .to_owned(),
                        );
                    }
                };
                Self::MapRemote(MapRemote {
                    scheme: new_scheme.as_deref().map(scheme).transpose()?,
                    host: host.clone(),
                    port: *port,
                    path,
                })
            }
            ActionConfig::RewriteHeaders {
                phase,
                set,
                add,
                remove,
                replace,
            } => Self::Headers(
                *phase,
                HeaderEdits {
                    set: set
                        .iter()
                        .map(|(n, v)| header_pair(n, v))
                        .collect::<Result<_, _>>()?,
                    add: add
                        .iter()
                        .map(|(n, v)| header_pair(n, v))
                        .collect::<Result<_, _>>()?,
                    remove: remove
                        .iter()
                        .map(|n| header_name(n))
                        .collect::<Result<_, _>>()?,
                    replace: replace
                        .iter()
                        .map(|r| Ok((header_name(&r.name)?, regex(&r.regex)?, r.with.clone())))
                        .collect::<Result<_, String>>()?,
                },
            ),
            ActionConfig::RewriteBody {
                phase,
                replace,
                json_set,
            } => Self::Body(
                *phase,
                BodyEdits {
                    replace: replace
                        .iter()
                        .map(|r| Ok((bytes_regex(&r.regex)?, r.with.clone().into_bytes())))
                        .collect::<Result<_, String>>()?,
                    json_set: json_set
                        .iter()
                        .map(|j| {
                            if j.path.is_empty() {
                                return Err("json_set needs a non-empty path".to_owned());
                            }
                            Ok((
                                j.path.split('.').map(str::to_owned).collect(),
                                j.value.clone(),
                            ))
                        })
                        .collect::<Result<_, String>>()?,
                },
            ),
            ActionConfig::Delay { ms } => Self::Delay(Duration::from_millis(*ms)),
            ActionConfig::Throttle {
                bytes_per_second,
                latency_ms,
            } => Self::Throttle(Throttle {
                rate: NonZeroU64::new(*bytes_per_second)
                    .ok_or("throttle needs bytes_per_second of at least 1")?,
                latency: Duration::from_millis(*latency_ms),
            }),
            ActionConfig::Breakpoint { request, response } => {
                if !request && !response {
                    return Err("a breakpoint needs request or response".to_owned());
                }
                Self::Breakpoint {
                    request: *request,
                    response: *response,
                }
            }
        })
    }

    /// Whether the action runs in the request phase, the response phase.
    fn phases(&self) -> (bool, bool) {
        match self {
            Self::Block(..) | Self::MapLocal(_) | Self::MapRemote(_) | Self::Delay(_) => {
                (true, false)
            }
            Self::Status(_) | Self::Throttle(_) => (false, true),
            Self::Headers(phase, _) | Self::Body(phase, _) => {
                (*phase == RulePhase::Request, *phase == RulePhase::Response)
            }
            Self::Breakpoint { request, response } => (*request, *response),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Applying rules.
// ---------------------------------------------------------------------------------------

/// The request as the client sent it, which every rule of the exchange matches against.
#[derive(Debug)]
struct Seen {
    scheme: &'static str,
    host: String,
    port: u16,
    method: Method,
    path: String,
    headers: HeaderMap,
}

/// What an exchange keeps in [`RequestCtx::extensions`]: its rule set and what it matched.
#[derive(Debug, Clone)]
struct Snapshot {
    set: Arc<RuleSet>,
    seen: Arc<Seen>,
}

impl Snapshot {
    fn take(rules: &Rules, ctx: &RequestCtx) -> Self {
        Self {
            set: rules.current(),
            seen: Arc::new(Seen {
                scheme: ctx.scheme,
                host: ctx.host.clone(),
                port: ctx.port,
                method: ctx.method.clone(),
                path: ctx.path.clone(),
                headers: ctx.headers.clone(),
            }),
        }
    }

    /// The exchange's snapshot, taken by the first stage; taken now if missing.
    fn of(rules: &Rules, ctx: &mut RequestCtx) -> Self {
        if let Some(snapshot) = ctx.extensions.get::<Self>() {
            return snapshot.clone();
        }
        let snapshot = Self::take(rules, ctx);
        ctx.extensions.insert(snapshot.clone());
        snapshot
    }

    /// The enabled request-phase rules that match, in order.
    fn request_rules(&self) -> impl Iterator<Item = &Rule> {
        self.set.enabled().filter(|r| {
            r.action.phases().0 && r.matcher.matches(&self.seen, &self.seen.headers, None)
        })
    }

    /// The enabled response-phase rules that match `response`, in order.
    fn response_rules(&self, response: &ResponseCtx) -> Vec<&Rule> {
        self.set
            .enabled()
            .filter(|r| {
                r.action.phases().1
                    && r.matcher
                        .matches(&self.seen, &response.headers, Some(response.status))
            })
            .collect()
    }
}

impl HeaderEdits {
    fn apply(&self, headers: &mut HeaderMap) {
        for name in &self.remove {
            headers.remove(name);
        }
        for (name, value) in &self.set {
            headers.insert(name.clone(), value.clone());
        }
        for (name, value) in &self.add {
            headers.append(name.clone(), value.clone());
        }
        for (name, regex, with) in &self.replace {
            let values: Vec<HeaderValue> = headers
                .get_all(name)
                .iter()
                .map(|value| {
                    value
                        .to_str()
                        .ok()
                        .map(|text| regex.replace_all(text, with.as_str()))
                        .and_then(|text| HeaderValue::from_str(&text).ok())
                        .unwrap_or_else(|| value.clone())
                })
                .collect();
            headers.remove(name);
            for value in values {
                headers.append(name.clone(), value);
            }
        }
    }
}

impl BodyEdits {
    fn apply(&self, body: &Bytes) -> Bytes {
        let mut bytes = body.to_vec();
        for (regex, with) in &self.replace {
            bytes = regex.replace_all(&bytes, with.as_slice()).into_owned();
        }
        if !self.json_set.is_empty()
            && let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(&bytes)
        {
            for (path, value) in &self.json_set {
                json_set(&mut json, path, value.clone());
            }
            if let Ok(out) = serde_json::to_vec(&json) {
                bytes = out;
            }
        }
        Bytes::from(bytes)
    }
}

/// Sets `value` at `path` in `json`, making objects for missing keys. An index past the end
/// of an array appends; a key into a non-object, non-array value replaces it with an object.
fn json_set(json: &mut serde_json::Value, path: &[String], value: serde_json::Value) {
    let Some((key, rest)) = path.split_first() else {
        *json = value;
        return;
    };
    let slot = match json {
        serde_json::Value::Array(items) => match key.parse::<usize>() {
            Ok(index) if index < items.len() => &mut items[index],
            Ok(_) => {
                items.push(serde_json::Value::Null);
                items.last_mut().expect("just pushed")
            }
            Err(_) => return,
        },
        other => {
            if !other.is_object() {
                *other = serde_json::Value::Object(serde_json::Map::new());
            }
            let serde_json::Value::Object(map) = other else {
                return;
            };
            map.entry(key.clone()).or_insert(serde_json::Value::Null)
        }
    };
    json_set(slot, rest, value);
}

impl MapRemote {
    fn apply(&self, ctx: &mut RequestCtx) {
        if let Some(scheme) = self.scheme {
            ctx.scheme = scheme;
            if self.port.is_none() {
                ctx.port = if scheme == "https" { 443 } else { 80 };
            }
        }
        if let Some(host) = &self.host {
            host.clone_into(&mut ctx.host);
        }
        if let Some(port) = self.port {
            ctx.port = port;
        }
        if let Some((from, to)) = &self.path
            && let Some(rest) = ctx.path.strip_prefix(from.as_str())
        {
            ctx.path = format!("{to}{rest}");
        }
    }
}

impl MapLocal {
    /// The response for `path` (path and query of the request).
    fn respond(&self, path: &str) -> Response<Bytes> {
        let file = if self.is_dir {
            match self.resolve(path) {
                Ok(file) => file,
                Err(status) => return plain(status, "map_local: not served\n"),
            }
        } else {
            self.root.clone()
        };
        match std::fs::metadata(&file) {
            Ok(meta) if meta.len() > MAX_LOCAL_FILE => {
                return plain(StatusCode::PAYLOAD_TOO_LARGE, "map_local: file too large\n");
            }
            Ok(_) => {}
            Err(_) => return plain(StatusCode::NOT_FOUND, "map_local: no such file\n"),
        }
        match std::fs::read(&file) {
            Ok(data) => {
                let mut response = Response::new(Bytes::from(data));
                response.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static(content_type(&file)),
                );
                response
            }
            Err(_) => plain(StatusCode::NOT_FOUND, "map_local: no such file\n"),
        }
    }

    /// Maps a request path into the directory, refusing anything that could leave it.
    ///
    /// # Errors
    ///
    /// `400` for a path with `..`, `.`, a backslash, a colon, a NUL or bad percent-encoding;
    /// `404` when the file does not exist or resolves (through symlinks) outside the root.
    fn resolve(&self, path: &str) -> Result<PathBuf, StatusCode> {
        let path = path.split_once('?').map_or(path, |(p, _)| p);
        let path = match &self.strip_prefix {
            Some(prefix) => path.strip_prefix(prefix.as_str()).unwrap_or(path),
            None => path,
        };
        let decoded = percent_decode(path).ok_or(StatusCode::BAD_REQUEST)?;
        let mut file = self.root.clone();
        for segment in decoded.split('/').filter(|s| !s.is_empty()) {
            if segment == "."
                || segment == ".."
                || segment.contains(['\\', ':', '\0'])
                || Path::new(segment)
                    .components()
                    .any(|c| !matches!(c, Component::Normal(_)))
            {
                return Err(StatusCode::BAD_REQUEST);
            }
            file.push(segment);
        }
        if file.is_dir() {
            file.push("index.html");
        }
        // Symlinks are resolved here; whatever they point at must still be inside the root.
        let real = file.canonicalize().map_err(|_| StatusCode::NOT_FOUND)?;
        if real.starts_with(&self.root) && real.is_file() {
            Ok(real)
        } else {
            Err(StatusCode::NOT_FOUND)
        }
    }
}

/// Decodes `%XX` escapes; `None` on a bad escape or invalid UTF-8.
fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The content type for a file's extension.
fn content_type(path: &Path) -> &'static str {
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    match extension.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" | "map" => "application/json",
        "txt" | "log" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "csv" => "text/csv; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "mp4" => "video/mp4",
        _ => "application/octet-stream",
    }
}

// ---------------------------------------------------------------------------------------
// The shared handle and its chain stages.
// ---------------------------------------------------------------------------------------

/// The live rules: the current set, where it came from and the last load error. Cloning is
/// cheap; all clones share the same set.
#[derive(Debug, Clone, Default)]
pub struct Rules {
    inner: Arc<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    current: RwLock<Arc<RuleSet>>,
    status: Mutex<Status>,
}

#[derive(Debug, Default, Clone)]
struct Status {
    file: Option<PathBuf>,
    error: Option<String>,
    modified: Option<SystemTime>,
}

/// The state `GET /api/v1/rules` reports.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// The current rules.
    pub rules: Vec<RuleConfig>,
    /// The watched rules file, if any.
    pub file: Option<PathBuf>,
    /// Why the last load of the file failed; the previous rules stay in force.
    pub error: Option<String>,
}

impl Rules {
    /// No rules.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads `path`; [`Rules::watch`] keeps it up to date afterwards.
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be read, parsed or compiled.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let rules = Self::new();
        let modified = modified(path);
        let set = load(path).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        rules.swap(set);
        {
            let mut status = rules.status();
            status.file = Some(path.to_owned());
            status.modified = modified;
        }
        Ok(rules)
    }

    /// The current set.
    ///
    /// # Panics
    ///
    /// When a thread panicked while swapping the set (lock poisoning).
    #[must_use]
    pub fn current(&self) -> Arc<RuleSet> {
        Arc::clone(&self.inner.current.read().expect("rules lock poisoned"))
    }

    /// Replaces the whole set at once. Exchanges in flight keep the set they started with.
    ///
    /// # Errors
    ///
    /// Fails with the rule errors; the current set stays.
    pub fn replace(&self, file: &RulesFile) -> Result<(), String> {
        let base = self
            .status()
            .file
            .as_deref()
            .and_then(Path::parent)
            .map(Path::to_owned);
        let set = RuleSet::compile(file, base.as_deref())?;
        self.swap(set);
        Ok(())
    }

    /// Flips `enabled` of rule `name`; returns the new state, or `None` for no such rule.
    ///
    /// # Panics
    ///
    /// When a thread panicked while swapping the set (lock poisoning).
    #[must_use = "None means there is no such rule"]
    pub fn toggle(&self, name: &str) -> Option<bool> {
        let mut current = self.inner.current.write().expect("rules lock poisoned");
        let mut rules = current.rules.clone();
        let rule = rules.iter_mut().find(|r| r.config.name == name)?;
        rule.config.enabled = !rule.config.enabled;
        let enabled = rule.config.enabled;
        *current = Arc::new(RuleSet::from_rules(rules));
        Some(enabled)
    }

    /// What `GET /api/v1/rules` shows.
    #[must_use]
    pub fn report(&self) -> Report {
        let status = self.status().clone();
        Report {
            rules: self.current().configs().rules,
            file: status.file,
            error: status.error,
        }
    }

    /// Reloads the watched file when its modification time changed. A broken file keeps
    /// the previous rules; the error goes to [`Report::error`] and stderr. Returns whether
    /// a new set was installed.
    #[expect(
        clippy::must_use_candidate,
        reason = "the watcher calls it for the side effect"
    )]
    pub fn reload_if_changed(&self) -> bool {
        let Some(path) = self.status().file.clone() else {
            return false;
        };
        let modified = modified(&path);
        if modified == self.status().modified {
            return false;
        }
        let result = load(&path);
        let mut status = self.status();
        status.modified = modified;
        match result {
            Ok(set) => {
                status.error = None;
                drop(status);
                self.swap(set);
                true
            }
            Err(e) => {
                eprintln!(
                    "{}: {}: {e}; keeping the previous rules",
                    crate::NAME,
                    path.display()
                );
                status.error = Some(e);
                false
            }
        }
    }

    /// Polls the rules file every `interval` and reloads it when it changes. The task ends
    /// when every other clone of this handle is gone.
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

    /// The chain stages to register, in this order: delay, main (rewrites, map-remote,
    /// block, map-local, status, throttle), breakpoint. `pauses` is the proxy's registry.
    #[must_use]
    pub fn interceptors(&self, pauses: &Pauses) -> Vec<Arc<dyn Interceptor>> {
        vec![
            Arc::new(DelayStage(self.clone())),
            Arc::new(MainStage(self.clone())),
            Arc::new(BreakpointStage(self.clone(), pauses.clone())),
        ]
    }

    fn swap(&self, set: RuleSet) {
        *self.inner.current.write().expect("rules lock poisoned") = Arc::new(set);
    }

    fn status(&self) -> std::sync::MutexGuard<'_, Status> {
        self.inner
            .status
            .lock()
            .expect("rules status lock poisoned")
    }
}

fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

fn load(path: &Path) -> Result<RuleSet, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let file: RulesFile = toml::from_str(&text).map_err(|e| e.to_string())?;
    RuleSet::compile(&file, path.parent())
}

/// Stage 1: takes the exchange's snapshot and sums the matching delays.
struct DelayStage(Rules);

impl Interceptor for DelayStage {
    fn name(&self) -> &'static str {
        "rules:delay"
    }

    fn on_request(&self, request: &mut RequestCtx) -> Action {
        let snapshot = Snapshot::of(&self.0, request);
        let mut total = Duration::ZERO;
        for rule in snapshot.request_rules() {
            if let Act::Delay(delay) = rule.action {
                total += delay;
                request.flags.push(rule.flag());
            }
        }
        if total.is_zero() {
            Action::Continue
        } else {
            Action::Delay(total)
        }
    }
}

/// Stage 2: rewrites, map-remote and the answering actions, in rule order.
struct MainStage(Rules);

impl Interceptor for MainStage {
    fn name(&self) -> &'static str {
        "rules"
    }

    fn needs_request_body(&self) -> bool {
        self.0.current().needs_request_body
    }

    fn needs_response_body(&self) -> bool {
        self.0.current().needs_response_body
    }

    fn on_request(&self, request: &mut RequestCtx) -> Action {
        let snapshot = Snapshot::of(&self.0, request);
        for rule in snapshot.request_rules() {
            let flag = rule.flag();
            match &rule.action {
                Act::Block(status, body) => {
                    request.flags.push(flag);
                    let mut response = Response::new(body.clone());
                    *response.status_mut() = *status;
                    return Action::Respond(response);
                }
                Act::MapLocal(local) => {
                    request.flags.push(flag);
                    return Action::Respond(local.respond(&snapshot.seen.path));
                }
                Act::MapRemote(remote) => remote.apply(request),
                Act::Headers(_, edits) => edits.apply(&mut request.headers),
                Act::Body(_, edits) => match &request.body {
                    Some(body) => request.body = Some(edits.apply(body)),
                    None => continue,
                },
                _ => continue,
            }
            request.flags.push(flag);
        }
        Action::Continue
    }

    fn on_response(&self, request: &RequestCtx, response: &mut ResponseCtx) -> Action {
        let Some(snapshot) = request.extensions.get::<Snapshot>() else {
            return Action::Continue;
        };
        for rule in snapshot.response_rules(response) {
            match &rule.action {
                Act::Status(status) => response.status = *status,
                Act::Headers(_, edits) => edits.apply(&mut response.headers),
                Act::Body(_, edits) => match &response.body {
                    Some(body) => response.body = Some(edits.apply(body)),
                    None => continue,
                },
                Act::Throttle(throttle) => response.throttle = Some(*throttle),
                _ => continue,
            }
            response.flags.push(rule.flag());
        }
        Action::Continue
    }
}

/// Stage 3: one pause per phase when any breakpoint rule matches.
struct BreakpointStage(Rules, Pauses);

impl Interceptor for BreakpointStage {
    fn name(&self) -> &'static str {
        "rules:breakpoint"
    }

    fn on_request(&self, request: &mut RequestCtx) -> Action {
        let snapshot = Snapshot::of(&self.0, request);
        let hits: Vec<Flag> = snapshot
            .request_rules()
            .filter(|r| matches!(r.action, Act::Breakpoint { request: true, .. }))
            .map(Rule::flag)
            .collect();
        if hits.is_empty() {
            return Action::Continue;
        }
        request.flags.extend(hits);
        let detail = Paused::of_request(request);
        Action::Pause(self.1.pause_with(request.id, Phase::Request, detail))
    }

    fn on_response(&self, request: &RequestCtx, response: &mut ResponseCtx) -> Action {
        let Some(snapshot) = request.extensions.get::<Snapshot>() else {
            return Action::Continue;
        };
        let hits: Vec<Flag> = snapshot
            .response_rules(response)
            .into_iter()
            .filter(|r| matches!(r.action, Act::Breakpoint { response: true, .. }))
            .map(Rule::flag)
            .collect();
        if hits.is_empty() {
            return Action::Continue;
        }
        response.flags.extend(hits);
        let detail = Paused::of_response(request, response);
        Action::Pause(self.1.pause_with(request.id, Phase::Response, detail))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(toml: &str) -> Result<RuleSet, String> {
        let file: RulesFile = toml::from_str(toml).map_err(|e| e.to_string())?;
        RuleSet::compile(&file, None)
    }

    fn seen(method: Method, host: &str, path: &str) -> Seen {
        let mut headers = HeaderMap::new();
        headers.insert("x-debug", HeaderValue::from_static("on-123"));
        Seen {
            scheme: "https",
            host: host.to_owned(),
            port: 443,
            method,
            path: path.to_owned(),
            headers,
        }
    }

    fn matcher(toml: &str) -> Matcher {
        let config: MatchConfig = toml::from_str(toml).expect("valid matcher");
        Matcher::compile(&config).expect("compiles")
    }

    fn hit(m: &Matcher, s: &Seen) -> bool {
        m.matches(s, &s.headers, None)
    }

    #[test]
    fn host_globs_are_anchored_and_case_insensitive() {
        let m = matcher(r#"host = "*.Example.com""#);
        assert!(hit(&m, &seen(Method::GET, "api.example.COM", "/")));
        assert!(hit(&m, &seen(Method::GET, "a.b.example.com.", "/")));
        assert!(!hit(&m, &seen(Method::GET, "example.com", "/")));
        assert!(!hit(&m, &seen(Method::GET, "api.example.com.evil", "/")));
        let m = matcher(r#"host = "api?.test""#);
        assert!(hit(&m, &seen(Method::GET, "api1.test", "/")));
        assert!(!hit(&m, &seen(Method::GET, "api12.test", "/")));
    }

    #[test]
    fn path_globs_ignore_the_query_and_regexes_see_it() {
        let m = matcher(r#"path = "/api/*/items""#);
        assert!(hit(&m, &seen(Method::GET, "h", "/api/v1/items?page=2")));
        assert!(!hit(&m, &seen(Method::GET, "h", "/api/v1/items/3")));
        let m = matcher(r#"path_regex = "page=\\d+$""#);
        assert!(hit(&m, &seen(Method::GET, "h", "/x?page=12")));
        assert!(!hit(&m, &seen(Method::GET, "h", "/x?page=a")));
        // Regex metacharacters in a glob are literal.
        let m = matcher(r#"path = "/a.b""#);
        assert!(!hit(&m, &seen(Method::GET, "h", "/axb")));
    }

    #[test]
    fn methods_headers_ports_and_schemes_match() {
        let m = matcher(r#"method = ["get", "POST"]"#);
        assert!(hit(&m, &seen(Method::POST, "h", "/")));
        assert!(!hit(&m, &seen(Method::PUT, "h", "/")));
        let m = matcher("header = { name = \"X-Debug\", value = \"^on-\\\\d+$\" }");
        assert!(hit(&m, &seen(Method::GET, "h", "/")));
        let m = matcher(r#"header = { name = "x-debug", value = "^off" }"#);
        assert!(!hit(&m, &seen(Method::GET, "h", "/")));
        let m = matcher(r#"header = { name = "x-missing" }"#);
        assert!(!hit(&m, &seen(Method::GET, "h", "/")));
        let m = matcher("port = 8443");
        assert!(!hit(&m, &seen(Method::GET, "h", "/")));
        let m = matcher(r#"scheme = "HTTPS""#);
        assert!(hit(&m, &seen(Method::GET, "h", "/")));
    }

    #[test]
    fn invalid_rules_are_errors_not_panics() {
        let bad = [
            r#"[[rules]]
name = "r"
match = { path_regex = "(unclosed" }
action = { type = "block" }"#,
            r#"[[rules]]
name = "r"
action = { type = "rewrite_headers", set = { "x-a" = "line\r\nbreak" } }"#,
            r#"[[rules]]
name = "bad name!"
action = { type = "block" }"#,
            r#"[[rules]]
name = "r"
match = { status = 200 }
action = { type = "block" }"#,
            r#"[[rules]]
name = "r"
action = { type = "throttle", bytes_per_second = 0 }"#,
            r#"[[rules]]
name = "r"
action = { type = "block", status = 1000 }"#,
            r#"[[rules]]
name = "r"
match = { path_regex = "a{1000}{1000}" }
action = { type = "block" }"#,
            r#"[[rules]]
name = "r"
action = { type = "map_local", path = "/definitely/not/here" }"#,
            r#"[[rules]]
name = "r"
action = { type = "block" }
[[rules]]
name = "r"
action = { type = "block" }"#,
        ];
        for toml in bad {
            assert!(set(toml).is_err(), "should fail: {toml}");
        }
        let unknown = "[[rules]]\nname = \"r\"\naction = { type = \"block\", stauts = 1 }";
        assert!(toml::from_str::<RulesFile>(unknown).is_err(), "typos fail");
    }

    #[test]
    fn configs_round_trip_through_json() -> Result<(), String> {
        let rules = set(r#"
[[rules]]
name = "a"
enabled = false
match = { host = "*.test", method = ["GET"] }
action = { type = "rewrite_body", phase = "response", json_set = [{ path = "a.0", value = 1 }] }
"#)?;
        let json = serde_json::to_string(&rules.configs()).map_err(|e| e.to_string())?;
        let back: RulesFile = serde_json::from_str(&json).map_err(|e| e.to_string())?;
        assert_eq!(back, rules.configs());
        Ok(())
    }

    #[test]
    fn json_set_makes_paths_and_indexes_arrays() {
        let mut json = serde_json::json!({"a": [1, {"b": 2}], "s": "x"});
        let path = |p: &str| p.split('.').map(str::to_owned).collect::<Vec<_>>();
        json_set(&mut json, &path("a.1.b"), serde_json::json!(3));
        json_set(&mut json, &path("a.5"), serde_json::json!(4));
        json_set(&mut json, &path("new.deep"), serde_json::json!(true));
        json_set(&mut json, &path("s.t"), serde_json::json!(null));
        assert_eq!(
            json,
            serde_json::json!({"a": [1, {"b": 3}, 4], "s": {"t": null}, "new": {"deep": true}})
        );
    }

    #[test]
    fn header_and_body_rewrites_apply() -> Result<(), String> {
        let rules = set(r#"
[[rules]]
name = "h"
action = { type = "rewrite_headers", set = { "x-a" = "1" }, add = { "x-b" = "2" }, remove = ["x-c"], replace = [{ name = "x-d", regex = "v(\\d)", with = "w$1" }] }
[[rules]]
name = "b"
action = { type = "rewrite_body", replace = [{ regex = "cat", with = "dog" }], json_set = [{ path = "n", value = 2 }] }
"#)?;
        let Act::Headers(_, headers) = &rules.rules[0].action else {
            return Err("headers".to_owned());
        };
        let mut map = HeaderMap::new();
        map.insert("x-c", HeaderValue::from_static("gone"));
        map.insert("x-b", HeaderValue::from_static("1"));
        map.insert("x-d", HeaderValue::from_static("v1 v2"));
        headers.apply(&mut map);
        assert_eq!(map["x-a"], "1");
        assert_eq!(map.get_all("x-b").iter().count(), 2);
        assert!(map.get("x-c").is_none());
        assert_eq!(map["x-d"], "w1 w2");
        let Act::Body(_, body) = &rules.rules[1].action else {
            return Err("body".to_owned());
        };
        let out = body.apply(&Bytes::from_static(br#"{"pet":"cat","n":1}"#));
        let out: serde_json::Value = serde_json::from_slice(&out).map_err(|e| e.to_string())?;
        assert_eq!(out, serde_json::json!({"n": 2, "pet": "dog"}));
        assert!(rules.needs_request_body && !rules.needs_response_body);
        Ok(())
    }

    #[test]
    fn map_remote_rewrites_the_target() -> Result<(), String> {
        let rules = set(r#"
[[rules]]
name = "m"
action = { type = "map_remote", scheme = "http", host = "127.0.0.1", path_from = "/v1", path_to = "/v2" }
"#)?;
        let Act::MapRemote(remote) = &rules.rules[0].action else {
            return Err("map_remote".to_owned());
        };
        let mut ctx = RequestCtx {
            id: 1,
            client: ([127, 0, 0, 1], 1).into(),
            scheme: "https",
            host: "api.test".to_owned(),
            port: 443,
            method: Method::GET,
            path: "/v1/users?x=1".to_owned(),
            headers: HeaderMap::new(),
            body: None,
            flags: Vec::new(),
            extensions: http::Extensions::new(),
        };
        remote.apply(&mut ctx);
        assert_eq!(
            (ctx.scheme, ctx.host.as_str(), ctx.port, ctx.path.as_str()),
            ("http", "127.0.0.1", 80, "/v2/users?x=1")
        );
        Ok(())
    }

    #[test]
    fn percent_decoding_is_strict() {
        assert_eq!(percent_decode("/a%20b").as_deref(), Some("/a b"));
        assert_eq!(percent_decode("%2e%2E").as_deref(), Some(".."));
        assert_eq!(percent_decode("%zz"), None);
        assert_eq!(percent_decode("%2"), None);
        assert_eq!(percent_decode("%ff"), None, "invalid UTF-8");
    }
}
