//! Session files: finished flows as JSON Lines, one [`Flow`] per line, the same
//! serialisation as `--json` (with `schema_version`), and WebSocket messages as
//! [`WsRecord`] lines (`"type": "ws_message"`) after the flow they belong to.
//!
//! Session files hold whatever the traffic held: bearer tokens, cookies, passwords in form
//! bodies. They are created readable by the owner only (mode 0600 on unix).

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read as _, Write as _};
use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::{self, error::RecvError};

use crate::console::escape;
use crate::events::{Flow, FlowEvent, SCHEMA_VERSION};
use crate::query::Query;
use crate::ws::{WsMessage, WsStore};

/// The `type` of a WebSocket message line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WsRecordType {
    /// `ws_message`.
    WsMessage,
}

/// One WebSocket message as a session line: `schema_version`, `"type": "ws_message"` and
/// the [`WsMessage`] fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsRecord {
    /// The schema version of this record.
    pub schema_version: u32,
    /// Always [`WsRecordType::WsMessage`].
    #[serde(rename = "type")]
    pub kind: WsRecordType,
    /// The message; its fields are flattened into this object.
    #[serde(flatten)]
    pub message: WsMessage,
}

/// Longest line [`read`] accepts, in bytes.
pub const MAX_LINE: usize = 64 * 1024 * 1024;

/// Appends flows to a session file.
#[derive(Debug)]
pub struct SessionWriter {
    file: BufWriter<File>,
}

/// Whether [`SessionWriter::create`] may add to an existing file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Existing {
    /// Append to it.
    Append,
    /// Refuse it.
    Refuse,
}

impl SessionWriter {
    /// Opens `path` for appending, creating it with mode 0600 on unix. An existing file
    /// readable by others is narrowed to 0600 with a warning on stderr; a symbolic link at
    /// `path` is refused.
    ///
    /// # Errors
    ///
    /// Fails when `path` is a symbolic link, the file cannot be opened or narrowed, or it
    /// exists and `existing` is [`Existing::Refuse`].
    pub fn create(path: &Path, existing: Existing) -> io::Result<Self> {
        crate::private_file::refuse_symlink(path)?;
        let mut options = OpenOptions::new();
        match existing {
            Existing::Append => options.append(true).create(true),
            Existing::Refuse => options.write(true).create_new(true),
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        if crate::private_file::narrow_to_owner(&file)? {
            eprintln!(
                "{}: warning: {} was open to other users; narrowed it to mode 0600",
                crate::NAME,
                path.display()
            );
        }
        Ok(Self {
            file: BufWriter::new(file),
        })
    }

    /// Writes one flow as a line and flushes it, so a crash loses at most that line.
    ///
    /// # Errors
    ///
    /// Fails when writing fails.
    pub fn append(&mut self, flow: &Flow) -> io::Result<()> {
        self.line(flow)
    }

    /// Writes one WebSocket message as a [`WsRecord`] line and flushes it.
    ///
    /// # Errors
    ///
    /// Fails when writing fails.
    pub fn append_message(&mut self, message: &WsMessage) -> io::Result<()> {
        self.line(&WsRecord {
            schema_version: SCHEMA_VERSION,
            kind: WsRecordType::WsMessage,
            message: message.clone(),
        })
    }

    fn line(&mut self, record: &impl Serialize) -> io::Result<()> {
        serde_json::to_writer(&mut self.file, record)?;
        self.file.write_all(b"\n")?;
        self.file.flush()
    }

    /// Appends every finished flow and WebSocket message from `events` on a blocking thread
    /// until the bus closes or a write fails; failures and lagging are reported on stderr.
    #[must_use = "the task runs on its own; keep the handle only to wait for it"]
    pub fn follow(
        mut self,
        mut events: broadcast::Receiver<FlowEvent>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::task::spawn_blocking(move || {
            loop {
                match events.blocking_recv() {
                    Ok(event) => {
                        let written = match (&event, event.flow()) {
                            (_, Some(flow)) => self.append(flow),
                            (FlowEvent::WsMessage(message), None) => self.append_message(message),
                            _ => Ok(()),
                        };
                        if let Err(e) = written {
                            eprintln!("{}: writing the session file: {e}", crate::NAME);
                            break;
                        }
                    }
                    Err(RecvError::Lagged(missed)) => {
                        eprintln!(
                            "{}: the session file fell behind and skipped {missed} events",
                            crate::NAME
                        );
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        })
    }
}

/// The flows read from a session file and what was odd about it.
#[derive(Debug, Default)]
pub struct Session {
    /// Flows in file order.
    pub flows: Vec<Flow>,
    /// WebSocket messages in file order.
    pub messages: Vec<WsMessage>,
    /// Problems that did not stop reading: a truncated last line, a newer schema.
    pub warnings: Vec<String>,
}

/// Reads a session file.
///
/// # Errors
///
/// Fails when the file cannot be read, a line other than the last is neither a flow record
/// nor a message record, or a line is longer than [`MAX_LINE`].
pub fn read(path: &Path) -> io::Result<Session> {
    let file = File::open(path)?;
    read_from(BufReader::new(file))
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))
}

/// Reads session lines from `reader`; see [`read`].
///
/// # Errors
///
/// As [`read`].
pub fn read_from(mut reader: impl BufRead) -> io::Result<Session> {
    let mut session = Session::default();
    let mut line = Vec::new();
    let mut newer = false;
    for number in 1.. {
        line.clear();
        let limit = u64::try_from(MAX_LINE).unwrap_or(u64::MAX) + 1;
        let read = reader.by_ref().take(limit).read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        let complete = line.last() == Some(&b'\n');
        if !complete && line.len() > MAX_LINE {
            return Err(invalid(format!(
                "line {number} is longer than {MAX_LINE} bytes"
            )));
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let parsed = serde_json::from_slice::<Flow>(&line)
            .map(|flow| (flow.schema_version, Some(flow), None))
            .or_else(|e| {
                serde_json::from_slice::<WsRecord>(&line)
                    .map(|r| (r.schema_version, None, Some(r.message)))
                    .map_err(|_| e)
            });
        match parsed {
            Ok((version, flow, message)) => {
                if version > SCHEMA_VERSION && !newer {
                    newer = true;
                    session.warnings.push(format!(
                        "line {number}: schema_version {version} is newer than \
                         {SCHEMA_VERSION}; fields this version does not know are ignored"
                    ));
                }
                session.flows.extend(flow);
                session.messages.extend(message);
            }
            Err(e) if !complete => {
                session.warnings.push(format!(
                    "line {number}: ignored a truncated last line ({e})"
                ));
                break;
            }
            Err(e) => return Err(invalid(format!("line {number}: not a flow record: {e}"))),
        }
    }
    Ok(session)
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Reads flows from `source` (stdin when `None`), printing warnings on stderr, and keeps
/// those matching `filter`, with their WebSocket messages in a store.
fn load(source: Option<&Path>, filter: Option<&str>) -> anyhow::Result<(Vec<Flow>, WsStore)> {
    let query = filter.map(Query::parse).transpose()?;
    let session = match source {
        Some(path) => read(path)?,
        None => read_from(io::stdin().lock()).context("reading flows from stdin")?,
    };
    for warning in &session.warnings {
        eprintln!("{}: warning: {}", crate::NAME, escape(warning));
    }
    let ws = WsStore::new(usize::MAX);
    for message in session.messages {
        ws.push(Arc::new(message));
    }
    let flows = session
        .flows
        .into_iter()
        .filter(|flow| {
            query
                .as_ref()
                .is_none_or(|q| q.matches_flow_with_ws(flow, Some(&ws)))
        })
        .collect();
    Ok((flows, ws))
}

/// `NAME view`: prints the flows of a session file as the live text log does, each
/// WebSocket upgrade followed by its messages as `--ws-log` prints them. Control characters
/// are escaped, as on the live console.
///
/// # Errors
///
/// Fails on a bad filter, an unreadable session file, or a write error.
pub fn view(session: &Path, filter: Option<&str>, out: &mut impl io::Write) -> anyhow::Result<()> {
    let (flows, ws) = load(Some(session), filter)?;
    for flow in flows {
        writeln!(out, "{}", escape(&flow.record.to_string()))?;
        for message in ws.list(flow.id(), None, usize::MAX) {
            writeln!(out, "  {}", escape(&crate::ws::log_line(&message)))?;
        }
    }
    Ok(())
}

/// `NAME export --har`: writes the matching flows of a session file (or JSON Lines on
/// stdin) as a HAR document to `out` (`-` for stdout). Returns the number of entries.
///
/// # Errors
///
/// Fails on a bad filter, unreadable input, or a write error.
pub fn export_har(
    session: Option<&Path>,
    filter: Option<&str>,
    out: &Path,
) -> anyhow::Result<usize> {
    let (flows, ws) = load(session, filter)?;
    // Each entry is built while it is written, so the document never sits in memory whole.
    let har = crate::har::StreamedHar::new(&flows, Some(&ws));
    let entries = har.entries();
    if out == Path::new("-") {
        let mut stdout = io::stdout().lock();
        serde_json::to_writer_pretty(&mut stdout, &har)?;
        writeln!(stdout)?;
    } else {
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options
            .open(out)
            .with_context(|| format!("creating {}", out.display()))?;
        let mut file = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut file, &har)?;
        file.flush()?;
    }
    Ok(entries)
}

/// `NAME import --har`: converts a HAR file to a new session file, `_webSocketMessages`
/// included as message records. Returns the number of flows written.
///
/// # Errors
///
/// Fails when the HAR file cannot be read or is malformed, or `session` exists.
pub fn import_har(har: &Path, session: &Path) -> anyhow::Result<usize> {
    let limit = u64::try_from(crate::har::MAX_HAR_BYTES).unwrap_or(u64::MAX) + 1;
    let mut document = Vec::new();
    File::open(har)
        .with_context(|| format!("opening {}", har.display()))?
        .take(limit)
        .read_to_end(&mut document)?;
    let (flows, messages) =
        crate::har::from_har_with_ws(&document).with_context(|| har.display().to_string())?;
    let mut by_flow: HashMap<u64, Vec<WsMessage>> = HashMap::new();
    for message in messages {
        by_flow.entry(message.flow_id).or_default().push(message);
    }
    let mut writer = SessionWriter::create(session, Existing::Refuse)
        .with_context(|| format!("creating {} (it must not exist yet)", session.display()))?;
    for flow in &flows {
        writer.append(flow)?;
        for message in by_flow.remove(&flow.id()).unwrap_or_default() {
            writer.append_message(&message)?;
        }
    }
    Ok(flows.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::Event;
    use crate::query::tests::exchange;

    fn flow(id: u64) -> Flow {
        Flow::new(Event::Exchange(Box::new(exchange(
            id,
            "GET",
            "https://a.test/",
            200,
        ))))
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "{}-session-{name}-{}",
            crate::NAME,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn writes_and_reads_back_with_owner_only_mode() -> io::Result<()> {
        let dir = temp_dir("rw");
        let path = dir.join("s.jsonl");
        let mut writer = SessionWriter::create(&path, Existing::Append)?;
        writer.append(&flow(1))?;
        writer.append(&flow(2))?;
        drop(writer);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path)?.permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(SessionWriter::create(&path, Existing::Refuse).is_err());
        let session = read(&path)?;
        assert_eq!(
            session.flows.iter().map(Flow::id).collect::<Vec<_>>(),
            [1, 2]
        );
        assert_eq!(session.warnings.len(), 0, "{:?}", session.warnings);
        // The record survives the trip unchanged.
        assert_eq!(
            serde_json::to_value(&session.flows[0])?,
            serde_json::to_value(flow(1))?
        );
        std::fs::remove_dir_all(dir)
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_wider_file_is_narrowed_and_a_symlink_refused() -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = temp_dir("narrow");
        let path = dir.join("s.jsonl");
        std::fs::write(&path, "")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        drop(SessionWriter::create(&path, Existing::Append)?);
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600
        );
        let link = dir.join("link.jsonl");
        std::os::unix::fs::symlink(&path, &link)?;
        assert!(SessionWriter::create(&link, Existing::Append).is_err());
        std::fs::remove_dir_all(dir)
    }

    #[test]
    fn tolerates_a_truncated_last_line_and_a_newer_schema() -> io::Result<()> {
        let mut text = serde_json::to_string(&flow(1))? + "\n\n";
        let mut newer = serde_json::to_value(flow(2))?;
        newer["schema_version"] = 99.into();
        newer["some_future_field"] = "x".into();
        text += &newer.to_string();
        text.push('\n');
        let third = serde_json::to_string(&flow(3))?;
        text += &third[..third.len() / 2];
        let session = read_from(text.as_bytes())?;
        assert_eq!(session.flows.len(), 2);
        assert_eq!(session.warnings.len(), 2, "{:?}", session.warnings);
        assert!(session.warnings[0].contains("newer"));
        assert!(session.warnings[1].contains("truncated"));
        Ok(())
    }

    fn ws_message(flow_id: u64, seq: u64, text: &str) -> WsMessage {
        let parsed = crate::ws::Parsed {
            kind: crate::ws::Kind::Text,
            kept: text.as_bytes().to_vec(),
            size: text.len() as u64,
            compression: None,
        };
        crate::ws::message(flow_id, seq, crate::ws::Direction::ClientToServer, &parsed)
    }

    fn ws_flow(id: u64) -> Flow {
        let mut x = exchange(id, "GET", "https://a.test/socket", 101);
        x.ws_messages = Some(0);
        Flow::new(Event::Exchange(Box::new(x)))
    }

    #[test]
    fn messages_round_trip_through_view_export_and_import() -> anyhow::Result<()> {
        let dir = temp_dir("ws");
        let path = dir.join("s.jsonl");
        let mut writer = SessionWriter::create(&path, Existing::Append)?;
        writer.append(&ws_flow(1))?;
        writer.append_message(&ws_message(1, 0, "hello"))?;
        writer.append(&flow(2))?;
        writer.append_message(&ws_message(1, 1, "world"))?;
        drop(writer);
        let text = std::fs::read_to_string(&path)?;
        let message_line = text.lines().nth(1).unwrap_or_default();
        let value: serde_json::Value = serde_json::from_str(message_line)?;
        assert_eq!(
            (value["type"].as_str(), value["schema_version"].as_u64()),
            (Some("ws_message"), Some(1))
        );
        let session = read(&path)?;
        assert_eq!(session.flows.len(), 2);
        assert_eq!(session.messages.len(), 2);
        assert_eq!(session.messages[1].data, "world");

        let mut out = Vec::new();
        view(&path, Some("ws:world"), &mut out)?;
        let printed = String::from_utf8(out)?;
        assert_eq!(printed.lines().count(), 3, "{printed}");
        assert!(printed.contains("ws #1 -> text 5 B"), "{printed}");

        let har = dir.join("out.har");
        assert_eq!(export_har(Some(&path), None, &har)?, 2);
        let document: serde_json::Value = serde_json::from_slice(&std::fs::read(&har)?)?;
        let sent = &document["log"]["entries"][0]["_webSocketMessages"];
        assert_eq!(sent.as_array().map(Vec::len), Some(2));
        assert_eq!(
            (sent[0]["type"].as_str(), sent[0]["data"].as_str()),
            (Some("send"), Some("hello"))
        );

        let imported = dir.join("imported.jsonl");
        assert_eq!(import_har(&har, &imported)?, 2);
        let back = read(&imported)?;
        let data: Vec<&str> = back.messages.iter().map(|m| m.data.as_str()).collect();
        assert_eq!(data, ["hello", "world"]);
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn view_escapes_terminal_controls() -> anyhow::Result<()> {
        let dir = temp_dir("escape");
        let path = dir.join("s.jsonl");
        let mut writer = SessionWriter::create(&path, Existing::Append)?;
        for (id, (raw, _)) in (1..).zip(crate::console::tests::HOSTILE) {
            let mut x = exchange(id, "GET", &format!("https://a.test/{raw}"), 200);
            x.reason = Some((*raw).to_owned());
            writer.append(&Flow::new(Event::Exchange(Box::new(x))))?;
        }
        drop(writer);
        let mut out = Vec::new();
        view(&path, None, &mut out)?;
        let printed = String::from_utf8(out)?;
        assert_eq!(
            printed.lines().count(),
            crate::console::tests::HOSTILE.len()
        );
        assert!(
            !printed.chars().any(|c| c.is_control() && c != '\n'),
            "{printed:?}"
        );
        for (_, shown) in crate::console::tests::HOSTILE {
            assert!(printed.contains(shown), "{shown} missing from {printed}");
        }
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn a_broken_middle_line_is_an_error_with_its_number() {
        let text = format!(
            "{{\"nope\":1}}\n{}\n",
            serde_json::to_string(&flow(1)).unwrap_or_default()
        );
        let error = read_from(text.as_bytes()).expect_err("broken line");
        assert!(error.to_string().contains("line 1"), "{error}");
    }
}
