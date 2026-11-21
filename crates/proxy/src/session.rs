//! Session files: finished flows as JSON Lines, one [`Flow`] per line, the same
//! serialisation as `--json` (with `schema_version`).
//!
//! Session files hold whatever the traffic held: bearer tokens, cookies, passwords in form
//! bodies. They are created readable by the owner only (mode 0600 on unix).

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read as _, Write as _};
use std::path::Path;

use anyhow::Context as _;
use tokio::sync::broadcast::{self, error::RecvError};

use crate::events::{Flow, FlowEvent, SCHEMA_VERSION};
use crate::query::Query;

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
    /// Opens `path` for appending, creating it with mode 0600 on unix.
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be opened, or exists and `existing` is
    /// [`Existing::Refuse`].
    pub fn create(path: &Path, existing: Existing) -> io::Result<Self> {
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
        Ok(Self {
            file: BufWriter::new(options.open(path)?),
        })
    }

    /// Writes one flow as a line and flushes it, so a crash loses at most that line.
    ///
    /// # Errors
    ///
    /// Fails when writing fails.
    pub fn append(&mut self, flow: &Flow) -> io::Result<()> {
        serde_json::to_writer(&mut self.file, flow)?;
        self.file.write_all(b"\n")?;
        self.file.flush()
    }

    /// Appends every finished flow from `events` on a blocking thread until the bus closes
    /// or a write fails; failures and lagging are reported on stderr.
    #[must_use = "the task runs on its own; keep the handle only to wait for it"]
    pub fn follow(
        mut self,
        mut events: broadcast::Receiver<FlowEvent>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::task::spawn_blocking(move || {
            loop {
                match events.blocking_recv() {
                    Ok(event) => {
                        if let Some(flow) = event.flow()
                            && let Err(e) = self.append(flow)
                        {
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
    /// Problems that did not stop reading: a truncated last line, a newer schema.
    pub warnings: Vec<String>,
}

/// Reads a session file.
///
/// # Errors
///
/// Fails when the file cannot be read, a line other than the last is not a flow record, or
/// a line is longer than [`MAX_LINE`].
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
        match serde_json::from_slice::<Flow>(&line) {
            Ok(flow) => {
                if flow.schema_version > SCHEMA_VERSION && !newer {
                    newer = true;
                    session.warnings.push(format!(
                        "line {number}: schema_version {} is newer than {SCHEMA_VERSION}; \
                         fields this version does not know are ignored",
                        flow.schema_version
                    ));
                }
                session.flows.push(flow);
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
/// those matching `filter`.
fn load(source: Option<&Path>, filter: Option<&str>) -> anyhow::Result<Vec<Flow>> {
    let query = filter.map(Query::parse).transpose()?;
    let session = match source {
        Some(path) => read(path)?,
        None => read_from(io::stdin().lock()).context("reading flows from stdin")?,
    };
    for warning in &session.warnings {
        eprintln!("{}: warning: {warning}", crate::NAME);
    }
    Ok(session
        .flows
        .into_iter()
        .filter(|flow| query.as_ref().is_none_or(|q| q.matches_flow(flow)))
        .collect())
}

/// `NAME view`: prints the flows of a session file as the live text log does.
///
/// # Errors
///
/// Fails on a bad filter, an unreadable session file, or a write error.
pub fn view(session: &Path, filter: Option<&str>, out: &mut impl io::Write) -> anyhow::Result<()> {
    for flow in load(Some(session), filter)? {
        writeln!(out, "{}", flow.record)?;
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
    let flows = load(session, filter)?;
    let har = crate::har::to_har(&flows);
    let entries = har.log.entries.len();
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

/// `NAME import --har`: converts a HAR file to a new session file. Returns the number of
/// flows written.
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
    let flows = crate::har::from_har(&document).with_context(|| har.display().to_string())?;
    let mut writer = SessionWriter::create(session, Existing::Refuse)
        .with_context(|| format!("creating {} (it must not exist yet)", session.display()))?;
    for flow in &flows {
        writer.append(flow)?;
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
