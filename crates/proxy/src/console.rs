//! Makes traffic-derived text safe to print to a terminal.
//!
//! Host names, URLs, header values, error text and device names come from the network, and
//! a terminal acts on control characters in them: `ESC]0;` sets the window title, `ESC]52;`
//! writes the clipboard in some terminals, `ESC[2K` with a carriage return erases and forges
//! a log line. Every line printed from traffic goes through [`escape`] (text) or
//! [`escape_json`] (JSON Lines) first.
//!
//! The exchange log is written by [`spawn_writer`]'s thread, so a terminal or pipe that reads
//! slowly, or not at all, never holds up the proxy: lines that do not fit its queue are
//! counted and dropped.

use std::borrow::Cow;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::time::Duration;

use crate::NAME;

/// How many lines the log writer queues before it drops new ones: about a second of output at
/// tens of thousands of exchanges per second, a few MB at most.
pub const QUEUE_LINES: usize = 16 * 1024;

/// One queued line and the stream it goes to.
enum Line {
    Out(String),
    Err(String),
}

/// State the senders and the writer thread share.
#[derive(Debug, Default)]
struct Shared {
    dropped: AtomicU64,
    closed: AtomicBool,
}

/// Queues lines for the log writer without ever waiting for it; cheap to clone.
#[derive(Clone, Debug)]
pub struct LogSender {
    queue: SyncSender<Line>,
    shared: Arc<Shared>,
}

impl LogSender {
    /// Queues a line for the standard output, or counts it as dropped when the queue is full.
    pub fn line(&self, line: String) {
        self.send(Line::Out(line));
    }

    /// Queues a line for the standard error, or counts it as dropped when the queue is full.
    pub fn notice(&self, line: String) {
        self.send(Line::Err(line));
    }

    /// Whether the output is gone (a closed pipe) and the writer has stopped.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::Relaxed)
    }

    fn send(&self, line: Line) {
        if self.is_closed() {
            return;
        }
        if let Err(TrySendError::Full(_)) = self.queue.try_send(line) {
            self.shared.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The log writer thread; [`LogWriter::finish`] waits for it to write what is queued.
#[derive(Debug)]
pub struct LogWriter {
    done: Receiver<()>,
    shared: Arc<Shared>,
}

impl LogWriter {
    /// Waits up to `timeout` for the writer to write and flush every queued line, which it
    /// does once every [`LogSender`] is dropped. Returns the number of lines that never made
    /// it out (dropped and not yet reported), so the caller can say so when the output is
    /// stuck.
    #[must_use]
    pub fn finish(self, timeout: Duration) -> u64 {
        // Disconnected means the thread ended, which is as good as its signal.
        let _ = self.done.recv_timeout(timeout);
        self.shared.dropped.swap(0, Ordering::Relaxed)
    }
}

/// Starts the log writer thread on the process's standard output and error.
///
/// # Errors
///
/// Fails when the operating system cannot start a thread.
pub fn spawn_writer() -> io::Result<(LogSender, LogWriter)> {
    spawn_writer_to(io::stdout(), io::stderr(), QUEUE_LINES)
}

/// Starts the log writer thread on `out` and `err` with room for `capacity` queued lines.
///
/// The thread writes lines as they come and flushes whenever the queue is empty. After lines
/// were dropped it writes one `N log lines dropped` notice to `err` once it has caught up.
/// When `out` fails (a closed pipe), it writes one line about it to `err` and stops; the
/// senders then discard everything.
///
/// # Errors
///
/// Fails when the operating system cannot start a thread.
pub fn spawn_writer_to<O, E>(out: O, err: E, capacity: usize) -> io::Result<(LogSender, LogWriter)>
where
    O: Write + Send + 'static,
    E: Write + Send + 'static,
{
    let (queue, lines) = mpsc::sync_channel(capacity);
    let (signal, done) = mpsc::channel();
    let shared = Arc::new(Shared::default());
    let thread_shared = Arc::clone(&shared);
    std::thread::Builder::new()
        .name("log-writer".into())
        .spawn(move || {
            write_log(&lines, &thread_shared, out, err);
            let _ = signal.send(());
        })?;
    let sender = LogSender {
        queue,
        shared: Arc::clone(&shared),
    };
    Ok((sender, LogWriter { done, shared }))
}

/// The writer thread's loop: runs until every sender is gone or `out` fails.
fn write_log(lines: &Receiver<Line>, shared: &Shared, out: impl Write, mut err: impl Write) {
    let mut out = io::BufWriter::new(out);
    while let Ok(first) = lines.recv() {
        let written = write_batch(first, lines, &mut out, &mut err).and_then(|()| out.flush());
        if let Err(e) = written {
            shared.closed.store(true, Ordering::Relaxed);
            let _ = writeln!(err, "{NAME}: {}; the exchange log stops here", describe(&e));
            return;
        }
        let dropped = shared.dropped.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            let _ = writeln!(
                err,
                "{NAME}: {dropped} log lines dropped (the output is too slow)"
            );
        }
    }
}

/// Writes `first` and every line already queued behind it.
fn write_batch(
    first: Line,
    lines: &Receiver<Line>,
    out: &mut impl Write,
    err: &mut impl Write,
) -> io::Result<()> {
    let mut next = Some(first);
    while let Some(line) = next {
        match line {
            Line::Out(line) => writeln!(out, "{line}")?,
            // A failing standard error has nowhere to be reported.
            Line::Err(line) => drop(writeln!(err, "{line}")),
        }
        next = lines.try_recv().ok();
    }
    Ok(())
}

/// What went wrong with the standard output, for the one line the writer prints about it.
fn describe(error: &io::Error) -> String {
    if error.kind() == io::ErrorKind::BrokenPipe {
        "the standard output is closed".to_owned()
    } else {
        format!("writing the standard output failed: {error}")
    }
}

/// `text` with every control character (C0, DEL, C1) shown as a `\u{1b}`-style escape;
/// other Unicode is kept. Borrows when there is nothing to escape.
#[must_use]
pub fn escape(text: &str) -> Cow<'_, str> {
    if !text.chars().any(char::is_control) {
        return Cow::Borrowed(text);
    }
    Cow::Owned(
        text.chars()
            .map(|c| {
                if c.is_control() {
                    c.escape_unicode().to_string()
                } else {
                    c.to_string()
                }
            })
            .collect(),
    )
}

/// A serialised JSON document with DEL and C1 characters written as `\u007f`-style escapes.
///
/// `serde_json` escapes C0 controls but writes DEL and C1 (U+0080 to U+009F, which some
/// terminals read as CSI and friends) raw. Raw control characters can only occur inside
/// JSON strings, where the `\uXXXX` form means the same character, so the result is the same
/// JSON value.
#[must_use]
pub fn escape_json(json: &str) -> Cow<'_, str> {
    if !json.chars().any(char::is_control) {
        return Cow::Borrowed(json);
    }
    Cow::Owned(
        json.chars()
            .map(|c| {
                if c.is_control() {
                    format!("\\u{:04x}", u32::from(c))
                } else {
                    c.to_string()
                }
            })
            .collect(),
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Escape sequences a hostile peer might send, with what the console must show instead.
    pub(crate) const HOSTILE: &[(&str, &str)] = &[
        ("\u{1b}]0;title\u{7}", "\\u{1b}]0;title\\u{7}"),
        ("\u{1b}]52;c;cHduZWQ=\u{7}", "\\u{1b}]52;c;cHduZWQ=\\u{7}"),
        ("\u{1b}[2K\rforged", "\\u{1b}[2K\\u{d}forged"),
        ("nul\0", "nul\\u{0}"),
        ("del\u{7f}", "del\\u{7f}"),
        ("csi\u{9b}31m", "csi\\u{9b}31m"),
    ];

    #[test]
    fn control_characters_are_escaped_and_text_is_kept() {
        for (raw, shown) in HOSTILE {
            assert_eq!(escape(raw), *shown, "input {raw:?}");
        }
        assert!(matches!(
            escape("héllo мир ✓"),
            Cow::Borrowed("héllo мир ✓")
        ));
    }

    #[test]
    fn json_keeps_its_value_without_raw_controls() -> serde_json::Result<()> {
        let value = serde_json::json!({ "url": "a\u{1b}[2K\r\u{7f}\u{9b}b" });
        let text = serde_json::to_string(&value)?;
        let escaped = escape_json(&text);
        assert!(!escaped.chars().any(char::is_control), "{escaped}");
        assert_eq!(serde_json::from_str::<serde_json::Value>(&escaped)?, value);
        Ok(())
    }

    /// A writer whose bytes the test reads back.
    #[derive(Clone, Default)]
    struct Buffer(Arc<std::sync::Mutex<Vec<u8>>>);

    impl Buffer {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("buffer lock")).into_owned()
        }
    }

    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("buffer lock").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A writer that is stuck until the test opens its gate, and says when it got stuck.
    struct Stuck {
        entered: mpsc::Sender<()>,
        gate: Receiver<()>,
        open: bool,
        out: Buffer,
    }

    impl Write for Stuck {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if !self.open {
                let _ = self.entered.send(());
                let _ = self.gate.recv();
                self.open = true;
            }
            self.out.write(bytes)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A standard output whose reader is gone.
    struct ClosedPipe;

    impl Write for ClosedPipe {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }

    const PATIENCE: Duration = Duration::from_secs(10);

    #[test]
    fn the_writer_writes_every_line_in_order() -> io::Result<()> {
        let (out, err) = (Buffer::default(), Buffer::default());
        let (log, writer) = spawn_writer_to(out.clone(), err.clone(), 8)?;
        log.line("one".into());
        log.notice("a notice".into());
        log.line("two".into());
        drop(log);
        assert_eq!(writer.finish(PATIENCE), 0);
        assert_eq!(out.text(), "one\ntwo\n");
        assert_eq!(err.text(), "a notice\n");
        Ok(())
    }

    #[test]
    fn a_stuck_output_never_blocks_the_sender_and_drops_are_reported() -> io::Result<()> {
        let (entered, stuck) = mpsc::channel();
        let (open, gate) = mpsc::channel();
        let (out, err) = (Buffer::default(), Buffer::default());
        let stuck_out = Stuck {
            entered,
            gate,
            open: false,
            out: out.clone(),
        };
        let (log, writer) = spawn_writer_to(stuck_out, err.clone(), 4)?;
        log.line("first".into());
        stuck
            .recv_timeout(PATIENCE)
            .expect("the writer reaches the output");
        for n in 0..100 {
            log.line(format!("line {n}"));
        }
        open.send(()).expect("the writer is waiting");
        drop(log);
        assert_eq!(writer.finish(PATIENCE), 0, "the drops were reported");
        assert_eq!(out.text(), "first\nline 0\nline 1\nline 2\nline 3\n");
        assert_eq!(
            err.text(),
            "wirust: 96 log lines dropped (the output is too slow)\n"
        );
        Ok(())
    }

    #[test]
    fn a_closed_output_stops_the_log_with_one_line() -> io::Result<()> {
        let err = Buffer::default();
        let (log, writer) = spawn_writer_to(ClosedPipe, err.clone(), 4)?;
        log.line("lost".into());
        let start = std::time::Instant::now();
        while !log.is_closed() {
            assert!(start.elapsed() < PATIENCE, "the writer never stopped");
            std::thread::sleep(Duration::from_millis(5));
        }
        log.line("ignored".into());
        log.notice("ignored too".into());
        drop(log);
        assert_eq!(writer.finish(PATIENCE), 0, "nothing counts as dropped");
        assert_eq!(
            err.text(),
            "wirust: the standard output is closed; the exchange log stops here\n"
        );
        Ok(())
    }
}
