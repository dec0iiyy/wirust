//! Keeps the console log short when a client rejects the proxy's certificate over and over.
//!
//! A phone with an app that does not trust the CA opens a new connection for every request,
//! and each one used to print the same long `TLS-FAIL` line. [`Folder`] prints the first
//! failure of a (host, error) pair in full, counts the repeats inside a [`WINDOW`] and prints
//! one summary line when the window closes. Only the console is affected: the flow store, the
//! UI and `--json` output still get one event per failure.
//!
//! The folder never reads a clock. Every call takes the current [`Instant`], so tests move
//! time by adding a [`Duration`] to a starting instant.

use std::time::{Duration, Instant};

use crate::flow::{self, TlsFailure};

/// How long the repeats of one failure are counted before their summary is printed.
pub const WINDOW: Duration = Duration::from_secs(30);

/// The failures of one (host, error) pair inside one window.
#[derive(Debug)]
struct Group {
    host: String,
    reason: String,
    /// When the first failure of the window printed; the window closes [`WINDOW`] later.
    opened: Instant,
    /// Repeats counted since the last summary.
    held: u32,
    /// `HH:MM:SS` of the latest repeat.
    last_time: String,
}

impl Group {
    fn closes(&self) -> Instant {
        self.opened + WINDOW
    }

    /// The summary of the repeats held so far, which resets the count.
    fn summary(&mut self) -> Option<String> {
        let held = std::mem::take(&mut self.held);
        (held > 0).then(|| {
            format!(
                "{} TLS-FAIL {} (x{held} more in the last {} s)  {}",
                self.last_time,
                self.host,
                WINDOW.as_secs(),
                self.reason
            )
        })
    }
}

/// Decides which console lines a stream of events turns into.
#[derive(Debug, Default)]
pub struct Folder {
    /// Open windows, oldest first.
    groups: Vec<Group>,
}

impl Folder {
    /// A folder with no open window.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The lines to print for one event whose own line is `text`, at time `now`.
    ///
    /// `failure` is the event's TLS failure, or `None` for any other event. A failure whose
    /// (host, error) pair has an open window is counted and prints nothing of its own; every
    /// other event prints `text` after the summaries of the windows that closed and of the
    /// repeats counted so far, so lines stay in the order things happened.
    pub fn lines(
        &mut self,
        now: Instant,
        failure: Option<&TlsFailure>,
        text: String,
    ) -> Vec<String> {
        let mut out = self.expire(now);
        if let Some(failure) = failure {
            let host = failure.host();
            let seen = self
                .groups
                .iter_mut()
                .find(|g| g.host == host && g.reason == failure.reason);
            if let Some(group) = seen {
                group.held += 1;
                flow::clock(&failure.time).clone_into(&mut group.last_time);
                return out;
            }
        }
        out.extend(self.groups.iter_mut().filter_map(Group::summary));
        out.push(text);
        if let Some(failure) = failure {
            self.groups.push(Group {
                host: failure.host().to_owned(),
                reason: failure.reason.clone(),
                opened: now,
                held: 0,
                last_time: flow::clock(&failure.time).to_owned(),
            });
        }
        out
    }

    /// The summaries of the windows that have closed by `now`; the windows are forgotten.
    pub fn expire(&mut self, now: Instant) -> Vec<String> {
        let mut out = Vec::new();
        self.groups.retain_mut(|group| {
            let open = group.closes() > now;
            if !open {
                out.extend(group.summary());
            }
            open
        });
        out
    }

    /// When the oldest open window closes: the time to call [`Folder::expire`] at, if no
    /// event comes first.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        self.groups.first().map(Group::closes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure(host: &str, reason: &str, time: &str) -> TlsFailure {
        TlsFailure {
            id: 1,
            time: format!("2026-01-02T{time}.000Z"),
            client: "127.0.0.1:1".parse().expect("an address"),
            target: format!("{host}:443"),
            sni: Some(host.to_owned()),
            ja4: "t13d".to_owned(),
            known_client: None,
            reason: reason.to_owned(),
        }
    }

    /// No lines at all.
    const NOTHING: [&str; 0] = [];

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// The failure as the console prints it, folded or not; the full line is a stand-in.
    fn feed(folder: &mut Folder, now: Instant, f: &TlsFailure) -> Vec<String> {
        folder.lines(now, Some(f), format!("FULL {} {}", f.host(), f.reason))
    }

    #[test]
    fn repeats_inside_the_window_collapse_into_one_summary() {
        let start = Instant::now();
        let mut folder = Folder::new();
        let a = failure("a.test", "UnknownCA", "10:00:00");
        assert_eq!(feed(&mut folder, start, &a), ["FULL a.test UnknownCA"]);
        for second in 1..=4 {
            let again = failure("a.test", "UnknownCA", &format!("10:00:0{second}"));
            assert_eq!(feed(&mut folder, start + secs(second), &again), NOTHING);
        }
        assert_eq!(folder.next_deadline(), Some(start + WINDOW));
        assert_eq!(folder.expire(start + secs(29)), NOTHING);
        assert_eq!(
            folder.expire(start + secs(30)),
            ["10:00:04 TLS-FAIL a.test (x4 more in the last 30 s)  UnknownCA"]
        );
        assert_eq!(folder.next_deadline(), None);
    }

    #[test]
    fn a_window_without_repeats_ends_silently_and_the_next_failure_prints_in_full() {
        let start = Instant::now();
        let mut folder = Folder::new();
        let a = failure("a.test", "UnknownCA", "10:00:00");
        feed(&mut folder, start, &a);
        assert_eq!(folder.expire(start + secs(31)), NOTHING);
        assert_eq!(
            feed(&mut folder, start + secs(40), &a),
            ["FULL a.test UnknownCA"]
        );
    }

    #[test]
    fn a_failure_after_the_window_flushes_the_old_summary_first() {
        let start = Instant::now();
        let mut folder = Folder::new();
        let a = failure("a.test", "UnknownCA", "10:00:00");
        feed(&mut folder, start, &a);
        feed(&mut folder, start + secs(2), &a);
        feed(&mut folder, start + secs(3), &a);
        let late = failure("a.test", "UnknownCA", "10:00:45");
        assert_eq!(
            feed(&mut folder, start + secs(45), &late),
            [
                "10:00:00 TLS-FAIL a.test (x2 more in the last 30 s)  UnknownCA",
                "FULL a.test UnknownCA"
            ]
        );
    }

    #[test]
    fn another_host_or_error_prints_in_full_and_flushes_what_was_counted() {
        let start = Instant::now();
        let mut folder = Folder::new();
        let a = failure("a.test", "UnknownCA", "10:00:00");
        feed(&mut folder, start, &a);
        feed(&mut folder, start + secs(1), &a);
        let b = failure("b.test", "UnknownCA", "10:00:02");
        assert_eq!(
            feed(&mut folder, start + secs(2), &b),
            [
                "10:00:00 TLS-FAIL a.test (x1 more in the last 30 s)  UnknownCA",
                "FULL b.test UnknownCA"
            ]
        );
        // Same host, other error: its own window.
        let timeout = failure("a.test", "handshake timed out", "10:00:03");
        assert_eq!(
            feed(&mut folder, start + secs(3), &timeout),
            ["FULL a.test handshake timed out"]
        );
        // `a.test` is still inside its window and keeps counting after the flush.
        assert_eq!(feed(&mut folder, start + secs(4), &a), NOTHING);
        assert_eq!(
            folder.expire(start + secs(30)),
            ["10:00:00 TLS-FAIL a.test (x1 more in the last 30 s)  UnknownCA"]
        );
    }

    #[test]
    fn other_events_flush_the_counted_repeats_before_their_line() {
        let start = Instant::now();
        let mut folder = Folder::new();
        let a = failure("a.test", "UnknownCA", "10:00:00");
        feed(&mut folder, start, &a);
        feed(&mut folder, start + secs(1), &a);
        assert_eq!(
            folder.lines(start + secs(2), None, "GET /".to_owned()),
            [
                "10:00:00 TLS-FAIL a.test (x1 more in the last 30 s)  UnknownCA",
                "GET /"
            ]
        );
        // Nothing is counted any more, so the next event prints alone.
        assert_eq!(
            folder.lines(start + secs(3), None, "GET /b".to_owned()),
            ["GET /b"]
        );
    }

    #[test]
    fn windows_close_in_the_order_they_opened() {
        let start = Instant::now();
        let mut folder = Folder::new();
        let a = failure("a.test", "UnknownCA", "10:00:00");
        let b = failure("b.test", "UnknownCA", "10:00:05");
        // Both hosts have a window before either gets a repeat counted.
        feed(&mut folder, start, &a);
        feed(&mut folder, start + secs(5), &b);
        feed(&mut folder, start + secs(6), &a);
        feed(&mut folder, start + secs(7), &b);
        assert_eq!(folder.next_deadline(), Some(start + secs(30)));
        assert_eq!(folder.expire(start + secs(30)).len(), 1);
        assert_eq!(folder.next_deadline(), Some(start + secs(35)));
        assert_eq!(folder.expire(start + secs(36)).len(), 1);
        assert_eq!(folder.next_deadline(), None);
    }

    #[test]
    fn a_failure_without_sni_is_keyed_by_the_target_host() {
        let start = Instant::now();
        let mut folder = Folder::new();
        let mut f = failure("a.test", "UnknownCA", "10:00:00");
        f.sni = None;
        assert_eq!(feed(&mut folder, start, &f).len(), 1);
        assert_eq!(feed(&mut folder, start + secs(1), &f), NOTHING);
        assert_eq!(f.host(), "a.test");
    }
}
