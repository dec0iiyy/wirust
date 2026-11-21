//! Runs operating-system tools (`networksetup`, `security`, `reg`, `certutil`, `gsettings`)
//! behind the [`CommandRunner`] trait, so the code that builds their arguments is tested
//! with a fake runner and never touches the real system in tests.

use std::process::Command;

use anyhow::Context as _;

/// What a finished command printed and whether it succeeded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    /// Whether the command exited with status 0.
    pub success: bool,
    /// Standard output, lossily decoded as UTF-8.
    pub stdout: String,
    /// Standard error, lossily decoded as UTF-8.
    pub stderr: String,
}

impl Output {
    /// A successful run that printed `stdout`.
    #[must_use]
    pub fn ok(stdout: &str) -> Self {
        Self {
            success: true,
            stdout: stdout.to_owned(),
            stderr: String::new(),
        }
    }

    /// A failed run that printed `stderr`.
    #[must_use]
    pub fn failed(stderr: &str) -> Self {
        Self {
            success: false,
            stdout: String::new(),
            stderr: stderr.to_owned(),
        }
    }
}

/// Runs one program with arguments, without a shell.
pub trait CommandRunner {
    /// Runs `program` with `args` and waits for it.
    ///
    /// # Errors
    ///
    /// Fails only when the program cannot be started; a non-zero exit is reported in
    /// [`Output::success`].
    fn run(&self, program: &str, args: &[String]) -> anyhow::Result<Output>;

    /// Runs the command and fails unless it exits with status 0.
    ///
    /// # Errors
    ///
    /// Fails when the program cannot be started or exits with a non-zero status.
    fn run_ok(&self, program: &str, args: &[String]) -> anyhow::Result<String> {
        let output = self.run(program, args)?;
        anyhow::ensure!(
            output.success,
            "`{program} {}` failed: {}",
            args.join(" "),
            output.stderr.trim()
        );
        Ok(output.stdout)
    }
}

/// The real runner: spawns the program with [`std::process::Command`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&self, program: &str, args: &[String]) -> anyhow::Result<Output> {
        let output = Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("running {program}"))?;
        Ok(Output {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// The desktop system whose settings tools are used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// `networksetup` and `security`.
    MacOs,
    /// The `HKCU` Internet Settings keys and `certutil`.
    Windows,
    /// `gsettings` when GNOME is present, otherwise printed instructions.
    Linux,
}

impl Platform {
    /// The platform this binary was built for; other Unix systems count as Linux.
    #[must_use]
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::MacOs
        } else if cfg!(windows) {
            Self::Windows
        } else {
            Self::Linux
        }
    }
}

/// Builds an argument vector from string slices.
pub(crate) fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|&part| part.to_owned()).collect()
}

#[cfg(test)]
pub(crate) mod fake {
    use std::cell::RefCell;

    use super::{CommandRunner, Output};

    /// A runner that records every command and answers from a list of canned replies.
    ///
    /// A reply matches when the command line (program and arguments joined by spaces)
    /// starts with its prefix; unmatched commands succeed with empty output.
    #[derive(Debug, Default)]
    pub(crate) struct FakeRunner {
        replies: Vec<(String, Output)>,
        calls: RefCell<Vec<String>>,
    }

    impl FakeRunner {
        pub(crate) fn reply(mut self, prefix: &str, output: Output) -> Self {
            self.replies.push((prefix.to_owned(), output));
            self
        }

        pub(crate) fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }

        /// The recorded commands that change something (everything but reads).
        pub(crate) fn writes(&self) -> Vec<String> {
            self.calls()
                .into_iter()
                .filter(|call| {
                    !(call.contains(" -get")
                        || call.contains(" -list")
                        || call.starts_with("reg query")
                        || call.starts_with("gsettings get")
                        || call.starts_with("security find-certificate")
                        || call.starts_with("security verify-cert")
                        || call.contains("-verifystore"))
                })
                .collect()
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, program: &str, args: &[String]) -> anyhow::Result<Output> {
            let line = std::iter::once(program)
                .chain(args.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(" ");
            self.calls.borrow_mut().push(line.clone());
            Ok(self
                .replies
                .iter()
                .find(|(prefix, _)| line.starts_with(prefix.as_str()))
                .map_or_else(|| Output::ok(""), |(_, output)| output.clone()))
        }
    }
}
