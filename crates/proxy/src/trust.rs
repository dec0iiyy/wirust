//! Trusts the wirust CA in the current user's trust store, and removes exactly that
//! certificate again, matched by fingerprint. Never asks for administrator rights.
//!
//! - macOS: the login keychain, with `security add-trusted-cert` / `remove-trusted-cert`
//!   and `delete-certificate`.
//! - Windows: the current user's Root store, with `certutil -user`.
//! - Linux: there is no per-user system store, so the commands are printed instead.

use std::fmt::Write as _;
use std::io::BufRead;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use aws_lc_rs::digest;

use crate::NAME;
use crate::oscmd::{CommandRunner, Platform, args};

/// Files the Linux instructions copy the CA to, checked by [`CaTrust::status`].
const LINUX_ANCHORS: [&str; 2] = [
    "/usr/local/share/ca-certificates/wirust.crt",
    "/etc/pki/ca-trust/source/anchors/wirust.pem",
];

/// Whether the CA is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStatus {
    /// In the user's trust store.
    Trusted,
    /// Not in the user's trust store.
    NotTrusted,
    /// This platform gives no way to tell (Linux without the anchor files).
    Unknown,
}

/// The wirust CA certificate and the platform tools that trust it.
#[derive(Debug)]
pub struct CaTrust<R: CommandRunner> {
    runner: R,
    platform: Platform,
    cert_path: PathBuf,
    pem: String,
    der: Vec<u8>,
    keychain: PathBuf,
}

impl<R: CommandRunner> CaTrust<R> {
    /// The CA at `cert_path` (PEM text `pem`, DER `der`) on `platform`.
    ///
    /// `home` is the user's home directory, where the macOS login keychain lives.
    pub fn new(
        runner: R,
        platform: Platform,
        (cert_path, pem, der): (&Path, &str, Vec<u8>),
        home: &Path,
    ) -> Self {
        Self {
            runner,
            platform,
            cert_path: cert_path.to_owned(),
            pem: pem.to_owned(),
            der,
            keychain: home.join("Library/Keychains/login.keychain-db"),
        }
    }

    /// The runner, for tests that inspect the recorded commands.
    pub fn runner(&self) -> &R {
        &self.runner
    }

    /// The SHA-256 fingerprint as colon-separated hex, as certificate viewers show it.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        hex(digest::digest(&digest::SHA256, &self.der).as_ref(), ":")
    }

    fn sha256(&self) -> String {
        hex(digest::digest(&digest::SHA256, &self.der).as_ref(), "")
    }

    /// The SHA-1 thumbprint, which `certutil` and `security delete-certificate` take.
    fn sha1(&self) -> String {
        hex(
            digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &self.der).as_ref(),
            "",
        )
    }

    /// What `install` or `uninstall` will do, shown before asking for confirmation.
    #[must_use]
    pub fn plan(&self, action: Action) -> String {
        let path = self.cert_path.display();
        let fingerprint = self.fingerprint();
        let store = match self.platform {
            Platform::MacOs => format!("your login keychain ({})", self.keychain.display()),
            Platform::Windows => "the current user's Root store".to_owned(),
            Platform::Linux => "nothing; the commands to run are printed".to_owned(),
        };
        let what = match action {
            Action::Install => format!(
                "Trust the {NAME} CA {path} in {store}.\nAnyone with its key (kept next to it) \
                 could then impersonate any site to this account. Remove it with `{NAME} ca \
                 uninstall` when you stop using the proxy."
            ),
            Action::Uninstall => format!(
                "Remove the {NAME} CA from {store}: only the certificate with this fingerprint."
            ),
        };
        format!("{what}\nSHA-256 fingerprint: {fingerprint}\n")
    }

    /// Trusts the CA for the current user.
    ///
    /// # Errors
    ///
    /// Fails when the platform tool fails or the user cancels its dialog.
    pub fn install(&self) -> anyhow::Result<String> {
        let path = self.cert_path.to_string_lossy();
        match self.platform {
            Platform::MacOs => {
                let keychain = self.keychain.to_string_lossy();
                self.runner.run_ok(
                    "security",
                    &args(&[
                        "add-trusted-cert",
                        "-r",
                        "trustRoot",
                        "-k",
                        &keychain,
                        &path,
                    ]),
                )?;
                Ok(format!(
                    "the {NAME} CA is now trusted in your login keychain"
                ))
            }
            Platform::Windows => {
                self.runner
                    .run_ok("certutil", &args(&["-user", "-addstore", "Root", &path]))?;
                Ok(format!(
                    "the {NAME} CA is now in the current user's Root store"
                ))
            }
            Platform::Linux => Ok(linux_install(&path)),
        }
    }

    /// Removes the CA, matched by fingerprint; any other certificate stays.
    ///
    /// # Errors
    ///
    /// Fails when the platform tool fails.
    pub fn uninstall(&self) -> anyhow::Result<String> {
        let path = self.cert_path.to_string_lossy();
        let sha1 = self.sha1();
        match self.platform {
            Platform::MacOs => {
                if self.status()? == TrustStatus::NotTrusted {
                    return Ok(format!(
                        "the {NAME} CA is not in your login keychain; nothing removed"
                    ));
                }
                let keychain = self.keychain.to_string_lossy();
                // Best effort: the trust settings may already be gone while the certificate
                // is still there; deleting the certificate removes it either way.
                self.runner
                    .run("security", &args(&["remove-trusted-cert", &path]))?;
                self.runner.run_ok(
                    "security",
                    &args(&["delete-certificate", "-Z", &sha1, &keychain]),
                )?;
                Ok(format!("removed the {NAME} CA from your login keychain"))
            }
            Platform::Windows => {
                if self.status()? == TrustStatus::NotTrusted {
                    return Ok(format!(
                        "the {NAME} CA is not in the current user's Root store; nothing removed"
                    ));
                }
                self.runner
                    .run_ok("certutil", &args(&["-user", "-delstore", "Root", &sha1]))?;
                Ok(format!(
                    "removed the {NAME} CA from the current user's Root store"
                ))
            }
            Platform::Linux => Ok(linux_uninstall()),
        }
    }

    /// Whether the CA is in the user's trust store.
    ///
    /// # Errors
    ///
    /// Fails when the platform tool cannot be started.
    pub fn status(&self) -> anyhow::Result<TrustStatus> {
        let found = match self.platform {
            Platform::MacOs => {
                let keychain = self.keychain.to_string_lossy();
                let cn = format!("{NAME} local CA");
                let output = self.runner.run(
                    "security",
                    &args(&["find-certificate", "-a", "-Z", "-c", &cn, &keychain]),
                )?;
                let sha256 = self.sha256();
                output.success && keychain_hashes(&output.stdout).any(|hash| hash == sha256)
            }
            // `-store` lists the certificate when it is there; `-verifystore` would also check
            // the chain and revocation, which an offline machine fails.
            Platform::Windows => {
                self.runner
                    .run(
                        "certutil",
                        &args(&["-user", "-store", "Root", &self.sha1()]),
                    )?
                    .success
            }
            Platform::Linux => {
                let installed = LINUX_ANCHORS.iter().any(|anchor| {
                    std::fs::read_to_string(anchor).is_ok_and(|text| text.trim() == self.pem.trim())
                });
                return Ok(if installed {
                    TrustStatus::Trusted
                } else {
                    TrustStatus::Unknown
                });
            }
        };
        Ok(if found {
            TrustStatus::Trusted
        } else {
            TrustStatus::NotTrusted
        })
    }
}

/// The two trust-store changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// `ca install`.
    Install,
    /// `ca uninstall`.
    Uninstall,
}

/// Prints `plan` to `out` and reads one line from `input`; only `yes` confirms.
///
/// # Errors
///
/// Fails when writing the prompt or reading the answer fails.
pub fn confirm(
    plan: &str,
    input: &mut impl BufRead,
    out: &mut impl std::io::Write,
) -> anyhow::Result<bool> {
    write!(out, "{plan}Type yes to continue: ")?;
    out.flush()?;
    let mut answer = String::new();
    input.read_line(&mut answer).context("reading the answer")?;
    Ok(answer.trim() == "yes")
}

/// Hash values in `security find-certificate -Z` output (`SHA-256 hash:` and `SHA-1 hash:`).
fn keychain_hashes(output: &str) -> impl Iterator<Item = &str> {
    output.lines().filter_map(|line| {
        let (label, hash) = line.split_once(" hash: ")?;
        label.starts_with("SHA-").then_some(hash.trim())
    })
}

fn hex(bytes: &[u8], separator: &str) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (i, byte) in bytes.iter().enumerate() {
        if i > 0 {
            out.push_str(separator);
        }
        let _ = write!(out, "{byte:02X}");
    }
    out
}

fn linux_install(path: &str) -> String {
    format!(
        "Linux has no per-user system trust store, so {NAME} changes nothing here. Run one of \
         these yourself (they need sudo):\n\
         \n  Debian, Ubuntu:  sudo cp \"{path}\" {deb} && sudo update-ca-certificates\
         \n  Fedora, RHEL:    sudo cp \"{path}\" {rh} && sudo update-ca-trust\
         \n  Arch:            sudo trust anchor --store \"{path}\"\n\
         \nChrome and Chromium read the NSS store; with certutil from libnss3-tools (nss-tools):\
         \n  certutil -d sql:$HOME/.pki/nssdb -A -t C,, -n \"{NAME} local CA\" -i \"{path}\"\n\
         \nFirefox keeps its own store: Settings > Privacy & Security > Certificates > View \
         Certificates > Authorities > Import.\n",
        deb = LINUX_ANCHORS[0],
        rh = LINUX_ANCHORS[1],
    )
}

fn linux_uninstall() -> String {
    format!(
        "Remove the files the install step copied, then rebuild the store:\n\
         \n  Debian, Ubuntu:  sudo rm {deb} && sudo update-ca-certificates --fresh\
         \n  Fedora, RHEL:    sudo rm {rh} && sudo update-ca-trust\
         \n  Arch:            sudo trust anchor --remove \"{NAME} local CA\"\
         \n  NSS:             certutil -d sql:$HOME/.pki/nssdb -D -n \"{NAME} local CA\"\n\
         \nFirefox: Settings > Privacy & Security > Certificates > View Certificates > \
         Authorities, select {NAME} local CA, Delete or Distrust.\n",
        deb = LINUX_ANCHORS[0],
        rh = LINUX_ANCHORS[1],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oscmd::Output;
    use crate::oscmd::fake::FakeRunner;

    const DER: &[u8] = b"not really a certificate";

    fn trust(runner: FakeRunner, platform: Platform) -> CaTrust<FakeRunner> {
        CaTrust::new(
            runner,
            platform,
            (Path::new("/cfg/ca-cert.pem"), "PEM", DER.to_vec()),
            Path::new("/home/u"),
        )
    }

    fn sha256() -> String {
        hex(digest::digest(&digest::SHA256, DER).as_ref(), "")
    }

    fn sha1() -> String {
        hex(
            digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, DER).as_ref(),
            "",
        )
    }

    /// The keychain path as the code builds it: `join` uses the host's separator, so the
    /// expected commands are built the same way and the tests also pass on Windows.
    fn keychain() -> String {
        Path::new("/home/u")
            .join("Library/Keychains/login.keychain-db")
            .display()
            .to_string()
    }

    fn keychain_output(sha256: &str) -> String {
        format!(
            "SHA-256 hash: {sha256}\nSHA-1 hash: 0000\nkeychain: \"/home/u/Library/Keychains/\
             login.keychain-db\"\nversion: 512\nclass: 0x80001000 \nattributes:\n    \
             \"labl\"<blob>=\"wirust local CA\"\n"
        )
    }

    #[test]
    fn fingerprint_is_colon_separated_sha256() {
        let ca = trust(FakeRunner::default(), Platform::MacOs);
        assert_eq!(ca.fingerprint().replace(':', ""), sha256());
        assert_eq!(ca.fingerprint().len(), 32 * 3 - 1);
        assert!(ca.plan(Action::Install).contains(&ca.fingerprint()));
    }

    #[test]
    fn mac_install_uses_the_login_keychain_without_admin_domain() -> anyhow::Result<()> {
        let ca = trust(FakeRunner::default(), Platform::MacOs);
        ca.install()?;
        assert_eq!(
            ca.runner().writes(),
            [format!(
                "security add-trusted-cert -r trustRoot -k {} /cfg/ca-cert.pem",
                keychain()
            )]
        );
        Ok(())
    }

    #[test]
    fn mac_uninstall_removes_only_the_matching_certificate() -> anyhow::Result<()> {
        let present = FakeRunner::default().reply(
            "security find-certificate",
            Output::ok(&keychain_output(&sha256())),
        );
        let ca = trust(present, Platform::MacOs);
        assert_eq!(ca.status()?, TrustStatus::Trusted);
        ca.uninstall()?;
        assert_eq!(
            ca.runner().writes(),
            [
                "security remove-trusted-cert /cfg/ca-cert.pem".to_owned(),
                format!("security delete-certificate -Z {} {}", sha1(), keychain()),
            ]
        );

        // Another certificate with the same name but a different fingerprint stays.
        let other = FakeRunner::default().reply(
            "security find-certificate",
            Output::ok(&keychain_output("ABCDEF")),
        );
        let ca = trust(other, Platform::MacOs);
        assert_eq!(ca.status()?, TrustStatus::NotTrusted);
        assert!(ca.uninstall()?.contains("nothing removed"));
        assert_eq!(ca.runner().writes(), Vec::<String>::new());
        Ok(())
    }

    #[test]
    fn windows_uses_the_user_root_store_by_thumbprint() -> anyhow::Result<()> {
        let ca = trust(FakeRunner::default(), Platform::Windows);
        ca.install()?;
        ca.uninstall()?;
        assert_eq!(
            ca.runner().writes(),
            [
                "certutil -user -addstore Root /cfg/ca-cert.pem".to_owned(),
                format!("certutil -user -delstore Root {}", sha1()),
            ]
        );
        let missing = FakeRunner::default().reply("certutil", Output::failed("not found"));
        let ca = trust(missing, Platform::Windows);
        assert_eq!(ca.status()?, TrustStatus::NotTrusted);
        // Presence in the store, not chain validity (`-verifystore` also checks revocation).
        assert_eq!(
            ca.runner().calls(),
            [format!("certutil -user -store Root {}", sha1())]
        );
        Ok(())
    }

    #[test]
    fn linux_only_prints_instructions() -> anyhow::Result<()> {
        let ca = trust(FakeRunner::default(), Platform::Linux);
        assert!(ca.install()?.contains("update-ca-certificates"));
        assert!(ca.uninstall()?.contains("Firefox"));
        assert_eq!(ca.runner().calls(), Vec::<String>::new());
        Ok(())
    }

    #[test]
    fn confirm_accepts_only_yes() -> anyhow::Result<()> {
        let mut out = Vec::new();
        assert!(confirm("plan\n", &mut "yes\n".as_bytes(), &mut out)?);
        assert!(!confirm("plan\n", &mut "y\n".as_bytes(), &mut out)?);
        assert!(!confirm("plan\n", &mut "".as_bytes(), &mut out)?);
        assert!(String::from_utf8_lossy(&out).starts_with("plan\nType yes"));
        Ok(())
    }
}
