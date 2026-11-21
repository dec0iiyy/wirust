//! The local certificate authority: created on first use, then loaded from the config
//! directory on every start.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::NAME;
use crate::clock::Utc;

/// Builds the date rcgen takes; out-of-range parts fall back to safe values.
macro_rules! date {
    ($year:expr, $month:expr, $day:expr) => {
        rcgen::date_time_ymd(
            i32::try_from($year).unwrap_or(9999),
            u8::try_from($month).unwrap_or(1),
            u8::try_from($day).unwrap_or(1),
        )
    };
}

const CERT_FILE: &str = "ca-cert.pem";
const KEY_FILE: &str = "ca-key.pem";
/// Validity of the CA certificate.
const CA_YEARS: i64 = 10;

/// The CA certificate and its signing key.
///
/// `Debug` prints the certificate path only; the key never leaves this type except as a
/// signature.
pub struct Ca {
    cert_path: PathBuf,
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

impl std::fmt::Debug for Ca {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ca")
            .field("cert_path", &self.cert_path)
            .finish_non_exhaustive()
    }
}

/// A leaf certificate and its private key, ready for a rustls server.
#[derive(Debug)]
pub struct Leaf {
    /// The DER certificate, signed by the CA.
    pub cert: CertificateDer<'static>,
    /// The PKCS#8 private key of the certificate.
    pub key: PrivateKeyDer<'static>,
}

impl Ca {
    /// The default config directory: the platform config dir joined with [`NAME`].
    ///
    /// # Errors
    ///
    /// Fails when the platform reports no config directory.
    pub fn default_dir() -> anyhow::Result<PathBuf> {
        dirs::config_dir()
            .map(|dir| dir.join(NAME))
            .context("the platform has no config directory; pass --config-dir")
    }

    /// Where the CA certificate is (or will be) stored in `dir`.
    #[must_use]
    pub fn cert_path(dir: &Path) -> PathBuf {
        dir.join(CERT_FILE)
    }

    /// Loads the CA from `dir`, creating the directory (mode `0700`) and a new CA (key file
    /// mode `0600`) when there is none.
    ///
    /// # Errors
    ///
    /// Fails on I/O errors, on an unreadable key or certificate, or when only one of the two
    /// files exists.
    pub fn load_or_create(dir: &Path) -> anyhow::Result<Self> {
        let cert_path = Self::cert_path(dir);
        let key_path = dir.join(KEY_FILE);
        match (cert_path.exists(), key_path.exists()) {
            (true, true) => {
                let cert_pem = fs::read_to_string(&cert_path)
                    .with_context(|| format!("reading {}", cert_path.display()))?;
                let key_pem = fs::read_to_string(&key_path)
                    .with_context(|| format!("reading {}", key_path.display()))?;
                let key = KeyPair::from_pem(&key_pem).context("parsing the CA key")?;
                Ok(Self {
                    cert_path,
                    cert_pem,
                    issuer: Issuer::new(ca_params(Utc::now()), key),
                })
            }
            (false, false) => {
                create_private_dir(dir)?;
                let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
                let cert = ca_params(Utc::now()).self_signed(&key)?;
                write_private(&key_path, key.serialize_pem().as_bytes())?;
                fs::write(&cert_path, cert.pem())
                    .with_context(|| format!("writing {}", cert_path.display()))?;
                Ok(Self {
                    cert_path,
                    cert_pem: cert.pem(),
                    issuer: Issuer::new(ca_params(Utc::now()), key),
                })
            }
            _ => bail!(
                "{} holds only one of {CERT_FILE} and {KEY_FILE}; restore the other or remove both",
                dir.display()
            ),
        }
    }

    /// The CA certificate in PEM.
    #[must_use]
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The CA certificate in DER, for clients that want a binary `.crt`.
    ///
    /// # Errors
    ///
    /// Fails if the stored PEM holds no certificate.
    pub fn cert_der(&self) -> anyhow::Result<Vec<u8>> {
        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject as _;
        let der = CertificateDer::from_pem_slice(self.cert_pem.as_bytes())
            .context("the CA file holds no PEM certificate")?;
        Ok(der.to_vec())
    }

    /// The path of the CA certificate file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.cert_path
    }

    /// Issues a one-year server certificate for `host` (a DNS name or an IP address).
    ///
    /// # Errors
    ///
    /// Fails when `host` is not a valid DNS name or IP address.
    pub fn issue(&self, host: &str) -> anyhow::Result<Leaf> {
        let now = Utc::now();
        let mut params = CertificateParams::new(vec![host.to_owned()])?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, host);
        params.not_before = date!(now.year, now.month, now.day.saturating_sub(1).max(1));
        params.not_after = date!(now.year + 1, now.month, now.day.min(28));
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let cert = params.signed_by(&key, &self.issuer)?;
        Ok(Leaf {
            cert: cert.der().clone(),
            key: PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        })
    }
}

/// The CA's parameters. The distinguished name is fixed, so the parameters rebuilt on a
/// later start name the same issuer as the stored certificate.
fn ca_params(now: Utc) -> CertificateParams {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, format!("{NAME} local CA"));
    params
        .distinguished_name
        .push(DnType::OrganizationName, NAME);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = date!(now.year, now.month, now.day.saturating_sub(1).max(1));
    params.not_after = date!(now.year + CA_YEARS, now.month, now.day.min(28));
    params
}

pub(crate) fn create_private_dir(dir: &Path) -> anyhow::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))
}

pub(crate) fn write_private(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_once_then_reuses() -> anyhow::Result<()> {
        let dir = std::env::temp_dir().join(format!("{NAME}-ca-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let first = Ca::load_or_create(&dir)?;
        let second = Ca::load_or_create(&dir)?;
        assert_eq!(first.cert_pem(), second.cert_pem());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |p: &Path| fs::metadata(p).map(|m| m.permissions().mode() & 0o777);
            assert_eq!(mode(&dir)?, 0o700);
            assert_eq!(mode(&dir.join(KEY_FILE))?, 0o600);
        }
        fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
