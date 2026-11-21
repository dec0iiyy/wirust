//! Per-host TLS server configurations, each with a leaf certificate signed by the CA.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rustls::ServerConfig;

use crate::ca::Ca;

/// Hosts cached before the cache is emptied; bounds memory for a client that visits many.
const MAX_HOSTS: usize = 4096;

/// ALPN protocols offered to clients, in preference order.
const ALPN: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// Leaf certificates by host name, issued on first use.
#[derive(Debug)]
pub struct CertCache {
    ca: Ca,
    configs: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl CertCache {
    /// A cache that signs with `ca`.
    #[must_use]
    pub fn new(ca: Ca) -> Self {
        Self {
            ca,
            configs: Mutex::new(HashMap::new()),
        }
    }

    /// The CA the cache signs with.
    #[must_use]
    pub fn ca(&self) -> &Ca {
        &self.ca
    }

    /// The server configuration for `host` (the SNI name, or the CONNECT host without one).
    ///
    /// # Errors
    ///
    /// Fails when `host` cannot be put in a certificate.
    pub fn server_config(&self, host: &str) -> anyhow::Result<Arc<ServerConfig>> {
        let host = host.to_ascii_lowercase();
        if let Some(config) = self.lock().get(&host) {
            return Ok(Arc::clone(config));
        }
        // Issued outside the lock: two first requests for one host may both sign, and the
        // later insert wins. Both certificates are valid.
        let leaf = self.ca.issue(&host)?;
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![leaf.cert], leaf.key)?;
        config.alpn_protocols = ALPN.iter().map(|p| p.to_vec()).collect();
        let config = Arc::new(config);
        let mut configs = self.lock();
        if configs.len() >= MAX_HOSTS {
            configs.clear();
        }
        configs.insert(host, Arc::clone(&config));
        Ok(config)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<ServerConfig>>> {
        self.configs
            .lock()
            .expect("certificate cache lock poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caches_by_host() -> anyhow::Result<()> {
        let dir =
            std::env::temp_dir().join(format!("{}-certs-test-{}", crate::NAME, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = CertCache::new(Ca::load_or_create(&dir)?);
        let a = cache.server_config("example.com")?;
        let again = cache.server_config("EXAMPLE.com")?;
        let b = cache.server_config("127.0.0.1")?;
        assert!(Arc::ptr_eq(&a, &again), "same host must reuse the config");
        assert!(!Arc::ptr_eq(&a, &b), "another host gets its own config");
        assert_eq!(a.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
