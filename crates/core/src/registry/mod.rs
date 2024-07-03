//! Registry inspection contract.
//!
//! The domain type is platform-neutral. The Windows implementation is the only
//! place that talks to the registry. Other targets fail with
//! [`Error::Unsupported`] instead of returning an empty report.

use serde::{Deserialize, Serialize};

use crate::Result;
#[cfg(not(windows))]
use crate::platform;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegistryOptions {
    /// Maximum number of entries to return after scanning.
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryEntry {
    /// Registry key path, e.g. `HKLM\SOFTWARE\...\Uninstall\Some App`.
    pub key: String,
    pub display_name: Option<String>,
    pub install_location: Option<String>,
    pub version: Option<String>,
    /// Why this entry is a cleanup candidate.
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryReport {
    pub platform: String,
    /// Number of uninstall subkeys inspected.
    pub scanned_keys: usize,
    pub entries: Vec<RegistryEntry>,
    pub scanned_at_unix_ms: u64,
}

#[cfg(windows)]
mod windows;

pub fn registry_scan(options: RegistryOptions) -> Result<RegistryReport> {
    #[cfg(windows)]
    {
        windows::scan(options)
    }
    #[cfg(not(windows))]
    {
        let _ = options;
        Err(platform::unsupported("registry-scan"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn registry_scan_is_available_on_windows() {
        let report = registry_scan(RegistryOptions::default()).unwrap();
        assert_eq!(report.platform, "windows");
        assert!(report.scanned_keys > 0, "expected at least one uninstall key, got {report:?}");
    }

    #[cfg(not(windows))]
    #[test]
    fn registry_scan_fails_without_windows() {
        let err = registry_scan(RegistryOptions::default()).unwrap_err();
        assert!(matches!(err, crate::Error::Unsupported { capability: "registry-scan", .. }), "unexpected: {err}");
    }
}
