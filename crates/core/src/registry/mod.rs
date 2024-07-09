//! Registry inspection contract.
//!
//! The domain type is platform-neutral. The Windows implementation is the only
//! place that talks to the registry. Other targets fail with
//! [`Error::Capability`] (`unsupported_platform`) instead of returning an empty
//! report.

use serde::{Deserialize, Serialize};

use crate::Result;
#[cfg(not(windows))]
use crate::platform;

pub mod analyze;
pub mod model;

pub use analyze::{RegistryFinding, ResidueKind};

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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegistryResidueOptions {
    /// Maximum number of findings to return (0 = all).
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryResidueReport {
    pub platform: String,
    /// Where the analyzed snapshot came from (`windows-registry` or a fixture).
    pub source: String,
    /// Registry keys included in the snapshot and analyzed.
    pub scanned_keys: usize,
    pub findings: Vec<RegistryFinding>,
    pub warnings: Vec<String>,
    pub scanned_at_unix_ms: u64,
}

/// Read-only residue analysis: orphan uninstall rows, dead file associations,
/// and failing startup entries. Nothing is modified, so this is always a
/// preview. Non-Windows targets fail with `unsupported_platform`.
pub fn registry_residue_scan(options: RegistryResidueOptions) -> Result<RegistryResidueReport> {
    #[cfg(windows)]
    {
        windows::residue_scan(options)
    }
    #[cfg(not(windows))]
    {
        let _ = options;
        Err(platform::unsupported("registry-residue-scan"))
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

    #[cfg(windows)]
    #[test]
    fn residue_scan_is_read_only_and_reports_evidence() {
        let report = registry_residue_scan(RegistryResidueOptions::default()).unwrap();
        assert_eq!(report.platform, "windows");
        assert_eq!(report.source, "windows-registry");
        assert!(report.scanned_keys > 0, "expected live registry keys, got {report:?}");
        for finding in &report.findings {
            assert!(!finding.evidence.is_empty(), "{finding:?}");
            assert!(!finding.safety.is_empty(), "{finding:?}");
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn registry_scan_fails_without_windows() {
        let err = registry_scan(RegistryOptions::default()).unwrap_err();
        assert_eq!(crate::capability_code(&err), Some("unsupported_platform"), "unexpected: {err}");
        assert!(matches!(err, crate::Error::Capability { capability: "registry-scan", .. }), "unexpected: {err}");
    }
}
