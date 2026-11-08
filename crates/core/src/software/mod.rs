//! Software-residue cleanup domain.
//!
//! Every candidate is anchored on an uninstall registry entry plus a path that
//! actually exists. Directories that are still installed, belong to user data,
//! or have no uninstall entry are never reported.

pub mod analyze;
#[cfg(windows)]
pub(crate) mod windows;

use serde::{Deserialize, Serialize};

use crate::Result;
#[cfg(not(windows))]
use crate::platform;

pub use analyze::{SoftwareFinding, SoftwareKind, SoftwareSkip};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SoftwareOptions {
    /// Maximum number of findings to return (0 or `None` = all).
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareReport {
    pub platform: String,
    /// Where the registry snapshot came from (`windows-registry` or a fixture).
    pub source: String,
    /// Uninstall subkeys inspected.
    pub uninstall_keys: usize,
    pub findings: Vec<SoftwareFinding>,
    /// Entries evaluated and rejected, with the reason.
    pub skipped: Vec<SoftwareSkip>,
    pub warnings: Vec<String>,
    pub scanned_at_unix_ms: u64,
}

/// Read-only residue scan. Nothing is removed, so this result is always a
/// preview. Non-Windows targets fail with `unsupported_platform`.
pub fn software_residue_scan(options: SoftwareOptions) -> Result<SoftwareReport> {
    #[cfg(windows)]
    {
        windows::scan(options)
    }
    #[cfg(not(windows))]
    {
        let _ = options;
        Err(platform::unsupported("software-residue-scan"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn live_scan_reports_anchored_candidates_only() {
        let report = software_residue_scan(SoftwareOptions::default()).unwrap();
        assert_eq!(report.platform, "windows");
        assert_eq!(report.source, "windows-registry");
        assert!(report.uninstall_keys > 0, "expected uninstall keys: {report:?}");
        for finding in &report.findings {
            assert!(finding.registry_key.to_ascii_lowercase().contains("uninstall"), "{finding:?}");
            assert!(!finding.evidence.is_empty(), "{finding:?}");
            assert!(!finding.safety.is_empty(), "{finding:?}");
            assert!(finding.removable);
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn software_scan_fails_with_unsupported_platform() {
        let err = software_residue_scan(SoftwareOptions::default()).unwrap_err();
        assert_eq!(crate::capability_code(&err), Some("unsupported_platform"), "{err}");
        assert!(matches!(err, crate::Error::Capability { capability: "software-residue-scan", .. }), "{err}");
    }
}
