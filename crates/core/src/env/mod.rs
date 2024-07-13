//! PATH environment-variable domain (Windows-bound).
//!
//! Rules live in [`analyze`] and run on a raw value, so fixtures cover them on
//! every platform. Registry access is behind [`PathStore`]; the Windows
//! implementation is the only module that reads or writes the real key.
//!
//! Failure contract: non-Windows targets return
//! [`Error::Capability`](crate::Error) with `unsupported_platform`. They never
//! return an empty report, because "no issues" would read as "healthy PATH".

pub mod analyze;
mod backup;
mod clean;
mod store;
#[cfg(windows)]
mod windows;

use serde::{Deserialize, Serialize};

#[cfg(not(windows))]
use crate::platform;
use crate::{Result, locations::BaseDirs};

pub use analyze::{EnvPathEntry, PathAnalysis, PathContext, PathIssue, PathScope};
pub use backup::EnvPathBackup;
pub use clean::{EnvPathCleanItem, EnvPathCleanOptions, EnvPathCleanReport, EnvPathCleanStatus, EnvPathSelection, clean_with};
pub use store::PathStore;

/// Limits are applied per scope after analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnvPathOptions {
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvPathScopeReport {
    pub scope: PathScope,
    pub key_path: String,
    pub present: bool,
    /// Every entry, healthy or not, so a dry-run and an execution result line
    /// up by `index`.
    pub entries: Vec<EnvPathEntry>,
    pub issues: usize,
    pub removable: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvPathReport {
    pub platform: String,
    pub scopes: Vec<EnvPathScopeReport>,
    /// Where the next clean will write its rollback pair.
    pub backup_dir: Option<String>,
    pub warnings: Vec<String>,
    pub scanned_at_unix_ms: u64,
}

/// Read-only PATH inspection for the user and machine scopes. Nothing is
/// modified, so this result is always a preview.
pub fn env_path_scan(options: EnvPathOptions) -> Result<EnvPathReport> {
    #[cfg(windows)]
    {
        windows::scan(options)
    }
    #[cfg(not(windows))]
    {
        let _ = options;
        Err(platform::unsupported("env-path-scan"))
    }
}

pub fn env_path_clean(options: EnvPathCleanOptions) -> Result<EnvPathCleanReport> {
    #[cfg(windows)]
    {
        windows::clean(options)
    }
    #[cfg(not(windows))]
    {
        let _ = options;
        Err(platform::unsupported("env-path-clean"))
    }
}

/// Shared scan pipeline, also used by fixture tests through a fake store.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn scan_with(store: &dyn PathStore, options: EnvPathOptions, ctx: &PathContext<'_>, dirs: &BaseDirs) -> Result<EnvPathReport> {
    let mut scopes = Vec::new();
    let mut warnings = Vec::new();
    for scope in [PathScope::User, PathScope::Machine] {
        let raw = store.read(scope)?;
        let analysis = analyze::analyze(scope, raw.as_deref(), ctx);
        warnings.extend(analysis.warnings);
        let issues = analysis.entries.iter().filter(|entry| entry.issue.is_some()).count();
        let removable = analysis.entries.iter().filter(|entry| entry.removable).count();
        let mut entries = analysis.entries;
        if let Some(limit) = options.limit.filter(|limit| *limit > 0)
            && entries.len() > limit
        {
            warnings.push(format!("{}: showing the first {limit} of {} entries", scope.id(), entries.len()));
            entries.truncate(limit);
        }
        scopes.push(EnvPathScopeReport { scope, key_path: scope.key_path().to_string(), present: raw.is_some(), entries, issues, removable });
    }

    Ok(EnvPathReport {
        platform: crate::platform::name().to_string(),
        scopes,
        backup_dir: backup::default_dir(dirs).map(|dir| dir.display().to_string()),
        warnings,
        scanned_at_unix_ms: backup::now_millis(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn live_scan_reports_both_scopes_without_preselecting_anything() {
        let report = env_path_scan(EnvPathOptions::default()).unwrap();
        assert_eq!(report.platform, "windows");
        assert_eq!(report.scopes.len(), 2);
        assert!(report.scopes.iter().any(|scope| scope.present), "expected at least one PATH value: {report:?}");

        for scope in &report.scopes {
            assert_eq!(scope.key_path, scope.scope.key_path());
            for entry in &scope.entries {
                assert!(!entry.default_selected, "PATH edits must never be pre-selected: {entry:?}");
                assert_eq!(entry.scope, scope.scope);
            }
        }
        assert!(report.backup_dir.is_some(), "the rollback directory must be announced up front");
    }

    #[cfg(not(windows))]
    #[test]
    fn both_path_capabilities_fail_with_unsupported_platform() {
        let err = env_path_scan(EnvPathOptions::default()).unwrap_err();
        assert_eq!(crate::capability_code(&err), Some("unsupported_platform"), "{err}");
        assert!(matches!(err, crate::Error::Capability { capability: "env-path-scan", .. }), "{err}");

        let err = env_path_clean(EnvPathCleanOptions { scope: PathScope::User, selections: Vec::new(), confirm: true, backup_dir: None })
            .unwrap_err();
        assert_eq!(crate::capability_code(&err), Some("unsupported_platform"), "{err}");
        assert!(matches!(err, crate::Error::Capability { capability: "env-path-clean", .. }), "{err}");
    }
}
