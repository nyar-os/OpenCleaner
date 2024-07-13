//! Platform identity, capability declaration, and platform-gated metadata
//! checks.
//!
//! This module owns the only platform `cfg` decision surface in the core. A
//! missing capability must surface as [`Error::Capability`] rather than as an
//! empty result or a substituted algorithm.

use std::{fs::Metadata, path::Path};

use serde::{Deserialize, Serialize};

use crate::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    Windows,
    Macos,
    Linux,
    Other,
}

pub const fn current() -> Platform {
    if cfg!(windows) {
        Platform::Windows
    }
    else if cfg!(target_os = "macos") {
        Platform::Macos
    }
    else if cfg!(target_os = "linux") {
        Platform::Linux
    }
    else {
        Platform::Other
    }
}

/// Rust `target_os` label, e.g. `windows`, `macos`, `linux`.
pub const fn name() -> &'static str {
    std::env::consts::OS
}

/// Rust `target_arch` label, e.g. `x86_64`, `aarch64`.
pub const fn arch() -> &'static str {
    std::env::consts::ARCH
}

/// Capabilities visible on the current build target.
///
/// A `false` flag means the gated call fails with a structured
/// [`crate::CapabilityState`] code; it never means "empty result".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    pub platform: String,
    pub arch: String,
    pub file_scan: bool,
    pub dev_scan: bool,
    pub dev_clean: bool,
    /// Whether [`crate::dev`] uses the OS recycle bin instead of permanent
    /// deletion.
    pub trash: bool,
    pub registry_scan: bool,
    pub registry_clean: bool,
    pub env_path_scan: bool,
    pub env_path_clean: bool,
    pub software_scan: bool,
    pub notes: Vec<String>,
}

pub fn capabilities() -> Capabilities {
    let mut capabilities = Capabilities {
        platform: name().to_string(),
        arch: arch().to_string(),
        file_scan: true,
        dev_scan: true,
        dev_clean: true,
        trash: trash_available(),
        registry_scan: registry_scan_available(),
        registry_clean: false,
        env_path_scan: env_path_available(),
        env_path_clean: env_path_available(),
        software_scan: software_available(),
        notes: Vec::new(),
    };
    capabilities.notes = domain_notes(&capabilities);
    capabilities
}

/// Notes describe domain capability state only. They never mention an OS or a
/// specific GUI toolkit, because the author surface must read the same shape on
/// every supported build target.
fn domain_notes(capabilities: &Capabilities) -> Vec<String> {
    let mut notes = Vec::new();
    if !capabilities.registry_scan {
        notes.push("registry scanning is unavailable".to_string());
    }
    if !capabilities.registry_clean {
        notes.push("registry cleaning is not implemented in this build".to_string());
    }
    if !capabilities.env_path_scan || !capabilities.env_path_clean {
        notes.push("PATH editing is not implemented in this build".to_string());
    }
    if !capabilities.software_scan {
        notes.push("software residue scanning is not implemented in this build".to_string());
    }
    if !capabilities.trash {
        notes.push("recycle bin is unavailable in this build, deletions are permanent".to_string());
    }
    notes
}

/// Whether registry inspection has an implementation for this build target.
#[cfg(windows)]
pub(crate) const fn registry_scan_available() -> bool {
    true
}

#[cfg(not(windows))]
pub(crate) const fn registry_scan_available() -> bool {
    false
}

/// Whether PATH inspection and editing are implemented for this build target.
#[cfg(windows)]
pub(crate) const fn env_path_available() -> bool {
    true
}

#[cfg(not(windows))]
pub(crate) const fn env_path_available() -> bool {
    false
}

/// Whether software-residue scanning is implemented for this build target.
#[cfg(windows)]
pub(crate) const fn software_available() -> bool {
    true
}

#[cfg(not(windows))]
pub(crate) const fn software_available() -> bool {
    false
}

/// Recycle-bin availability for this build and OS.
#[cfg(windows)]
pub(crate) const fn trash_available() -> bool {
    true
}

#[cfg(not(windows))]
pub(crate) const fn trash_available() -> bool {
    false
}

/// Build the structured failure for a capability that is not available on the
/// current platform. Dead code on the platform that implements the capability.
#[allow(dead_code)]
pub(crate) fn unsupported(capability: &'static str) -> Error {
    Error::unsupported_platform(capability)
}

/// Volume identity used to explain cross-volume deletions.
#[cfg(windows)]
pub(crate) fn volume_of(path: &Path) -> Option<String> {
    use std::path::{Component, Prefix};

    match path.components().next()? {
        Component::Prefix(prefix) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => Some(format!("{}:", char::from(letter).to_ascii_uppercase())),
            _ => Some(prefix.as_os_str().to_string_lossy().to_string()),
        },
        _ => None,
    }
}

#[cfg(not(windows))]
pub(crate) fn volume_of(path: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;

    fs_metadata(path).map(|meta| format!("dev:{}", meta.dev()))
}

#[cfg(not(windows))]
fn fs_metadata(path: &Path) -> Option<Metadata> {
    std::fs::symlink_metadata(path).ok()
}

/// Windows junctions and reparse points can form cycles in temp trees, so the
/// portable traversal must not descend into them.
#[cfg(windows)]
pub(crate) fn is_link_like(meta: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// On Unix, `DirEntry::metadata` does not follow symlinks, so symbolic links
/// already fail the `is_dir` check. No extra platform call is needed.
#[cfg(not(windows))]
pub(crate) fn is_link_like(_meta: &Metadata) -> bool {
    false
}
