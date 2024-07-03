//! Platform identity, capability declaration, and platform-gated metadata
//! checks.
//!
//! This module owns the only platform `cfg` decision surface in the core. A
//! missing capability must surface as [`Error::Unsupported`] rather than as an
//! empty result or a substituted algorithm.

use std::fs::Metadata;

use serde::{Deserialize, Serialize};

#[cfg(not(windows))]
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
/// `registry_clean` stays `false` everywhere because deletion is not
/// implemented in this build. It is a declared limitation, not a silent
/// success path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    pub platform: String,
    pub arch: String,
    pub file_scan: bool,
    pub registry_scan: bool,
    pub registry_clean: bool,
    pub gui: bool,
    pub notes: Vec<String>,
}

pub fn capabilities() -> Capabilities {
    let mut notes = Vec::new();
    if cfg!(windows) {
        notes.push("registry cleaning is not implemented in this build".to_string());
    }
    else {
        let platform = name();
        notes.push(format!("registry scanning is unavailable on {platform}"));
        notes.push("WebView2 GUI is unavailable outside Windows".to_string());
    }

    Capabilities {
        platform: name().to_string(),
        arch: arch().to_string(),
        file_scan: true,
        registry_scan: cfg!(windows),
        registry_clean: false,
        gui: cfg!(windows),
        notes,
    }
}

/// Build the structured failure for a capability that is not available on the
/// current platform.
#[cfg(not(windows))]
pub(crate) fn unsupported(capability: &'static str) -> Error {
    Error::Unsupported { capability, platform: name() }
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
