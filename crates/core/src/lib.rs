//! Open Cleaner core: portable scan kernel, platform capabilities, and
//! platform-gated registry inspection.
//!
//! Platform rules:
//! - Domain traits describe semantics only. Win32/registry calls live in
//!   `#[cfg(windows)]` submodules.
//! - Missing platform capabilities return [`Error::Unsupported`]; they never
//!   degrade silently into an empty result.

mod error;
pub mod platform;
pub mod registry;
pub mod scan;

pub use error::{Error, Result};
pub use platform::{Capabilities, Platform, capabilities};
pub use registry::{RegistryEntry, RegistryOptions, RegistryReport, registry_scan};
pub use scan::{ScanEntry, ScanOptions, ScanReport, default_scan_root, scan};
