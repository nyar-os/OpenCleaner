//! Open Cleaner core: portable scan kernel, platform capabilities, developer
//! artifact cleanup, and platform-gated registry inspection.
//!
//! Platform rules:
//! - Domain logic (rules, models, analysis) contains no `cfg` branches.
//! - Win32 / registry / recycle-bin calls live in `#[cfg(windows)]` submodules.
//! - Missing capabilities return [`Error::Capability`] with a
//!   `unsupported_platform` / `not_implemented` / `dependency_blocked` code.
//!   They never degrade silently into an empty result.

mod error;
pub mod dev;
pub mod locations;
pub mod platform;
pub mod registry;
pub mod scan;

pub use dev::{
    CleanStatus, DeleteMode, DevArtifact, DevCleanItem, DevCleanOptions, DevCleanReport, DevPlan, DevPlanItem, DevScanOptions,
    DevScanReport, RiskLevel, SkipReason, dev_clean, dev_plan, dev_scan,
};
pub use error::{CapabilityState, Error, Result, capability_code};
pub use locations::{BaseDirs, base_dirs};
pub use platform::{Capabilities, Platform, capabilities};
pub use registry::{RegistryEntry, RegistryOptions, RegistryReport, registry_scan};
pub use scan::{ScanEntry, ScanOptions, ScanReport, default_scan_root, scan};
