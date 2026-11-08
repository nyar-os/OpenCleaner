//! Open Cleaner core: portable scan kernel, platform capabilities, developer
//! artifact cleanup, and platform-gated registry inspection.
//!
//! Platform rules:
//! - Domain logic (rules, models, analysis) contains no `cfg` branches.
//! - Win32 / registry / recycle-bin calls live in `#[cfg(windows)]` submodules.
//! - Missing capabilities return [`Error::Capability`] with a
//!   `unsupported_platform` / `not_implemented` / `dependency_blocked` code.
//!   They never degrade silently into an empty result.

pub mod anchors;
pub mod build_dirs;
pub mod dev;
pub mod env;
mod error;
pub mod locations;
pub mod platform;
pub mod registry;
mod safety;
pub mod scan;
pub mod software;
pub mod temp;

pub use anchors::{
    BuildRootCleanItem, BuildRootCleanOptions, BuildRootCleanReport, BuildRootConfig, BuildRootDeclaration, BuildRootEntry, BuildRootOptions,
    BuildRootPlan, build_root_clean, build_root_config, build_root_plan, default_build_root_config, parse_build_root_config,
};
pub use build_dirs::{
    BuildDirDeclaration, BuildDirOptions, BuildDirReport, BuildOutputProbe, DeclarationOrigin, UncoveredDirectory, build_dir_scan,
};
pub use dev::{
    CleanStatus, DeleteMode, DevArtifact, DevCleanItem, DevCleanOptions, DevCleanReport, DevCleanTarget, DevPlan, DevPlanItem, DevProfile,
    DevScanOptions, DevScanReport, DevSizeBaseline, DevStageTiming, RiskLevel, SizeSource, SkipReason, dev_clean, dev_plan, dev_scan,
};
pub use env::{
    EnvPathBackup, EnvPathCleanItem, EnvPathCleanOptions, EnvPathCleanReport, EnvPathCleanStatus, EnvPathEntry, EnvPathOptions, EnvPathReport,
    EnvPathScopeReport, EnvPathSelection, PathIssue, PathScope, env_path_clean, env_path_scan,
};
pub use error::{CapabilityState, Error, Result, capability_code};
pub use locations::{BaseDirs, base_dirs};
pub use platform::{Capabilities, Platform, capabilities};
pub use registry::{
    RegistryEntry, RegistryFinding, RegistryOptions, RegistryReport, RegistryResidueOptions, RegistryResidueReport, ResidueKind,
    registry_residue_scan, registry_scan,
};
pub use scan::{ScanEntry, ScanOptions, ScanReport, default_scan_root, scan};
pub use software::{SoftwareFinding, SoftwareKind, SoftwareOptions, SoftwareReport, SoftwareSkip, software_residue_scan};
pub use temp::{
    CwdProbeReport, TempCleanOptions, TempCleanReport, TempFailure, TempFile, TempGroup, TempOptions, TempPlan, TempSkips, temp_clean,
    temp_plan,
};
