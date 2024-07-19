use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Structured reason a capability is unavailable.
///
/// These strings are the only accepted failure vocabulary for gated
/// capabilities. Callers (CLI/UI/NAPI) surface them verbatim; they must never
/// be replaced by an empty result or a silent skip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    /// The capability is meaningless on this OS.
    UnsupportedPlatform,
    /// The capability is valid on this OS but this build does not implement it.
    NotImplemented,
    /// A required host dependency is missing.
    DependencyBlocked,
}

impl CapabilityState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::NotImplemented => "not_implemented",
            Self::DependencyBlocked => "dependency_blocked",
        }
    }
}

impl std::fmt::Display for CapabilityState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Message(String),
    /// A capability that exists in the domain model but cannot run here.
    #[error("{capability} is unavailable ({state}): {detail}")]
    Capability { capability: &'static str, state: CapabilityState, detail: String },
}

impl Error {
    /// Failure for a capability that does not exist on the current OS.
    /// (Only reachable from platform-gated modules, so it is dead code on the
    /// matching platform.)
    #[allow(dead_code)]
    pub(crate) fn unsupported_platform(capability: &'static str) -> Self {
        let platform = crate::platform::name();
        Self::Capability { capability, state: CapabilityState::UnsupportedPlatform, detail: format!("not available on {platform}") }
    }

    pub(crate) fn not_implemented(capability: &'static str) -> Self {
        Self::Capability { capability, state: CapabilityState::NotImplemented, detail: "not implemented in this build".to_string() }
    }

    #[allow(dead_code)]
    pub(crate) fn dependency_blocked(capability: &'static str, detail: impl Into<String>) -> Self {
        Self::Capability { capability, state: CapabilityState::DependencyBlocked, detail: detail.into() }
    }
}

/// Stable machine-readable code for capability failures (`unsupported_platform`
/// / `not_implemented` / `dependency_blocked`). Returns `None` for ordinary
/// errors.
pub fn capability_code(error: &Error) -> Option<&'static str> {
    match error {
        Error::Capability { state, .. } => Some(state.as_str()),
        _ => None,
    }
}

pub type Result<T> = std::result::Result<T, Error>;
