//! Storage abstraction for the persistent `Path` value.
//!
//! The analysis and cleanup orchestration run against this trait, so the whole
//! pipeline is unit-testable without touching a real registry.

use super::analyze::PathScope;
use crate::Result;

pub trait PathStore {
    /// Current raw `Path` value, `None` when the key or value is absent.
    fn read(&self, scope: PathScope) -> Result<Option<String>>;
    /// Replace the value. Must not be called without a written backup.
    fn write(&self, scope: PathScope, value: &str) -> Result<()>;
}
