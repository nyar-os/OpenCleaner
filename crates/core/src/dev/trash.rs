//! Recycle-bin dispatch.
//!
//! Permanent deletion is always available. The recycle bin is a platform
//! capability: when it is unavailable the caller must say "permanent", never
//! claim recoverability.

use std::path::Path;

use crate::{Error, Result};

#[cfg(not(windows))]
mod unix;
#[cfg(windows)]
mod windows;

pub fn supported() -> bool {
    crate::platform::trash_available()
}

pub fn trash_path(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        windows::trash_path(path)
    }
    #[cfg(not(windows))]
    {
        unix::trash_path(path)
    }
}

/// Permanent recursive removal. Never follows symlinks.
pub fn remove_permanently(path: &Path) -> Result<()> {
    std::fs::remove_dir_all(path).map_err(|source| Error::Io { path: path.display().to_string(), source })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_matches_platform_declaration() {
        assert_eq!(supported(), crate::platform::trash_available());
    }
}
