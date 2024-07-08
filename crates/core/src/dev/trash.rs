//! Recycle-bin dispatch.
//!
//! Permanent deletion is always available. The recycle bin is a platform
//! capability: when it is unavailable the caller must say "permanent", never
//! claim recoverability.

use std::path::Path;

use crate::{Error, Result};

#[cfg(windows)]
mod windows;
#[cfg(not(windows))]
mod unix;

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
        let _ = path;
        Err(Error::not_implemented("dev-trash"))
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
