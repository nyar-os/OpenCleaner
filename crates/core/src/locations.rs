//! Platform base directories expressed as data.
//!
//! The domain only consumes [`BaseDirs`]; the per-OS mapping lives in
//! [`resolve_dirs`] and is unit-tested with an injected environment so fixtures
//! do not depend on the host.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::platform::{self, Platform};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseDirs {
    pub home: Option<PathBuf>,
    pub local_app_data: Option<PathBuf>,
    pub app_data: Option<PathBuf>,
    pub program_data: Option<PathBuf>,
    pub program_files: Option<PathBuf>,
    /// Per-user cache root (`~/.cache`, `~/Library/Caches`,
    /// `%LOCALAPPDATA%`).
    pub cache_dir: Option<PathBuf>,
    /// Per-user data root (`~/.local/share`, `~/Library/Application Support`,
    /// `%LOCALAPPDATA%`).
    pub data_dir: Option<PathBuf>,
    pub cargo_home: Option<PathBuf>,
}

pub fn base_dirs() -> BaseDirs {
    resolve_dirs(platform::current(), |key| std::env::var(key).ok())
}

/// Resolve base directories for an explicit platform and environment.
pub fn resolve_dirs(platform: Platform, env: impl Fn(&str) -> Option<String>) -> BaseDirs {
    let non_empty =
        |key: &str| -> Option<PathBuf> { env(key).map(|value| value.trim().to_string()).filter(|value| !value.is_empty()).map(PathBuf::from) };

    let home = match platform {
        Platform::Windows => non_empty("USERPROFILE").or_else(|| {
            let drive = env("HOMEDRIVE").filter(|value| !value.trim().is_empty())?;
            let path = env("HOMEPATH").filter(|value| !value.trim().is_empty())?;
            Some(PathBuf::from(format!("{drive}{path}")))
        }),
        _ => non_empty("HOME"),
    };

    let (local_app_data, app_data, program_data, program_files, cache_dir, data_dir) = match platform {
        Platform::Windows => {
            let local = non_empty("LOCALAPPDATA").or_else(|| home.as_ref().map(|h| h.join("AppData").join("Local")));
            let roaming = non_empty("APPDATA").or_else(|| home.as_ref().map(|h| h.join("AppData").join("Roaming")));
            let program_data = non_empty("ProgramData").or_else(|| home.as_ref().map(|_| PathBuf::from(r"C:\ProgramData")));
            let program_files = non_empty("ProgramFiles").or_else(|| home.as_ref().map(|_| PathBuf::from(r"C:\Program Files")));
            (local.clone(), roaming, program_data, program_files, local.clone(), local)
        }
        Platform::Macos => (
            None,
            None,
            None,
            None,
            home.as_ref().map(|h| h.join("Library").join("Caches")),
            home.as_ref().map(|h| h.join("Library").join("Application Support")),
        ),
        _ => (
            None,
            None,
            None,
            None,
            non_empty("XDG_CACHE_HOME").or_else(|| home.as_ref().map(|h| h.join(".cache"))),
            non_empty("XDG_DATA_HOME").or_else(|| home.as_ref().map(|h| h.join(".local").join("share"))),
        ),
    };

    let cargo_home = non_empty("CARGO_HOME").or_else(|| home.as_ref().map(|h| h.join(".cargo")));

    BaseDirs { home, local_app_data, app_data, program_data, program_files, cache_dir, data_dir, cargo_home }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn env_from(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: BTreeMap<String, String> = pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect();
        move |key: &str| map.get(key).cloned()
    }

    #[test]
    fn windows_layout_uses_userprofile_and_localappdata() {
        let home = PathBuf::from(r"C:\Users\dev");
        let local = PathBuf::from(r"C:\Users\dev\AppData\Local");
        let roaming = PathBuf::from(r"C:\Users\dev\AppData\Roaming");
        let dirs = resolve_dirs(
            Platform::Windows,
            env_from(&[
                ("USERPROFILE", r"C:\Users\dev"),
                ("LOCALAPPDATA", r"C:\Users\dev\AppData\Local"),
                ("APPDATA", r"C:\Users\dev\AppData\Roaming"),
                ("ProgramData", r"D:\Data"),
                ("ProgramFiles", r"D:\Programs"),
            ]),
        );

        // Build expected paths with `PathBuf`/`join` so host separator rules match
        // `resolve_dirs` on Unix CI runners as well as Windows.
        assert_eq!(dirs.home, Some(home.clone()));
        assert_eq!(dirs.local_app_data, Some(local.clone()));
        assert_eq!(dirs.app_data, Some(roaming));
        assert_eq!(dirs.program_data, Some(PathBuf::from(r"D:\Data")));
        assert_eq!(dirs.program_files, Some(PathBuf::from(r"D:\Programs")));
        assert_eq!(dirs.cache_dir, Some(local));
        assert_eq!(dirs.cargo_home, Some(home.join(".cargo")));
    }

    #[test]
    fn windows_layout_falls_back_to_drive_and_windows_defaults() {
        let home = PathBuf::from(r"C:\Users\dev");
        let dirs = resolve_dirs(Platform::Windows, env_from(&[("HOMEDRIVE", "C:"), ("HOMEPATH", r"\Users\dev")]));

        assert_eq!(dirs.home, Some(home.clone()));
        assert_eq!(dirs.local_app_data, Some(home.join("AppData").join("Local")));
        assert_eq!(dirs.program_data, Some(PathBuf::from(r"C:\ProgramData")));
    }

    #[test]
    fn linux_layout_uses_xdg_and_home() {
        let dirs = resolve_dirs(
            Platform::Linux,
            env_from(&[("HOME", "/home/dev"), ("XDG_CACHE_HOME", "/cache"), ("XDG_DATA_HOME", "/data"), ("CARGO_HOME", "/cargo")]),
        );

        assert_eq!(dirs.cache_dir.as_deref(), Some(std::path::Path::new("/cache")));
        assert_eq!(dirs.data_dir.as_deref(), Some(std::path::Path::new("/data")));
        assert_eq!(dirs.cargo_home.as_deref(), Some(std::path::Path::new("/cargo")));
        assert_eq!(dirs.program_data, None);
    }

    #[test]
    fn linux_layout_defaults_to_home_cache_and_local_share() {
        let dirs = resolve_dirs(Platform::Linux, env_from(&[("HOME", "/home/dev")]));

        assert_eq!(dirs.cache_dir.as_deref(), Some(std::path::Path::new("/home/dev/.cache")));
        assert_eq!(dirs.data_dir.as_deref(), Some(std::path::Path::new("/home/dev/.local/share")));
        assert_eq!(dirs.cargo_home.as_deref(), Some(std::path::Path::new("/home/dev/.cargo")));
    }

    #[test]
    fn macos_layout_uses_library_dirs() {
        let dirs = resolve_dirs(Platform::Macos, env_from(&[("HOME", "/Users/dev")]));

        assert_eq!(dirs.cache_dir.as_deref(), Some(std::path::Path::new("/Users/dev/Library/Caches")));
        assert_eq!(dirs.data_dir.as_deref(), Some(std::path::Path::new("/Users/dev/Library/Application Support")));
    }
}
