//! Level-2 global caches.
//!
//! Each entry declares the manifest anchor that must have been seen during the
//! project scan. The path tables themselves are per-OS implementation details
//! and live in `windows.rs` / `unix.rs`.

use std::path::PathBuf;

use crate::locations::BaseDirs;

use super::rules::{Ecosystem, ManifestKind};

#[derive(Debug, Clone)]
pub struct GlobalCacheSpec {
    pub path: PathBuf,
    pub ecosystem: Ecosystem,
    pub anchor: ManifestKind,
    /// Human-readable rule, e.g. `Cargo.toml → cargo registry cache`.
    pub rule: &'static str,
}

#[cfg(not(windows))]
mod unix;
#[cfg(windows)]
mod windows;

/// Resolve every known global cache path. Missing base directories simply drop
/// the related specs; existence is checked by the caller.
pub fn specs(dirs: &BaseDirs) -> Vec<GlobalCacheSpec> {
    specs_with_env(dirs, |key| std::env::var(key).ok())
}

#[cfg(windows)]
pub fn specs_with_env(dirs: &BaseDirs, env: impl Fn(&str) -> Option<String>) -> Vec<GlobalCacheSpec> {
    windows::specs(dirs, env)
}

#[cfg(not(windows))]
pub fn specs_with_env(dirs: &BaseDirs, env: impl Fn(&str) -> Option<String>) -> Vec<GlobalCacheSpec> {
    unix::specs(dirs, env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn dirs(home: &Path, local: &Path, cache: &Path, data: &Path) -> BaseDirs {
        BaseDirs {
            home: Some(home.to_path_buf()),
            local_app_data: Some(local.to_path_buf()),
            app_data: Some(home.join("Roaming")),
            program_data: Some(home.join("ProgramData")),
            program_files: Some(home.join("Program Files")),
            cache_dir: Some(cache.to_path_buf()),
            data_dir: Some(data.to_path_buf()),
            cargo_home: Some(home.join(".cargo")),
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_specs_cover_the_documented_ecosystems() {
        let base = std::env::temp_dir().join("open-cleaner-global-specs");
        let env = |key: &str| -> Option<String> {
            match key {
                "GOCACHE" => Some(base.join("go-build").display().to_string()),
                "GOMODCACHE" => Some(base.join("go-mod").display().to_string()),
                _ => None,
            }
        };
        let specs = specs_with_env(&dirs(&base, &base.join("Local"), &base, &base), env);

        for path in [
            base.join(".cargo").join("registry"),
            base.join(".cargo").join("git"),
            base.join("Local").join("npm-cache"),
            base.join("Local").join("pnpm").join("store"),
            base.join("Local").join("Yarn").join("Cache"),
            base.join("go-build"),
        ] {
            assert!(specs.iter().any(|spec| spec.path == path), "missing {path:?}");
        }

        let cargo = specs.iter().find(|spec| spec.path == base.join(".cargo").join("registry")).unwrap();
        assert_eq!(cargo.anchor, ManifestKind::CargoToml);
        assert_eq!(cargo.ecosystem, Ecosystem::Cargo);
        assert!(cargo.rule.contains("Cargo.toml"));
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_specs_cover_the_documented_ecosystems() {
        let base = std::env::temp_dir().join("open-cleaner-global-specs");
        let env = |key: &str| -> Option<String> {
            match key {
                "GOCACHE" => Some(base.join("go-build").display().to_string()),
                "GOMODCACHE" => Some(base.join("go-mod").display().to_string()),
                _ => None,
            }
        };
        let specs = specs_with_env(&dirs(&base, &base, &base, &base.join("share")), env);

        for path in [base.join(".cargo").join("registry"), base.join(".npm").join("_cacache"), base.join("go-build")] {
            assert!(specs.iter().any(|spec| spec.path == path), "missing {path:?}");
        }
    }
}
