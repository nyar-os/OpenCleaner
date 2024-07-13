//! Windows registry storage for the persistent `Path` value.
//!
//! Reads `HKCU\Environment` and the machine scope under `Session Manager`. Both
//! values are `REG_EXPAND_SZ`, so `%VAR%` references are preserved on write.

use std::path::Path;

use super::{EnvPathCleanOptions, EnvPathCleanReport, EnvPathOptions, EnvPathReport, PathContext, PathScope, PathStore, clean};
use crate::{
    Error, Result,
    locations::base_dirs,
    registry::win32::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, Hkey, KEY_READ, OwnedKey, string_value},
};

const USER_ENV: &str = r"Environment";
const MACHINE_ENV: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

fn key_of(scope: PathScope) -> (Hkey, &'static str) {
    match scope {
        PathScope::User => (HKEY_CURRENT_USER, USER_ENV),
        PathScope::Machine => (HKEY_LOCAL_MACHINE, MACHINE_ENV),
    }
}

pub(super) struct RegistryPathStore;

impl PathStore for RegistryPathStore {
    fn read(&self, scope: PathScope) -> Result<Option<String>> {
        let (hive, path) = key_of(scope);
        let Some(key) = OwnedKey::open(hive, path, KEY_READ)
        else {
            return Ok(None);
        };
        let Some(value) = key.value("Path")
        else {
            return Ok(None);
        };
        Ok(string_value(&value))
    }

    fn write(&self, scope: PathScope, value: &str) -> Result<()> {
        let (hive, path) = key_of(scope);
        let Some(key) = OwnedKey::open_for_write(hive, path)
        else {
            return Err(Error::Message(format!("cannot open {} for writing (elevation may be required)", scope.key_path())));
        };
        if !key.set_expand_string("Path", value) {
            return Err(Error::Message(format!("cannot write Path at {} (access denied)", scope.key_path())));
        }
        Ok(())
    }
}

fn context<'a>(dir_exists: &'a dyn Fn(&str) -> bool, env: &'a dyn Fn(&str) -> Option<String>) -> PathContext<'a> {
    PathContext { dir_exists, env }
}

pub(super) fn scan(options: EnvPathOptions) -> Result<EnvPathReport> {
    let dirs = base_dirs();
    let dir_exists = |path: &str| Path::new(path).is_dir();
    let env = |name: &str| std::env::var(name).ok();
    super::scan_with(&RegistryPathStore, options, &context(&dir_exists, &env), &dirs)
}

pub(super) fn clean(options: EnvPathCleanOptions) -> Result<EnvPathCleanReport> {
    let dirs = base_dirs();
    let dir_exists = |path: &str| Path::new(path).is_dir();
    let env = |name: &str| std::env::var(name).ok();
    clean::clean_with(&RegistryPathStore, options, &context(&dir_exists, &env), &dirs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::analyze;

    #[test]
    fn reads_the_user_path_and_announces_the_backup_dir() {
        // Only exercise the reader unless the test has write access: the store
        // must never be probed with a mutating write outside an explicit clean.
        let read = RegistryPathStore.read(PathScope::User).unwrap();
        assert!(read.is_none() || read.as_deref().is_some_and(|value| !value.is_empty()));

        let dirs = base_dirs();
        let report = scan(EnvPathOptions::default()).unwrap();
        assert_eq!(report.backup_dir, dirs.data_dir.as_ref().map(|dir| dir.join("OpenCleaner").join("backups").display().to_string()));
    }

    #[test]
    fn analyze_matches_the_rules_module() {
        let read = RegistryPathStore.read(PathScope::User).unwrap();
        let dir_exists = |path: &str| Path::new(path).is_dir();
        let env = |name: &str| std::env::var(name).ok();
        let ctx = context(&dir_exists, &env);
        let analysis = analyze::analyze(PathScope::User, read.as_deref(), &ctx);
        if let Some(value) = read {
            assert!(!analysis.entries.is_empty(), "expected entries for {value}");
        }
    }
}
