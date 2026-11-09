//! Rollback artifacts for PATH edits: a JSON record plus a `.reg` restore
//! script that recreates the original value with the same `REG_EXPAND_SZ`
//! semantics.

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use super::analyze::PathScope;
use crate::{Error, Result, locations::BaseDirs};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvPathBackup {
    pub json_path: String,
    pub reg_path: String,
    pub original: String,
    /// Text of the `.reg` file, so callers can show it without re-reading.
    pub restore_reg_text: String,
}

pub(crate) struct BackupRequest<'a> {
    pub scope: PathScope,
    pub original: &'a str,
    pub removed: &'a [(usize, String)],
    pub created_at_unix_ms: u64,
}

/// Default backup location: the per-user data directory, never the working
/// directory.
pub(crate) fn default_dir(dirs: &BaseDirs) -> Option<PathBuf> {
    dirs.data_dir.as_ref().map(|dir| dir.join("OpenCleaner").join("backups"))
}

pub(crate) fn write(request: &BackupRequest<'_>, dir: Option<&Path>, dirs: &BaseDirs) -> Result<EnvPathBackup> {
    let Some(dir) = dir.map(Path::to_path_buf).or_else(|| default_dir(dirs))
    else {
        return Err(Error::dependency_blocked("env-path-backup", "no per-user data directory is available for the rollback file"));
    };
    fs::create_dir_all(&dir).map_err(|source| Error::Io { path: dir.display().to_string(), source })?;

    let stamp = request.created_at_unix_ms;
    let stem = format!("path-env-{}-{stamp}", request.scope.id());
    let json_path = dir.join(format!("{stem}.json"));
    let reg_path = dir.join(format!("{stem}.reg"));
    let restore_reg_text = restore_reg_text(request.scope, request.original);

    let body = serde_json::json!({
        "scope": request.scope.id(),
        "keyPath": request.scope.key_path(),
        "name": "Path",
        "original": request.original,
        "changed": request.removed.iter().map(|(index, raw)| serde_json::json!({ "index": index, "raw": raw })).collect::<Vec<_>>(),
        "createdAtUnixMs": request.created_at_unix_ms,
        "restoreFile": reg_path.display().to_string(),
    });
    let text = serde_json::to_string_pretty(&body).map_err(|error| Error::Message(format!("cannot encode PATH backup: {error}")))?;

    fs::write(&json_path, text).map_err(|source| Error::Io { path: json_path.display().to_string(), source })?;
    fs::write(&reg_path, &restore_reg_text).map_err(|source| Error::Io { path: reg_path.display().to_string(), source })?;

    Ok(EnvPathBackup {
        json_path: json_path.display().to_string(),
        reg_path: reg_path.display().to_string(),
        original: request.original.to_string(),
        restore_reg_text,
    })
}

/// Build a `.reg` snippet that restores the original `Path` value.
///
/// `hex(2)` is the textual form of `REG_EXPAND_SZ`, so `%VAR%` references in
/// the original survive a round trip instead of being frozen by expansion.
pub(crate) fn restore_reg_text(scope: PathScope, original: &str) -> String {
    let hive = match scope {
        PathScope::User => "HKEY_CURRENT_USER",
        PathScope::Machine => "HKEY_LOCAL_MACHINE",
    };
    let subkey = match scope {
        PathScope::User => r"Environment",
        PathScope::Machine => r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
    };

    let mut units: Vec<u16> = original.encode_utf16().collect();
    units.push(0);
    let hex: Vec<String> = units.iter().flat_map(|unit| unit.to_le_bytes()).map(|byte| format!("{byte:02x}")).collect();

    format!("Windows Registry Editor Version 5.00\r\n\r\n[{hive}\\{subkey}]\r\n\"Path\"=hex(2):{hex}\r\n", hex = hex.join(","))
}

pub(crate) fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|duration| duration.as_millis() as u64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_script_uses_expandable_string_encoding() {
        let text = restore_reg_text(PathScope::User, r"C:\Windows;%USERPROFILE%\bin");

        assert!(text.starts_with("Windows Registry Editor Version 5.00\r\n"));
        assert!(text.contains(r"[HKEY_CURRENT_USER\Environment]"), "{text}");
        assert!(text.contains("\"Path\"=hex(2):"), "{text}");
        // UTF-16LE of `C` is 43 00 and the value ends with a NUL terminator,
        // so the last two bytes are `00,00`.
        assert!(text.contains("43,00,3a,00"), "{text}");
        assert!(text.trim_end().ends_with("00,00"), "{text}");
    }

    #[test]
    fn machine_scope_points_at_the_session_manager_key() {
        let text = restore_reg_text(PathScope::Machine, r"C:\Windows");
        assert!(text.contains(r"[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment]"), "{text}");
    }

    #[test]
    fn backup_files_are_written_outside_the_working_directory() {
        let dir = crate::fixtures::fixture_dir("env-backup");
        let request = BackupRequest {
            scope: PathScope::User,
            original: r"C:\Windows;%USERPROFILE%\bin",
            removed: &[(1, r"%USERPROFILE%\bin".to_string())],
            created_at_unix_ms: 42,
        };
        let backup = write(&request, Some(&dir), &BaseDirs::default()).unwrap();

        let json = fs::read_to_string(&backup.json_path).unwrap();
        assert!(json.contains("\"original\""), "{json}");
        assert!(json.contains("USERPROFILE"), "{json}");
        assert!(backup.reg_path.ends_with("path-env-user-42.reg"), "{}", backup.reg_path);
        assert!(fs::read_to_string(&backup.reg_path).unwrap().contains("hex(2):"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_backup_directory_is_a_structured_failure() {
        let request = BackupRequest { scope: PathScope::User, original: "x", removed: &[], created_at_unix_ms: 1 };
        let err = write(&request, None, &BaseDirs::default()).unwrap_err();
        assert_eq!(crate::capability_code(&err), Some("dependency_blocked"), "{err}");
    }
}
