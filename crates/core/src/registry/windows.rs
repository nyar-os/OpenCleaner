//! Read-only Windows registry inspection.
//!
//! This is the only module in the core that decides *which* registry keys the
//! residue rules read. The raw Win32 calls live in [`super::win32`].

use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use super::{
    RegistryEntry, RegistryOptions, RegistryReport, RegistryResidueOptions, RegistryResidueReport,
    analyze::{self, AnalyzeContext},
    model::RegistrySnapshot,
    win32::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, OwnedKey, hive_label, map_value},
};
use crate::Result;

const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

/// Copy one live key (values only) into the platform-neutral snapshot.
fn record_key(snapshot: &mut RegistrySnapshot, hive: super::win32::Hkey, label: &str, path: &str, sam: u32) {
    let Some(key) = OwnedKey::open(hive, path, sam)
    else {
        return;
    };
    let full = format!("{label}\\{path}");
    snapshot.insert(full.clone());
    for (name, value) in key.values() {
        snapshot.set_value(&full, &name, map_value(&value));
    }
}

fn collect_class_associations(snapshot: &mut RegistrySnapshot, hive: super::win32::Hkey, label: &str, sam: u32, root: &str) {
    let Some(parent) = OwnedKey::open(hive, root, sam)
    else {
        return;
    };
    for name in parent.subkeys() {
        record_key(snapshot, hive, label, &format!(r"{root}\{name}\shell\open\command"), sam);
        if name.eq_ignore_ascii_case("Applications") || name.eq_ignore_ascii_case("SystemFileAssociations") {
            let Some(container) = OwnedKey::open(hive, &format!(r"{root}\{name}"), sam)
            else {
                continue;
            };
            for child in container.subkeys() {
                record_key(snapshot, hive, label, &format!(r"{root}\{name}\{child}\shell\open\command"), sam);
            }
        }
    }
}

/// Capture only the keys the residue rules use. Reading the whole registry
/// would be slow and unnecessary.
pub(crate) fn snapshot_registry() -> RegistrySnapshot {
    let mut snapshot = RegistrySnapshot { source: "windows-registry".to_string(), keys: Vec::new(), warnings: Vec::new() };

    for (hive, label, sam, root) in [
        (HKEY_LOCAL_MACHINE, "HKLM", KEY_READ | KEY_WOW64_64KEY, UNINSTALL),
        (HKEY_LOCAL_MACHINE, "HKLM", KEY_READ | KEY_WOW64_64KEY, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (HKEY_CURRENT_USER, "HKCU", KEY_READ, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    ] {
        let Some(parent) = OwnedKey::open(hive, root, sam)
        else {
            continue;
        };
        for name in parent.subkeys() {
            record_key(&mut snapshot, hive, label, &format!(r"{root}\{name}"), sam);
        }
    }

    for (hive, label, sam, root) in [
        (HKEY_CURRENT_USER, "HKCU", KEY_READ, r"Software\Classes"),
        (HKEY_LOCAL_MACHINE, "HKLM", KEY_READ | KEY_WOW64_64KEY, r"SOFTWARE\Classes"),
    ] {
        collect_class_associations(&mut snapshot, hive, label, sam, root);
    }

    for (hive, label, sam, root) in [
        (HKEY_CURRENT_USER, "HKCU", KEY_READ, r"Software\Microsoft\Windows\CurrentVersion"),
        (HKEY_LOCAL_MACHINE, "HKLM", KEY_READ | KEY_WOW64_64KEY, r"SOFTWARE\Microsoft\Windows\CurrentVersion"),
        (HKEY_LOCAL_MACHINE, "HKLM", KEY_READ | KEY_WOW64_64KEY, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion"),
    ] {
        for suffix in ["Run", "RunOnce"] {
            record_key(&mut snapshot, hive, label, &format!(r"{root}\{suffix}"), sam);
        }
    }

    snapshot
}

pub(super) fn residue_scan(options: RegistryResidueOptions) -> Result<RegistryResidueReport> {
    let snapshot = snapshot_registry();
    let exists = |path: &Path| path.exists();
    let env = |name: &str| std::env::var(name).ok();
    let ctx = AnalyzeContext { exists: &exists, env: &env };
    let mut findings = analyze::analyze(&snapshot, &ctx);

    let available = findings.len();
    let limit = options.limit.unwrap_or(0);
    let mut warnings = snapshot.warnings.clone();
    if limit > 0 && findings.len() > limit {
        findings.truncate(limit);
        warnings.push(format!("{available} findings found; showing the first {limit}"));
    }

    Ok(RegistryResidueReport {
        platform: crate::platform::name().to_string(),
        source: snapshot.source,
        scanned_keys: snapshot.keys.len(),
        findings,
        warnings,
        scanned_at_unix_ms: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0),
    })
}

pub(super) fn scan(options: RegistryOptions) -> Result<RegistryReport> {
    let limit = options.limit.unwrap_or(100).max(1);
    let mut entries = Vec::new();
    let mut scanned_keys = 0usize;

    for (hive, sam) in [(HKEY_LOCAL_MACHINE, KEY_READ | KEY_WOW64_64KEY), (HKEY_CURRENT_USER, KEY_READ)] {
        let Some(root) = OwnedKey::open(hive, UNINSTALL, sam)
        else {
            continue;
        };

        for name in root.subkeys() {
            scanned_keys += 1;
            let subkey = format!("{UNINSTALL}\\{name}");
            let Some(key) = OwnedKey::open(hive, &subkey, sam)
            else {
                continue;
            };
            if let Some(flag) = key.value("SystemComponent").as_ref().and_then(super::win32::dword_value)
                && flag == 1
            {
                continue;
            }

            let display_name = key.value("DisplayName").as_ref().and_then(super::win32::string_value);
            let install_location = key.value("InstallLocation").as_ref().and_then(super::win32::string_value);
            let version = key.value("DisplayVersion").as_ref().and_then(super::win32::string_value);

            let Some(location) = install_location
            else {
                continue;
            };
            let location = location.trim_matches('"').trim().to_string();
            if location.is_empty() || Path::new(&location).exists() {
                continue;
            }

            entries.push(RegistryEntry {
                key: format!("{}\\{subkey}", hive_label(hive)),
                display_name,
                install_location: Some(location),
                version,
                reason: "install-location-missing".to_string(),
            });
        }
    }

    entries.sort_by(|a, b| a.key.cmp(&b.key));
    entries.truncate(limit);

    Ok(RegistryReport {
        platform: crate::platform::name().to_string(),
        scanned_keys,
        entries,
        scanned_at_unix_ms: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0),
    })
}
