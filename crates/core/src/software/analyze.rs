//! Software-residue rules. Every candidate is anchored on an uninstall
//! registry entry, and the analysis runs on a snapshot so fixtures cover it on
//! every platform.

use serde::{Deserialize, Serialize};

use crate::registry::{
    analyze::expand_env,
    model::{RegistrySnapshot, RegistryValue},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SoftwareKind {
    /// A leftover product directory where the recorded install path is gone.
    InstallDirectory,
    /// A leftover configuration or cache directory for an uninstalled product.
    ConfigDirectory,
}

impl SoftwareKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InstallDirectory => "install-directory",
            Self::ConfigDirectory => "config-directory",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareFinding {
    pub id: String,
    pub kind: SoftwareKind,
    pub path: String,
    pub bytes: u64,
    pub display_name: String,
    /// Registry key that anchors this candidate.
    pub registry_key: String,
    pub install_location: Option<String>,
    /// Which rule matched, e.g. `missing-install-location-sibling`.
    pub rule: String,
    pub evidence: String,
    pub safety: String,
    pub removable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareSkip {
    pub registry_key: String,
    pub display_name: Option<String>,
    /// `still-installed`, `system-component`, `update-package`,
    /// `no-display-name` or `user-data`.
    pub reason: String,
}

pub struct SoftwareContext<'a> {
    pub dir_exists: &'a dyn Fn(&str) -> bool,
    pub file_exists: &'a dyn Fn(&str) -> bool,
    pub list_dir: &'a dyn Fn(&str) -> Vec<String>,
    pub dir_size: &'a dyn Fn(&str) -> u64,
    pub env: &'a dyn Fn(&str) -> Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SoftwareAnalysis {
    pub findings: Vec<SoftwareFinding>,
    pub skipped: Vec<SoftwareSkip>,
    pub warnings: Vec<String>,
    /// Uninstall subkeys inspected.
    pub uninstall_keys: usize,
}

/// Standard install roots used when the recorded install location is empty.
fn install_roots(ctx: &SoftwareContext<'_>) -> Vec<String> {
    let mut roots = Vec::new();
    for name in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
        let Some(value) = (ctx.env)(name)
        else {
            continue;
        };
        let value = if name == "LOCALAPPDATA" { format!("{value}\\Programs") } else { value };
        if (ctx.dir_exists)(&value) {
            roots.push(value);
        }
    }
    roots
}

/// Roots that hold per-user / per-machine configuration and cache data.
fn config_roots(ctx: &SoftwareContext<'_>) -> Vec<String> {
    let mut roots = Vec::new();
    for name in ["LOCALAPPDATA", "APPDATA", "ProgramData"] {
        let Some(value) = (ctx.env)(name)
        else {
            continue;
        };
        if (ctx.dir_exists)(&value) {
            roots.push(value);
        }
    }
    roots
}

/// Documents, Desktop, Downloads and Pictures are user data and must never be
/// candidates, even if a name matches.
fn user_data_roots(ctx: &SoftwareContext<'_>) -> Vec<String> {
    let Some(profile) = (ctx.env)("USERPROFILE")
    else {
        return Vec::new();
    };
    ["Documents", "Desktop", "Downloads", "Pictures", "Videos", "Music"].iter().map(|name| format!("{profile}\\{name}")).collect()
}

fn is_under(path: &str, root: &str) -> bool {
    let path = path.replace('/', "\\").to_ascii_lowercase();
    let root = root.replace('/', "\\").to_ascii_lowercase();
    let root = root.trim_end_matches('\\');
    !root.is_empty() && path.starts_with(root) && path[root.len()..].starts_with('\\')
}

pub fn analyze(snapshot: &RegistrySnapshot, ctx: &SoftwareContext<'_>) -> SoftwareAnalysis {
    let mut analysis = SoftwareAnalysis { warnings: snapshot.warnings.clone(), ..SoftwareAnalysis::default() };
    let user_data = user_data_roots(ctx);
    let install_roots = install_roots(ctx);
    let config_roots = config_roots(ctx);
    let mut seen: Vec<String> = Vec::new();

    for key in &snapshot.keys {
        if !key.path.to_ascii_lowercase().contains(r"\currentversion\uninstall\") {
            continue;
        }
        analysis.uninstall_keys += 1;

        let display_name = value(&key.values, "DisplayName");
        let Some(display_name) = display_name
        else {
            analysis.skipped.push(SoftwareSkip { registry_key: key.path.clone(), display_name: None, reason: "no-display-name".to_string() });
            continue;
        };
        if dword(&key.values, "SystemComponent") == Some(1) {
            analysis.skipped.push(SoftwareSkip {
                registry_key: key.path.clone(),
                display_name: Some(display_name),
                reason: "system-component".to_string(),
            });
            continue;
        }
        if value(&key.values, "ParentKeyName").is_some_and(|parent| !parent.is_empty()) {
            analysis.skipped.push(SoftwareSkip {
                registry_key: key.path.clone(),
                display_name: Some(display_name),
                reason: "update-package".to_string(),
            });
            continue;
        }
        if value(&key.values, "ReleaseType").is_some_and(|kind| {
            let kind = kind.to_ascii_lowercase();
            kind.contains("update") || kind.contains("hotfix")
        }) {
            analysis.skipped.push(SoftwareSkip {
                registry_key: key.path.clone(),
                display_name: Some(display_name),
                reason: "update-package".to_string(),
            });
            continue;
        }

        let install_location = value(&key.values, "InstallLocation").and_then(|location| expand_env(&location, ctx.env));
        let install_location =
            install_location.map(|location| location.trim().trim_matches('"').trim().to_string()).filter(|location| !location.is_empty());

        // A live install location means the product is still installed: never a
        // cleanup candidate.
        if let Some(location) = &install_location
            && (ctx.dir_exists)(location)
        {
            analysis.skipped.push(SoftwareSkip {
                registry_key: key.path.clone(),
                display_name: Some(display_name),
                reason: "still-installed".to_string(),
            });
            continue;
        }

        // An uninstaller or display icon that still exists proves the product is
        // present. Without this guard, a live install whose uninstall row omits
        // `InstallLocation` (Steam and some MSI rows do) would look like leftover.
        if still_installed(&key.values, ctx) {
            analysis.skipped.push(SoftwareSkip {
                registry_key: key.path.clone(),
                display_name: Some(display_name),
                reason: "still-installed".to_string(),
            });
            continue;
        }

        let product = normalize_name(&display_name);
        let mut candidates: Vec<(SoftwareKind, String, String)> = Vec::new();

        if let Some(location) = &install_location {
            // The recorded folder is gone. Walk up to the nearest ancestor that
            // still exists, then look for the product directory there, which is
            // where a reinstall or an in-place update would have left it.
            if let Some(ancestor) = existing_ancestor(location, ctx) {
                for child in (ctx.list_dir)(&ancestor) {
                    if normalize_name(&child) == product {
                        candidates.push((
                            SoftwareKind::InstallDirectory,
                            join(&ancestor, &child),
                            "missing-install-location-sibling".to_string(),
                        ));
                    }
                }
            }
        }
        else {
            for root in &install_roots {
                for child in (ctx.list_dir)(root) {
                    if normalize_name(&child) == product {
                        candidates.push((SoftwareKind::InstallDirectory, join(root, &child), "standard-install-root".to_string()));
                    }
                }
            }
        }

        // Configuration and cache leftovers only exist once the app itself is
        // gone, which the checks above already established.
        for root in &config_roots {
            for child in (ctx.list_dir)(root) {
                if normalize_name(&child) == product {
                    candidates.push((SoftwareKind::ConfigDirectory, join(root, &child), "config-root-exact-name".to_string()));
                }
            }
        }

        for (kind, path, rule) in candidates {
            if user_data.iter().any(|root| is_under(&path, root)) {
                analysis.skipped.push(SoftwareSkip {
                    registry_key: key.path.clone(),
                    display_name: Some(display_name.clone()),
                    reason: "user-data".to_string(),
                });
                continue;
            }
            let normalized = crate::env::analyze::normalize(&path);
            if seen.contains(&normalized) {
                continue;
            }
            seen.push(normalized.clone());

            let evidence = match kind {
                SoftwareKind::InstallDirectory => {
                    format!("uninstall entry points at a missing install location but {path} exists")
                }
                SoftwareKind::ConfigDirectory => {
                    format!("uninstall entry for {display_name} has no live install location and {path} matches the product name")
                }
            };
            let safety = match kind {
                SoftwareKind::InstallDirectory => {
                    "the recorded install folder no longer exists, so this directory cannot be the running product".to_string()
                }
                SoftwareKind::ConfigDirectory => {
                    "the product is uninstalled and this folder is not a user document, desktop, download or picture folder".to_string()
                }
            };
            analysis.findings.push(SoftwareFinding {
                id: format!("{}-{normalized}", kind.as_str()),
                kind,
                bytes: (ctx.dir_size)(&path),
                path,
                display_name: display_name.clone(),
                registry_key: key.path.clone(),
                install_location: install_location.clone(),
                rule,
                evidence,
                safety,
                removable: true,
            });
        }
    }

    analysis.findings.sort_by(|left, right| left.path.cmp(&right.path));
    analysis
}

fn value(values: &std::collections::BTreeMap<String, RegistryValue>, name: &str) -> Option<String> {
    values
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.data.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn dword(values: &std::collections::BTreeMap<String, RegistryValue>, name: &str) -> Option<u32> {
    let typed = values.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value)?;
    if typed.kind != crate::registry::model::RegistryValueKind::Dword {
        return None;
    }
    typed.data.parse().ok()
}

/// Case and whitespace insensitive product-name comparison. Path separators
/// and trademark suffixes are not significant.
fn normalize_name(name: &str) -> String {
    name.split_whitespace().collect::<Vec<_>>().join(" ").to_ascii_lowercase()
}

/// A product is still installed when its uninstaller or display icon exists on
/// disk, even if `InstallLocation` is absent or stale.
fn still_installed(values: &std::collections::BTreeMap<String, RegistryValue>, ctx: &SoftwareContext<'_>) -> bool {
    for name in ["UninstallString", "QuietUninstallString", "DisplayIcon"] {
        let Some(raw) = value(values, name)
        else {
            continue;
        };
        let Some(path) = executable_path(&raw, ctx.env)
        else {
            continue;
        };
        if (ctx.file_exists)(&path) {
            return true;
        }
    }
    false
}

/// Extract the executable path from a registry command line such as
/// `"C:\App\uninstall.exe" /S` or `C:\App\app.exe,0`.
fn executable_path(raw: &str, env: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    let raw = raw.trim();
    let target = if let Some(rest) = raw.strip_prefix('"') {
        rest.split('"').next().unwrap_or(rest)
    }
    else if let Some(index) = raw.to_ascii_lowercase().find(".exe") {
        &raw[..index + 4]
    }
    else {
        raw.split_whitespace().next().unwrap_or(raw)
    };
    let target = target.split(',').next().unwrap_or(target).trim();
    let expanded = expand_env(target, env)?;
    let expanded = expanded.trim().trim_matches('"').trim().to_string();
    (!expanded.is_empty()).then_some(expanded)
}

fn parent_of(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches(['\\', '/']);
    let index = trimmed.rfind(['\\', '/'])?;
    (index > 0).then(|| trimmed[..index].to_string())
}

/// Nearest ancestor of `path` that exists on disk, walking toward the root.
fn existing_ancestor(path: &str, ctx: &SoftwareContext<'_>) -> Option<String> {
    let mut current = parent_of(path);
    while let Some(dir) = current {
        if (ctx.dir_exists)(&dir) {
            return Some(dir);
        }
        current = parent_of(&dir);
    }
    None
}

fn join(parent: &str, child: &str) -> String {
    format!("{}\\{child}", parent.trim_end_matches(['\\', '/']))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::registry::model::parse_reg;

    const REG_FIXTURE: &str = r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\LiveApp]
"DisplayName"="Live App"
"InstallLocation"="C:\\Program Files\\Live App"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\GoneApp]
"DisplayName"="Gone App"
"InstallLocation"="C:\\Program Files\\Gone App\\app-1.2"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ConfigApp]
"DisplayName"="Config App"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SystemApp]
"DisplayName"="System App"
"SystemComponent"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PatchApp]
"DisplayName"="Patch App"
"ParentKeyName"="GoneApp"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\DocsApp]
"DisplayName"="Docs App"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SteamLike]
"DisplayName"="Steam Like"
"UninstallString"="\"C:\\Program Files (x86)\\Steam Like\\steam.exe\" --uninstall"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NoName]
"InstallLocation"="C:\\Program Files\\No Name"
"#;

    struct Fixture {
        dirs: Vec<String>,
        files: Vec<String>,
        children: BTreeMap<String, Vec<String>>,
        env: BTreeMap<String, String>,
    }

    impl Fixture {
        fn analyze(&self, snapshot: &RegistrySnapshot) -> SoftwareAnalysis {
            let dir_exists = |path: &str| self.dirs.iter().any(|dir| dir == &crate::env::analyze::normalize(path));
            let file_exists = |path: &str| self.files.iter().any(|file| file == &crate::env::analyze::normalize(path));
            let list_dir = |path: &str| self.children.get(&crate::env::analyze::normalize(path)).cloned().unwrap_or_default();
            let dir_size = |_: &str| 4096u64;
            let env = |name: &str| self.env.get(name).cloned();
            let ctx =
                SoftwareContext { dir_exists: &dir_exists, file_exists: &file_exists, list_dir: &list_dir, dir_size: &dir_size, env: &env };
            super::analyze(snapshot, &ctx)
        }
    }

    fn normalized(value: &str) -> String {
        crate::env::analyze::normalize(value)
    }

    fn fixture() -> Fixture {
        let mut children = BTreeMap::new();
        children.insert(normalized(r"C:\Program Files"), vec!["Gone App".to_string(), "Live App".to_string()]);
        children.insert(normalized(r"C:\Program Files (x86)"), vec!["Steam Like".to_string()]);
        children.insert(
            normalized(r"C:\ProgramData"),
            vec!["Config App".to_string(), "Ghost App".to_string(), "System App".to_string(), "Patch App".to_string()],
        );
        children.insert(normalized(r"C:\Users\me\AppData\Local"), vec!["Config App".to_string(), "Docs App".to_string()]);
        children.insert(normalized(r"C:\Users\me\Documents"), vec!["Docs App".to_string()]);

        let mut env = BTreeMap::new();
        env.insert("ProgramFiles".to_string(), r"C:\Program Files".to_string());
        env.insert("LOCALAPPDATA".to_string(), r"C:\Users\me\AppData\Local".to_string());
        env.insert("APPDATA".to_string(), r"C:\Users\me\AppData\Roaming".to_string());
        env.insert("ProgramData".to_string(), r"C:\ProgramData".to_string());
        env.insert("USERPROFILE".to_string(), r"C:\Users\me".to_string());

        Fixture {
            dirs: vec![
                normalized(r"C:\Program Files"),
                normalized(r"C:\Program Files\Live App"),
                normalized(r"C:\Program Files (x86)"),
                normalized(r"C:\Program Files (x86)\Steam Like"),
                normalized(r"C:\ProgramData"),
                normalized(r"C:\ProgramData\Config App"),
                normalized(r"C:\ProgramData\Ghost App"),
                normalized(r"C:\ProgramData\System App"),
                normalized(r"C:\ProgramData\Patch App"),
                normalized(r"C:\Users\me\AppData\Local"),
                normalized(r"C:\Users\me\AppData\Local\Config App"),
                normalized(r"C:\Users\me\AppData\Local\Docs App"),
                normalized(r"C:\Users\me\Documents"),
                normalized(r"C:\Users\me\Documents\Docs App"),
            ],
            files: vec![normalized(r"C:\Program Files (x86)\Steam Like\steam.exe")],
            children,
            env,
        }
    }

    #[test]
    fn finds_leftover_install_and_config_directories_with_anchors() {
        let snapshot = parse_reg(REG_FIXTURE, "fixture.reg");
        let fixture = fixture();
        let analysis = fixture.analyze(&snapshot);

        let paths: Vec<&str> = analysis.findings.iter().map(|finding| finding.path.as_str()).collect();
        assert!(paths.iter().any(|path| path.ends_with(r"Program Files\Gone App")), "{paths:?}");
        assert!(paths.iter().any(|path| path.ends_with(r"ProgramData\Config App")), "{paths:?}");
        assert!(paths.iter().any(|path| path.ends_with(r"AppData\Local\Config App")), "{paths:?}");

        for finding in &analysis.findings {
            assert!(!finding.evidence.is_empty(), "{finding:?}");
            assert!(!finding.safety.is_empty(), "{finding:?}");
            assert!(!finding.rule.is_empty(), "{finding:?}");
            assert!(finding.registry_key.to_ascii_lowercase().contains("uninstall"), "{finding:?}");
            assert_eq!(finding.bytes, 4096);
            assert!(finding.removable);
        }
        assert_eq!(analysis.uninstall_keys, 8);
    }

    #[test]
    fn still_installed_system_components_and_updates_are_not_candidates() {
        let snapshot = parse_reg(REG_FIXTURE, "fixture.reg");
        let fixture = fixture();
        let analysis = fixture.analyze(&snapshot);

        let paths: Vec<&str> = analysis.findings.iter().map(|finding| finding.path.as_str()).collect();
        assert!(!paths.iter().any(|path| path.ends_with(r"Program Files\Live App")), "{paths:?}");
        assert!(!paths.iter().any(|path| path.ends_with(r"Program Files (x86)\Steam Like")), "{paths:?}");
        assert!(!paths.iter().any(|path| path.ends_with(r"ProgramData\System App")), "{paths:?}");
        assert!(!paths.iter().any(|path| path.ends_with(r"ProgramData\Patch App")), "{paths:?}");

        let reasons: Vec<&str> = analysis.skipped.iter().map(|skip| skip.reason.as_str()).collect();
        assert!(reasons.contains(&"still-installed"), "{reasons:?}");
        assert!(reasons.contains(&"system-component"), "{reasons:?}");
        assert!(reasons.contains(&"update-package"), "{reasons:?}");
        assert!(reasons.contains(&"no-display-name"), "{reasons:?}");
        // A live uninstaller proves the product is still installed even when
        // `InstallLocation` is absent from the uninstall row.
        assert!(
            analysis.skipped.iter().any(|skip| skip.reason == "still-installed" && skip.display_name.as_deref() == Some("Steam Like")),
            "{:#?}",
            analysis.skipped
        );
    }

    #[test]
    fn user_data_directories_are_never_candidates() {
        let snapshot = parse_reg(REG_FIXTURE, "fixture.reg");

        // A local app data root that resolves inside Documents must not turn
        // user files into cleanup candidates.
        let mut children = BTreeMap::new();
        children.insert(normalized(r"C:\Users\me\Documents"), vec!["Docs App".to_string()]);
        let mut env = BTreeMap::new();
        env.insert("LOCALAPPDATA".to_string(), r"C:\Users\me\Documents".to_string());
        env.insert("USERPROFILE".to_string(), r"C:\Users\me".to_string());
        let fixture = Fixture { dirs: vec![normalized(r"C:\Users\me\Documents")], files: Vec::new(), children, env };

        let analysis = fixture.analyze(&snapshot);
        let paths: Vec<&str> = analysis.findings.iter().map(|finding| finding.path.as_str()).collect();
        assert!(!paths.iter().any(|path| path.contains("Docs App")), "{paths:?}");
        assert!(analysis.skipped.iter().any(|skip| skip.reason == "user-data"), "{:#?}", analysis.skipped);
    }

    #[test]
    fn directories_without_an_uninstall_anchor_are_not_recognized() {
        let snapshot = parse_reg(REG_FIXTURE, "fixture.reg");
        let fixture = fixture();
        let analysis = fixture.analyze(&snapshot);

        let paths: Vec<&str> = analysis.findings.iter().map(|finding| finding.path.as_str()).collect();
        assert!(!paths.iter().any(|path| path.ends_with(r"ProgramData\Ghost App")), "{paths:?}");
    }

    #[test]
    fn empty_install_roots_fall_back_to_no_candidates() {
        let snapshot = parse_reg(REG_FIXTURE, "fixture.reg");
        let fixture = Fixture { dirs: Vec::new(), files: Vec::new(), children: BTreeMap::new(), env: BTreeMap::new() };
        let analysis = fixture.analyze(&snapshot);
        assert!(analysis.findings.is_empty(), "{:#?}", analysis.findings);
        assert_eq!(analysis.uninstall_keys, 8);
    }
}
