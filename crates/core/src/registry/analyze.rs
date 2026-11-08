//! Registry residue rules. Pure functions over [`RegistrySnapshot`] so the
//! same logic is covered by `.reg` fixtures on every platform.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::model::{RegistrySnapshot, RegistryValueKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResidueKind {
    /// Orphan `Uninstall` entry whose install folder is gone.
    UninstallResidue,
    /// `Software\Classes\...\shell\open\command` pointing at a missing exe.
    FileAssociation,
    /// `CurrentVersion\Run` / `RunOnce` value pointing at a missing exe.
    StartupItem,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryFinding {
    pub kind: ResidueKind,
    pub key_path: String,
    /// Startup value name; `None` for key-level findings.
    pub value_name: Option<String>,
    pub display_name: Option<String>,
    /// The path that failed the existence check.
    pub target: String,
    pub evidence: String,
    /// Why removing this entry is safe.
    pub safety: String,
}

pub struct AnalyzeContext<'a> {
    pub exists: &'a dyn Fn(&Path) -> bool,
    pub env: &'a dyn Fn(&str) -> Option<String>,
}

pub fn analyze(snapshot: &RegistrySnapshot, ctx: &AnalyzeContext<'_>) -> Vec<RegistryFinding> {
    let mut findings = Vec::new();
    for key in &snapshot.keys {
        let upper = key.path.to_ascii_uppercase();

        if is_uninstall_key(&upper)
            && let Some(finding) = uninstall_residue(snapshot, key, ctx)
        {
            findings.push(finding);
        }
        if upper.contains(r"\SOFTWARE\CLASSES\")
            && upper.ends_with(r"\SHELL\OPEN\COMMAND")
            && let Some(finding) = file_association(snapshot, key, ctx)
        {
            findings.push(finding);
        }
        if is_startup_key(&upper) {
            findings.extend(startup_items(key, ctx));
        }
    }

    findings.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.key_path.cmp(&b.key_path)).then_with(|| a.value_name.cmp(&b.value_name)));
    findings.dedup_by(|a, b| a.kind == b.kind && a.key_path == b.key_path && a.value_name == b.value_name);
    findings
}

fn is_uninstall_key(upper: &str) -> bool {
    // HKLM\SOFTWARE\...\Uninstall\<id> or HKLM\SOFTWARE\WOW6432Node\...\Uninstall\<id>
    upper.contains(r"\CURRENTVERSION\UNINSTALL\")
}

fn is_startup_key(upper: &str) -> bool {
    upper.ends_with(r"\CURRENTVERSION\RUN") || upper.ends_with(r"\CURRENTVERSION\RUNONCE")
}

/// Only an absolute path can be checked by existence. A bare command name such
/// as `MsiExec.exe`, a value without an extension or an unexpanded `%1` is
/// resolved by the shell through `PATH` and its own lookup rules, so a failed
/// path check says nothing about whether the target is gone.
pub(crate) fn absolute_target(text: &str) -> Option<String> {
    let text = text.trim();
    let bytes = text.as_bytes();
    let absolute = match bytes {
        [letter, b':', separator, ..] => letter.is_ascii_alphabetic() && (*separator == b'\\' || *separator == b'/'),
        [b'\\', b'\\', ..] => true,
        _ => false,
    };
    absolute.then(|| text.to_string())
}

fn uninstall_residue(snapshot: &RegistrySnapshot, key: &super::model::RegistryKey, ctx: &AnalyzeContext<'_>) -> Option<RegistryFinding> {
    if snapshot.value(&key.path, "SystemComponent").and_then(dword).map(|value| value == 1).unwrap_or(false) {
        return None;
    }
    if snapshot.value(&key.path, "ParentKeyName").is_some() {
        return None;
    }
    let display_name = resolved_text(snapshot, &key.path, "DisplayName", ctx)?;
    let location = resolved_text(snapshot, &key.path, "InstallLocation", ctx)?;
    let location = absolute_target(&location)?;
    if (ctx.exists)(Path::new(&location)) {
        return None;
    }
    Some(RegistryFinding {
        kind: ResidueKind::UninstallResidue,
        key_path: key.path.clone(),
        value_name: None,
        display_name: Some(display_name),
        target: location.clone(),
        evidence: format!("InstallLocation does not exist: {location}"),
        safety: "the install folder is gone, so this orphan row only pollutes the installed-apps list".to_string(),
    })
}

fn file_association(snapshot: &RegistrySnapshot, key: &super::model::RegistryKey, ctx: &AnalyzeContext<'_>) -> Option<RegistryFinding> {
    let command = resolved_text(snapshot, &key.path, "", ctx)?;
    let exe = resolve_executable(&command, ctx)?;
    if (ctx.exists)(Path::new(&exe)) {
        return None;
    }
    let prog_id = association_name(&key.path)?;
    Some(RegistryFinding {
        kind: ResidueKind::FileAssociation,
        key_path: key.path.clone(),
        value_name: None,
        display_name: Some(prog_id.clone()),
        target: exe.clone(),
        evidence: format!("open command executable does not exist: {exe}"),
        safety: format!("the handler for {prog_id} is missing, so Windows already falls back to the default handler"),
    })
}

fn startup_items(key: &super::model::RegistryKey, ctx: &AnalyzeContext<'_>) -> Vec<RegistryFinding> {
    let mut findings = Vec::new();
    for (name, value) in &key.values {
        if name.is_empty() {
            continue;
        }
        if !matches!(value.kind, RegistryValueKind::String | RegistryValueKind::ExpandString) {
            continue;
        }
        let Some(command) = resolve_text(value, ctx)
        else {
            continue;
        };
        let Some(exe) = resolve_executable(&command, ctx)
        else {
            continue;
        };
        if (ctx.exists)(Path::new(&exe)) {
            continue;
        }
        findings.push(RegistryFinding {
            kind: ResidueKind::StartupItem,
            key_path: key.path.clone(),
            value_name: Some(name.clone()),
            display_name: Some(name.clone()),
            target: exe.clone(),
            evidence: format!("startup command executable does not exist: {exe}"),
            safety: "the startup command cannot run, so removing the value only stops a failing launch attempt".to_string(),
        });
    }
    findings
}

fn association_name(key_path: &str) -> Option<String> {
    let upper = key_path.to_ascii_uppercase();
    let classes = upper.find(r"\SOFTWARE\CLASSES\")?;
    let start = classes + r"\SOFTWARE\CLASSES\".len();
    let end = upper.rfind(r"\SHELL\OPEN\COMMAND")?;
    if end <= start {
        return None;
    }
    Some(key_path[start..end].to_string())
}

fn resolved_text(snapshot: &RegistrySnapshot, key_path: &str, name: &str, ctx: &AnalyzeContext<'_>) -> Option<String> {
    let value = snapshot.value(key_path, name)?;
    resolve_text(value, ctx)
}

fn resolve_text(value: &super::model::RegistryValue, ctx: &AnalyzeContext<'_>) -> Option<String> {
    if !matches!(value.kind, RegistryValueKind::String | RegistryValueKind::ExpandString) {
        return None;
    }
    let text = value.data.trim().trim_matches('"').trim();
    if text.is_empty() {
        return None;
    }
    if text.contains('%') { expand_env(text, ctx.env) } else { Some(text.to_string()) }
}

fn dword(value: &super::model::RegistryValue) -> Option<u32> {
    (value.kind == RegistryValueKind::Dword).then(|| value.data.parse().ok()).flatten()
}

/// Expand `%NAME%` segments. Unknown variables abort the expansion so the
/// entry is reported as "not recognized" instead of guessed.
pub fn expand_env(value: &str, env: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    let mut output = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find('%') {
        output.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('%')
        else {
            output.push_str(&rest[start..]);
            return Some(output);
        };
        let name = &after[..end];
        let replacement = env(name)?;
        output.push_str(&replacement);
        rest = &after[end + 1..];
    }
    output.push_str(rest);
    Some(output)
}

/// Extract the executable path from a command line. Quoted paths are taken
/// verbatim; otherwise the prefix up to `.exe` is used so unquoted paths with
/// spaces still resolve. A command that does not name an absolute file is
/// reported as unrecognized, never as a missing target.
pub fn resolve_executable(command: &str, ctx: &AnalyzeContext<'_>) -> Option<String> {
    let text = command.trim();
    let candidate = if let Some(rest) = text.strip_prefix('"') {
        rest.split('"').next()?.trim()
    }
    else {
        let lower = text.to_ascii_lowercase();
        match lower.find(".exe") {
            Some(index) => text[..index + 4].trim(),
            None => text.split_whitespace().next().unwrap_or("").trim(),
        }
    };
    let candidate = candidate.trim_matches('"').trim();
    if candidate.is_empty() {
        return None;
    }
    let candidate = if candidate.contains('%') { expand_env(candidate, ctx.env)? } else { candidate.to_string() };
    let candidate = absolute_target(&candidate)?;
    // The shell resolves an extension-less name through `PATHEXT`, so a missing
    // file at that exact path proves nothing about the target.
    has_extension(&candidate).then_some(candidate)
}

/// True when the last path segment carries a non-empty extension.
fn has_extension(text: &str) -> bool {
    let name = text.rsplit(['\\', '/']).next().unwrap_or(text);
    match name.rsplit_once('.') {
        Some((stem, extension)) => !stem.is_empty() && !extension.is_empty(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, path::PathBuf};

    use super::*;
    use crate::registry::model::{RegistryValue, parse_reg};

    const FIXTURE: &str = r#"Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\Gone App]
"DisplayName"="Gone App"
"InstallLocation"="C:\\Program Files\\Gone App"
"DisplayVersion"="1.2.3"

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\Installed App]
"DisplayName"="Installed App"
"InstallLocation"="C:\\Program Files\\Installed App"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{PATCH}]
"DisplayName"="Update KB123"
"ParentKeyName"="Windows"
"InstallLocation"="C:\\Program Files\\Gone App"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{COMPONENT}]
"DisplayName"="Runtime"
"SystemComponent"=dword:00000001
"InstallLocation"="D:\\Missing Runtime"

[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Legacy]
"DisplayName"="Legacy Tool"
"InstallLocation"="D:\\Legacy Tool"

[HKEY_CURRENT_USER\Software\Classes\gonefile\shell\open\command]
@="\"C:\\Program Files\\Gone App\\gone.exe\" \"%1\""

[HKEY_CURRENT_USER\Software\Classes\.ok\shell\open\command]
@="\"C:\\Program Files\\Installed App\\viewer.exe\" \"%1\""

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Applications\missing.exe\shell\open\command]
@="\"C:\\Tools\\missing.exe\" /open"

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
"GoneAgent"="C:\\Program Files\\Gone App\\agent.exe /run"
"AliveAgent"="\"C:\\Program Files\\Installed App\\alive.exe\""

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce]
"Expanding"="%ProgramFiles%\\Gone App\\setup.exe /silent"
"UnknownVar"="%NOT_DEFINED%\\tool.exe"
"#;

    /// Registry rows whose command is not an absolute path: a bare uninstaller
    /// name, a shell placeholder, a command without an extension and a relative
    /// install location. None of them can be checked by path lookup.
    const BARE_COMMANDS: &str = r#"Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\Portable App]
"DisplayName"="Portable App"
"InstallLocation"="..\\Portable App"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\barefile\shell\open\command]
@="MsiExec.exe /X{BARE-ID}"

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
"NoExtension"="perfmon /res"
"ShellPlaceholder"="%1"
"#;

    fn existing(paths: &[&str]) -> BTreeSet<PathBuf> {
        paths.iter().map(PathBuf::from).collect()
    }

    /// Paths that exist on the fake machine: the installed app folder plus its
    /// binaries. Missing binaries must still be reported.
    fn installed() -> BTreeSet<PathBuf> {
        existing(&[
            r"C:\Program Files\Installed App",
            r"C:\Program Files\Installed App\viewer.exe",
            r"C:\Program Files\Installed App\alive.exe",
        ])
    }

    #[test]
    fn finds_uninstall_residue_with_evidence_and_safety() {
        let snapshot = parse_reg(FIXTURE, "fixture.reg");
        let existing = existing(&[r"C:\Program Files\Installed App"]);
        let env = |name: &str| match name {
            "ProgramFiles" => Some(r"C:\Program Files".to_string()),
            _ => None,
        };
        let exists = |path: &Path| existing.iter().any(|candidate| candidate.as_path() == path);
        let ctx = AnalyzeContext { exists: &exists, env: &env };
        let findings = analyze(&snapshot, &ctx);

        let uninstall: Vec<_> = findings.iter().filter(|f| f.kind == ResidueKind::UninstallResidue).collect();
        assert_eq!(uninstall.len(), 2, "{uninstall:#?}");
        assert!(uninstall.iter().any(|f| f.key_path.ends_with("Gone App") && f.target == r"C:\Program Files\Gone App"));
        assert!(uninstall.iter().any(|f| f.key_path.contains("WOW6432Node") && f.target == r"D:\Legacy Tool"));

        let gone = uninstall.iter().find(|f| f.key_path.ends_with("Gone App")).unwrap();
        assert!(gone.evidence.contains("does not exist"));
        assert!(!gone.safety.is_empty());
        assert_eq!(gone.display_name.as_deref(), Some("Gone App"));

        // Installed, patch and system-component entries are excluded.
        assert!(!findings.iter().any(|f| f.target == r"C:\Program Files\Installed App"));
        assert!(!findings.iter().any(|f| f.display_name.as_deref() == Some("Update KB123")));
        assert!(!findings.iter().any(|f| f.display_name.as_deref() == Some("Runtime")));
    }

    #[test]
    fn finds_invalid_file_associations_only_when_the_handler_is_missing() {
        let snapshot = parse_reg(FIXTURE, "fixture.reg");
        let existing = installed();
        let env = |_: &str| None;
        let exists = |path: &Path| existing.iter().any(|candidate| candidate.as_path() == path);
        let ctx = AnalyzeContext { exists: &exists, env: &env };
        let findings = analyze(&snapshot, &ctx);

        let associations: Vec<_> = findings.iter().filter(|f| f.kind == ResidueKind::FileAssociation).collect();
        assert_eq!(associations.len(), 2, "{associations:#?}");
        assert!(associations.iter().any(|f| f.key_path.contains("gonefile") && f.target.ends_with("gone.exe")));
        assert!(associations.iter().any(|f| f.key_path.contains("Applications") && f.target.ends_with("missing.exe")));
        assert!(!associations.iter().any(|f| f.key_path.contains(".ok")), "existing handler must not be reported");
    }

    #[test]
    fn finds_failing_startup_items_and_skips_unexpandable_values() {
        let snapshot = parse_reg(FIXTURE, "fixture.reg");
        let existing = installed();
        let env = |name: &str| match name {
            "ProgramFiles" => Some(r"C:\Program Files".to_string()),
            _ => None,
        };
        let exists = |path: &Path| existing.iter().any(|candidate| candidate.as_path() == path);
        let ctx = AnalyzeContext { exists: &exists, env: &env };
        let findings = analyze(&snapshot, &ctx);

        let startup: Vec<_> = findings.iter().filter(|f| f.kind == ResidueKind::StartupItem).collect();
        assert_eq!(startup.len(), 2, "{startup:#?}");
        assert!(startup.iter().any(|f| f.value_name.as_deref() == Some("GoneAgent")));

        // `%ProgramFiles%\Gone App\setup.exe` expands and is missing.
        assert!(startup.iter().any(|f| f.value_name.as_deref() == Some("Expanding")));
        // Unknown variables are not recognized, never guessed.
        assert!(!findings.iter().any(|f| f.value_name.as_deref() == Some("UnknownVar")));
        // The healthy startup value is excluded.
        assert!(!findings.iter().any(|f| f.value_name.as_deref() == Some("AliveAgent")));
    }

    #[test]
    fn bare_commands_and_missing_extensions_are_not_missing_targets() {
        let snapshot = parse_reg(BARE_COMMANDS, "bare.reg");
        let empty = BTreeSet::new();
        let env = |_: &str| None;
        let exists = |path: &Path| empty.iter().any(|candidate: &PathBuf| candidate.as_path() == path);
        let ctx = AnalyzeContext { exists: &exists, env: &env };
        let findings = analyze(&snapshot, &ctx);

        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn expansion_and_executable_extraction_handle_quoted_unquoted_and_failures() {
        let env = |name: &str| match name {
            "ProgramFiles" => Some(r"C:\Program Files".to_string()),
            _ => None,
        };
        let always_false = |_: &Path| false;
        let ctx = AnalyzeContext { exists: &always_false, env: &env };

        assert_eq!(resolve_executable(r#""C:\Program Files\App\app.exe" "%1""#, &ctx).as_deref(), Some(r"C:\Program Files\App\app.exe"));
        assert_eq!(resolve_executable(r"C:\Program Files\App\app.exe /run", &ctx).as_deref(), Some(r"C:\Program Files\App\app.exe"));
        assert_eq!(resolve_executable(r#"%ProgramFiles%\App\app.exe"#, &ctx).as_deref(), Some(r"C:\Program Files\App\app.exe"));
        assert_eq!(resolve_executable(r#"%UNKNOWN%\app.exe"#, &ctx), None);
        // A full path without an extension is resolved through `PATHEXT`, so it
        // is not a checkable target either.
        assert_eq!(resolve_executable(r"C:\Tools\perfmon", &ctx), None);
        assert_eq!(expand_env(r#"%UNKNOWN%\x"#, &env), None);
    }

    #[test]
    fn snapshot_values_are_kind_checked() {
        let mut snapshot = RegistrySnapshot::default();
        snapshot.insert(r"HKCU\Software\Vendor");
        snapshot.set_value(r"HKCU\Software\Vendor", "Path", RegistryValue { kind: RegistryValueKind::Dword, data: "7".into() });
        let env = |_: &str| None;
        let always_false = |_: &Path| false;
        let ctx = AnalyzeContext { exists: &always_false, env: &env };
        assert!(resolved_text(&snapshot, r"HKCU\Software\Vendor", "Path", &ctx).is_none());
    }
}
