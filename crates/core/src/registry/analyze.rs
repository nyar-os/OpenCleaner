//! Registry residue rules. Pure functions over [`RegistrySnapshot`] so the
//! same logic is covered by `.reg` fixtures on every platform.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::model::{RegistrySnapshot, RegistryValueKind};
use crate::software::analyze::{self as software, InstallVerdict, SoftwareContext};

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
    /// File-system and process inputs of the install evidence chain. Every
    /// uninstall-key verdict comes from this one chain, shared with the
    /// software domain, so both commands answer the same way for a key.
    pub software: &'a SoftwareContext<'a>,
}

pub fn analyze(snapshot: &RegistrySnapshot, ctx: &AnalyzeContext<'_>) -> Vec<RegistryFinding> {
    let mut findings = Vec::new();
    let install_roots = software::install_roots(ctx.software);
    for key in &snapshot.keys {
        let upper = key.path.to_ascii_uppercase();

        if is_uninstall_key(&upper)
            && let Some(finding) = uninstall_residue(key, ctx, &install_roots)
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

/// An orphan uninstall row. The verdict is not "the recorded install path is
/// missing": that fact alone cannot separate an orphan from a product that is
/// still installed through an executable, a running image, an MSI registration
/// or a recently written directory. The row is residue only when the shared
/// install evidence chain says the product is gone, which is the same answer
/// the software domain gives for the same key.
fn uninstall_residue(key: &super::model::RegistryKey, ctx: &AnalyzeContext<'_>, install_roots: &[String]) -> Option<RegistryFinding> {
    let state = software::installation(&key.values, install_roots, ctx.software);
    let display_name = state.display_name.clone()?;
    if state.verdict != InstallVerdict::Gone {
        return None;
    }
    // Without a recorded absolute path there is no target to point at, and the
    // row is left alone instead of guessing one.
    let location = state.install_location.clone().and_then(|location| absolute_target(&location))?;
    // The chain already proved the product is gone. This extra check keeps the
    // evidence text true when the recorded path survives as a plain file.
    if (ctx.exists)(Path::new(&location)) {
        return None;
    }
    Some(RegistryFinding {
        kind: ResidueKind::UninstallResidue,
        key_path: key.path.clone(),
        value_name: None,
        display_name: Some(display_name),
        target: location.clone(),
        evidence: format!(
            "recorded install path {location} is missing, no recorded executable exists, no process runs from it, and no matching directory was written recently"
        ),
        safety: "the product behind this row is gone by every piece of evidence, so removing the row only clears an orphan entry".to_string(),
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
    use std::{
        collections::BTreeMap,
        path::{Path, PathBuf},
    };

    use super::*;
    use crate::{
        registry::model::{RegistryValue, parse_reg},
        software::analyze::{SoftwareAnalysis, SoftwareKind},
    };

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

    /// A fake machine: which directories and files exist, what each directory
    /// lists, the environment, and which directories carry recent writes.
    /// The registry context and the shared software context read the same
    /// tables, so a cross-domain test compares two answers over one machine.
    #[derive(Default)]
    struct Machine {
        dirs: Vec<PathBuf>,
        files: Vec<PathBuf>,
        children: BTreeMap<String, Vec<String>>,
        env: BTreeMap<String, String>,
        /// Directories of executable images used by running processes.
        images: Vec<String>,
    }

    impl Machine {
        /// Split `entries` into directories and `.exe` files and add them.
        fn new(entries: &[&str]) -> Self {
            let mut machine = Self::default();
            for entry in entries {
                let path = PathBuf::from(entry);
                if path.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("exe")) {
                    machine.files.push(path);
                }
                else {
                    machine.dirs.push(path);
                }
            }
            machine
        }

        fn with_env(mut self, name: &str, value: &str) -> Self {
            self.env.insert(name.to_string(), value.to_string());
            self
        }

        fn with_children(mut self, dir: &str, children: &[&str]) -> Self {
            self.children.insert(crate::env::analyze::normalize(dir), children.iter().map(ToString::to_string).collect());
            self
        }

        fn exists(&self, path: &Path) -> bool {
            self.dirs.iter().chain(self.files.iter()).any(|known| known.as_path() == path)
        }

        fn is_dir(&self, path: &str) -> bool {
            self.dirs.iter().any(|known| known.as_path() == Path::new(path))
        }

        fn is_file(&self, path: &str) -> bool {
            self.files.iter().any(|known| known.as_path() == Path::new(path))
        }

        fn children_of(&self, path: &str) -> Vec<String> {
            self.children.get(&crate::env::analyze::normalize(path)).cloned().unwrap_or_default()
        }

        /// No directory here is fresh: every listed directory is older than the
        /// freshness window.
        fn newest(&self, path: &str) -> Option<u64> {
            let entries = self.children_of(path);
            (!entries.is_empty()).then(|| crate::safety::now_unix_ms().saturating_sub(crate::safety::freshness_window_ms() * 4))
        }

        /// Runs `run` with contexts over this machine. The contexts borrow
        /// closures local to this call, so they cannot be returned.
        fn with_context<R>(&self, run: impl FnOnce(&AnalyzeContext<'_>, &SoftwareContext<'_>) -> R) -> R {
            let dir_exists = |path: &str| self.is_dir(path);
            let file_exists = |path: &str| self.is_file(path);
            let list_dir = |path: &str| self.children_of(path);
            let dir_size = |_: &str| 0u64;
            let env = |name: &str| self.env.get(name).cloned();
            let images = || self.images.clone();
            let newest = |path: &str| self.newest(path);
            let software = SoftwareContext {
                dir_exists: &dir_exists,
                file_exists: &file_exists,
                list_dir: &list_dir,
                dir_size: &dir_size,
                env: &env,
                process_image_dirs: &images,
                newest_entry_unix_ms: &newest,
            };
            let exists = |path: &Path| self.exists(path);
            let ctx = AnalyzeContext { exists: &exists, env: &env, software: &software };
            run(&ctx, &software)
        }

        fn findings(&self, snapshot: &RegistrySnapshot) -> Vec<RegistryFinding> {
            self.with_context(|ctx, _| analyze(snapshot, ctx))
        }

        fn both(&self, snapshot: &RegistrySnapshot) -> (Vec<RegistryFinding>, SoftwareAnalysis) {
            self.with_context(|ctx, chain| (analyze(snapshot, ctx), software::analyze(snapshot, chain)))
        }

        fn resolve(&self, command: &str) -> Option<String> {
            self.with_context(|ctx, _| resolve_executable(command, ctx))
        }

        fn resolved(&self, snapshot: &RegistrySnapshot, key: &str, name: &str) -> Option<String> {
            self.with_context(|ctx, _| resolved_text(snapshot, key, name, ctx))
        }
    }

    /// Paths that exist on the fake machine: the installed app folder plus its
    /// binaries. Missing binaries must still be reported.
    fn installed() -> Machine {
        Machine::new(&[
            r"C:\Program Files\Installed App",
            r"C:\Program Files\Installed App\viewer.exe",
            r"C:\Program Files\Installed App\alive.exe",
        ])
    }

    #[test]
    fn finds_uninstall_residue_with_evidence_and_safety() {
        let snapshot = parse_reg(FIXTURE, "fixture.reg");
        let machine = Machine::new(&[r"C:\Program Files\Installed App"]);
        let findings = machine.findings(&snapshot);

        let uninstall: Vec<_> = findings.iter().filter(|f| f.kind == ResidueKind::UninstallResidue).collect();
        assert_eq!(uninstall.len(), 2, "{uninstall:#?}");
        assert!(uninstall.iter().any(|f| f.key_path.ends_with("Gone App") && f.target == r"C:\Program Files\Gone App"));
        assert!(uninstall.iter().any(|f| f.key_path.contains("WOW6432Node") && f.target == r"D:\Legacy Tool"));

        let gone = uninstall.iter().find(|f| f.key_path.ends_with("Gone App")).unwrap();
        assert!(gone.evidence.contains("is missing"), "{gone:#?}");
        assert!(gone.evidence.contains("no recorded executable exists"), "{gone:#?}");
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
        let findings = installed().findings(&snapshot);

        let associations: Vec<_> = findings.iter().filter(|f| f.kind == ResidueKind::FileAssociation).collect();
        assert_eq!(associations.len(), 2, "{associations:#?}");
        assert!(associations.iter().any(|f| f.key_path.contains("gonefile") && f.target.ends_with("gone.exe")));
        assert!(associations.iter().any(|f| f.key_path.contains("Applications") && f.target.ends_with("missing.exe")));
        assert!(!associations.iter().any(|f| f.key_path.contains(".ok")), "existing handler must not be reported");
    }

    #[test]
    fn finds_failing_startup_items_and_skips_unexpandable_values() {
        let snapshot = parse_reg(FIXTURE, "fixture.reg");
        let findings = installed().with_env("ProgramFiles", r"C:\Program Files").findings(&snapshot);

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
        let findings = Machine::default().findings(&snapshot);

        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn expansion_and_executable_extraction_handle_quoted_unquoted_and_failures() {
        let machine = Machine::default().with_env("ProgramFiles", r"C:\Program Files");

        assert_eq!(machine.resolve(r#""C:\Program Files\App\app.exe" "%1""#).as_deref(), Some(r"C:\Program Files\App\app.exe"));
        assert_eq!(machine.resolve(r"C:\Program Files\App\app.exe /run").as_deref(), Some(r"C:\Program Files\App\app.exe"));
        assert_eq!(machine.resolve(r#"%ProgramFiles%\App\app.exe"#).as_deref(), Some(r"C:\Program Files\App\app.exe"));
        assert_eq!(machine.resolve(r#"%UNKNOWN%\app.exe"#), None);
        // A full path without an extension is resolved through `PATHEXT`, so it
        // is not a checkable target either.
        assert_eq!(machine.resolve(r"C:\Tools\perfmon"), None);
        assert_eq!(expand_env(r#"%UNKNOWN%\x"#, &|_: &str| None), None);
    }

    #[test]
    fn snapshot_values_are_kind_checked() {
        let mut snapshot = RegistrySnapshot::default();
        snapshot.insert(r"HKCU\Software\Vendor");
        snapshot.set_value(r"HKCU\Software\Vendor", "Path", RegistryValue { kind: RegistryValueKind::Dword, data: "7".into() });
        assert!(Machine::default().resolved(&snapshot, r"HKCU\Software\Vendor", "Path").is_none());
    }

    /// Rows where a single fact ("`InstallLocation` is missing") and the shared
    /// install evidence chain disagree. `Live Row` records a stale path while
    /// its uninstaller still exists, `{MSI ROW}` is an installer registration,
    /// `{PATCH ROW}` is an update of another product, `Stale Row` keeps a
    /// matching directory but nothing else, and `Orphan Row` keeps nothing.
    const SHARED: &str = r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Stale Row]
"DisplayName"="Stale Row"
"InstallLocation"="C:\\Program Files\\Stale Row\\1.0"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Live Row]
"DisplayName"="Live Row"
"InstallLocation"="C:\\Program Files\\Live Row\\1.0"
"UninstallString"="\"C:\\Program Files\\Live Row\\uninstall.exe\" /S"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{MSI ROW}]
"DisplayName"="Msi Row"
"InstallLocation"="C:\\Program Files\\Msi Row\\1.0"
"WindowsInstaller"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{PATCH ROW}]
"DisplayName"="Patch Row"
"ReleaseType"="Update"
"InstallLocation"="C:\\Program Files\\Ghost Row"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Orphan Row]
"DisplayName"="Orphan Row"
"InstallLocation"="C:\\Program Files\\Orphan Row"
"#;

    fn shared_machine() -> Machine {
        Machine::new(&[
            r"C:\Program Files",
            r"C:\Program Files\Stale Row",
            r"C:\Program Files\Msi Row",
            r"C:\Program Files\Live Row",
            r"C:\Program Files\Live Row\uninstall.exe",
        ])
        .with_env("ProgramFiles", r"C:\Program Files")
        .with_children(r"C:\Program Files", &["Live Row", "Msi Row", "Stale Row"])
    }

    /// One uninstall key, one answer. The registry command and the software
    /// command are asked about the same keys over the same machine, and their
    /// verdicts must agree. This assertion exists because the domains used to
    /// decide independently: the registry called a row an orphan the moment its
    /// recorded install path was missing, while the software domain counted the
    /// product as installed whenever an executable, a running process, an MSI
    /// registration or a recent write proved otherwise. A key could then be
    /// "installed" in one report and "residue" in the other, and whichever
    /// report the user acted on would contradict the other.
    #[test]
    fn both_domains_reach_the_same_verdict_for_one_uninstall_key() {
        let snapshot = parse_reg(SHARED, "shared.reg");
        let machine = shared_machine();
        let (findings, analysis) = machine.both(&snapshot);

        let residue = |path: &str| findings.iter().any(|finding| finding.kind == ResidueKind::UninstallResidue && finding.key_path == path);
        let installed = |path: &str| analysis.skipped.iter().any(|skip| skip.registry_key == path && skip.reason == "still-installed");
        let not_a_product = |path: &str| {
            analysis.skipped.iter().any(|skip| {
                skip.registry_key == path && matches!(skip.reason.as_str(), "system-component" | "update-package" | "no-display-name")
            })
        };
        let offered =
            |path: &str| analysis.findings.iter().any(|finding| finding.registry_key == path && finding.kind == SoftwareKind::InstallDirectory);

        // Both call `Live Row` installed: its recorded path is stale but its
        // uninstaller still exists.
        let live = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Live Row";
        assert!(installed(live), "software skips: {:#?}", analysis.skipped);
        assert!(!residue(live), "{findings:#?}");

        // Both call `Stale Row` residue: nothing proves presence and a matching
        // directory survives.
        let stale = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Stale Row";
        assert!(residue(stale), "{findings:#?}");
        assert!(offered(stale), "software findings: {:#?}", analysis.findings);

        // An installer registration and an update patch are excluded by both,
        // with or without a surviving directory.
        for key in [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{MSI ROW}",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{PATCH ROW}",
        ] {
            assert!(!residue(key), "{key} {findings:#?}");
        }

        // The same rule stated over every uninstall key in the fixture.
        for key in &snapshot.keys {
            if !key.path.to_ascii_uppercase().contains(r"\CURRENTVERSION\UNINSTALL\") {
                continue;
            }
            assert!(!(residue(&key.path) && installed(&key.path)), "installed in one domain and residue in the other: {}", key.path);
            assert!(!(residue(&key.path) && not_a_product(&key.path)), "not a product row but reported as residue: {}", key.path);
            if offered(&key.path) {
                assert!(residue(&key.path), "software offers {} but the registry does not treat the row as orphaned", key.path);
            }
        }
    }
}
