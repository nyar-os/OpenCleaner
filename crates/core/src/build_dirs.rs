//! Explicit Cargo build-output declarations.
//!
//! A shared build directory has no project manifest, so the manifest-anchored
//! developer rule can never claim it. This domain accepts exactly two explicit
//! declarations: the `CARGO_TARGET_DIR` environment variable, and the
//! `build.target-dir` key of a Cargo config file, resolved the way Cargo
//! resolves it (the working directory and its ancestors, nearest file wins).
//!
//! Every declaration carries its source, the key, the raw text, the base a
//! relative value was resolved against, and the absolute path it resolved to.
//! A declaration that cannot be used is reported with a reason. It is never
//! dropped silently, and it is never replaced by a directory-name guess.
//!
//! The operator-declared build-root config is a separate source and is not
//! read here: two declaration strengths must not be merged into one.
//!
//! This domain is read-only. It has no plan step and no delete step, and its
//! output cannot be handed to any cleanup call.

use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    locations::{BaseDirs, base_dirs},
    platform, safety,
};

/// Environment variable Cargo reads for an explicit target directory.
pub const ENV_KEY: &str = "CARGO_TARGET_DIR";
/// Cargo config key for an explicit target directory.
pub const CONFIG_KEY: &str = "build.target-dir";
/// Preferred config file name inside a `.cargo` directory.
const CONFIG_FILE: &str = "config.toml";
/// Older config file name Cargo still accepts when the `.toml` form is absent.
const LEGACY_CONFIG_FILE: &str = "config";
/// Default size floor for the uncovered-directory list.
pub const DEFAULT_MIN_BYTES: u64 = 512 * 1024 * 1024;

fn default_min_bytes() -> u64 {
    DEFAULT_MIN_BYTES
}

/// Which explicit declaration produced an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeclarationOrigin {
    /// `CARGO_TARGET_DIR`.
    Environment,
    /// `build.target-dir` in a Cargo config file.
    CargoConfig,
}

impl DeclarationOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Environment => "environment",
            Self::CargoConfig => "cargo-config",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BuildDirOptions {
    /// Directory whose Cargo configuration is resolved. Defaults to the
    /// current working directory.
    pub cwd: Option<String>,
    /// Directories searched one level down for build output that no
    /// declaration covers.
    pub roots: Vec<String>,
    /// Size floor for the uncovered-directory list.
    #[serde(default = "default_min_bytes")]
    pub min_bytes: u64,
}

impl BuildDirOptions {
    fn resolved_min_bytes(&self) -> u64 {
        if self.min_bytes == 0 { default_min_bytes() } else { self.min_bytes }
    }
}

/// One explicit declaration, valid or not.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildDirDeclaration {
    pub origin: DeclarationOrigin,
    /// Environment variable name, or the config file that holds the key.
    pub source: String,
    /// The key that was declared.
    pub key: String,
    /// Value exactly as declared.
    pub raw: String,
    /// Directory a relative value was resolved against. `None` for an
    /// absolute value and for a value that could not be resolved.
    pub base: Option<String>,
    /// Absolute path this declaration resolves to. Echoes `raw` when it could
    /// not be made absolute, so an invalid record still shows the request.
    pub resolved: String,
    pub relative: bool,
    /// The value is an absolute path inside a location Cargo may use.
    pub accepted: bool,
    /// The resolved path exists and is a directory.
    pub exists: bool,
    /// `accepted && exists`: this declaration names a real directory now.
    pub valid: bool,
    /// Why `valid` is false. Present for every unusable declaration.
    pub reason: Option<String>,
    /// A higher-priority declaration wins over this one.
    pub shadowed_by: Option<String>,
    /// Cargo uses this declaration when it is accepted.
    pub effective: bool,
}

/// A directory that carries Cargo build-output markers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildOutputProbe {
    pub path: String,
    pub bytes: u64,
    /// Marker names found, for example `.rustc_info.json`.
    pub markers: Vec<String>,
    /// A valid declaration names this directory or one of its ancestors.
    pub covered: bool,
    /// Declaration that covers it, as `source -> resolved`.
    pub covered_by: Option<String>,
}

/// A directory large enough to matter that no declaration names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UncoveredDirectory {
    pub path: String,
    pub bytes: u64,
    /// Cargo build-output markers found at this directory or its immediate
    /// children. Empty means nothing structurally identifies it as build
    /// output, and it is listed because of its size only.
    pub markers: Vec<String>,
    pub note: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BuildDirReport {
    /// Directory the declarations were resolved from.
    pub cwd: String,
    /// Every declaration found, in precedence order.
    pub declarations: Vec<BuildDirDeclaration>,
    /// Resolved path of the declaration Cargo would use, when one is accepted.
    pub effective_path: Option<String>,
    /// Source of that declaration.
    pub effective_source: Option<String>,
    pub roots: Vec<String>,
    /// Marker-carrying directories found under `roots`.
    pub probes: Vec<BuildOutputProbe>,
    /// Large directories under `roots` that no declaration covers.
    pub uncovered: Vec<UncoveredDirectory>,
    pub warnings: Vec<String>,
    pub scanned_at_unix_ms: u64,
}

/// Read the explicit declarations and, for explicit roots, the build output
/// that none of them covers. Nothing is measured outside the given roots and
/// nothing is modified anywhere.
pub fn build_dir_scan(options: BuildDirOptions) -> Result<BuildDirReport> {
    let env = |key: &str| std::env::var(key).ok();
    build_dir_report(options, &env, &base_dirs())
}

/// Testable form with an injected environment and base directories.
fn build_dir_report(options: BuildDirOptions, env: &dyn Fn(&str) -> Option<String>, dirs: &BaseDirs) -> Result<BuildDirReport> {
    let cwd = match options.cwd.as_deref().map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => normalize(&std::path::absolute(PathBuf::from(value)).unwrap_or_else(|_| PathBuf::from(value))),
        None => std::env::current_dir().map_err(|error| Error::Message(format!("build-dirs: no working directory: {error}")))?,
    };

    let mut warnings = vec!["the operator-declared build-root config is a separate source and is not evaluated here".to_string()];
    let mut declarations = collect_declarations(&cwd, env, dirs, &mut warnings);
    apply_precedence(&mut declarations);

    let effective = declarations.iter().find(|item| item.effective);
    if effective.is_none() {
        warnings.push(format!("no explicit build-output declaration applies to {}", cwd.display()));
    }

    let roots: Vec<PathBuf> = options
        .roots
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| {
            let path = PathBuf::from(value);
            normalize(&std::path::absolute(&path).unwrap_or(path))
        })
        .collect();
    let mut probes = Vec::new();
    let mut uncovered = Vec::new();
    for root in &roots {
        scan_root(root, &declarations, options.resolved_min_bytes(), &mut probes, &mut uncovered, &mut warnings);
    }

    probes.sort_by(|left, right| right.bytes.cmp(&left.bytes).then_with(|| left.path.cmp(&right.path)));
    uncovered.sort_by(|left, right| right.bytes.cmp(&left.bytes).then_with(|| left.path.cmp(&right.path)));

    Ok(BuildDirReport {
        cwd: cwd.display().to_string(),
        effective_path: effective.map(|item| item.resolved.clone()),
        effective_source: effective.map(|item| item.source.clone()),
        declarations,
        roots: roots.iter().map(|path| path.display().to_string()).collect(),
        probes,
        uncovered,
        warnings,
        scanned_at_unix_ms: safety::now_unix_ms(),
    })
}

/// One config file that can declare a target directory.
#[derive(Debug, Clone)]
struct ConfigFile {
    path: PathBuf,
    /// Directory a relative value in this file is resolved against.
    base: PathBuf,
}

fn config_file_for(dir: &Path, cargo_dir: &Path, warnings: &mut Vec<String>) -> Option<ConfigFile> {
    let preferred = cargo_dir.join(CONFIG_FILE);
    let legacy = cargo_dir.join(LEGACY_CONFIG_FILE);
    if preferred.is_file() {
        if legacy.is_file() {
            warnings.push(format!("{} is ignored because {} exists", legacy.display(), preferred.display()));
        }
        return Some(ConfigFile { path: preferred, base: dir.to_path_buf() });
    }
    if legacy.is_file() {
        warnings.push(format!("{} uses the legacy file name without the .toml extension", legacy.display()));
        return Some(ConfigFile { path: legacy, base: dir.to_path_buf() });
    }
    None
}

/// Config files from the working directory upward, nearest first, followed by
/// the Cargo home config which has the lowest precedence.
fn config_files(cwd: &Path, dirs: &BaseDirs, warnings: &mut Vec<String>) -> Vec<ConfigFile> {
    let mut files = Vec::new();
    for dir in cwd.ancestors() {
        let cargo_dir = dir.join(".cargo");
        if let Some(file) = config_file_for(dir, &cargo_dir, warnings) {
            files.push(file);
        }
    }
    if let Some(cargo_home) = dirs.cargo_home.as_deref()
        && let Some(file) = config_file_for(cargo_home, cargo_home, warnings)
        && !files.iter().any(|known| safety::path_key(&known.path) == safety::path_key(&file.path))
    {
        files.push(file);
    }
    files
}

fn collect_declarations(
    cwd: &Path,
    env: &dyn Fn(&str) -> Option<String>,
    dirs: &BaseDirs,
    warnings: &mut Vec<String>,
) -> Vec<BuildDirDeclaration> {
    let mut declarations = Vec::new();
    if let Some(value) = env(ENV_KEY) {
        declarations.push(environment_declaration(&value, cwd));
    }
    for file in config_files(cwd, dirs, warnings) {
        let text = match fs::read_to_string(&file.path) {
            Ok(text) => text,
            Err(error) => {
                warnings.push(format!("cannot read {}: {error}", file.path.display()));
                continue;
            }
        };
        for entry in scan_config(&text) {
            declarations.push(config_declaration(&file, &entry));
        }
    }
    declarations
}

fn environment_declaration(value: &str, cwd: &Path) -> BuildDirDeclaration {
    let raw = value.to_string();
    let mut declaration = BuildDirDeclaration {
        origin: DeclarationOrigin::Environment,
        source: ENV_KEY.to_string(),
        key: ENV_KEY.to_string(),
        raw: raw.clone(),
        base: None,
        resolved: raw.clone(),
        relative: false,
        accepted: false,
        exists: false,
        valid: false,
        reason: None,
        shadowed_by: None,
        effective: false,
    };
    resolve_value(&mut declaration, &raw, cwd);
    declaration
}

fn config_declaration(file: &ConfigFile, entry: &ConfigEntry) -> BuildDirDeclaration {
    let mut declaration = BuildDirDeclaration {
        origin: DeclarationOrigin::CargoConfig,
        source: file.path.display().to_string(),
        key: CONFIG_KEY.to_string(),
        raw: entry.raw.clone(),
        base: None,
        resolved: entry.raw.clone(),
        relative: false,
        accepted: false,
        exists: false,
        valid: false,
        reason: None,
        shadowed_by: None,
        effective: false,
    };
    match &entry.value {
        Some(value) => resolve_value(&mut declaration, value, &file.base),
        None => declaration.reason = Some(format!("line {}: {}", entry.line, entry.issue.as_deref().unwrap_or("value is not a TOML string"))),
    }
    declaration
}

/// Resolve the declared value into an absolute path, then decide whether the
/// declaration may name a build output directory. `value` is the decoded
/// string, so a config file that escaped its path is read the way Cargo reads
/// it, while `declaration.raw` keeps the text the user wrote.
fn resolve_value(declaration: &mut BuildDirDeclaration, value: &str, base: &Path) {
    let raw = value.trim().to_string();
    if raw.is_empty() {
        declaration.reason = Some("empty value".to_string());
        return;
    }
    let path = PathBuf::from(&raw);
    let resolved = if path.is_absolute() {
        path
    }
    else {
        if path.components().next().is_some_and(|component| matches!(component, Component::Prefix(_))) {
            declaration.reason = Some(format!("drive-relative path cannot be resolved: {raw}"));
            return;
        }
        declaration.relative = true;
        declaration.base = Some(base.display().to_string());
        normalize(&base.join(&path))
    };
    declaration.resolved = resolved.display().to_string();
    declaration.accepted = true;
    if let Err(reason) = validate_location(&resolved) {
        declaration.accepted = false;
        declaration.reason = Some(reason);
        return;
    }
    declaration.exists = resolved.is_dir();
    declaration.valid = declaration.exists;
    if !declaration.exists {
        declaration.reason = Some(format!("declared path does not exist: {}", declaration.resolved));
    }
}

/// A declared target directory must not be a filesystem root, a system
/// directory, or inside installed software.
fn validate_location(path: &Path) -> std::result::Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("not an absolute path: {}", path.display()));
    }
    if is_volume_root(path) {
        return Err(format!("a filesystem root can never be a build target: {}", path.display()));
    }
    if safety::has_protected_component(path) {
        return Err(format!("declared path points into a system or installed directory: {}", path.display()));
    }
    safety::ensure_not_install_root(path, "build-dirs").map_err(|error| error.to_string())
}

fn is_volume_root(path: &Path) -> bool {
    let mut rooted = false;
    let mut normal = 0usize;
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => rooted = true,
            Component::Normal(_) => normal += 1,
            _ => {}
        }
    }
    rooted && normal == 0
}

/// Lexical normalization without touching the filesystem: `.` is dropped and
/// `..` pops the previous component. Symlinks are never resolved.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// A single declaration wins and every other one is marked as shadowed. Only
/// accepted declarations take part, so an unusable higher-priority value does
/// not hide a usable lower one.
fn apply_precedence(declarations: &mut [BuildDirDeclaration]) {
    let mut winner: Option<String> = None;
    for declaration in declarations.iter_mut() {
        if !declaration.accepted {
            continue;
        }
        match &winner {
            None => {
                declaration.effective = true;
                winner = Some(declaration.source.clone());
            }
            Some(source) => declaration.shadowed_by = Some(source.clone()),
        }
    }
}

fn marker_names(dir: &Path) -> Vec<String> {
    let mut found = Vec::new();
    if dir.join(".rustc_info.json").is_file() {
        found.push(".rustc_info.json".to_string());
    }
    if dir.join("CACHEDIR.TAG").is_file() {
        found.push("CACHEDIR.TAG".to_string());
    }
    for profile in ["debug", "release"] {
        if dir.join(profile).join(".fingerprint").is_dir() {
            found.push(format!("{profile}/.fingerprint"));
        }
    }
    found
}

fn immediate_dirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(read) = fs::read_dir(dir)
    else {
        return Vec::new();
    };
    let mut dirs = Vec::new();
    for entry in read.flatten() {
        let Ok(meta) = entry.metadata()
        else {
            continue;
        };
        if !meta.is_dir() || platform::is_link_like(&meta) || meta.file_type().is_symlink() {
            continue;
        }
        dirs.push(entry.path());
    }
    dirs
}

/// Marker evidence for a directory and its immediate children. Depth is fixed:
/// a build output root can sit one level below the probed directory.
fn probe_markers(dir: &Path) -> Vec<(PathBuf, Vec<String>)> {
    let mut hits = Vec::new();
    let own = marker_names(dir);
    if !own.is_empty() {
        hits.push((dir.to_path_buf(), own));
    }
    for child in immediate_dirs(dir) {
        let names = marker_names(&child);
        if !names.is_empty() {
            hits.push((child, names));
        }
    }
    hits
}

fn declaring_source(declaration: &BuildDirDeclaration) -> String {
    format!("{} -> {}", declaration.source, declaration.resolved)
}

fn scan_root(
    root: &Path,
    declarations: &[BuildDirDeclaration],
    min_bytes: u64,
    probes: &mut Vec<BuildOutputProbe>,
    uncovered: &mut Vec<UncoveredDirectory>,
    warnings: &mut Vec<String>,
) {
    if !root.is_dir() {
        warnings.push(format!("probe root does not exist: {}", root.display()));
        return;
    }
    let read = match fs::read_dir(root) {
        Ok(read) => read,
        Err(error) => {
            warnings.push(format!("cannot list probe root {}: {error}", root.display()));
            return;
        }
    };
    for entry in read.flatten() {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path)
        else {
            continue;
        };
        if !meta.is_dir() || platform::is_link_like(&meta) || meta.file_type().is_symlink() {
            continue;
        }
        let hits = probe_markers(&path);
        let covered = declarations.iter().find(|item| item.accepted && safety::is_within(Path::new(&item.resolved), &path));
        for (hit_path, markers) in &hits {
            let bytes = safety::collect_usage(hit_path).bytes;
            let covered_by = declarations.iter().find(|item| item.accepted && safety::is_within(Path::new(&item.resolved), hit_path));
            probes.push(BuildOutputProbe {
                path: hit_path.display().to_string(),
                bytes,
                markers: markers.clone(),
                covered: covered_by.is_some(),
                covered_by: covered_by.map(declaring_source),
            });
        }

        let usage = safety::collect_usage(&path);
        if usage.bytes < min_bytes {
            continue;
        }
        if covered.is_some() {
            continue;
        }
        let markers: Vec<String> = hits.iter().flat_map(|(_, names)| names.iter().cloned()).collect::<BTreeSet<_>>().into_iter().collect();
        let partial = declarations.iter().find(|item| item.accepted && safety::is_within(&path, Path::new(&item.resolved)));
        let note = match partial {
            Some(item) => format!("only part of this directory is declared: {}", declaring_source(item)),
            None if markers.is_empty() => "no declaration and no Cargo output marker: listed because of its size only".to_string(),
            None => "Cargo output markers present but no declaration names this directory".to_string(),
        };
        uncovered.push(UncoveredDirectory { path: path.display().to_string(), bytes: usage.bytes, markers, note });
    }
}

/// One `build.target-dir` occurrence with its 1-based line number.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfigEntry {
    line: u64,
    raw: String,
    value: Option<String>,
    /// Why `value` is `None`, when the key was found but unreadable.
    issue: Option<String>,
}

/// Read `build.target-dir` out of a Cargo config file. Only that key is
/// extracted: the rest of the file belongs to Cargo, and a hand-written
/// reader must not pretend to validate a whole TOML document.
fn scan_config(text: &str) -> Vec<ConfigEntry> {
    let mut entries = Vec::new();
    let mut section = String::new();
    for (index, line) in text.lines().enumerate() {
        let number = index as u64 + 1;
        let stripped = strip_comment(line).trim();
        if stripped.is_empty() {
            continue;
        }
        if stripped.starts_with('[') && stripped.ends_with(']') {
            section = stripped[1..stripped.len() - 1].trim().to_string();
            continue;
        }
        let Some((key, value)) = stripped.split_once('=')
        else {
            continue;
        };
        let key = key.trim().trim_matches('"').trim().to_string();
        let full = if section.is_empty() { key } else { format!("{section}.{key}") };
        if full != CONFIG_KEY {
            continue;
        }
        let raw = value.trim().to_string();
        let (value, issue) = match parse_toml_string(&raw) {
            Ok(value) => (Some(value), None),
            Err(issue) => (None, Some(issue)),
        };
        entries.push(ConfigEntry { line: number, raw, value, issue });
    }
    entries
}

/// Strip a trailing `#` comment while leaving quoted text intact.
fn strip_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (index, ch) in line.char_indices() {
        match quote {
            Some(mark) => {
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' && mark == '"' {
                    escaped = true;
                    continue;
                }
                if ch == mark {
                    quote = None;
                }
            }
            None => {
                if ch == '"' || ch == '\'' {
                    quote = Some(ch);
                    continue;
                }
                if ch == '#' {
                    return &line[..index];
                }
            }
        }
    }
    line
}

/// Parse a single-line TOML string value. Multi-line strings and unknown
/// escapes are refused with a reason instead of being rewritten.
fn parse_toml_string(raw: &str) -> std::result::Result<String, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("empty value".to_string());
    }
    if value.starts_with("\"\"\"") || value.starts_with("'''") {
        return Err("multi-line TOML strings are not supported".to_string());
    }
    if let Some(rest) = value.strip_prefix('\'') {
        let close = rest.find('\'').ok_or_else(|| "unterminated string".to_string())?;
        return trailing_is_empty(&rest[close + 1..])
            .map_err(|()| "trailing content after the value".to_string())
            .map(|()| rest[..close].to_string());
    }
    if let Some(rest) = value.strip_prefix('"') {
        let mut out = String::new();
        let mut escaped = false;
        for (index, ch) in rest.char_indices() {
            if escaped {
                match ch {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'r' => out.push('\r'),
                    'b' => out.push('\u{8}'),
                    'f' => out.push('\u{c}'),
                    other => return Err(format!("unsupported TOML escape `\\{other}`")),
                }
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '"' => return trailing_is_empty(&rest[index + 1..]).map(|()| out).map_err(|_| "trailing content after the value".to_string()),
                _ => out.push(ch),
            }
        }
        return Err("unterminated string".to_string());
    }
    Err("value is not a TOML string".to_string())
}

fn trailing_is_empty(rest: &str) -> std::result::Result<(), ()> {
    if rest.trim().is_empty() { Ok(()) } else { Err(()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_dirs() -> BaseDirs {
        BaseDirs::default()
    }

    fn no_env(_key: &str) -> Option<String> {
        None
    }

    fn report(cwd: &Path, env_value: Option<&str>, dirs: &BaseDirs) -> BuildDirReport {
        let env = move |key: &str| if key == ENV_KEY { env_value.map(str::to_string) } else { None };
        build_dir_report(BuildDirOptions { cwd: Some(cwd.display().to_string()), ..BuildDirOptions::default() }, &env, dirs).unwrap()
    }

    fn write(path: &Path, text: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, text).unwrap();
    }

    fn synthetic_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("open-cleaner-build-dirs-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn section_and_dotted_key_are_both_read() {
        let text = "build.target-dir = \"D:\\\\other\"\n[build]\ntarget-dir = 'C:\\sample\\cache'\n[profile.release]\nopt-level = 3\n";
        let entries = scan_config(text);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].line, 1);
        assert_eq!(entries[0].value.as_deref(), Some(r"D:\other"));
        assert_eq!(entries[1].line, 3);
        assert_eq!(entries[1].value.as_deref(), Some(r"C:\sample\cache"));
    }

    #[test]
    fn unrelated_keys_and_other_sections_are_ignored() {
        let text = "[build]\njobs = 4\n[net]\ntarget-dir = 'x'\n";
        assert!(scan_config(text).is_empty());
    }

    #[test]
    fn non_string_and_multiline_values_are_reported_with_a_reason() {
        let entries = scan_config("[build]\ntarget-dir = 12\ntarget-dir = '''a'''\n");
        assert_eq!(entries.len(), 2);
        assert!(entries[0].value.is_none());
        assert!(entries[0].issue.as_deref().unwrap().contains("not a TOML string"));
        assert!(entries[1].issue.as_deref().unwrap().contains("multi-line"));
    }

    #[test]
    fn nearest_config_wins_and_a_farther_one_is_shadowed() {
        let root = synthetic_root("nearest");
        write(&root.join("alpha").join(".cargo").join("config.toml"), "[build]\ntarget-dir = 'cache'\n");
        write(&root.join("alpha").join("beta").join(".cargo").join("config.toml"), "[build]\ntarget-dir = 'local-cache'\n");
        let cwd = root.join("alpha").join("beta");

        let report = report(&cwd, None, &empty_dirs());

        assert_eq!(report.declarations.len(), 2);
        assert_eq!(report.declarations[0].source, root.join("alpha").join("beta").join(".cargo").join("config.toml").display().to_string());
        assert!(report.declarations[0].effective);
        assert!(!report.declarations[0].valid);
        assert!(report.declarations[0].reason.as_deref().unwrap().contains("does not exist"));
        assert_eq!(report.declarations[0].base, Some(cwd.display().to_string()));
        assert_eq!(report.declarations[0].resolved, normalize(&cwd.join("local-cache")).display().to_string());
        assert!(report.declarations[1].shadowed_by.is_some());
        assert_eq!(report.effective_source.as_deref(), Some(report.declarations[0].source.as_str()));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn environment_wins_over_every_config_file() {
        let root = synthetic_root("environment");
        write(&root.join(".cargo").join("config.toml"), "[build]\ntarget-dir = 'from-config'\n");
        let report = report(&root, Some(r"C:\sample\env-target"), &empty_dirs());

        assert_eq!(report.declarations.len(), 2);
        assert_eq!(report.declarations[0].origin, DeclarationOrigin::Environment);
        assert!(report.declarations[0].effective);
        assert_eq!(report.declarations[0].raw, r"C:\sample\env-target");
        assert_eq!(report.declarations[0].base, None);
        assert!(!report.declarations[0].relative);
        assert_eq!(report.declarations[1].shadowed_by.as_deref(), Some(ENV_KEY));
        assert_eq!(report.effective_path.as_deref(), Some(r"C:\sample\env-target"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn empty_environment_value_is_reported_and_does_not_hide_the_config() {
        let root = synthetic_root("empty-env");
        write(&root.join(".cargo").join("config.toml"), "[build]\ntarget-dir = 'from-config'\n");
        let report = report(&root, Some("   "), &empty_dirs());

        assert_eq!(report.declarations[0].origin, DeclarationOrigin::Environment);
        assert!(!report.declarations[0].accepted);
        assert_eq!(report.declarations[0].reason.as_deref(), Some("empty value"));
        assert!(report.declarations[1].effective, "an unusable value must not shadow a usable one");
        assert!(report.declarations[1].shadowed_by.is_none());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn legacy_config_name_is_read_when_the_toml_form_is_absent() {
        let root = synthetic_root("legacy");
        write(&root.join(".cargo").join("config"), "[build]\ntarget-dir = 'from-legacy'\n");
        let report = report(&root, None, &empty_dirs());

        assert_eq!(report.declarations.len(), 1);
        assert!(report.declarations[0].source.ends_with("config"));
        assert!(report.warnings.iter().any(|warning| warning.contains("legacy")));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cargo_home_config_is_read_after_the_walk() {
        let root = synthetic_root("cargo-home");
        let home = root.join("cargo-home");
        write(&home.join("config.toml"), "[build]\ntarget-dir = 'from-home'\n");
        let project = root.join("project");
        write(&project.join(".cargo").join("config.toml"), "[build]\ntarget-dir = 'from-project'\n");
        let dirs = BaseDirs { cargo_home: Some(home.clone()), ..BaseDirs::default() };

        let report = report(&project, None, &dirs);

        assert_eq!(report.declarations.len(), 2);
        assert!(report.declarations[0].effective);
        assert_eq!(report.declarations[0].source, project.join(".cargo").join("config.toml").display().to_string());
        assert_eq!(report.declarations[1].source, home.join("config.toml").display().to_string());
        assert!(report.declarations[1].shadowed_by.is_some());
        assert_eq!(report.declarations[1].base, Some(home.display().to_string()));
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(windows)]
    #[test]
    fn system_locations_are_rejected_with_a_reason() {
        assert!(validate_location(Path::new(r"C:\ProgramData\sample\cache")).is_err());
        assert!(validate_location(Path::new(r"C:\Windows\sample")).is_err());
        assert!(validate_location(Path::new(r"C:\")).is_err());
    }

    #[test]
    fn probes_mark_directories_and_uncovered_entries_carry_markers() {
        let root = synthetic_root("probe");
        let covered = root.join("declared-output");
        fs::create_dir_all(covered.join("debug")).unwrap();
        write(&covered.join(".rustc_info.json"), "{}");
        write(&covered.join("CACHEDIR.TAG"), "Signature: sample");
        write(&covered.join("debug").join(".fingerprint").join("x"), "x");
        let loose = root.join("loose-output");
        write(&loose.join(".rustc_info.json"), "{}");
        write(&loose.join("blob.bin"), &"x".repeat(4096));
        let quiet = root.join("quiet-empty");
        fs::create_dir_all(&quiet).unwrap();

        let config = root.join(".cargo");
        write(&config.join("config.toml"), &format!("[build]\ntarget-dir = '{}'\n", covered.display()));
        let report = build_dir_report(
            BuildDirOptions { cwd: Some(root.display().to_string()), roots: vec![root.display().to_string()], min_bytes: 1 },
            &no_env,
            &empty_dirs(),
        )
        .unwrap();

        let covered_probe = report.probes.iter().find(|probe| probe.path == covered.display().to_string()).unwrap();
        assert!(covered_probe.covered);
        assert!(covered_probe.covered_by.as_deref().unwrap().contains("declared-output"));
        assert!(covered_probe.markers.contains(&".rustc_info.json".to_string()));

        let uncovered = report.uncovered.iter().find(|item| item.path == loose.display().to_string()).unwrap();
        assert!(uncovered.markers.contains(&".rustc_info.json".to_string()));
        assert!(!uncovered.note.contains("only part"));
        assert!(!report.uncovered.iter().any(|item| item.path == covered.display().to_string()));
        assert!(!report.uncovered.iter().any(|item| item.path == quiet.display().to_string()));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_directory_holding_a_declaration_is_still_reported_as_uncovered() {
        let root = synthetic_root("partial");
        let parent = root.join("parent-output");
        fs::create_dir_all(parent.join("nested")).unwrap();
        write(&parent.join("blob.bin"), &"x".repeat(4096));
        let config = root.join(".cargo");
        write(&config.join("config.toml"), &format!("[build]\ntarget-dir = '{}'\n", parent.join("nested").display()));

        let report = build_dir_report(
            BuildDirOptions { cwd: Some(root.display().to_string()), roots: vec![root.display().to_string()], min_bytes: 1 },
            &no_env,
            &empty_dirs(),
        )
        .unwrap();

        let entry = report.uncovered.iter().find(|item| item.path == parent.display().to_string()).unwrap();
        assert!(entry.note.contains("only part of this directory is declared"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn drive_relative_values_are_refused() {
        let root = synthetic_root("drive-relative");
        let mut declaration = BuildDirDeclaration {
            origin: DeclarationOrigin::CargoConfig,
            source: "sample".to_string(),
            key: CONFIG_KEY.to_string(),
            raw: "C:cache".to_string(),
            base: None,
            resolved: String::new(),
            relative: false,
            accepted: false,
            exists: false,
            valid: false,
            reason: None,
            shadowed_by: None,
            effective: false,
        };
        resolve_value(&mut declaration, "C:cache", &root);
        if cfg!(windows) {
            assert!(!declaration.accepted);
            assert!(declaration.reason.as_deref().unwrap().contains("drive-relative"));
        }
        let _ = fs::remove_dir_all(&root);
    }
}
