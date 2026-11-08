//! Cargo build-output discovery: explicit declarations plus marker proof.
//!
//! A shared build directory has no project manifest, so the manifest-anchored
//! developer rule can never claim it. Part one accepts exactly two explicit
//! declarations: the `CARGO_TARGET_DIR` environment variable, and the
//! `build.target-dir` key of a Cargo config file, resolved the way Cargo
//! resolves it (the working directory and its ancestors, nearest file wins).
//!
//! Every declaration carries its source, the key, the raw text, the base a
//! relative value was resolved against, and the absolute path it resolved to.
//! A declaration that cannot be used is reported with a reason. It is never
//! dropped silently, and it is never replaced by a directory-name guess.
//!
//! Part two walks explicit probe roots and accepts a directory as Cargo build
//! output only when `CACHEDIR.TAG` sits next to a Cargo-specific marker:
//! `.rustc_info.json`, or `*/debug/.fingerprint` / `*/release/.fingerprint`
//! below it. The tag alone is never enough, because other tools write it too.
//! Directory names carry no weight here: a directory called `target` is not a
//! candidate by name, and output found anywhere else is. The report lists the
//! marker files that actually matched, so the reason is auditable.
//!
//! The operator-declared build-root config is a separate source and is not
//! read here: two declaration strengths must not be merged into one. It is
//! only compared for overlap, and a match it already covers is excluded from
//! this domain's unique byte total.
//!
//! This domain is read-only. It has no plan step and no delete step, and its
//! output cannot be handed to any cleanup call.

use std::{
    collections::{BTreeMap, BTreeSet},
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
    /// Directories probed for marker-proven build output.
    pub roots: Vec<String>,
    /// Size floor for the uncovered-directory list.
    #[serde(default = "default_min_bytes")]
    pub min_bytes: u64,
    /// Levels below each root that are inspected. `1` checks only the root's
    /// immediate children. A matched directory is never descended into, so an
    /// inner build output is not reported twice.
    #[serde(default = "default_depth")]
    pub depth: usize,
}

impl BuildDirOptions {
    fn resolved_min_bytes(&self) -> u64 {
        if self.min_bytes == 0 { default_min_bytes() } else { self.min_bytes }
    }

    fn resolved_depth(&self) -> usize {
        match self.depth {
            0 => default_depth(),
            value => value.min(3),
        }
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

/// How a directory earned its place in the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatchAttribution {
    /// `CACHEDIR.TAG` together with at least one Cargo-specific marker. Never a
    /// directory name, a declaration and never a manifest anchor.
    CargoMarkers,
}

/// A directory proven to be Cargo build output by marker files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildOutputMatch {
    pub path: String,
    pub bytes: u64,
    /// Absolute paths of the marker files that satisfied the rule.
    pub evidence: Vec<String>,
    pub attribution: MatchAttribution,
    /// The satisfied rule in one sentence.
    pub reason: String,
    /// A declaration also names this directory or one of its ancestors.
    pub covered_by_declaration: Option<String>,
    /// The separate build-root config also covers this path, so the same bytes
    /// are already accounted for there.
    pub also_in_build_roots: bool,
}

/// Marker-proven build output that the location rules refuse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectedDirectory {
    pub path: String,
    pub evidence: Vec<String>,
    pub reason: String,
}

/// One entry of the separate build-root config, compared with this domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildRootOverlap {
    pub path: String,
    pub line: u64,
    pub exists: bool,
    /// Bytes, only when the path was measured inside a probe root.
    pub bytes: Option<u64>,
    /// A marker match lies at or inside this declared path.
    pub matched_by_markers: bool,
    pub note: String,
}

/// A directory large enough to matter that no marker match and no declaration
/// covers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UncoveredDirectory {
    pub path: String,
    pub bytes: u64,
    /// Absolute marker paths that were found but did not satisfy the rule.
    /// Empty means nothing structural exists, and it listed because of size.
    pub evidence: Vec<String>,
    pub reason: String,
    /// The separate build-root config already declares this directory, so the
    /// gap exists only in this domain and the bytes are not unaccounted for.
    pub also_in_build_roots: bool,
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
    /// Config file the overlap comparison read, when one was found.
    pub build_root_config: Option<String>,
    /// Directories proven to be Cargo build output by markers.
    pub matches: Vec<BuildOutputMatch>,
    /// Marker-proven directories refused by the location rules.
    pub rejected: Vec<RejectedDirectory>,
    /// Large directories that no marker match and no declaration covers.
    pub uncovered: Vec<UncoveredDirectory>,
    /// Entries of the separate build-root config, compared for overlap only.
    pub build_roots: Vec<BuildRootOverlap>,
    /// Bytes of all unique matches.
    pub matched_bytes: u64,
    /// Part of `matched_bytes` that the build-root config already counts.
    pub matched_bytes_in_build_roots: u64,
    /// `matched_bytes - matched_bytes_in_build_roots`.
    pub unique_matched_bytes: u64,
    pub warnings: Vec<String>,
    pub scanned_at_unix_ms: u64,
}

/// Read the explicit declarations and, for explicit roots, the marker-proven
/// build output. Nothing is measured outside the given roots and nothing is
/// modified anywhere.
pub fn build_dir_scan(options: BuildDirOptions) -> Result<BuildDirReport> {
    let env = |key: &str| std::env::var(key).ok();
    let build_roots = crate::anchors::default_build_root_config();
    build_dir_report(options, &env, &base_dirs(), build_roots.as_deref())
}

/// Testable form with an injected environment, base directories and an
/// explicit build-root config path.
fn build_dir_report(
    options: BuildDirOptions,
    env: &dyn Fn(&str) -> Option<String>,
    dirs: &BaseDirs,
    build_root_config: Option<&Path>,
) -> Result<BuildDirReport> {
    let cwd = match options.cwd.as_deref().map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => normalize(&std::path::absolute(PathBuf::from(value)).unwrap_or_else(|_| PathBuf::from(value))),
        None => std::env::current_dir().map_err(|error| Error::Message(format!("build-dirs: no working directory: {error}")))?,
    };

    let mut warnings = vec![
        "the operator-declared build-root config is a separate source: it is only compared for overlap and is never merged into this domain's totals"
            .to_string(),
    ];
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

    let mut output = ProbeOutput::default();
    for root in &roots {
        scan_root(root, options.resolved_depth(), &declarations, options.resolved_min_bytes(), &mut output, &mut warnings);
    }
    let mut matches = output.matches;
    let mut rejected = output.rejected;
    let mut uncovered = output.uncovered;
    let measured = output.measured;

    dedupe_by_path(&mut matches, |item| &item.path);
    dedupe_by_path(&mut rejected, |item| &item.path);
    dedupe_by_path(&mut uncovered, |item| &item.path);
    matches.sort_by(|left, right| right.bytes.cmp(&left.bytes).then_with(|| left.path.cmp(&right.path)));
    rejected.sort_by(|left, right| left.path.cmp(&right.path));
    uncovered.sort_by(|left, right| right.bytes.cmp(&left.bytes).then_with(|| left.path.cmp(&right.path)));

    let (declared_roots, config_path) = build_root_declarations(build_root_config, &mut warnings);
    let build_roots = compare_build_roots(declared_roots, &mut matches, &measured);
    let matched_bytes: u64 = matches.iter().map(|item| item.bytes).sum();
    let matched_bytes_in_build_roots: u64 = matches.iter().filter(|item| item.also_in_build_roots).map(|item| item.bytes).sum();
    let covered_by_build_roots: Vec<String> = build_roots.iter().filter(|item| item.exists).map(|item| item.path.clone()).collect();
    for item in &mut uncovered {
        let path = Path::new(&item.path);
        item.also_in_build_roots = covered_by_build_roots.iter().any(|declared| safety::is_within(Path::new(declared), path));
    }

    Ok(BuildDirReport {
        cwd: cwd.display().to_string(),
        effective_path: effective.map(|item| item.resolved.clone()),
        effective_source: effective.map(|item| item.source.clone()),
        declarations,
        roots: roots.iter().map(|path| path.display().to_string()).collect(),
        build_root_config: config_path,
        matches,
        rejected,
        uncovered,
        build_roots,
        matched_bytes,
        matched_bytes_in_build_roots,
        unique_matched_bytes: matched_bytes.saturating_sub(matched_bytes_in_build_roots),
        warnings,
        scanned_at_unix_ms: safety::now_unix_ms(),
    })
}

fn dedupe_by_path<T>(items: &mut Vec<T>, path: impl Fn(&T) -> &String) {
    let mut seen = BTreeSet::new();
    items.retain(|item| seen.insert(safety::path_key(Path::new(path(item)))));
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

const TAG_NAME: &str = "CACHEDIR.TAG";
const PROFILE_FINGERPRINTS: [&str; 2] = ["debug", "release"];
const FINGERPRINT_DIR: &str = ".fingerprint";

fn default_depth() -> usize {
    2
}

fn child_dir(entry: &fs::DirEntry) -> Option<PathBuf> {
    let meta = entry.metadata().ok()?;
    if !meta.is_dir() || platform::is_link_like(&meta) || meta.file_type().is_symlink() {
        return None;
    }
    Some(entry.path())
}

fn immediate_dirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(read) = fs::read_dir(dir)
    else {
        return Vec::new();
    };
    read.flatten().filter_map(|entry| child_dir(&entry)).collect()
}

fn is_plain_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir() && !platform::is_link_like(&meta) && !meta.file_type().is_symlink())
}

/// The rule names the profile directory itself: `debug/.fingerprint` or
/// `release/.fingerprint` directly below the target root.
fn profile_fingerprint(dir: &Path) -> Option<PathBuf> {
    PROFILE_FINGERPRINTS.iter().map(|profile| dir.join(profile).join(FINGERPRINT_DIR)).find(|path| is_plain_dir(path))
}

/// Every Cargo release writes one `*.rustc_info.json` at the target root. The
/// pattern is matched on the file name, so a renamed or prefixed copy still
/// counts while a directory of that name never does.
fn rustc_info_file(dir: &Path) -> Option<PathBuf> {
    let read = fs::read_dir(dir).ok()?;
    for entry in read.flatten() {
        if !entry.file_name().to_string_lossy().ends_with("rustc_info.json") {
            continue;
        }
        if let Ok(meta) = entry.metadata()
            && meta.is_file()
        {
            return Some(entry.path());
        }
    }
    None
}

/// The markers present at a directory, whether or not they satisfy the rule.
#[derive(Debug, Default)]
struct MarkerState {
    tag: Option<PathBuf>,
    info: Option<PathBuf>,
    fingerprint: Option<PathBuf>,
}

impl MarkerState {
    fn scan(dir: &Path) -> Self {
        let mut state = Self::default();
        let tag = dir.join(TAG_NAME);
        if tag.is_file() {
            state.tag = Some(tag);
        }
        state.info = rustc_info_file(dir);
        state.fingerprint = profile_fingerprint(dir);
        state
    }

    fn has_cargo_marker(&self) -> bool {
        self.info.is_some() || self.fingerprint.is_some()
    }

    fn evidence(&self) -> Vec<String> {
        [self.tag.as_ref(), self.info.as_ref(), self.fingerprint.as_ref()]
            .into_iter()
            .flatten()
            .map(|path| path.display().to_string())
            .collect()
    }
}

/// `CACHEDIR.TAG` alone is used by other tools, so a directory counts as Cargo
/// build output only when the tag and a Cargo-specific marker both hold.
fn cargo_build_evidence(dir: &Path) -> Option<Vec<PathBuf>> {
    let tag = dir.join(TAG_NAME);
    if !tag.is_file() {
        return None;
    }
    if let Some(info) = rustc_info_file(dir) {
        return Some(vec![tag, info]);
    }
    let fingerprint = profile_fingerprint(dir)?;
    Some(vec![tag, fingerprint])
}

fn refusal(path: &Path) -> Option<String> {
    if is_volume_root(path) {
        return Some("a filesystem root is never a build-output candidate".to_string());
    }
    if safety::has_protected_component(path) {
        return Some("inside a system or installed directory".to_string());
    }
    safety::ensure_not_install_root(path, "build-dirs").err().map(|error| error.to_string())
}

fn declaring_source(declaration: &BuildDirDeclaration) -> String {
    format!("{} -> {}", declaration.source, declaration.resolved)
}

#[derive(Default)]
struct ProbeOutput {
    matches: Vec<BuildOutputMatch>,
    rejected: Vec<RejectedDirectory>,
    uncovered: Vec<UncoveredDirectory>,
    measured: BTreeMap<String, u64>,
}

fn push_match(path: &Path, bytes: u64, evidence: Vec<PathBuf>, declarations: &[BuildDirDeclaration], output: &mut ProbeOutput) {
    let evidence: Vec<String> = evidence.iter().map(|item| item.display().to_string()).collect();
    if let Some(reason) = refusal(path) {
        output.rejected.push(RejectedDirectory { path: path.display().to_string(), evidence, reason });
        return;
    }
    output.matches.push(BuildOutputMatch {
        path: path.display().to_string(),
        bytes,
        evidence,
        attribution: MatchAttribution::CargoMarkers,
        reason: format!("{TAG_NAME} is present together with a Cargo-specific marker"),
        covered_by_declaration: declarations
            .iter()
            .find(|item| item.accepted && safety::is_within(Path::new(&item.resolved), path))
            .map(declaring_source),
        also_in_build_roots: false,
    });
}

fn scan_root(
    root: &Path,
    depth: usize,
    declarations: &[BuildDirDeclaration],
    min_bytes: u64,
    output: &mut ProbeOutput,
    warnings: &mut Vec<String>,
) {
    let meta = match fs::symlink_metadata(root) {
        Ok(meta) => meta,
        Err(error) => {
            warnings.push(format!("cannot inspect probe root {}: {error}", root.display()));
            return;
        }
    };
    if platform::is_link_like(&meta) || meta.file_type().is_symlink() {
        warnings.push(format!("probe root is a symbolic link or junction and is never followed: {}", root.display()));
        return;
    }
    if !meta.is_dir() {
        warnings.push(format!("probe root does not exist or is not a directory: {}", root.display()));
        return;
    }
    let read = match fs::read_dir(root) {
        Ok(read) => read,
        Err(error) => {
            warnings.push(format!("cannot list probe root {}: {error}", root.display()));
            return;
        }
    };
    let mut links = 0u64;
    let mut unreadable = 0u64;
    for entry in read.flatten() {
        let Ok(meta) = entry.metadata()
        else {
            unreadable += 1;
            continue;
        };
        if platform::is_link_like(&meta) || meta.file_type().is_symlink() {
            links += 1;
            continue;
        }
        if !meta.is_dir() {
            continue;
        }
        let path = entry.path();

        // A hit ends the walk here: descending into a build output would only
        // report the same bytes again under a nested name.
        if let Some(evidence) = cargo_build_evidence(&path) {
            let bytes = safety::collect_usage(&path).bytes;
            output.measured.insert(safety::path_key(&path), bytes);
            push_match(&path, bytes, evidence, declarations, output);
            continue;
        }

        // Build output can sit below a container that is not one itself.
        if depth > 1 && probe_below(&path, 2, depth, declarations, output) {
            continue;
        }

        let usage = safety::collect_usage(&path);
        if usage.errors > 0 {
            unreadable += 1;
        }
        output.measured.insert(safety::path_key(&path), usage.bytes);
        if usage.bytes < min_bytes {
            continue;
        }
        if declarations.iter().any(|item| item.accepted && safety::is_within(Path::new(&item.resolved), &path)) {
            continue;
        }
        let state = MarkerState::scan(&path);
        let partial = declarations.iter().find(|item| item.accepted && safety::is_within(&path, Path::new(&item.resolved)));
        let reason = match refusal(&path) {
            Some(refusal_reason) => format!("{refusal_reason}, so this directory is never a candidate; {}", uncovered_reason(&state, partial)),
            None => uncovered_reason(&state, partial),
        };
        output.uncovered.push(UncoveredDirectory {
            path: path.display().to_string(),
            bytes: usage.bytes,
            evidence: state.evidence(),
            reason,
            also_in_build_roots: false,
        });
    }
    if links > 0 {
        warnings.push(format!("{links} symbolic link(s) or junction(s) under {} were not followed", root.display()));
    }
    if unreadable > 0 {
        warnings.push(format!("{unreadable} entries under {} could not be read, so some sizes are understated", root.display()));
    }
}

/// Probe the direct children of a container, and deeper while `level < depth`.
/// Returns `true` when anything at or below matched, so the container is then
/// known to hold build output and is not listed as a gap of its own.
fn probe_below(container: &Path, level: usize, depth: usize, declarations: &[BuildDirDeclaration], output: &mut ProbeOutput) -> bool {
    let mut found = false;
    for child in immediate_dirs(container) {
        if let Some(evidence) = cargo_build_evidence(&child) {
            let bytes = safety::collect_usage(&child).bytes;
            output.measured.entry(safety::path_key(&child)).or_insert(bytes);
            push_match(&child, bytes, evidence, declarations, output);
            found = true;
            continue;
        }
        if level < depth && probe_below(&child, level + 1, depth, declarations, output) {
            found = true;
        }
    }
    found
}

fn uncovered_reason(state: &MarkerState, partial: Option<&BuildDirDeclaration>) -> String {
    if let Some(item) = partial {
        return format!("only part of this directory is declared: {}", declaring_source(item));
    }
    match (state.tag.is_some(), state.has_cargo_marker()) {
        (true, false) => format!("{TAG_NAME} alone is not enough: a Cargo-specific marker is missing"),
        (false, true) => "a Cargo-specific marker exists but CACHEDIR.TAG is missing, so the rule does not apply".to_string(),
        _ => "neither CACHEDIR.TAG nor a Cargo-specific marker at this directory, so it is listed because of its size only (output below the probe depth is not inspected)".to_string(),
    }
}

/// Read the separate build-root config only to compare it, never to merge it.
fn build_root_declarations(config: Option<&Path>, warnings: &mut Vec<String>) -> (Vec<crate::anchors::BuildRootDeclaration>, Option<String>) {
    let Some(path) = config.map(Path::to_path_buf)
    else {
        warnings.push("no build-root config path, so the separate source cannot be compared".to_string());
        return (Vec::new(), None);
    };
    match fs::read_to_string(&path) {
        Ok(text) => {
            let parsed = crate::anchors::parse_build_root_config(&text, &path.display().to_string());
            (parsed.declarations, Some(parsed.config_path))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            warnings.push(format!("build-root config not found, nothing to compare: {}", path.display()));
            (Vec::new(), None)
        }
        Err(error) => {
            warnings.push(format!("cannot read build-root config {}: {error}", path.display()));
            (Vec::new(), None)
        }
    }
}

fn compare_build_roots(
    declarations: Vec<crate::anchors::BuildRootDeclaration>,
    matches: &mut [BuildOutputMatch],
    measured: &BTreeMap<String, u64>,
) -> Vec<BuildRootOverlap> {
    let mut overlaps = Vec::new();
    for declaration in declarations {
        let declared = PathBuf::from(&declaration.path);
        let exists = declared.is_dir();
        let bytes = measured.get(&safety::path_key(&declared)).copied();
        let covers = matches.iter().filter(|item| safety::is_within(&declared, Path::new(&item.path))).count();
        let inside = matches.iter().any(|item| safety::is_within(Path::new(&item.path), &declared));
        if covers > 0 {
            for item in matches.iter_mut().filter(|item| safety::is_within(&declared, Path::new(&item.path))) {
                item.also_in_build_roots = true;
            }
        }
        let note = if covers > 0 {
            format!("{covers} marker match(es) inside this declared path are already counted by build-roots")
        }
        else if inside {
            "a marker match contains this declared path, so the overlap is partial and not subtracted".to_string()
        }
        else if bytes.is_none() {
            "no marker match, and the path lies outside every probe root so it was not measured here".to_string()
        }
        else {
            "no marker match".to_string()
        };
        overlaps.push(BuildRootOverlap {
            path: declaration.path,
            line: declaration.line,
            exists,
            bytes,
            matched_by_markers: covers > 0 || inside,
            note,
        });
    }
    overlaps
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
        build_dir_report(BuildDirOptions { cwd: Some(cwd.display().to_string()), ..BuildDirOptions::default() }, &env, dirs, None).unwrap()
    }

    fn probe_report(root: &Path, config: Option<&Path>, options: BuildDirOptions) -> BuildDirReport {
        let options = BuildDirOptions { cwd: Some(root.display().to_string()), roots: vec![root.display().to_string()], ..options };
        build_dir_report(options, &no_env, &empty_dirs(), config).unwrap()
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

    fn tag(dir: &Path) {
        write(&dir.join(TAG_NAME), "Signature: 8a477f597d28d172789f06886806bc55");
    }

    #[test]
    fn the_tag_alone_is_never_enough_and_a_cargo_marker_alone_is_never_enough() {
        let root = synthetic_root("markers");

        let with_info = root.join("with-info");
        tag(&with_info);
        write(&with_info.join(".rustc_info.json"), "{}");
        write(&with_info.join("blob.bin"), &"x".repeat(4096));

        let with_fingerprint = root.join("with-fingerprint");
        tag(&with_fingerprint);
        write(&with_fingerprint.join("release").join(FINGERPRINT_DIR).join("sample"), "x");

        let tag_only = root.join("tag-only");
        tag(&tag_only);
        write(&tag_only.join("blob.bin"), &"x".repeat(4096));

        let marker_only = root.join("marker-only");
        write(&marker_only.join(".rustc_info.json"), "{}");
        write(&marker_only.join("blob.bin"), &"x".repeat(4096));

        let quiet = root.join("quiet-empty");
        fs::create_dir_all(&quiet).unwrap();

        let report = probe_report(&root, None, BuildDirOptions { min_bytes: 1, ..BuildDirOptions::default() });

        let matched: Vec<&str> = report.matches.iter().map(|item| item.path.as_str()).collect();
        assert!(matched.contains(&with_info.display().to_string().as_str()), "tag plus .rustc_info.json must match");
        assert!(matched.contains(&with_fingerprint.display().to_string().as_str()), "tag plus */release/.fingerprint must match");
        assert!(!matched.contains(&tag_only.display().to_string().as_str()), "CACHEDIR.TAG is written by other tools too");
        assert!(!matched.contains(&marker_only.display().to_string().as_str()), "a Cargo marker without the tag is not a proof");
        assert!(report.matches.iter().all(|item| item.attribution == MatchAttribution::CargoMarkers));

        let evidence = &report.matches.iter().find(|item| item.path == with_info.display().to_string()).unwrap().evidence;
        assert!(evidence.iter().any(|value| value.ends_with(TAG_NAME)), "{evidence:?}");
        assert!(evidence.iter().any(|value| value.ends_with("rustc_info.json")), "{evidence:?}");
        assert!(evidence.iter().all(|value| Path::new(value).is_absolute()), "{evidence:?}");

        let uncovered = report.uncovered.iter().find(|item| item.path == tag_only.display().to_string()).unwrap();
        assert!(uncovered.reason.contains("CACHEDIR.TAG alone is not enough"), "{}", uncovered.reason);
        assert!(uncovered.evidence.iter().any(|value| value.ends_with(TAG_NAME)));
        assert_eq!(uncovered.bytes, 4096 + "Signature: 8a477f597d28d172789f06886806bc55".len() as u64);

        let marker = report.uncovered.iter().find(|item| item.path == marker_only.display().to_string()).unwrap();
        assert!(marker.reason.contains("CACHEDIR.TAG is missing"), "{}", marker.reason);
        assert!(!report.uncovered.iter().any(|item| item.path == quiet.display().to_string()));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_match_is_never_descended_into_so_inner_directories_are_not_reported_twice() {
        let root = synthetic_root("nested");
        let container = root.join("container");
        let inner = container.join("inner-output");
        tag(&inner);
        write(&inner.join(".rustc_info.json"), "{}");
        write(&inner.join("blob.bin"), &"x".repeat(4096));
        let deeper = inner.join("debug");
        write(&deeper.join(FINGERPRINT_DIR).join("sample"), "x");
        write(&deeper.join("blob.bin"), &"x".repeat(4096));

        let report = probe_report(&root, None, BuildDirOptions { min_bytes: 1, ..BuildDirOptions::default() });

        assert_eq!(report.matches.len(), 1, "one match only: {:?}", report.matches.iter().map(|item| &item.path).collect::<Vec<_>>());
        assert_eq!(report.matches[0].path, inner.display().to_string());
        assert!(!report.matches.iter().any(|item| item.path == deeper.display().to_string()));
        assert!(!report.uncovered.iter().any(|item| item.path == container.display().to_string()));
        assert_eq!(report.matched_bytes, report.matches[0].bytes);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_same_directory_found_under_two_roots_is_counted_once() {
        let root = synthetic_root("dedupe");
        let output = root.join("same-output");
        tag(&output);
        write(&output.join(".rustc_info.json"), "{}");
        write(&output.join("blob.bin"), &"x".repeat(4096));

        let options = BuildDirOptions {
            roots: vec![root.display().to_string(), root.display().to_string(), output.display().to_string()],
            min_bytes: 1,
            ..BuildDirOptions::default()
        };
        let report =
            build_dir_report(BuildDirOptions { cwd: Some(root.display().to_string()), ..options }, &no_env, &empty_dirs(), None).unwrap();

        assert_eq!(report.matches.len(), 1);
        assert_eq!(report.matched_bytes, report.matches[0].bytes);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_declaration_that_covers_a_match_is_named_in_the_entry() {
        let root = synthetic_root("covered");
        let output = root.join("declared-output");
        tag(&output);
        write(&output.join(".rustc_info.json"), "{}");
        write(&output.join("blob.bin"), &"x".repeat(4096));
        write(&root.join(".cargo").join("config.toml"), &format!("[build]\ntarget-dir = '{}'\n", output.display()));

        let report = probe_report(&root, None, BuildDirOptions { min_bytes: 1, ..BuildDirOptions::default() });

        let entry = &report.matches[0];
        let source = entry.covered_by_declaration.as_deref().unwrap();
        assert!(source.contains(ENV_KEY) || source.contains(".cargo"), "{source}");
        assert!(source.contains(&output.display().to_string()), "{source}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_proven_directory_inside_a_refused_location_is_reported_as_rejected() {
        assert!(refusal(Path::new(r"C:\")).is_some());
        assert!(refusal(Path::new(r"C:\Windows\sample")).is_some());

        let mut output = ProbeOutput::default();
        let evidence = vec![PathBuf::from(r"C:\Windows\sample").join(TAG_NAME)];
        push_match(Path::new(r"C:\Windows\sample"), 1, evidence, &[], &mut output);
        assert!(output.matches.is_empty());
        assert_eq!(output.rejected.len(), 1);
        assert!(output.rejected[0].reason.contains("system"));
    }

    #[test]
    fn a_directory_holding_a_declaration_is_still_reported_as_uncovered() {
        let root = synthetic_root("partial");
        let parent = root.join("parent-output");
        fs::create_dir_all(parent.join("nested")).unwrap();
        write(&parent.join("blob.bin"), &"x".repeat(4096));
        write(&root.join(".cargo").join("config.toml"), &format!("[build]\ntarget-dir = '{}'\n", parent.join("nested").display()));

        let report = probe_report(&root, None, BuildDirOptions { min_bytes: 1, ..BuildDirOptions::default() });

        let entry = report.uncovered.iter().find(|item| item.path == parent.display().to_string()).unwrap();
        assert!(entry.reason.contains("only part of this directory is declared"), "{}", entry.reason);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_build_root_entry_already_counted_elsewhere_is_not_counted_twice() {
        let root = synthetic_root("overlap");
        let shared = root.join("shared-output");
        tag(&shared);
        write(&shared.join(".rustc_info.json"), "{}");
        write(&shared.join("blob.bin"), &"x".repeat(4096));
        let other = root.join("other-output");
        tag(&other);
        write(&other.join(".rustc_info.json"), "{}");
        write(&other.join("blob.bin"), &"x".repeat(2048));

        let config = root.join("build-roots.conf");
        let gap = root.join("large-gap");
        write(&gap.join("blob.bin"), &"x".repeat(8192));
        write(&config, &format!("# shared build outputs\n{}\n{}\n{}\n", shared.display(), root.join("absent").display(), gap.display()));

        let report = probe_report(&root, Some(&config), BuildDirOptions { min_bytes: 1, ..BuildDirOptions::default() });

        assert_eq!(report.build_root_config.as_deref(), Some(config.display().to_string().as_str()));
        assert_eq!(report.matches.len(), 2);
        assert!(report.matches.iter().find(|item| item.path == shared.display().to_string()).unwrap().also_in_build_roots);
        assert!(!report.matches.iter().find(|item| item.path == other.display().to_string()).unwrap().also_in_build_roots);

        let shared_bytes = report.matches.iter().find(|item| item.path == shared.display().to_string()).unwrap().bytes;
        assert_eq!(
            report.matched_bytes,
            shared_bytes + report.matches.iter().find(|item| item.path == other.display().to_string()).unwrap().bytes
        );
        assert_eq!(report.matched_bytes_in_build_roots, shared_bytes);
        assert_eq!(report.unique_matched_bytes, report.matched_bytes - shared_bytes);

        let declared: Vec<&BuildRootOverlap> = report.build_roots.iter().collect();
        assert_eq!(declared.len(), 3);
        assert_eq!(declared[0].line, 2);
        assert!(declared[0].matched_by_markers);
        assert!(declared[0].bytes.is_some(), "a declared path inside a probe root is measured");
        assert!(declared[0].note.contains("already counted by build-roots"));
        assert!(!declared[1].exists);
        assert!(!declared[1].matched_by_markers);
        assert!(declared[1].bytes.is_none());

        let gap_entry = report.uncovered.iter().find(|item| item.path == gap.display().to_string()).unwrap();
        assert!(gap_entry.also_in_build_roots, "a build-roots declaration must be visible on the gap entry");
        assert!(!report.uncovered.iter().any(|item| item.path == shared.display().to_string()));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn depth_one_only_inspects_the_direct_children_of_a_root() {
        let root = synthetic_root("depth");
        let container = root.join("container");
        let inner = container.join("inner-output");
        tag(&inner);
        write(&inner.join(".rustc_info.json"), "{}");

        let report = probe_report(&root, None, BuildDirOptions { min_bytes: 1, depth: 1, ..BuildDirOptions::default() });

        assert!(report.matches.is_empty(), "depth 1 must not look below a root's children");
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
