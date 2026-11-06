//! Developer artifact cleanup domain.
//!
//! Pipeline: manifest-anchored scan → dry-run plan → explicit clean. No
//! candidate is ever derived from a bare directory name.

mod global;
pub mod rules;
mod trash;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    locations::{BaseDirs, base_dirs},
    platform,
};

use self::rules::{Ecosystem, ManifestKind, ProjectRule};

/// Default cleanup workers. Serial on purpose: on a local volume the metadata
/// work of deletion is already serialized, and parallel measurement of one
/// artifact interleaving with deletion of another measured slower at every
/// worker count above one. High-latency volumes can opt in via `concurrency`.
const DEFAULT_CLEAN_CONCURRENCY: usize = 1;
/// Upper bound for a caller-supplied worker count.
const MAX_CLEAN_CONCURRENCY: usize = 8;
/// Parent-directory lock stripes. Siblings hash to one stripe and serialize.
const PARENT_STRIPES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskLevel {
    /// Level 1: project-local, rebuildable without downloading.
    ProjectLocal,
    /// Level 2: global cache; rebuildable but requires network again.
    GlobalCache,
}

impl RiskLevel {
    pub const fn level(self) -> u8 {
        match self {
            Self::ProjectLocal => 1,
            Self::GlobalCache => 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevStageTiming {
    pub name: String,
    pub elapsed_ms: f64,
}

/// Opt-in cleanup measurements. Absent unless `OPEN_CLEANER_PROFILE` is set to
/// a non-empty value other than `0`, so normal runs pay no measurement cost.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DevProfile {
    pub stages: Vec<DevStageTiming>,
    pub dirs_visited: u64,
    pub files_visited: u64,
    pub bytes_measured: u64,
    pub peak_working_set_bytes: Option<u64>,
    pub peak_handle_count: Option<u32>,
}

impl DevProfile {
    fn add(&mut self, name: &str, elapsed: Duration) {
        self.stages.push(DevStageTiming { name: name.to_string(), elapsed_ms: elapsed.as_secs_f64() * 1000.0 });
    }

    fn sample_peak(&mut self) {
        let (working_set, handles) = platform::process_peak_usage();
        if let Some(bytes) = working_set {
            self.peak_working_set_bytes = Some(self.peak_working_set_bytes.unwrap_or(0).max(bytes));
        }
        if let Some(count) = handles {
            self.peak_handle_count = Some(self.peak_handle_count.unwrap_or(0).max(count));
        }
    }
}

fn profiling_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("OPEN_CLEANER_PROFILE").is_ok_and(|value| !value.is_empty() && value != "0"))
}

#[derive(Debug, Clone, Default)]
struct ScanProfile {
    walk: Duration,
    measure: Duration,
    dirs: u64,
    files: u64,
    bytes: u64,
}

#[derive(Debug, Clone, Default)]
struct SizeStats {
    bytes: u64,
    dirs: u64,
    files: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DevScanOptions {
    /// Directories searched for projects. Empty = current working directory.
    pub roots: Vec<String>,
    /// Include level-2 global caches (requires an anchor in the scanned roots).
    pub include_global: bool,
    pub max_depth: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevArtifact {
    pub path: String,
    pub bytes: u64,
    pub level: u8,
    pub risk: RiskLevel,
    pub ecosystem: Ecosystem,
    /// Why this path is a candidate, e.g. `Cargo.toml → target/`.
    pub rule: String,
    /// The manifest anchor that justified the hit.
    pub anchor: String,
    /// Owning project root for level 1; `None` for global caches.
    pub project_root: Option<String>,
    pub volume: Option<String>,
    /// The artifact lives on a different volume than its anchor/scan root.
    pub cross_volume: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevScanReport {
    pub roots: Vec<String>,
    pub scanned_projects: usize,
    pub anchors: Vec<String>,
    pub artifacts: Vec<DevArtifact>,
    pub warnings: Vec<String>,
    pub scanned_at_unix_ms: u64,
    pub profile: Option<DevProfile>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeleteMode {
    Trash,
    Permanent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SkipReason {
    SymlinkNotFollowed,
    ProtectedPath,
    ManifestMissing,
    RuleMismatch,
    NotFound,
    NotADirectory,
    InUseOrLocked,
}

impl SkipReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SymlinkNotFollowed => "symlink-not-followed",
            Self::ProtectedPath => "protected-path",
            Self::ManifestMissing => "manifest-missing",
            Self::RuleMismatch => "rule-mismatch",
            Self::NotFound => "not-found",
            Self::NotADirectory => "not-a-directory",
            Self::InUseOrLocked => "in-use-or-locked",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevPlanItem {
    pub artifact: DevArtifact,
    pub removable: bool,
    pub skip_reason: Option<SkipReason>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevPlan {
    pub roots: Vec<String>,
    pub mode: DeleteMode,
    /// False when the requested mode cannot run on this platform/build. The
    /// plan stays inspectable; execution must fail instead of downgrading.
    pub mode_supported: bool,
    pub items: Vec<DevPlanItem>,
    pub total_bytes: u64,
    pub removable_bytes: u64,
    pub skipped_bytes: u64,
    pub warnings: Vec<String>,
    pub scanned_at_unix_ms: u64,
    pub profile: Option<DevProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevCleanOptions {
    /// Paths taken from a dry-run plan. They are re-validated against the
    /// filesystem before anything is deleted.
    pub paths: Vec<String>,
    pub mode: DeleteMode,
    pub confirm: bool,
    /// Cleanup workers. Defaults to 1 (serial) and is clamped to 1..=8. Values
    /// above 1 only help when probe latency dominates a slow volume.
    #[serde(default)]
    pub concurrency: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CleanStatus {
    Deleted,
    Trashed,
    Skipped,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevCleanItem {
    pub path: String,
    pub bytes: u64,
    pub status: CleanStatus,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevCleanReport {
    pub mode: DeleteMode,
    /// True only when the requested mode was available and `confirm` was set.
    pub executed: bool,
    pub items: Vec<DevCleanItem>,
    pub freed_bytes: u64,
    pub warnings: Vec<String>,
    pub profile: Option<DevProfile>,
}

pub fn dev_scan(options: DevScanOptions) -> Result<DevScanReport> {
    dev_scan_with(options, &base_dirs())
}

pub fn dev_plan(options: DevScanOptions, mode: DeleteMode) -> Result<DevPlan> {
    let dirs = base_dirs();
    let mut report = dev_scan_with(options, &dirs)?;
    let mut warnings = report.warnings.clone();
    let mode_supported = match mode {
        DeleteMode::Permanent => true,
        DeleteMode::Trash => trash::supported(),
    };
    if !mode_supported {
        warnings.push(format!("recycle bin is unavailable on {}; this plan can only be executed with permanent deletion", platform::name()));
    }

    let mut profile = report.profile.take();
    let analysis_start = profile.as_ref().map(|_| Instant::now());
    let mut items = Vec::with_capacity(report.artifacts.len());
    for artifact in report.artifacts {
        let skip_reason = evaluate(&artifact, &dirs);
        if let Some(profile) = profile.as_mut()
            && items.len() % 256 == 0
        {
            profile.sample_peak();
        }
        items.push(DevPlanItem { removable: skip_reason.is_none(), artifact, skip_reason });
    }
    if let (Some(profile), Some(start)) = (profile.as_mut(), analysis_start) {
        profile.add("analysis", start.elapsed());
        profile.sample_peak();
    }

    let total_bytes: u64 = items.iter().map(|item| item.artifact.bytes).sum();
    let removable_bytes: u64 = items.iter().filter(|item| item.removable).map(|item| item.artifact.bytes).sum();
    let skipped_bytes = total_bytes.saturating_sub(removable_bytes);

    let volumes: BTreeSet<String> = items.iter().filter_map(|item| item.artifact.volume.clone()).collect();
    if volumes.len() > 1 {
        warnings.push(format!("candidates span multiple volumes: {}", volumes.into_iter().collect::<Vec<_>>().join(", ")));
    }
    if mode == DeleteMode::Trash {
        warnings.push("recycle bins are per volume; each moved item goes to the bin on its own volume".to_string());
    }

    Ok(DevPlan {
        roots: report.roots,
        mode,
        mode_supported,
        items,
        total_bytes,
        removable_bytes,
        skipped_bytes,
        warnings,
        scanned_at_unix_ms: report.scanned_at_unix_ms,
        profile,
    })
}

pub fn dev_clean(options: DevCleanOptions) -> Result<DevCleanReport> {
    if !options.confirm {
        return Err(Error::Message("dev clean requires explicit confirmation (confirm=true)".to_string()));
    }
    if options.mode == DeleteMode::Trash && !trash::supported() {
        return Err(Error::not_implemented("dev-trash"));
    }

    let dirs = base_dirs();
    let total = options.paths.len();
    let degree = clean_concurrency(options.concurrency).min(total.max(1));

    // Tasks are dispatched dynamically so a single large tree never blocks the
    // remaining work, and siblings under one parent share a stripe so two
    // deletions never race for the same directory handle.
    let cursor = AtomicUsize::new(0);
    let results = Mutex::new(Vec::with_capacity(total));
    let stripes: Vec<Mutex<()>> = (0..PARENT_STRIPES).map(|_| Mutex::new(())).collect();
    let profile_on = profiling_enabled();
    let validate_nanos = AtomicU64::new(0);
    let delete_nanos = AtomicU64::new(0);
    let peak = PeakSample::default();

    std::thread::scope(|scope| {
        for _ in 0..degree {
            scope.spawn(|| {
                let mut outcomes = Vec::new();
                let mut validate = Duration::ZERO;
                let mut delete = Duration::ZERO;
                loop {
                    let index = cursor.fetch_add(1, Ordering::Relaxed);
                    let Some(raw) = options.paths.get(index)
                    else {
                        break;
                    };

                    let path = PathBuf::from(raw);
                    let stripe = &stripes[parent_stripe(&path)];
                    let _stripe_guard = stripe.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

                    // Gates first, then delete. The probe-to-delete window is
                    // one item wide instead of one whole batch.
                    let validate_start = profile_on.then(Instant::now);
                    let artifact = artifact_for_clean(&path, &dirs);
                    let skip = artifact.as_ref().and_then(|artifact| evaluate(artifact, &dirs));
                    if let Some(start) = validate_start {
                        validate += start.elapsed();
                    }

                    let Some(artifact) = artifact
                    else {
                        outcomes.push(CleanOutcome {
                            index,
                            item: DevCleanItem {
                                path: raw.clone(),
                                bytes: 0,
                                status: CleanStatus::Skipped,
                                reason: Some("unverified-path".to_string()),
                            },
                            warning: None,
                        });
                        peak.sample();
                        continue;
                    };
                    if let Some(reason) = skip {
                        outcomes.push(CleanOutcome {
                            index,
                            item: DevCleanItem {
                                path: raw.clone(),
                                bytes: artifact.bytes,
                                status: CleanStatus::Skipped,
                                reason: Some(reason.as_str().to_string()),
                            },
                            warning: None,
                        });
                        peak.sample();
                        continue;
                    }

                    let delete_start = profile_on.then(Instant::now);
                    let result = match options.mode {
                        DeleteMode::Trash => trash::trash_path(&path).map(|()| CleanStatus::Trashed),
                        DeleteMode::Permanent => trash::remove_permanently(&path).map(|()| CleanStatus::Deleted),
                    };
                    if let Some(start) = delete_start {
                        delete += start.elapsed();
                    }

                    // One failing item never stops the batch and is always
                    // reported individually.
                    let (status, reason, warning) = match result {
                        Ok(status) if !path.exists() => (status, None, None),
                        Ok(_) => (CleanStatus::Failed, Some("path still exists after deletion".to_string()), None),
                        Err(err) => (CleanStatus::Failed, Some(err.to_string()), Some(format!("{raw}: {err}"))),
                    };
                    outcomes.push(CleanOutcome {
                        index,
                        item: DevCleanItem { path: raw.clone(), bytes: artifact.bytes, status, reason },
                        warning,
                    });
                    peak.sample();
                }

                results.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).extend(outcomes);
                validate_nanos.fetch_add(validate.as_nanos().min(u64::MAX as u128) as u64, Ordering::Relaxed);
                delete_nanos.fetch_add(delete.as_nanos().min(u64::MAX as u128) as u64, Ordering::Relaxed);
            });
        }
    });

    let mut outcomes = results.into_inner().unwrap_or_else(|poisoned| poisoned.into_inner());
    outcomes.sort_by_key(|outcome| outcome.index);

    let mut warnings = Vec::new();
    for outcome in &outcomes {
        if let Some(warning) = &outcome.warning {
            warnings.push(warning.clone());
        }
    }
    let items: Vec<DevCleanItem> = outcomes.into_iter().map(|outcome| outcome.item).collect();
    let freed_bytes = items
        .iter()
        .filter(|item| matches!(item.status, CleanStatus::Deleted | CleanStatus::Trashed))
        .map(|item| item.bytes)
        .fold(0u64, u64::saturating_add);

    let mut profile = profile_on.then(DevProfile::default);
    if let Some(profile) = profile.as_mut() {
        profile.add("validate", Duration::from_nanos(validate_nanos.load(Ordering::Relaxed)));
        profile.add("delete", Duration::from_nanos(delete_nanos.load(Ordering::Relaxed)));
        profile.peak_working_set_bytes = peak.working_set();
        profile.peak_handle_count = peak.handles();
    }

    Ok(DevCleanReport { mode: options.mode, executed: true, items, freed_bytes, warnings, profile })
}

struct CleanOutcome {
    index: usize,
    item: DevCleanItem,
    warning: Option<String>,
}

/// Requested worker count, clamped so small or slow volumes are not flooded.
fn clean_concurrency(requested: Option<usize>) -> usize {
    requested.unwrap_or(DEFAULT_CLEAN_CONCURRENCY).clamp(1, MAX_CLEAN_CONCURRENCY)
}

/// Stable shard key for the parent directory of an artifact. Siblings resolve
/// to the same stripe and are serialized, everything else runs in parallel.
fn parent_stripe(path: &Path) -> usize {
    let parent = path.parent().unwrap_or(path);
    (fnv1a(parent.as_os_str().as_encoded_bytes()) % PARENT_STRIPES as u64) as usize
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(byte.to_ascii_lowercase());
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

#[derive(Default)]
struct PeakSample {
    working_set: AtomicU64,
    handles: AtomicU32,
}

impl PeakSample {
    fn sample(&self) {
        let (working_set, handles) = platform::process_peak_usage();
        if let Some(bytes) = working_set {
            self.working_set.fetch_max(bytes, Ordering::Relaxed);
        }
        if let Some(count) = handles {
            self.handles.fetch_max(count, Ordering::Relaxed);
        }
    }

    fn working_set(&self) -> Option<u64> {
        match self.working_set.load(Ordering::Relaxed) {
            0 => None,
            bytes => Some(bytes),
        }
    }

    fn handles(&self) -> Option<u32> {
        match self.handles.load(Ordering::Relaxed) {
            0 => None,
            count => Some(count),
        }
    }
}

fn dev_scan_with(options: DevScanOptions, dirs: &BaseDirs) -> Result<DevScanReport> {
    let roots = resolve_roots(&options.roots)?;
    let max_depth = options.max_depth.unwrap_or(5).max(1);

    let mut collector = Collector {
        artifacts: BTreeMap::new(),
        anchors: BTreeSet::new(),
        scanned_projects: 0,
        warnings: Vec::new(),
        dirs,
        root_volume: roots.first().and_then(|root| platform::volume_of(root)),
        profile: profiling_enabled().then(ScanProfile::default),
    };

    for root in &roots {
        collector.walk(root, 0, max_depth);
    }
    if options.include_global {
        collector.collect_global();
    }

    let profile = collector.profile.map(|profile| {
        let mut report =
            DevProfile { dirs_visited: profile.dirs, files_visited: profile.files, bytes_measured: profile.bytes, ..DevProfile::default() };
        report.add("scan", profile.walk);
        report.add("measurement", profile.measure);
        report.sample_peak();
        report
    });

    let mut artifacts: Vec<DevArtifact> = collector.artifacts.into_values().collect();
    artifacts.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));

    let available = artifacts.len();
    let mut warnings = collector.warnings;
    let limit = options.limit.unwrap_or(0);
    if limit > 0 && artifacts.len() > limit {
        artifacts.truncate(limit);
        warnings.push(format!("{available} artifacts found; showing the largest {limit}"));
    }

    Ok(DevScanReport {
        roots: roots.iter().map(|root| root.display().to_string()).collect(),
        scanned_projects: collector.scanned_projects,
        anchors: collector.anchors.iter().map(|kind| kind.id().to_string()).collect(),
        artifacts,
        warnings,
        scanned_at_unix_ms: epoch_millis(),
        profile,
    })
}

struct Collector<'a> {
    artifacts: BTreeMap<String, DevArtifact>,
    anchors: BTreeSet<ManifestKind>,
    scanned_projects: usize,
    warnings: Vec<String>,
    dirs: &'a BaseDirs,
    root_volume: Option<String>,
    profile: Option<ScanProfile>,
}

impl Collector<'_> {
    /// One dive per directory. The listing answers three questions at once:
    /// which anchors live here, which subdirectories exist, and which of them
    /// may be an artifact. Source files that are not manifests are never
    /// stat'ed.
    fn walk(&mut self, dir: &Path, depth: usize, max_depth: usize) {
        let started = self.profile.as_ref().map(|_| Instant::now());
        let mut manifests = BTreeSet::new();
        let mut children: Vec<PathBuf> = Vec::new();
        let mut unreadable = false;

        match fs::read_dir(dir) {
            Ok(read) => {
                for item in read.flatten() {
                    let Ok(file_type) = item.file_type()
                    else {
                        continue;
                    };
                    if file_type.is_dir() {
                        // Reparse points are never descended into.
                        let path = item.path();
                        let Ok(meta) = item.metadata()
                        else {
                            continue;
                        };
                        if !meta.is_dir() || platform::is_link_like(&meta) {
                            continue;
                        }
                        children.push(path);
                    }
                    else if file_type.is_file()
                        && let Some(kind) = ManifestKind::from_os_name(&item.file_name())
                    {
                        manifests.insert(kind);
                    }
                }
            }
            Err(_) => unreadable = true,
        }

        if !manifests.is_empty() {
            self.scanned_projects += 1;
            for manifest in &manifests {
                self.anchors.insert(*manifest);
                for rule in rules::project_rules(*manifest) {
                    self.add_project_artifact(dir, &children, rule);
                }
            }
        }

        if unreadable {
            self.warnings.push(format!("cannot read {}; subtree skipped", dir.display()));
        }
        if depth < max_depth {
            for child in &children {
                let Some(name) = child.file_name()
                else {
                    continue;
                };
                if rules::should_skip_descend(name) {
                    continue;
                }
                self.walk(child, depth + 1, max_depth);
            }
        }

        if let (Some(profile), Some(start)) = (self.profile.as_mut(), started) {
            profile.walk += start.elapsed();
            profile.dirs += 1;
        }
    }

    fn add_project_artifact(&mut self, root: &Path, children: &[PathBuf], rule: &'static ProjectRule) {
        let mut parts = rule.artifact.split('/');
        let first = parts.next().unwrap_or(rule.artifact);
        let path = if parts.next().is_some() {
            rules::artifact_path(root, rule.artifact)
        }
        else {
            let Some(child) = children.iter().find(|child| child.file_name().is_some_and(|name| os_eq_ignore_ascii(name, first)))
            else {
                return;
            };
            child.clone()
        };

        let Ok(meta) = fs::symlink_metadata(&path)
        else {
            return;
        };
        if !meta.is_dir() || platform::is_link_like(&meta) {
            return;
        }
        if rules::is_protected(&path) {
            return;
        }
        let key = path.to_string_lossy().to_ascii_lowercase();
        if self.artifacts.contains_key(&key) {
            return;
        }

        let mut warnings = Vec::new();
        let stats = self.measure(&path, &mut warnings);
        let bytes = stats.bytes;
        let volume = platform::volume_of(&path);
        let root_volume = platform::volume_of(root);
        let cross_volume = match (&volume, &root_volume) {
            (Some(a), Some(b)) => a != b,
            _ => false,
        };
        let artifact = DevArtifact {
            path: path.display().to_string(),
            bytes,
            level: 1,
            risk: RiskLevel::ProjectLocal,
            ecosystem: rule.ecosystem,
            rule: format!("{} → {}/", rule.anchor.id(), rule.artifact),
            anchor: rule.anchor.id().to_string(),
            project_root: Some(root.display().to_string()),
            volume,
            cross_volume,
            warnings,
        };
        self.artifacts.insert(key, artifact);
    }

    /// Size one artifact subtree in a single dive. Every artifact found during
    /// the walk is measured exactly once, and the measurement is not skipped
    /// for subtrees that did not become candidates.
    fn measure(&mut self, path: &Path, warnings: &mut Vec<String>) -> SizeStats {
        let started = self.profile.as_ref().map(|_| Instant::now());
        let stats = dir_size(path, warnings);
        if let (Some(profile), Some(start)) = (self.profile.as_mut(), started) {
            profile.measure += start.elapsed();
            profile.dirs += stats.dirs;
            profile.files += stats.files;
            profile.bytes += stats.bytes;
        }
        stats
    }

    fn collect_global(&mut self) {
        let specs = global::specs(self.dirs);
        for spec in specs {
            if !self.anchors.contains(&spec.anchor) {
                continue;
            }
            let Ok(meta) = fs::symlink_metadata(&spec.path)
            else {
                continue;
            };
            if !meta.is_dir() || platform::is_link_like(&meta) {
                continue;
            }
            let key = spec.path.to_string_lossy().to_ascii_lowercase();
            if self.artifacts.contains_key(&key) {
                continue;
            }
            let mut warnings = Vec::new();
            let stats = self.measure(&spec.path, &mut warnings);
            let bytes = stats.bytes;
            let volume = platform::volume_of(&spec.path);
            let cross_volume = match (&volume, &self.root_volume) {
                (Some(a), Some(b)) => a != b,
                _ => false,
            };
            let artifact = DevArtifact {
                path: spec.path.display().to_string(),
                bytes,
                level: 2,
                risk: RiskLevel::GlobalCache,
                ecosystem: spec.ecosystem,
                rule: spec.rule.to_string(),
                anchor: spec.anchor.id().to_string(),
                project_root: None,
                volume,
                cross_volume,
                warnings,
            };
            self.artifacts.insert(key, artifact);
        }
    }
}

fn os_eq_ignore_ascii(name: &std::ffi::OsStr, expected: &str) -> bool {
    match name.to_str() {
        Some(text) => text.eq_ignore_ascii_case(expected),
        None => name.to_string_lossy().eq_ignore_ascii_case(expected),
    }
}

fn resolve_roots(input: &[String]) -> Result<Vec<PathBuf>> {
    let candidates: Vec<PathBuf> = if input.is_empty() {
        vec![std::env::current_dir().map_err(|source| Error::Io { path: ".".to_string(), source })?]
    }
    else {
        input.iter().map(PathBuf::from).collect()
    };

    let mut roots: Vec<PathBuf> = Vec::new();
    for candidate in candidates {
        if !candidate.exists() {
            return Err(Error::Message(format!("scan root does not exist: {}", candidate.display())));
        }
        let absolute = std::path::absolute(&candidate).map_err(|source| Error::Io { path: candidate.display().to_string(), source })?;
        if !absolute.is_dir() {
            return Err(Error::Message(format!("scan root is not a directory: {}", absolute.display())));
        }
        let key = absolute.to_string_lossy().to_ascii_lowercase();
        if !roots.iter().any(|root| root.to_string_lossy().to_ascii_lowercase() == key) {
            roots.push(absolute);
        }
    }
    Ok(roots)
}

fn evaluate(artifact: &DevArtifact, dirs: &BaseDirs) -> Option<SkipReason> {
    let path = Path::new(&artifact.path);
    if rules::is_protected(path) || is_base_dir(path, dirs) {
        return Some(SkipReason::ProtectedPath);
    }
    let Ok(meta) = fs::symlink_metadata(path)
    else {
        return Some(SkipReason::NotFound);
    };
    if platform::is_link_like(&meta) || meta.file_type().is_symlink() {
        return Some(SkipReason::SymlinkNotFollowed);
    }
    if !meta.is_dir() {
        return Some(SkipReason::NotADirectory);
    }

    if artifact.level == 1 {
        let matched = rules::match_rule_suffix(path);
        let Some((rule, root)) = matched
        else {
            return Some(SkipReason::RuleMismatch);
        };
        let manifests = rules::detect_manifests(&root);
        if !manifests.contains(&rule.anchor) {
            return Some(SkipReason::ManifestMissing);
        }
    }
    else {
        let specs = global::specs(dirs);
        let ecosystem = artifact.ecosystem;
        if !specs.iter().any(|spec| spec.path == path && spec.ecosystem == ecosystem) {
            return Some(SkipReason::RuleMismatch);
        }
    }

    if probe_in_use(path) {
        return Some(SkipReason::InUseOrLocked);
    }
    None
}

fn is_base_dir(path: &Path, dirs: &BaseDirs) -> bool {
    [
        dirs.home.as_ref(),
        dirs.local_app_data.as_ref(),
        dirs.app_data.as_ref(),
        dirs.program_data.as_ref(),
        dirs.program_files.as_ref(),
        dirs.cache_dir.as_ref(),
        dirs.data_dir.as_ref(),
        dirs.cargo_home.as_ref(),
    ]
    .into_iter()
    .flatten()
    .any(|dir| paths_equal(path, dir))
}

fn paths_equal(a: &Path, b: &Path) -> bool {
    a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy())
}

/// Rename probe: an occupied or locked directory cannot be renamed on Windows.
/// The original name is restored immediately; the probe never deletes data.
fn probe_in_use(path: &Path) -> bool {
    let Some(parent) = path.parent()
    else {
        return true;
    };
    let Some(name) = path.file_name()
    else {
        return true;
    };
    let probe = parent.join(format!(".{}.open-cleaner-probe", name.to_string_lossy()));
    if probe.exists() {
        return true;
    }
    if fs::rename(path, &probe).is_err() {
        return true;
    }
    fs::rename(&probe, path).is_err()
}

fn artifact_for_clean(path: &Path, dirs: &BaseDirs) -> Option<DevArtifact> {
    if !path.is_absolute() {
        return None;
    }
    if let Some((rule, root)) = rules::resolve_project_artifact(path) {
        let mut warnings = Vec::new();
        let bytes = dir_size(path, &mut warnings).bytes;
        let volume = platform::volume_of(path);
        let root_volume = platform::volume_of(&root);
        let cross_volume = match (&volume, &root_volume) {
            (Some(a), Some(b)) => a != b,
            _ => false,
        };
        return Some(DevArtifact {
            path: path.display().to_string(),
            bytes,
            level: 1,
            risk: RiskLevel::ProjectLocal,
            ecosystem: rule.ecosystem,
            rule: format!("{} → {}/", rule.anchor.id(), rule.artifact),
            anchor: rule.anchor.id().to_string(),
            project_root: Some(root.display().to_string()),
            volume,
            cross_volume,
            warnings,
        });
    }

    let specs = global::specs(dirs);
    let spec = specs.iter().find(|spec| spec.path == path)?;
    let mut warnings = Vec::new();
    let bytes = dir_size(path, &mut warnings).bytes;
    Some(DevArtifact {
        path: path.display().to_string(),
        bytes,
        level: 2,
        risk: RiskLevel::GlobalCache,
        ecosystem: spec.ecosystem,
        rule: spec.rule.to_string(),
        anchor: spec.anchor.id().to_string(),
        project_root: None,
        volume: platform::volume_of(path),
        cross_volume: false,
        warnings,
    })
}

fn dir_size(path: &Path, warnings: &mut Vec<String>) -> SizeStats {
    let mut stats = SizeStats::default();
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        stats.dirs += 1;
        let Ok(read) = fs::read_dir(&dir)
        else {
            if warnings.len() < 8 {
                warnings.push(format!("cannot read {}; size may be incomplete", dir.display()));
            }
            continue;
        };
        for item in read.flatten() {
            // `DirEntry::metadata` does not follow symlinks and reuses the
            // attributes already carried by the directory listing, so measured
            // files cost no extra path allocation or stat on Windows.
            let Ok(meta) = item.metadata()
            else {
                continue;
            };
            if platform::is_link_like(&meta) {
                continue;
            }
            if meta.is_dir() {
                stack.push(item.path());
            }
            else if meta.is_file() {
                stats.files += 1;
                stats.bytes = stats.bytes.saturating_add(meta.len());
            }
        }
    }
    stats
}

fn epoch_millis() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::{io::Write, sync::Mutex};

    use super::*;

    /// Serialize tests that touch the process environment or shared fixture
    /// roots; `cargo test` runs them in parallel otherwise.
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn fixture(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("open-cleaner-dev-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn touch(path: &Path, bytes: usize) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut file = fs::File::create(path).unwrap();
        file.write_all(&vec![0u8; bytes]).unwrap();
    }

    fn base(root: &Path) -> BaseDirs {
        BaseDirs {
            home: Some(root.join("home")),
            local_app_data: Some(root.join("local")),
            app_data: Some(root.join("roaming")),
            program_data: None,
            program_files: None,
            cache_dir: Some(root.join("cache")),
            data_dir: Some(root.join("data")),
            cargo_home: Some(root.join("home").join(".cargo")),
        }
    }

    #[test]
    fn scan_uses_manifest_anchors_and_ignores_bare_names() {
        let _guard = FIXTURE_LOCK.lock().unwrap();
        let root = fixture("scan");

        // Anchored Cargo project with target.
        touch(&root.join("cargo-app").join("Cargo.toml"), 16);
        touch(&root.join("cargo-app").join("target").join("debug").join("app.bin"), 1024);
        touch(&root.join("cargo-app").join("Cargo.lock"), 32);
        touch(&root.join("cargo-app").join("src").join("main.rs"), 64);
        touch(&root.join("cargo-app").join(".git").join("config"), 8);

        // Anchored node project with several artifacts plus a source tree.
        touch(&root.join("node-app").join("package.json"), 16);
        touch(&root.join("node-app").join("node_modules").join("dep").join("index.js"), 2048);
        touch(&root.join("node-app").join("dist").join("bundle.js"), 512);
        touch(&root.join("node-app").join("src").join("index.js"), 128);

        // Same names without a manifest must be ignored.
        touch(&root.join("fake").join("target").join("data.bin"), 4096);
        touch(&root.join("fake").join("node_modules").join("dep").join("index.js"), 4096);

        let report = dev_scan_with(
            DevScanOptions { roots: vec![root.display().to_string()], include_global: false, max_depth: None, limit: None },
            &base(&root),
        )
        .unwrap();

        let paths: Vec<&str> = report.artifacts.iter().map(|a| a.path.as_str()).collect();
        let target = root.join("cargo-app").join("target").display().to_string();
        let modules = root.join("node-app").join("node_modules").display().to_string();
        let dist = root.join("node-app").join("dist").display().to_string();

        assert!(paths.contains(&target.as_str()), "missing target: {paths:?}");
        assert!(paths.contains(&modules.as_str()), "missing node_modules: {paths:?}");
        assert!(paths.contains(&dist.as_str()), "missing dist: {paths:?}");
        assert!(!paths.iter().any(|path| path.contains("fake")), "bare names must not be candidates: {paths:?}");
        assert!(!paths.iter().any(|path| path.contains("src")), "sources must not be candidates: {paths:?}");
        assert!(!paths.iter().any(|path| path.contains(".git")), ".git must not be candidates: {paths:?}");
        assert!(!paths.iter().any(|path| path.contains("Cargo.lock")), "lockfiles must not be candidates: {paths:?}");

        let target_entry = report.artifacts.iter().find(|a| a.path == target).unwrap();
        assert_eq!(target_entry.bytes, 1024);
        assert_eq!(target_entry.level, 1);
        assert_eq!(target_entry.risk, RiskLevel::ProjectLocal);
        assert_eq!(target_entry.ecosystem, Ecosystem::Cargo);
        assert_eq!(target_entry.rule, "Cargo.toml → target/");
        assert_eq!(target_entry.anchor, "Cargo.toml");
        assert_eq!(target_entry.project_root.as_deref(), Some(root.join("cargo-app").display().to_string().as_str()));

        assert_eq!(report.scanned_projects, 2);
        assert_eq!(report.anchors, vec!["Cargo.toml".to_string(), "package.json".to_string()]);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn global_caches_require_an_anchor_and_the_opt_in() {
        let _guard = FIXTURE_LOCK.lock().unwrap();
        let root = fixture("global");
        touch(&root.join("project").join("Cargo.toml"), 16);
        touch(&root.join("home").join(".cargo").join("registry").join("cache").join("a.bin"), 700);

        let dirs = BaseDirs { cargo_home: Some(root.join("home").join(".cargo")), ..BaseDirs::default() };
        let options = DevScanOptions { roots: vec![root.display().to_string()], include_global: true, max_depth: None, limit: None };

        let report = dev_scan_with(options.clone(), &dirs).unwrap();
        let registry = root.join("home").join(".cargo").join("registry").display().to_string();
        assert!(report.artifacts.iter().any(|a| a.path == registry && a.level == 2), "{:?}", report.artifacts);

        let without_anchor =
            DevScanOptions { roots: vec![root.join("home").display().to_string()], include_global: true, max_depth: None, limit: None };
        let report = dev_scan_with(without_anchor, &dirs).unwrap();
        assert!(report.artifacts.is_empty(), "no Cargo.toml means no cargo cache: {:?}", report.artifacts);

        let without_opt_in = DevScanOptions { include_global: false, ..options };
        let report = dev_scan_with(without_opt_in, &dirs).unwrap();
        assert!(report.artifacts.iter().all(|a| a.level == 1));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn plan_reports_missing_manifest_and_protected_paths() {
        let _guard = FIXTURE_LOCK.lock().unwrap();
        let root = fixture("plan-skip");
        touch(&root.join("app").join("Cargo.toml"), 16);
        touch(&root.join("app").join("target").join("a.bin"), 100);
        touch(&root.join("app").join("Cargo.lock"), 10);

        let report = dev_scan_with(
            DevScanOptions { roots: vec![root.display().to_string()], include_global: false, max_depth: None, limit: None },
            &base(&root),
        )
        .unwrap();
        let artifact = report.artifacts.into_iter().find(|a| a.path.contains("target")).unwrap();

        fs::remove_file(root.join("app").join("Cargo.toml")).unwrap();
        let plan = dev_plan_with(report_of(vec![artifact], &root), DeleteMode::Permanent, &base(&root));
        assert_eq!(plan.items[0].skip_reason, Some(SkipReason::ManifestMissing));
        assert!(!plan.items[0].removable);
        assert_eq!(plan.removable_bytes, 0);
        assert_eq!(plan.total_bytes, 100);

        let lockfile = DevArtifact {
            path: root.join("app").join("Cargo.lock").display().to_string(),
            bytes: 10,
            level: 1,
            risk: RiskLevel::ProjectLocal,
            ecosystem: Ecosystem::Cargo,
            rule: "Cargo.toml → target/".to_string(),
            anchor: "Cargo.toml".to_string(),
            project_root: None,
            volume: None,
            cross_volume: false,
            warnings: Vec::new(),
        };
        assert_eq!(evaluate(&lockfile, &base(&root)), Some(SkipReason::ProtectedPath));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn probe_detects_leftover_marker_and_skips() {
        let _guard = FIXTURE_LOCK.lock().unwrap();
        let root = fixture("probe");
        let dir = root.join("target");
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(root.join(".target.open-cleaner-probe")).unwrap();
        assert!(probe_in_use(&dir));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn clean_requires_confirmation_and_rejects_unverified_paths() {
        let _guard = FIXTURE_LOCK.lock().unwrap();
        let root = fixture("clean-guard");
        let source = root.join("app");
        fs::create_dir_all(source.join("target")).unwrap();
        touch(&source.join("target").join("a.bin"), 256);
        touch(&source.join("Cargo.toml"), 8);

        let err = dev_clean(DevCleanOptions {
            paths: vec![source.join("target").display().to_string()],
            mode: DeleteMode::Permanent,
            confirm: false,
            concurrency: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("confirmation"), "{err}");
        assert!(source.join("target").exists(), "dry-run guard must not delete");

        let outside = root.join("outside");
        fs::create_dir_all(&outside).unwrap();
        let report = dev_clean(DevCleanOptions {
            paths: vec![outside.display().to_string()],
            mode: DeleteMode::Permanent,
            confirm: true,
            concurrency: None,
        })
        .unwrap();
        assert_eq!(report.items[0].status, CleanStatus::Skipped);
        assert!(outside.exists(), "unverified path must survive");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn clean_deletes_only_anchored_artifact_and_matches_plan_bytes() {
        let _guard = FIXTURE_LOCK.lock().unwrap();
        let root = fixture("clean");
        touch(&root.join("app").join("Cargo.toml"), 8);
        touch(&root.join("app").join("target").join("debug").join("a.bin"), 300);
        touch(&root.join("app").join("src").join("main.rs"), 32);

        let target = root.join("app").join("target");
        let report = dev_clean(DevCleanOptions {
            paths: vec![target.display().to_string()],
            mode: DeleteMode::Permanent,
            confirm: true,
            concurrency: None,
        })
        .unwrap();

        assert_eq!(report.items.len(), 1);
        assert_eq!(report.items[0].status, CleanStatus::Deleted);
        assert_eq!(report.items[0].bytes, 300);
        assert_eq!(report.freed_bytes, 300);
        assert!(!target.exists());
        assert!(root.join("app").join("src").join("main.rs").exists(), "sources must survive");

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(not(windows))]
    #[test]
    fn trash_mode_fails_explicitly_outside_windows() {
        let err = dev_clean(DevCleanOptions {
            paths: vec![std::env::temp_dir().display().to_string()],
            mode: DeleteMode::Trash,
            confirm: true,
            concurrency: None,
        })
        .unwrap_err();
        assert_eq!(crate::capability_code(&err), Some("not_implemented"), "{err}");
    }

    #[test]
    fn artifact_sizing_covers_nested_content_without_becoming_projects() {
        let _guard = FIXTURE_LOCK.lock().unwrap();
        let root = fixture("sizing");
        let app = root.join("app");
        touch(&app.join("Cargo.toml"), 8);
        touch(&app.join("target").join("debug").join("a.bin"), 512);
        touch(&app.join("target").join("incremental").join("deep").join("b.bin"), 700);
        // A nested project inside an artifact is never discovered, yet its
        // bytes still belong to the parent artifact.
        touch(&app.join("target").join("node_modules").join("dep").join("package.json"), 40);
        touch(&app.join("target").join("node_modules").join("dep").join("index.js"), 1_024);

        let report = dev_scan_with(
            DevScanOptions { roots: vec![root.display().to_string()], include_global: false, max_depth: None, limit: None },
            &base(&root),
        )
        .unwrap();

        assert_eq!(report.artifacts.len(), 1, "only the anchored target may be a candidate: {:?}", report.artifacts);
        assert_eq!(report.scanned_projects, 1, "nested projects must not be discovered");
        let artifact = &report.artifacts[0];
        assert_eq!(artifact.bytes, 512 + 700 + 40 + 1_024);
        assert_eq!(dir_size(Path::new(&artifact.path), &mut Vec::new()).bytes, artifact.bytes);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn concurrent_clean_deletes_every_artifact_and_reports_order() {
        let _guard = FIXTURE_LOCK.lock().unwrap();
        let root = fixture("concurrent-clean");

        let mut paths = Vec::new();
        let mut expected = 0u64;
        for project in 0..8 {
            let app = root.join(format!("app{project}"));
            touch(&app.join("Cargo.toml"), 8);
            for index in 0..5 {
                touch(&app.join("target").join("debug").join(format!("f{index}.bin")), 256);
            }
            paths.push(app.join("target").display().to_string());
            expected += 5 * 256;

            // Two artifacts sharing one parent exercise the sibling stripe.
            touch(&app.join("package.json"), 16);
            touch(&app.join("node_modules").join("dep").join("index.js"), 512);
            touch(&app.join("dist").join("bundle.js"), 128);
            paths.push(app.join("node_modules").display().to_string());
            paths.push(app.join("dist").display().to_string());
            expected += 512 + 128;
        }

        let report =
            dev_clean(DevCleanOptions { paths: paths.clone(), mode: DeleteMode::Permanent, confirm: true, concurrency: Some(4) }).unwrap();

        assert_eq!(report.items.len(), paths.len());
        assert!(report.items.iter().all(|item| item.status == CleanStatus::Deleted), "{:?}", report.items);
        assert_eq!(report.freed_bytes, expected);
        for (index, item) in report.items.iter().enumerate() {
            assert_eq!(item.path, paths[index], "results stay in input order");
            assert!(!Path::new(&item.path).exists(), "{} survived", item.path);
        }

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(windows)]
    #[test]
    fn locked_artifact_is_skipped_and_deleted_once_released() {
        use std::os::windows::fs::OpenOptionsExt;

        let _guard = FIXTURE_LOCK.lock().unwrap();
        let root = fixture("locked");
        let app = root.join("app");
        touch(&app.join("Cargo.toml"), 8);
        touch(&app.join("target").join("debug").join("a.bin"), 256);
        let target = app.join("target");

        let lock = fs::OpenOptions::new().read(true).share_mode(0).open(target.join("debug").join("a.bin")).unwrap();
        let report = dev_clean(DevCleanOptions {
            paths: vec![target.display().to_string()],
            mode: DeleteMode::Permanent,
            confirm: true,
            concurrency: Some(2),
        })
        .unwrap();
        assert_eq!(report.items[0].status, CleanStatus::Skipped);
        assert_eq!(report.items[0].reason.as_deref(), Some("in-use-or-locked"));
        assert!(target.exists(), "an occupied artifact must survive");
        assert_eq!(report.freed_bytes, 0);
        drop(lock);

        let report = dev_clean(DevCleanOptions {
            paths: vec![target.display().to_string()],
            mode: DeleteMode::Permanent,
            confirm: true,
            concurrency: Some(2),
        })
        .unwrap();
        assert_eq!(report.items[0].status, CleanStatus::Deleted);
        assert!(!target.exists());

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(windows)]
    #[test]
    fn symlinked_artifact_is_never_reported_or_deleted() {
        let _guard = FIXTURE_LOCK.lock().unwrap();
        let root = fixture("symlink");
        let store = root.join("store");
        touch(&store.join("data.bin"), 4_096);
        let app = root.join("app");
        touch(&app.join("Cargo.toml"), 8);
        let target = app.join("target");
        if std::os::windows::fs::symlink_dir(&store, &target).is_err() {
            // A host without symlink privilege cannot exercise this gate.
            let _ = fs::remove_dir_all(&root);
            return;
        }

        let report = dev_scan_with(
            DevScanOptions { roots: vec![root.display().to_string()], include_global: false, max_depth: None, limit: None },
            &base(&root),
        )
        .unwrap();
        assert!(report.artifacts.is_empty(), "a linked artifact must not be reported: {:?}", report.artifacts);

        let report = dev_clean(DevCleanOptions {
            paths: vec![target.display().to_string()],
            mode: DeleteMode::Permanent,
            confirm: true,
            concurrency: Some(2),
        })
        .unwrap();
        assert_eq!(report.items[0].status, CleanStatus::Skipped);
        assert_eq!(report.items[0].reason.as_deref(), Some("symlink-not-followed"));
        assert!(target.exists(), "the link itself must survive");
        assert!(store.join("data.bin").exists(), "the link target must survive");

        fs::remove_dir(&target).unwrap();
        let _ = fs::remove_dir_all(&root);
    }

    // Helpers that bypass environment-dependent base dirs.
    fn report_of(artifacts: Vec<DevArtifact>, root: &Path) -> DevScanReport {
        DevScanReport {
            roots: vec![root.display().to_string()],
            scanned_projects: 1,
            anchors: vec!["Cargo.toml".to_string()],
            artifacts,
            warnings: Vec::new(),
            scanned_at_unix_ms: 0,
            profile: None,
        }
    }

    fn dev_plan_with(report: DevScanReport, mode: DeleteMode, dirs: &BaseDirs) -> DevPlan {
        let mut items = Vec::new();
        for artifact in report.artifacts {
            let skip_reason = evaluate(&artifact, dirs);
            items.push(DevPlanItem { removable: skip_reason.is_none(), artifact, skip_reason });
        }
        let total_bytes: u64 = items.iter().map(|item| item.artifact.bytes).sum();
        let removable_bytes: u64 = items.iter().filter(|item| item.removable).map(|item| item.artifact.bytes).sum();
        DevPlan {
            roots: report.roots,
            mode,
            mode_supported: mode == DeleteMode::Permanent || trash::supported(),
            items,
            total_bytes,
            removable_bytes,
            skipped_bytes: total_bytes - removable_bytes,
            warnings: Vec::new(),
            scanned_at_unix_ms: report.scanned_at_unix_ms,
            profile: None,
        }
    }
}
