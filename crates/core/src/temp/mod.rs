//! Temp-directory reclamation at file granularity.
//!
//! A temp root holds hundreds of thousands of unrelated files written by
//! different programs, so nothing here operates on directories. Each file is
//! classified by age, re-checked for protection and occupancy, and removed
//! individually. A file that another process holds open is counted and skipped
//! without aborting the batch.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    dev::rules,
    platform,
    safety::{self, DEFAULT_AGE_DAYS, ProcessPaths},
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TempOptions {
    /// Root to walk. Defaults to the process temp directory.
    pub root: Option<String>,
    /// Only files older than this are touched. Defaults to [`DEFAULT_AGE_DAYS`].
    pub older_than_days: Option<u64>,
    /// Number of sample paths printed by a plan. Zero prints all of them.
    pub sample_limit: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TempCleanOptions {
    pub root: Option<String>,
    pub older_than_days: Option<u64>,
    /// Timestamp from the plan. Candidates are derived from it so the plan and
    /// the execution cover the same files even when the clock moves on.
    pub cutoff_unix_ms: Option<u64>,
    pub confirm: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TempSkips {
    pub recent: u64,
    pub symlink: u64,
    pub protected: u64,
    pub in_use: u64,
    pub cwd_shielded: u64,
    /// Directories under a running process's own `TEMP`/`TMP` value.
    pub process_temp: u64,
    /// Directories hosting the executable image of a running process.
    pub program_shielded: u64,
    pub unreadable: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TempGroup {
    pub label: String,
    pub files: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TempFile {
    pub path: String,
    pub bytes: u64,
    pub age_days: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TempPlan {
    pub root: String,
    pub older_than_days: u64,
    pub cutoff_unix_ms: u64,
    pub scanned_files: u64,
    pub scanned_bytes: u64,
    pub candidate_files: u64,
    pub candidate_bytes: u64,
    pub skipped: TempSkips,
    pub age_groups: Vec<TempGroup>,
    pub extension_groups: Vec<TempGroup>,
    pub samples: Vec<TempFile>,
    pub samples_truncated: bool,
    pub cwd_probe: CwdProbeReport,
    pub warnings: Vec<String>,
    pub scanned_at_unix_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CwdProbeReport {
    pub supported: bool,
    pub processes: u32,
    pub resolved: u32,
    pub failed: u32,
    /// Distinct in-root process temp directories that were excluded.
    pub temp_dirs: u32,
    /// Distinct in-root directories hosting a running process image that were
    /// excluded.
    pub program_dirs: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TempFailure {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TempCleanReport {
    pub root: String,
    pub older_than_days: u64,
    pub cutoff_unix_ms: u64,
    pub executed: bool,
    pub candidate_files: u64,
    pub deleted_files: u64,
    pub freed_bytes: u64,
    pub skipped: TempSkips,
    pub failures: Vec<TempFailure>,
    pub warnings: Vec<String>,
    pub finished_at_unix_ms: u64,
}

struct ScanOutput {
    candidates: Vec<Candidate>,
    scanned_files: u64,
    scanned_bytes: u64,
    skipped: TempSkips,
    warnings: Vec<String>,
    paths: ProcessPaths,
    /// Process `TEMP`/`TMP` directories inside the root, excluding the root
    /// itself. Anything below these is never entered.
    temp_dirs: Vec<PathBuf>,
    /// Directories that host a running process image and live inside the root.
    program_dirs: Vec<PathBuf>,
}

struct Candidate {
    path: PathBuf,
    bytes: u64,
    age_days: u64,
}

fn threshold_days(value: Option<u64>) -> u64 {
    value.unwrap_or(DEFAULT_AGE_DAYS).clamp(1, 365)
}

fn resolve_root(root: Option<&str>) -> PathBuf {
    root.map(PathBuf::from).unwrap_or_else(std::env::temp_dir)
}

fn age_days(cutoff_ms: u64, threshold_ms: u64, modified_ms: u64) -> u64 {
    cutoff_ms.saturating_sub(modified_ms).max(threshold_ms) / (24 * 60 * 60 * 1000)
}

fn modified_unix_ms(meta: &std::fs::Metadata) -> Option<u64> {
    meta.modified().ok().and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok()).map(|elapsed| elapsed.as_millis() as u64)
}

fn is_cwd_shielded(dir: &Path, paths: &ProcessPaths) -> bool {
    paths.dirs.iter().any(|cwd| safety::is_within(cwd, dir))
}

fn is_in_shielded_dir(dir: &Path, shielded: &[PathBuf]) -> bool {
    shielded.iter().any(|entry| safety::is_within(entry, dir))
}

fn walk(root: &Path, threshold_days_value: u64, cutoff_ms: u64) -> Result<ScanOutput> {
    let paths = safety::process_paths();
    let temp_dirs: Vec<PathBuf> = paths
        .temp_dirs
        .iter()
        .filter(|temp| safety::is_within(root, temp) && safety::path_key(temp) != safety::path_key(root))
        .cloned()
        .collect();
    let program_dirs: Vec<PathBuf> = paths
        .image_dirs
        .iter()
        .filter(|dir| safety::is_within(root, dir) && safety::path_key(dir) != safety::path_key(root))
        .cloned()
        .collect();
    let mut output = ScanOutput {
        candidates: Vec::new(),
        scanned_files: 0,
        scanned_bytes: 0,
        skipped: TempSkips::default(),
        warnings: Vec::new(),
        paths,
        temp_dirs,
        program_dirs,
    };
    if !output.paths.supported {
        output.warnings.push("process working directories could not be enumerated on this platform".to_string());
    }
    else if output.paths.failed > 0 {
        output.warnings.push(format!(
            "{} of {} processes could not be read, their working and temp directories are unknown",
            output.paths.failed, output.paths.processes
        ));
    }

    let threshold_ms = threshold_days_value * 24 * 60 * 60 * 1000;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let read = match std::fs::read_dir(&dir) {
            Ok(read) => read,
            Err(error) => {
                output.skipped.unreadable += 1;
                output.warnings.push(format!("cannot read {}: {error}", dir.display()));
                continue;
            }
        };
        for entry in read {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    output.skipped.unreadable += 1;
                    output.warnings.push(format!("cannot read an entry in {}: {error}", dir.display()));
                    continue;
                }
            };
            let meta = match entry.metadata() {
                Ok(meta) => meta,
                Err(error) => {
                    output.skipped.unreadable += 1;
                    output.warnings.push(format!("cannot stat {}: {error}", entry.path().display()));
                    continue;
                }
            };
            if platform::is_link_like(&meta) || meta.file_type().is_symlink() {
                output.skipped.symlink += 1;
                continue;
            }
            let path = entry.path();
            if meta.is_dir() {
                if safety::has_protected_component(&path) {
                    output.skipped.protected += 1;
                    continue;
                }
                if is_cwd_shielded(&path, &output.paths) {
                    output.skipped.cwd_shielded += 1;
                    continue;
                }
                if is_in_shielded_dir(&path, &output.temp_dirs) {
                    output.skipped.process_temp += 1;
                    continue;
                }
                if is_in_shielded_dir(&path, &output.program_dirs) {
                    output.skipped.program_shielded += 1;
                    continue;
                }
                stack.push(path);
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            if !safety::is_within(root, &path) {
                output.skipped.protected += 1;
                continue;
            }
            if rules::is_protected(&path) {
                output.skipped.protected += 1;
                continue;
            }
            output.scanned_files += 1;
            output.scanned_bytes = output.scanned_bytes.saturating_add(meta.len());
            let Some(modified_ms) = modified_unix_ms(&meta)
            else {
                output.skipped.unreadable += 1;
                continue;
            };
            if modified_ms.saturating_add(threshold_ms) > cutoff_ms {
                output.skipped.recent += 1;
                continue;
            }
            output.candidates.push(Candidate { path, bytes: meta.len(), age_days: age_days(cutoff_ms, threshold_ms, modified_ms) });
        }
    }
    Ok(output)
}

fn age_bucket(days: u64) -> &'static str {
    match days {
        0..=6 => "under 7 days",
        7..=13 => "7-14 days",
        14..=29 => "14-30 days",
        30..=89 => "30-90 days",
        _ => "90 days and older",
    }
}

fn extension_key(path: &Path) -> String {
    path.extension()
        .map(|value| value.to_string_lossy().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "(none)".to_string())
}

fn group_by<F: Fn(&Candidate) -> String>(candidates: &[Candidate], key: F) -> Vec<TempGroup> {
    let mut groups: std::collections::BTreeMap<String, TempGroup> = std::collections::BTreeMap::new();
    for candidate in candidates {
        let label = key(candidate);
        let group = groups.entry(label.clone()).or_insert_with(|| TempGroup { label, files: 0, bytes: 0 });
        group.files += 1;
        group.bytes = group.bytes.saturating_add(candidate.bytes);
    }
    let mut groups: Vec<TempGroup> = groups.into_values().collect();
    groups.sort_by(|left, right| right.bytes.cmp(&left.bytes).then_with(|| left.label.cmp(&right.label)));
    groups
}

/// Read-only plan. Occupancy is probed per file, and probed files are counted,
/// never deleted.
pub fn temp_plan(options: TempOptions) -> Result<TempPlan> {
    let root = resolve_root(options.root.as_deref());
    let meta = safety::ensure_cleanup_root(&root, "temp-plan")?;
    if !meta.is_dir() {
        return Err(Error::Message(format!("temp-plan: root is not a directory: {}", root.display())));
    }
    let older_than_days = threshold_days(options.older_than_days);
    let cutoff_ms = safety::now_unix_ms();
    let scanned = walk(&root, older_than_days, cutoff_ms)?;

    let mut accepted = Vec::new();
    let mut skipped = scanned.skipped;
    for candidate in scanned.candidates {
        if safety::probe_file_in_use(&candidate.path) {
            skipped.in_use += 1;
            continue;
        }
        accepted.push(candidate);
    }

    let candidate_bytes = accepted.iter().fold(0u64, |total, item| total.saturating_add(item.bytes));
    let age_groups = group_by(&accepted, |item| age_bucket(item.age_days).to_string());
    let extension_groups = group_by(&accepted, |item| extension_key(&item.path));
    let mut sorted = accepted.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| right.bytes.cmp(&left.bytes).then_with(|| left.path.cmp(&right.path)));
    let sample_limit = options.sample_limit.unwrap_or(50) as usize;
    let samples = if sample_limit == 0 { sorted.len() } else { sample_limit.min(sorted.len()) };
    let sample_items: Vec<TempFile> = sorted
        .iter()
        .take(samples)
        .map(|item| TempFile { path: item.path.display().to_string(), bytes: item.bytes, age_days: item.age_days })
        .collect();

    Ok(TempPlan {
        root: root.display().to_string(),
        older_than_days,
        cutoff_unix_ms: cutoff_ms,
        scanned_files: scanned.scanned_files,
        scanned_bytes: scanned.scanned_bytes,
        candidate_files: sorted.len() as u64,
        candidate_bytes,
        skipped,
        age_groups,
        extension_groups,
        samples: sample_items,
        samples_truncated: samples < sorted.len(),
        cwd_probe: CwdProbeReport {
            supported: scanned.paths.supported,
            processes: scanned.paths.processes,
            resolved: scanned.paths.resolved,
            failed: scanned.paths.failed,
            temp_dirs: scanned.temp_dirs.len() as u32,
            program_dirs: scanned.program_dirs.len() as u32,
        },
        warnings: scanned.warnings,
        scanned_at_unix_ms: safety::now_unix_ms(),
    })
}

/// Removes the candidate files derived from `cutoff_unix_ms`. Every file is
/// re-validated, re-probed, and reported individually when it fails.
pub fn temp_clean(options: TempCleanOptions) -> Result<TempCleanReport> {
    if !options.confirm {
        return Err(Error::Message("temp-clean: refusing to delete without confirm".to_string()));
    }
    let root = resolve_root(options.root.as_deref());
    safety::ensure_cleanup_root(&root, "temp-clean")?;
    let older_than_days = threshold_days(options.older_than_days);
    let cutoff_ms = options.cutoff_unix_ms.ok_or_else(|| Error::Message("temp-clean: cutoff_unix_ms is required".to_string()))?;
    let cutoff_ms = cutoff_ms.min(safety::now_unix_ms());
    let threshold_ms = older_than_days * 24 * 60 * 60 * 1000;
    let scanned = walk(&root, older_than_days, cutoff_ms)?;
    let warnings = scanned.warnings;

    let mut skipped = scanned.skipped;
    let mut deleted_files = 0u64;
    let mut freed_bytes = 0u64;
    let mut failures: Vec<TempFailure> = Vec::new();
    let mut candidates = 0u64;

    for candidate in scanned.candidates {
        let meta = match std::fs::symlink_metadata(&candidate.path) {
            Ok(meta) => meta,
            Err(error) => {
                failures.push(TempFailure { path: candidate.path.display().to_string(), reason: error.to_string() });
                continue;
            }
        };
        if platform::is_link_like(&meta) || meta.file_type().is_symlink() {
            skipped.symlink += 1;
            continue;
        }
        if !meta.is_file() || !safety::is_within(&root, &candidate.path) || rules::is_protected(&candidate.path) {
            skipped.protected += 1;
            continue;
        }
        let Some(modified_ms) = modified_unix_ms(&meta)
        else {
            skipped.unreadable += 1;
            continue;
        };
        if modified_ms.saturating_add(threshold_ms) > cutoff_ms {
            skipped.recent += 1;
            continue;
        }
        candidates += 1;
        if safety::probe_file_in_use(&candidate.path) {
            skipped.in_use += 1;
            continue;
        }
        match std::fs::remove_file(&candidate.path) {
            Ok(()) => {
                deleted_files += 1;
                freed_bytes = freed_bytes.saturating_add(meta.len());
            }
            Err(error) => failures.push(TempFailure { path: candidate.path.display().to_string(), reason: error.to_string() }),
        }
    }

    Ok(TempCleanReport {
        root: root.display().to_string(),
        older_than_days,
        cutoff_unix_ms: cutoff_ms,
        executed: true,
        candidate_files: candidates,
        deleted_files,
        freed_bytes,
        skipped,
        failures,
        warnings,
        finished_at_unix_ms: safety::now_unix_ms(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn unique_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("open-cleaner-test-{label}-{}-{}", std::process::id(), safety::now_unix_ms()));
        std::fs::create_dir_all(&root).expect("create fixture root");
        root
    }

    fn write_file(path: &Path, bytes: usize, age_days: u64) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create fixture dirs");
        }
        let mut file = std::fs::File::create(path).expect("create fixture file");
        file.write_all(&vec![b'x'; bytes]).expect("write fixture file");
        let stamp = std::time::SystemTime::now() - std::time::Duration::from_secs(age_days * 24 * 60 * 60);
        file.set_modified(stamp).expect("set fixture mtime");
    }

    #[test]
    fn plan_keeps_recent_files_and_groups_candidates() {
        let root = unique_root("temp-plan");
        write_file(&root.join("old.bin"), 4096, 20);
        write_file(&root.join("older.log"), 2048, 40);
        write_file(&root.join("fresh.tmp"), 1024, 0);
        let report =
            temp_plan(TempOptions { root: Some(root.display().to_string()), older_than_days: Some(7), sample_limit: Some(0) }).expect("plan");
        assert_eq!(report.candidate_files, 2);
        assert_eq!(report.candidate_bytes, 6144);
        assert_eq!(report.skipped.recent, 1);
        assert!(report.extension_groups.iter().any(|group| group.label == "bin" && group.files == 1));
        assert!(report.age_groups.iter().any(|group| group.label == "14-30 days"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn clean_removes_only_files_older_than_the_threshold() {
        let root = unique_root("temp-clean");
        let old = root.join("old.tmp");
        let fresh = root.join("fresh.tmp");
        write_file(&old, 1024, 20);
        write_file(&fresh, 1024, 0);
        let plan =
            temp_plan(TempOptions { root: Some(root.display().to_string()), older_than_days: Some(7), sample_limit: Some(0) }).expect("plan");
        let report = temp_clean(TempCleanOptions {
            root: Some(root.display().to_string()),
            older_than_days: Some(7),
            cutoff_unix_ms: Some(plan.cutoff_unix_ms),
            confirm: true,
        })
        .expect("clean");
        assert_eq!(report.deleted_files, 1);
        assert!(!old.exists());
        assert!(fresh.exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn clean_requires_confirmation() {
        let error = temp_clean(TempCleanOptions::default()).unwrap_err();
        assert!(error.to_string().contains("confirm"), "{error}");
    }
}
