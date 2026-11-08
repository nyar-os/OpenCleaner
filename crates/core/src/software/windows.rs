//! Windows software-residue scan. Reuses the registry snapshot and only reads
//! the file system, so it is always a preview.

use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use super::{
    SoftwareOptions, SoftwareReport,
    analyze::{self, SoftwareContext},
};
use crate::{Result, platform};

pub(super) fn scan(options: SoftwareOptions) -> Result<SoftwareReport> {
    let snapshot = crate::registry::windows::snapshot_registry();
    let ctx = live_context();

    let analysis = analyze::analyze(&snapshot, &ctx);
    let mut findings = analysis.findings;
    let mut warnings = analysis.warnings;
    if let Some(limit) = options.limit.filter(|limit| *limit > 0)
        && findings.len() > limit
    {
        warnings.push(format!("showing the first {limit} of {} findings", findings.len()));
        findings.truncate(limit);
    }

    Ok(SoftwareReport {
        platform: platform::name().to_string(),
        source: snapshot.source,
        uninstall_keys: analysis.uninstall_keys,
        findings,
        skipped: analysis.skipped,
        warnings,
        scanned_at_unix_ms: SystemTime::now().duration_since(UNIX_EPOCH).map(|duration| duration.as_millis() as u64).unwrap_or(0),
    })
}

/// The live file-system and process inputs of the install evidence chain. The
/// software and registry commands both build their context from this one table,
/// so one uninstall key cannot be judged from different inputs depending on
/// which command asked.
pub(crate) fn live_context() -> SoftwareContext<'static> {
    SoftwareContext {
        dir_exists: &dir_exists,
        file_exists: &file_exists,
        list_dir: &list_dir,
        dir_size: &dir_size,
        env: &env,
        process_image_dirs: &process_image_dirs,
        newest_entry_unix_ms: &newest_entry_unix_ms,
    }
}

fn dir_exists(path: &str) -> bool {
    Path::new(path).is_dir()
}

fn file_exists(path: &str) -> bool {
    Path::new(path).is_file()
}

fn list_dir(path: &str) -> Vec<String> {
    let read = fs::read_dir(path);
    read.map(|entries| {
        entries
            .flatten()
            .filter(|entry| entry.file_type().map(|kind| kind.is_dir() && !kind.is_symlink()).unwrap_or(false))
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect()
    })
    .unwrap_or_default()
}

fn dir_size(path: &str) -> u64 {
    size_of(Path::new(path))
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn process_image_dirs() -> Vec<String> {
    crate::safety::process_paths().image_dirs.iter().map(|dir| dir.to_string_lossy().to_string()).collect()
}

fn newest_entry_unix_ms(path: &str) -> Option<u64> {
    crate::safety::newest_entry_unix_ms(Path::new(path))
}

/// Directory size without following links or reparse points.
fn size_of(path: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(read) = fs::read_dir(&dir)
        else {
            continue;
        };
        for entry in read.flatten() {
            let Ok(meta) = fs::symlink_metadata(entry.path())
            else {
                continue;
            };
            if platform::is_link_like(&meta) {
                continue;
            }
            if meta.is_dir() {
                stack.push(entry.path());
            }
            else if meta.is_file() {
                total = total.saturating_add(meta.len());
            }
        }
    }
    total
}
