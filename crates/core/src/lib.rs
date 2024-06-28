//! Disk scan helpers for `@wae/open-cleaner`.

use std::{
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Message(String),
}

pub type Result<T> = std::result::Result<T, ScanError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    /// Root directory to scan. Defaults to the process temp directory.
    pub root: Option<String>,
    /// Maximum number of entries to return (largest first).
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanEntry {
    pub path: String,
    pub bytes: u64,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub root: String,
    pub total_bytes: u64,
    pub entries: Vec<ScanEntry>,
    pub scanned_at_unix_ms: u64,
}

pub fn default_scan_root() -> PathBuf {
    std::env::temp_dir()
}

pub fn scan(options: ScanOptions) -> Result<ScanReport> {
    let root = options.root.map(PathBuf::from).unwrap_or_else(default_scan_root);
    let limit = options.limit.unwrap_or(50).max(1);

    if !root.exists() {
        return Err(ScanError::Message(format!("scan root does not exist: {}", root.display())));
    }

    let mut entries = Vec::new();
    let mut total_bytes = 0u64;
    collect_entries(&root, &root, &mut entries, &mut total_bytes, 0)?;

    entries.sort_by_key(|a| std::cmp::Reverse(a.bytes));
    entries.truncate(limit);

    let scanned_at_unix_ms = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);

    Ok(ScanReport { root: root.display().to_string(), total_bytes, entries, scanned_at_unix_ms })
}

fn collect_entries(root: &Path, current: &Path, out: &mut Vec<ScanEntry>, total: &mut u64, depth: usize) -> Result<()> {
    if depth > 8 {
        return Ok(());
    }

    let read = fs::read_dir(current).map_err(|source| ScanError::Io { path: current.display().to_string(), source })?;

    for item in read {
        let entry = item.map_err(|source| ScanError::Io { path: current.display().to_string(), source })?;
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        if meta.is_file() {
            let bytes = meta.len();
            *total = total.saturating_add(bytes);
            out.push(ScanEntry { path: path.display().to_string(), bytes, kind: classify(&path, root).to_string() });
        }
        else if meta.is_dir() {
            // Skip reparse points / junctions that often loop on Windows temp trees.
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
                if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    continue;
                }
            }
            collect_entries(root, &path, out, total, depth + 1)?;
        }
    }
    Ok(())
}

fn classify(path: &Path, root: &Path) -> &'static str {
    let text = path.to_string_lossy().to_ascii_lowercase();
    let root_text = root.to_string_lossy().to_ascii_lowercase();
    if text.contains("cache") {
        "cache"
    }
    else if text.contains("temp") || root_text.contains("temp") {
        "temp"
    }
    else if text.ends_with(".log") {
        "log"
    }
    else {
        "file"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn scans_fixture_directory() {
        let dir = std::env::temp_dir().join(format!("open-cleaner-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("cache")).unwrap();
        {
            let mut f = fs::File::create(dir.join("cache").join("a.bin")).unwrap();
            f.write_all(&[0u8; 2048]).unwrap();
            f.sync_all().unwrap();
        }

        let report = scan(ScanOptions { root: Some(dir.display().to_string()), limit: Some(10) }).unwrap();

        assert!(
            report.total_bytes >= 2048,
            "unexpected report: root={} total={} entries={:?}",
            report.root,
            report.total_bytes,
            report.entries
        );
        assert!(!report.entries.is_empty());
        assert!(report.entries.iter().any(|e| e.kind == "cache"));

        let _ = fs::remove_dir_all(&dir);
    }
}
