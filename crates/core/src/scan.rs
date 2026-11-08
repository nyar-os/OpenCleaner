//! Portable directory scan kernel: traversal, size aggregation, and
//! classification. No platform API is called directly here.

use std::{
    fs, io,
    path::{Path, PathBuf},
    time::SystemTime,
};

use serde::{Deserialize, Serialize};

use crate::{Error, Result, platform};

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
    /// Directories whose listing was denied. Their subtrees are skipped rather
    /// than failing the whole scan, so `total_bytes` is a lower bound whenever
    /// this is non-zero.
    pub unreadable_dirs: usize,
    /// The denied directory at the top of each skipped subtree. Nothing below
    /// it was measured.
    pub unreadable_paths: Vec<String>,
    pub entries: Vec<ScanEntry>,
    pub scanned_at_unix_ms: u64,
}

pub fn default_scan_root() -> PathBuf {
    std::env::temp_dir()
}

pub fn scan(options: ScanOptions) -> Result<ScanReport> {
    scan_with(options, &|path| fs::read_dir(path))
}

fn scan_with(options: ScanOptions, read_dir: &dyn Fn(&Path) -> io::Result<fs::ReadDir>) -> Result<ScanReport> {
    let root = options.root.map(PathBuf::from).unwrap_or_else(default_scan_root);
    let limit = options.limit.unwrap_or(50).max(1);

    if !root.exists() {
        return Err(Error::Message(format!("scan root does not exist: {}", root.display())));
    }

    // The root itself must be listable, otherwise there is no scan to report.
    let read = read_dir(&root).map_err(|source| Error::Io { path: root.display().to_string(), source })?;

    let mut walk = Walk { root: &root, entries: Vec::new(), total_bytes: 0, unreadable: Vec::new(), read_dir };
    walk.collect(read, 0);
    let mut entries = walk.entries;
    let unreadable_dirs = walk.unreadable.len();
    let mut unreadable_paths: Vec<String> = walk.unreadable.iter().map(|path| path.display().to_string()).collect();

    // Highest level first, so the report starts at the subtree boundary.
    unreadable_paths.sort_by_key(|path| (Path::new(path).components().count(), path.clone()));
    unreadable_paths.dedup();

    entries.sort_by_key(|a| std::cmp::Reverse(a.bytes));
    entries.truncate(limit);

    let scanned_at_unix_ms = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);

    Ok(ScanReport {
        root: root.display().to_string(),
        total_bytes: walk.total_bytes,
        unreadable_dirs,
        unreadable_paths,
        entries,
        scanned_at_unix_ms,
    })
}

struct Walk<'a> {
    root: &'a Path,
    entries: Vec<ScanEntry>,
    total_bytes: u64,
    unreadable: Vec<PathBuf>,
    read_dir: &'a dyn Fn(&Path) -> io::Result<fs::ReadDir>,
}

impl Walk<'_> {
    fn collect(&mut self, read: fs::ReadDir, depth: usize) {
        if depth > 8 {
            return;
        }

        for item in read {
            // An entry that cannot be read cannot be classified, so it is
            // skipped like an unreadable subtree.
            let Ok(entry) = item
            else {
                continue;
            };
            let path = entry.path();
            let Ok(meta) = entry.metadata()
            else {
                continue;
            };

            if meta.is_file() {
                let bytes = meta.len();
                self.total_bytes = self.total_bytes.saturating_add(bytes);
                self.entries.push(ScanEntry { path: path.display().to_string(), bytes, kind: classify(&path, self.root).to_string() });
            }
            else if meta.is_dir() {
                // Skip reparse points / junctions that often loop on Windows temp trees.
                if platform::is_link_like(&meta) {
                    continue;
                }
                match (self.read_dir)(&path) {
                    Ok(read) => self.collect(read, depth + 1),
                    // A denied directory skips only its own subtree. The rest of
                    // the scan continues and the report says what was skipped.
                    Err(_) => self.unreadable.push(path),
                }
            }
        }
    }
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

    #[test]
    fn unreadable_subtrees_are_skipped_and_reported() {
        let dir = std::env::temp_dir().join(format!("open-cleaner-unreadable-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("free").join("nested")).unwrap();
        fs::create_dir_all(dir.join("locked")).unwrap();
        fs::create_dir_all(dir.join("free").join("locked")).unwrap();
        for (path, bytes) in [
            (dir.join("free").join("nested").join("a.bin"), 512usize),
            (dir.join("locked").join("b.bin"), 4096usize),
            (dir.join("free").join("locked").join("c.bin"), 4096usize),
        ] {
            let mut file = fs::File::create(path).unwrap();
            file.write_all(&vec![0u8; bytes]).unwrap();
            file.sync_all().unwrap();
        }

        let report = scan_with(ScanOptions { root: Some(dir.display().to_string()), limit: Some(10) }, &|path| {
            if path.ends_with("locked") { Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied")) } else { fs::read_dir(path) }
        })
        .unwrap();

        // A denied directory skips only its own subtree: the readable sibling
        // is still measured and the denied bytes are not counted.
        assert_eq!(report.unreadable_dirs, 2, "{report:#?}");
        assert_eq!(
            report.unreadable_paths,
            vec![dir.join("locked").display().to_string(), dir.join("free").join("locked").display().to_string()]
        );
        assert_eq!(report.total_bytes, 512, "{report:#?}");
        assert!(report.entries.iter().any(|entry| entry.path.ends_with("a.bin")));
        assert!(!report.entries.iter().any(|entry| entry.path.ends_with("b.bin") || entry.path.ends_with("c.bin")));

        let _ = fs::remove_dir_all(&dir);
    }
}
