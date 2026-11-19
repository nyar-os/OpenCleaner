//! Portable directory scan kernel: traversal, size aggregation, and
//! classification. No platform API is called directly here.

use std::{
    path::{Path, PathBuf},
    time::SystemTime,
};

use boost_fs::walk::{ErrorPolicy, Walker};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

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

/// Depth cap of the scan. Entries deeper than this below the root are not
/// listed, which keeps temp trees with pathological nesting finite.
const MAX_DEPTH: usize = 9;

pub fn scan(options: ScanOptions) -> Result<ScanReport> {
    let root = options.root.map(PathBuf::from).unwrap_or_else(default_scan_root);
    let limit = options.limit.unwrap_or(50).max(1);

    if !root.exists() {
        return Err(Error::Message(format!("scan root does not exist: {}", root.display())));
    }

    // The `boost-fs` walk kernel owns the traversal: the depth bound, the pruning of
    // reparse points that often loop on Windows temp trees, and the listing itself.
    // Entry sizes come from the listing attributes, so the scan never stats twice.
    let mut entries: Vec<ScanEntry> = Vec::new();
    let mut total_bytes = 0u64;
    let mut unreadable: Vec<PathBuf> = Vec::new();

    for item in Walker::new(&root).max_depth(MAX_DEPTH).error_policy(ErrorPolicy::Lenient) {
        match item {
            Ok(entry) => {
                if !entry.is_file() {
                    continue;
                }
                // An entry whose attributes cannot be read cannot be measured, so it is
                // skipped like an unreadable subtree.
                let Ok(meta) = entry.metadata()
                else {
                    continue;
                };
                let bytes = meta.len();
                total_bytes = total_bytes.saturating_add(bytes);
                entries.push(ScanEntry { path: entry.path().display().to_string(), bytes, kind: classify(entry.path(), &root).to_string() });
            }
            Err(error) => {
                let Some(path) = error.path() else { continue };
                // The root itself must be listable, otherwise there is no scan to report.
                if path == root.as_path() {
                    return Err(Error::Io { path: root.display().to_string(), source: error.into() });
                }
                // A denied directory skips only its own subtree. The rest of
                // the scan continues and the report says what was skipped.
                unreadable.push(path.to_path_buf());
            }
        }
    }

    let unreadable_dirs = unreadable.len();
    let mut unreadable_paths: Vec<String> = unreadable.iter().map(|path| path.display().to_string()).collect();

    // Highest level first, so the report starts at the subtree boundary.
    unreadable_paths.sort_by_key(|path| (Path::new(path).components().count(), path.clone()));
    unreadable_paths.dedup();

    entries.sort_by_key(|a| std::cmp::Reverse(a.bytes));
    entries.truncate(limit);

    let scanned_at_unix_ms = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);

    Ok(ScanReport {
        root: root.display().to_string(),
        total_bytes,
        unreadable_dirs,
        unreadable_paths,
        entries,
        scanned_at_unix_ms,
    })
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
    use std::{fs, io::Write};

    #[test]
    fn scans_fixture_directory() {
        let dir = crate::fixtures::fixture_dir("scan");
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

    /// A directory held so that listing it fails while its attributes stay readable.
    ///
    /// On Windows an exclusive handle makes `ReadDirectory` fail with a sharing
    /// violation. On Unix the mode is cleared and restored on drop, which fails
    /// only where the test does not run with privileges that bypass it.
    struct LockedDir {
        /// Only read when restoring the mode on Unix; the Windows handle drops itself.
        #[cfg_attr(windows, allow(dead_code))]
        path: PathBuf,
        #[cfg(windows)]
        _handle: fs::File,
        #[cfg(not(windows))]
        restore: fs::Permissions,
    }

    impl LockedDir {
        fn new(path: &Path) -> Self {
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
                // A directory listing needs backup semantics, and an exclusive
                // listing handle makes every later `ReadDirectory` fail.
                let _handle = fs::OpenOptions::new()
                    .read(true)
                    .share_mode(0)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                    .open(path)
                    .expect("lock directory");
                Self { path: path.to_path_buf(), _handle }
            }
            #[cfg(not(windows))]
            {
                use std::os::unix::fs::PermissionsExt;
                let restore = fs::metadata(path).expect("read permissions").permissions();
                fs::set_permissions(path, fs::Permissions::from_mode(0o000)).expect("clear permissions");
                Self { path: path.to_path_buf(), restore }
            }
        }
    }

    impl Drop for LockedDir {
        fn drop(&mut self) {
            #[cfg(not(windows))]
            {
                let _ = fs::set_permissions(&self.path, self.restore.clone());
            }
        }
    }

    #[test]
    fn unreadable_subtrees_are_skipped_and_reported() {
        let dir = crate::fixtures::fixture_dir("scan-unreadable");
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

        let _locked = LockedDir::new(&dir.join("locked"));
        let _locked_nested = LockedDir::new(&dir.join("free").join("locked"));

        let report = scan(ScanOptions { root: Some(dir.display().to_string()), limit: Some(10) }).unwrap();

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

        drop(_locked);
        drop(_locked_nested);
        let _ = fs::remove_dir_all(&dir);
    }
}
