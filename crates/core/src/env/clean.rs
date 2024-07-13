//! PATH cleanup orchestration: re-analyze, re-validate the caller's selection,
//! write a rollback pair, then write and verify the new value.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{
    analyze::{self, PathContext, PathScope},
    backup::{self, BackupRequest, EnvPathBackup},
    store::PathStore,
};
use crate::{Error, Result, locations::BaseDirs};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvPathCleanStatus {
    Removed,
    Skipped,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvPathSelection {
    /// Index from the dry-run report.
    pub index: usize,
    /// Raw value from the same report; must still match before anything is
    /// written.
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvPathCleanOptions {
    pub scope: PathScope,
    /// Entries the user explicitly selected. Empty means nothing to do.
    pub selections: Vec<EnvPathSelection>,
    /// PATH is high risk: execution always needs an explicit confirmation.
    pub confirm: bool,
    /// Override for the rollback directory. Defaults to the per-user data dir.
    pub backup_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvPathCleanItem {
    pub index: usize,
    pub raw: String,
    pub status: EnvPathCleanStatus,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvPathCleanReport {
    pub scope: PathScope,
    pub key_path: String,
    /// True only when the new value was written and verified.
    pub executed: bool,
    pub items: Vec<EnvPathCleanItem>,
    pub removed: usize,
    pub original: Option<String>,
    pub new_value: Option<String>,
    pub backup: Option<EnvPathBackup>,
    pub warnings: Vec<String>,
}

pub fn clean_with(store: &dyn PathStore, options: EnvPathCleanOptions, ctx: &PathContext<'_>, dirs: &BaseDirs) -> Result<EnvPathCleanReport> {
    if !options.confirm {
        return Err(Error::Message("env PATH clean requires explicit confirmation (confirm=true)".to_string()));
    }
    if options.selections.is_empty() {
        return Err(Error::Message("env PATH clean requires at least one selected entry".to_string()));
    }
    let scope = options.scope;
    let key_path = scope.key_path().to_string();
    let Some(original) = store.read(scope)?
    else {
        return Err(Error::Message(format!("no Path value at {key_path}")));
    };

    let analysis = analyze::analyze(scope, Some(&original), ctx);
    let mut items = Vec::new();
    let mut selected: BTreeSet<usize> = BTreeSet::new();
    let mut considered: BTreeSet<usize> = BTreeSet::new();

    for selection in &options.selections {
        if !considered.insert(selection.index) {
            continue;
        }
        let skip = |items: &mut Vec<EnvPathCleanItem>, reason: &str| {
            items.push(EnvPathCleanItem {
                index: selection.index,
                raw: selection.raw.clone(),
                status: EnvPathCleanStatus::Skipped,
                reason: Some(reason.to_string()),
            });
        };
        let Some(entry) = analysis.entries.get(selection.index)
        else {
            skip(&mut items, "stale-selection");
            continue;
        };
        if entry.raw != selection.raw {
            skip(&mut items, "stale-selection");
            continue;
        }
        if entry.issue.is_none() {
            skip(&mut items, "not-flagged");
            continue;
        }
        if !entry.removable {
            let reason = entry.issue.map(|issue| format!("report-only ({})", issue.as_str())).unwrap_or_else(|| "report-only".to_string());
            skip(&mut items, &reason);
            continue;
        }
        selected.insert(selection.index);
    }

    let mut warnings = Vec::new();
    if scope == PathScope::Machine {
        warnings.push("machine-wide PATH writes normally require elevation".to_string());
    }
    warnings.push("already running programs keep their current PATH until they restart".to_string());

    if selected.is_empty() {
        return Ok(EnvPathCleanReport {
            scope,
            key_path,
            executed: false,
            items,
            removed: 0,
            original: Some(original),
            new_value: None,
            backup: None,
            warnings,
        });
    }

    let kept: Vec<&str> = analysis.entries.iter().filter(|entry| !selected.contains(&entry.index)).map(|entry| entry.raw.as_str()).collect();
    let new_value = kept.join(";");
    let removed: Vec<(usize, String)> =
        selected.iter().filter_map(|index| analysis.entries.get(*index)).map(|entry| (entry.index, entry.raw.clone())).collect();

    let created_at_unix_ms = backup::now_millis();
    let request = BackupRequest { scope, original: &original, removed: &removed, created_at_unix_ms };
    let dir = options.backup_dir.as_deref().map(std::path::Path::new);
    let backup = backup::write(&request, dir, dirs)?;

    if let Err(error) = store.write(scope, &new_value) {
        for index in &selected {
            items.push(EnvPathCleanItem {
                index: *index,
                raw: analysis.entries[*index].raw.clone(),
                status: EnvPathCleanStatus::Failed,
                reason: Some(error.to_string()),
            });
        }
        return Ok(EnvPathCleanReport {
            scope,
            key_path,
            executed: false,
            items,
            removed: 0,
            original: Some(original),
            new_value: Some(new_value),
            backup: Some(backup),
            warnings,
        });
    }

    match store.read(scope)? {
        Some(value) if value == new_value => {
            for index in &selected {
                items.push(EnvPathCleanItem {
                    index: *index,
                    raw: analysis.entries[*index].raw.clone(),
                    status: EnvPathCleanStatus::Removed,
                    reason: None,
                });
            }
            Ok(EnvPathCleanReport {
                scope,
                key_path,
                executed: true,
                items,
                removed: selected.len(),
                original: Some(original),
                new_value: Some(new_value),
                backup: Some(backup),
                warnings,
            })
        }
        other => {
            // The value on disk does not match what we wrote. Put the original
            // back instead of leaving a half-applied PATH behind.
            let restore = store.write(scope, &original);
            if restore.is_err() {
                warnings.push(format!("restoring the original Path value also failed; use {}", backup.reg_path));
            }
            let detail = match other.as_deref() {
                Some(value) => format!("write verification failed, Path reads back as {value}"),
                None => "write verification failed, Path is missing".to_string(),
            };
            for index in &selected {
                items.push(EnvPathCleanItem {
                    index: *index,
                    raw: analysis.entries[*index].raw.clone(),
                    status: EnvPathCleanStatus::Failed,
                    reason: Some(detail.clone()),
                });
            }
            Ok(EnvPathCleanReport {
                scope,
                key_path,
                executed: false,
                items,
                removed: 0,
                original: Some(original),
                new_value: Some(new_value),
                backup: Some(backup),
                warnings,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeSet, fs};

    use super::*;
    use crate::env::PathIssue;

    struct FakeStore {
        value: RefCell<Option<String>>,
        fail_write: bool,
        corrupt_write: bool,
        writes: RefCell<usize>,
    }

    impl FakeStore {
        fn new(value: &str) -> Self {
            Self { value: RefCell::new(Some(value.to_string())), fail_write: false, corrupt_write: false, writes: RefCell::new(0) }
        }
    }

    impl PathStore for FakeStore {
        fn read(&self, _scope: PathScope) -> Result<Option<String>> {
            Ok(self.value.borrow().clone())
        }

        fn write(&self, _scope: PathScope, value: &str) -> Result<()> {
            if self.fail_write {
                return Err(Error::Message("access denied".to_string()));
            }
            let corrupt = self.corrupt_write && *self.writes.borrow() == 0;
            *self.writes.borrow_mut() += 1;
            *self.value.borrow_mut() = Some(if corrupt { "corrupted".to_string() } else { value.to_string() });
            Ok(())
        }
    }

    fn dirs(root: &std::path::Path) -> BaseDirs {
        BaseDirs { data_dir: Some(root.join("data")), ..BaseDirs::default() }
    }

    fn existing(paths: &[&str]) -> BTreeSet<String> {
        paths.iter().map(|path| analyze::normalize(path)).collect()
    }

    fn exists_in(dirs: &BTreeSet<String>) -> impl Fn(&str) -> bool + '_ {
        move |path: &str| dirs.contains(&analyze::normalize(path))
    }

    fn run_clean(
        store: &FakeStore,
        dirs_set: &BTreeSet<String>,
        selections: Vec<EnvPathSelection>,
        confirm: bool,
        backup_dir: Option<String>,
        base: &BaseDirs,
    ) -> Result<EnvPathCleanReport> {
        let dir_exists = exists_in(dirs_set);
        let env = |_: &str| None;
        let ctx = PathContext { dir_exists: &dir_exists, env: &env };
        clean_with(store, EnvPathCleanOptions { scope: PathScope::User, selections, confirm, backup_dir }, &ctx, base)
    }

    fn analyze_value(value: &str, dirs_set: &BTreeSet<String>) -> crate::env::PathAnalysis {
        let dir_exists = exists_in(dirs_set);
        let env = |_: &str| None;
        let ctx = PathContext { dir_exists: &dir_exists, env: &env };
        analyze::analyze(PathScope::User, Some(value), &ctx)
    }

    fn fixture(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("open-cleaner-env-clean-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    const PATH: &str = r"C:\Windows;C:\Gone\bin;C:\Windows;C:\Old\bin";

    #[test]
    fn refuses_without_confirmation_and_leaves_the_value_untouched() {
        let store = FakeStore::new(PATH);
        let dirs_set = existing(&[r"C:\Windows"]);
        let err =
            run_clean(&store, &dirs_set, vec![EnvPathSelection { index: 1, raw: r"C:\Gone\bin".into() }], false, None, &BaseDirs::default())
                .unwrap_err();
        assert!(err.to_string().contains("confirmation"), "{err}");
        assert_eq!(store.value.borrow().as_deref(), Some(PATH));
    }

    #[test]
    fn removes_only_selected_flagged_entries_and_writes_the_backup() {
        let root = fixture("remove");
        let store = FakeStore::new(PATH);
        let dirs_set = existing(&[r"C:\Windows"]);

        // Dry-run first: entry #1 is missing, entry #3 is missing.
        let analysis = analyze_value(PATH, &dirs_set);
        let flagged: Vec<usize> = analysis.entries.iter().filter(|entry| entry.removable).map(|entry| entry.index).collect();
        assert_eq!(flagged, vec![1, 2, 3], "{:#?}", analysis.entries);

        let report = run_clean(
            &store,
            &dirs_set,
            vec![EnvPathSelection { index: 1, raw: r"C:\Gone\bin".into() }, EnvPathSelection { index: 3, raw: r"C:\Old\bin".into() }],
            true,
            Some(root.join("backups").display().to_string()),
            &dirs(&root),
        )
        .unwrap();

        assert!(report.executed);
        assert_eq!(report.removed, 2);
        assert_eq!(report.new_value.as_deref(), Some(r"C:\Windows;C:\Windows"));
        assert_eq!(store.value.borrow().as_deref(), Some(r"C:\Windows;C:\Windows"));
        let backup = report.backup.as_ref().expect("backup is mandatory");
        assert_eq!(backup.original, PATH);
        let json = fs::read_to_string(&backup.json_path).unwrap();
        assert!(json.contains("\"index\": 1"), "{json}");
        assert!(json.contains(r"C:\\Gone\\bin"), "{json}");
        assert!(fs::read_to_string(&backup.reg_path).unwrap().contains("hex(2):"));

        // Every executed item is one of the dry-run findings.
        for item in &report.items {
            assert_eq!(item.status, EnvPathCleanStatus::Removed);
            assert!(flagged.contains(&item.index), "{item:?}");
        }

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn stale_report_only_and_healthy_selections_are_skipped() {
        let store = FakeStore::new(PATH);
        let root = fixture("skip");
        let dirs_set = existing(&[r"C:\Windows"]);

        let report = run_clean(
            &store,
            &dirs_set,
            vec![
                // Index 1 no longer holds the raw value from the report.
                EnvPathSelection { index: 1, raw: r"C:\Different".into() },
                // Index 0 is healthy.
                EnvPathSelection { index: 0, raw: r"C:\Windows".into() },
                // Out of range.
                EnvPathSelection { index: 99, raw: "x".into() },
            ],
            true,
            Some(root.join("backups").display().to_string()),
            &dirs(&root),
        )
        .unwrap();

        assert!(!report.executed);
        assert_eq!(report.removed, 0);
        assert!(report.backup.is_none());
        assert_eq!(store.value.borrow().as_deref(), Some(PATH));
        assert_eq!(report.items.len(), 3);
        assert!(report.items.iter().all(|item| item.status == EnvPathCleanStatus::Skipped), "{:#?}", report.items);
        assert_eq!(report.items[0].reason.as_deref(), Some("stale-selection"));
        assert_eq!(report.items[1].reason.as_deref(), Some("not-flagged"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn report_only_entries_cannot_be_removed_even_when_selected() {
        let value = format!("{PATH};;%UNKNOWN%\\bin");
        let store = FakeStore::new(&value);
        let root = fixture("report-only");
        let dirs_set = existing(&[r"C:\Windows"]);

        let analysis = analyze_value(&value, &dirs_set);
        let empty = analysis.entries.iter().find(|entry| entry.issue == Some(PathIssue::Empty)).unwrap();
        let unresolved = analysis.entries.iter().find(|entry| entry.issue == Some(PathIssue::Unresolved)).unwrap();
        assert!(!empty.removable && !unresolved.removable);

        let report = run_clean(
            &store,
            &dirs_set,
            vec![
                EnvPathSelection { index: empty.index, raw: empty.raw.clone() },
                EnvPathSelection { index: unresolved.index, raw: unresolved.raw.clone() },
            ],
            true,
            Some(root.join("backups").display().to_string()),
            &dirs(&root),
        )
        .unwrap();

        assert!(!report.executed);
        assert!(report.items.iter().any(|item| item.reason.as_deref() == Some("report-only (empty)")), "{:#?}", report.items);
        assert!(report.items.iter().any(|item| item.reason.as_deref() == Some("report-only (unresolved)")), "{:#?}", report.items);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_failed_write_reports_failure_without_claiming_removal() {
        let store = FakeStore { value: RefCell::new(Some(PATH.to_string())), fail_write: true, corrupt_write: false, writes: RefCell::new(0) };
        let root = fixture("fail");
        let report = run_clean(
            &store,
            &existing(&[r"C:\Windows"]),
            vec![EnvPathSelection { index: 1, raw: r"C:\Gone\bin".into() }],
            true,
            Some(root.join("backups").display().to_string()),
            &dirs(&root),
        )
        .unwrap();

        assert!(!report.executed);
        assert_eq!(report.removed, 0);
        assert_eq!(report.items[0].status, EnvPathCleanStatus::Failed);
        assert_eq!(store.value.borrow().as_deref(), Some(PATH));
        assert!(report.backup.is_some(), "the rollback file must exist even when the write fails");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_corrupted_write_is_rolled_back() {
        let store = FakeStore { value: RefCell::new(Some(PATH.to_string())), fail_write: false, corrupt_write: true, writes: RefCell::new(0) };
        let root = fixture("corrupt");
        let report = run_clean(
            &store,
            &existing(&[r"C:\Windows"]),
            vec![EnvPathSelection { index: 1, raw: r"C:\Gone\bin".into() }],
            true,
            Some(root.join("backups").display().to_string()),
            &dirs(&root),
        )
        .unwrap();

        assert!(!report.executed);
        assert_eq!(report.items[0].status, EnvPathCleanStatus::Failed);
        assert_eq!(store.value.borrow().as_deref(), Some(PATH), "the original value must be restored");

        let _ = fs::remove_dir_all(&root);
    }
}
