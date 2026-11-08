//! PATH value rules. Pure functions over a raw `Path` value so the same logic
//! is covered by fixtures on every platform.

use serde::{Deserialize, Serialize};

use crate::registry::analyze::expand_env;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PathScope {
    /// `HKCU\Environment` — per-user, no elevation needed.
    User,
    /// `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment` —
    /// machine-wide, normally requires elevation to write.
    Machine,
}

impl PathScope {
    pub const fn id(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Machine => "machine",
        }
    }

    pub const fn key_path(self) -> &'static str {
        match self {
            Self::User => r"HKCU\Environment",
            Self::Machine => r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PathIssue {
    /// Empty segment, usually a doubled or trailing separator.
    Empty,
    /// Contains `%VAR%` that the environment cannot expand.
    Unresolved,
    /// Repeats an earlier entry after normalization.
    Duplicate,
    /// The expanded directory does not exist.
    Missing,
}

impl PathIssue {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Unresolved => "unresolved",
            Self::Duplicate => "duplicate",
            Self::Missing => "missing",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvPathEntry {
    pub scope: PathScope,
    pub key_path: String,
    /// Zero-based position inside the raw `;`-separated value.
    pub index: usize,
    /// The segment exactly as written (whitespace trimmed).
    pub raw: String,
    /// `%VAR%` expansion; `None` when the segment is empty or unresolvable.
    pub expanded: Option<String>,
    pub issue: Option<PathIssue>,
    pub evidence: String,
    pub safety: String,
    /// Whether removing this segment is offered at all. Empty and unresolvable
    /// segments are report-only.
    pub removable: bool,
    /// PATH is high risk: nothing is selected by default.
    pub default_selected: bool,
    /// Earlier entry this duplicate issue refers to.
    pub related_index: Option<usize>,
}

pub struct PathContext<'a> {
    pub dir_exists: &'a dyn Fn(&str) -> bool,
    pub env: &'a dyn Fn(&str) -> Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathAnalysis {
    pub entries: Vec<EnvPathEntry>,
    pub warnings: Vec<String>,
}

pub fn analyze(scope: PathScope, value: Option<&str>, ctx: &PathContext<'_>) -> PathAnalysis {
    let key_path = scope.key_path().to_string();
    let Some(value) = value
    else {
        return PathAnalysis { entries: Vec::new(), warnings: vec![format!("no Path value at {key_path}")] };
    };
    if value.trim().is_empty() {
        return PathAnalysis { entries: Vec::new(), warnings: vec![format!("Path value at {key_path} is empty")] };
    }

    let mut entries = Vec::new();
    let mut seen: Vec<Seen> = Vec::new();
    for (index, segment) in value.split(';').enumerate() {
        let raw = segment.trim().to_string();
        if raw.is_empty() {
            entries.push(EnvPathEntry {
                scope,
                key_path: key_path.clone(),
                index,
                raw,
                expanded: None,
                issue: Some(PathIssue::Empty),
                evidence: "empty PATH segment, usually a doubled or trailing separator".to_string(),
                safety: String::new(),
                removable: false,
                default_selected: false,
                related_index: None,
            });
            continue;
        }

        let expanded = if raw.contains('%') {
            match expand_env(&raw, ctx.env) {
                Some(value) => value,
                None => {
                    let evidence = format!("cannot expand environment variable in {raw}");
                    entries.push(EnvPathEntry {
                        scope,
                        key_path: key_path.clone(),
                        index,
                        raw,
                        expanded: None,
                        issue: Some(PathIssue::Unresolved),
                        evidence,
                        safety: String::new(),
                        removable: false,
                        default_selected: false,
                        related_index: None,
                    });
                    continue;
                }
            }
        }
        else {
            raw.clone()
        };
        let expanded = expanded.trim().trim_matches('"').trim().to_string();
        if expanded.is_empty() {
            entries.push(EnvPathEntry {
                scope,
                key_path: key_path.clone(),
                index,
                raw,
                expanded: None,
                issue: Some(PathIssue::Empty),
                evidence: "segment expands to nothing".to_string(),
                safety: String::new(),
                removable: false,
                default_selected: false,
                related_index: None,
            });
            continue;
        }

        let normalized = normalize(&expanded);
        if let Some(first) = seen.iter().find(|seen| seen.normalized == normalized) {
            entries.push(EnvPathEntry {
                scope,
                key_path: key_path.clone(),
                index,
                raw,
                expanded: Some(expanded),
                issue: Some(PathIssue::Duplicate),
                evidence: format!("repeats entry #{} ({})", first.index, first.normalized),
                safety: format!("the earlier identical entry (#{}) stays, so every lookup resolves exactly the same", first.index),
                removable: true,
                default_selected: false,
                related_index: Some(first.index),
            });
            continue;
        }

        let exists = (ctx.dir_exists)(&expanded);
        if !exists {
            entries.push(EnvPathEntry {
                scope,
                key_path: key_path.clone(),
                index,
                raw,
                expanded: Some(expanded),
                issue: Some(PathIssue::Missing),
                evidence: "the expanded directory does not exist".to_string(),
                safety: "a PATH entry that points at a missing folder cannot resolve anything, so removing it does not change which program is found"
                    .to_string(),
                removable: true,
                default_selected: false,
                related_index: None,
            });
            seen.push(Seen { index, normalized });
            continue;
        }

        entries.push(EnvPathEntry {
            scope,
            key_path: key_path.clone(),
            index,
            raw,
            expanded: Some(expanded),
            issue: None,
            evidence: String::new(),
            safety: String::new(),
            removable: false,
            default_selected: false,
            related_index: None,
        });
        seen.push(Seen { index, normalized });
    }

    PathAnalysis { entries, warnings: Vec::new() }
}

struct Seen {
    index: usize,
    normalized: String,
}

/// Windows path comparison: case-insensitive, `/` and `\` equivalent, trailing
/// separator ignored. Written as text so fixtures run identically everywhere.
pub(crate) fn normalize(path: &str) -> String {
    let trimmed = path.trim().trim_matches('"').trim();
    let mut out = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        out.push(if ch == '/' { '\\' } else { ch.to_ascii_lowercase() });
    }
    while out.contains("\\\\") {
        out = out.replace("\\\\", "\\");
    }
    while out.len() > 3 && out.ends_with('\\') {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::registry::model::parse_reg;

    const REG_FIXTURE: &str = r#"Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Environment]
"Path"="C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32;C:\\Gone\\bin;C:\\Program Files\\App\\bin;C:\\Program Files\\App\\bin\\tools;%MISSING_VAR%\\tools;;C:\\Program Files\\App\\bin"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment]
"Path"="C:\\Windows;C:\\Windows\\system32"
"#;

    fn existing() -> BTreeSet<String> {
        [r"C:\Windows\system32", r"C:\Windows", r"C:\Program Files\App\bin", r"C:\Program Files\App\bin\tools"]
            .into_iter()
            .map(normalize)
            .collect()
    }

    fn exists_in(dirs: &BTreeSet<String>) -> impl Fn(&str) -> bool + '_ {
        move |path: &str| dirs.contains(&normalize(path))
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn classifies_missing_duplicate_and_report_only_segments() {
        let snapshot = parse_reg(REG_FIXTURE, "fixture.reg");
        let raw = snapshot.value(PathScope::User.key_path(), "Path").map(|value| value.data.clone());
        let dirs = existing();
        let dir_exists = exists_in(&dirs);
        let ctx = PathContext { dir_exists: &dir_exists, env: &no_env };
        let analysis = analyze(PathScope::User, raw.as_deref(), &ctx);

        let issue = |index: usize| analysis.entries[index].issue;
        assert_eq!(issue(0), None, "{:#?}", analysis.entries);
        assert_eq!(issue(1), None);
        // `C:\Windows\System32` repeats `C:\Windows\system32`.
        assert_eq!(issue(2), Some(PathIssue::Duplicate));
        assert_eq!(analysis.entries[2].related_index, Some(0));
        // Missing folder.
        assert_eq!(issue(3), Some(PathIssue::Missing));
        assert_eq!(issue(4), None);
        // A child of an earlier entry is its own lookup directory: PATH is
        // searched flat, so `...\App\bin` does not cover `...\App\bin\tools`.
        assert_eq!(issue(5), None);
        assert_eq!(analysis.entries[5].related_index, None);
        // Unknown variable is reported but never removable.
        assert_eq!(issue(6), Some(PathIssue::Unresolved));
        assert!(!analysis.entries[6].removable);
        // Empty segment from the doubled separator.
        assert_eq!(issue(7), Some(PathIssue::Empty));
        assert!(!analysis.entries[7].removable);
        // Trailing repeat of entry #4.
        assert_eq!(issue(8), Some(PathIssue::Duplicate));
        assert_eq!(analysis.entries[8].related_index, Some(4));

        for entry in &analysis.entries {
            assert!(!entry.default_selected, "PATH entries must never be pre-selected: {entry:?}");
            assert_eq!(entry.scope, PathScope::User);
            assert_eq!(entry.key_path, PathScope::User.key_path());
        }
        for entry in analysis.entries.iter().filter(|entry| entry.issue.is_some()) {
            assert!(!entry.evidence.is_empty(), "{entry:?}");
            if entry.removable {
                assert!(!entry.safety.is_empty(), "{entry:?}");
            }
        }
        assert!(analysis.entries.iter().filter(|entry| entry.issue.is_none()).all(|entry| !entry.removable));
    }

    #[test]
    fn expansion_feeds_the_existence_check() {
        let snapshot = parse_reg(REG_FIXTURE, "fixture.reg");
        let machine = snapshot.value(PathScope::Machine.key_path(), "Path").map(|value| value.data.clone());
        let env = |name: &str| match name {
            "MISSING_VAR" => Some(r"C:\Gone\bin".to_string()),
            _ => None,
        };
        let dirs = existing();
        let dir_exists = exists_in(&dirs);
        let ctx = PathContext { dir_exists: &dir_exists, env: &env };
        let analysis = analyze(PathScope::Machine, machine.as_deref(), &ctx);

        assert_eq!(analysis.entries.len(), 2);
        assert_eq!(analysis.entries[0].issue, None);
        // `C:\Windows\system32` is a separate lookup directory, not a redundant
        // child of the earlier `C:\Windows` entry.
        assert_eq!(analysis.entries[1].issue, None);
        assert_eq!(analysis.warnings.len(), 0);
    }

    #[test]
    fn resolved_variables_turn_into_real_findings() {
        let dirs = existing();
        let env = |name: &str| match name {
            "MISSING_VAR" => Some(r"C:\Not There".to_string()),
            _ => None,
        };
        let dir_exists = exists_in(&dirs);
        let ctx = PathContext { dir_exists: &dir_exists, env: &env };
        let analysis = analyze(PathScope::User, Some(r"%MISSING_VAR%\tools"), &ctx);

        assert_eq!(analysis.entries[0].issue, Some(PathIssue::Missing));
        assert_eq!(analysis.entries[0].expanded.as_deref(), Some(r"C:\Not There\tools"));
        assert!(analysis.entries[0].removable);
    }

    #[test]
    fn quotes_and_slashes_are_normalized_for_comparison() {
        let dirs = existing();
        let dir_exists = exists_in(&dirs);
        let ctx = PathContext { dir_exists: &dir_exists, env: &no_env };
        let analysis = analyze(PathScope::User, Some(r#""C:/Program Files/App/bin";C:\Program Files\App\bin\"#), &ctx);

        assert_eq!(analysis.entries[0].issue, None, "{:#?}", analysis.entries);
        assert_eq!(analysis.entries[1].issue, Some(PathIssue::Duplicate));
        assert_eq!(analysis.entries[1].related_index, Some(0));
    }

    #[test]
    fn empty_values_and_missing_values_are_not_silently_healthy() {
        let dirs = existing();
        let dir_exists = exists_in(&dirs);
        let ctx = PathContext { dir_exists: &dir_exists, env: &no_env };
        assert!(analyze(PathScope::User, None, &ctx).warnings[0].contains("no Path value"));
        assert!(analyze(PathScope::User, Some("   "), &ctx).warnings[0].contains("empty"));
    }

    #[test]
    fn drive_root_does_not_shadow_its_children() {
        let dirs: BTreeSet<String> = [r"C:\", r"C:\Windows"].into_iter().map(normalize).collect();
        let dir_exists = exists_in(&dirs);
        let ctx = PathContext { dir_exists: &dir_exists, env: &no_env };
        let analysis = analyze(PathScope::User, Some(r"C:\;C:\Windows"), &ctx);
        assert_eq!(analysis.entries[0].issue, None);
        assert_eq!(analysis.entries[1].issue, None);
    }
}
