//! Manifest anchors and the fixed artifact rule table.
//!
//! A directory name is never enough on its own: every candidate must be
//! justified by a manifest in the owning project root.

use std::{
    ffi::OsStr,
    fs,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManifestKind {
    CargoToml,
    PackageJson,
    PnpmLock,
    YarnLock,
    PackageLock,
    PyProject,
    GoMod,
    Gradle,
    Maven,
    Gemfile,
    Nuget,
}

impl ManifestKind {
    /// Canonical anchor file name used in reports (`*.csproj` stands for the
    /// NuGet family).
    pub const fn id(self) -> &'static str {
        match self {
            Self::CargoToml => "Cargo.toml",
            Self::PackageJson => "package.json",
            Self::PnpmLock => "pnpm-lock.yaml",
            Self::YarnLock => "yarn.lock",
            Self::PackageLock => "package-lock.json",
            Self::PyProject => "pyproject.toml",
            Self::GoMod => "go.mod",
            Self::Gradle => "build.gradle",
            Self::Maven => "pom.xml",
            Self::Gemfile => "Gemfile",
            Self::Nuget => "*.csproj",
        }
    }

    /// Case-insensitive manifest match without allocating a lowercase copy.
    fn from_name_ci(name: &str) -> Option<Self> {
        const NAMES: &[(&str, ManifestKind)] = &[
            ("cargo.toml", ManifestKind::CargoToml),
            ("package.json", ManifestKind::PackageJson),
            ("pnpm-lock.yaml", ManifestKind::PnpmLock),
            ("yarn.lock", ManifestKind::YarnLock),
            ("package-lock.json", ManifestKind::PackageLock),
            ("pyproject.toml", ManifestKind::PyProject),
            ("go.mod", ManifestKind::GoMod),
            ("build.gradle", ManifestKind::Gradle),
            ("build.gradle.kts", ManifestKind::Gradle),
            ("settings.gradle", ManifestKind::Gradle),
            ("settings.gradle.kts", ManifestKind::Gradle),
            ("pom.xml", ManifestKind::Maven),
            ("gemfile", ManifestKind::Gemfile),
            ("packages.config", ManifestKind::Nuget),
        ];
        for (candidate, kind) in NAMES {
            if name.eq_ignore_ascii_case(candidate) {
                return Some(*kind);
            }
        }
        if ends_with_ignore_ascii(name, ".csproj") || ends_with_ignore_ascii(name, ".sln") {
            return Some(Self::Nuget);
        }
        None
    }

    /// Manifest detection from a directory entry name. Non-UTF-8 names fall
    /// back to a lossy comparison; manifests are ASCII in practice.
    pub fn from_os_name(name: &OsStr) -> Option<Self> {
        match name.to_str() {
            Some(text) => Self::from_name_ci(text),
            None => Self::from_name_ci(&name.to_string_lossy()),
        }
    }
}

fn ends_with_ignore_ascii(name: &str, suffix: &str) -> bool {
    name.len() >= suffix.len() && name.as_bytes()[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix.as_bytes())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ecosystem {
    Cargo,
    Node,
    Npm,
    Pnpm,
    Yarn,
    Python,
    Go,
    Gradle,
    Maven,
    Nuget,
    Bundler,
}

impl Ecosystem {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::Node => "node",
            Self::Npm => "npm",
            Self::Pnpm => "pnpm",
            Self::Yarn => "yarn",
            Self::Python => "python",
            Self::Go => "go",
            Self::Gradle => "gradle",
            Self::Maven => "maven",
            Self::Nuget => "nuget",
            Self::Bundler => "bundler",
        }
    }
}

/// One project-local artifact rule: a manifest anchor plus a fixed relative
/// directory.
#[derive(Debug, Clone, Copy)]
pub struct ProjectRule {
    pub anchor: ManifestKind,
    pub ecosystem: Ecosystem,
    pub artifact: &'static str,
}

/// Level-1 (project-local, rebuildable) rules. Directory names outside this
/// table are never candidates.
pub const PROJECT_RULES: &[ProjectRule] = &[
    ProjectRule { anchor: ManifestKind::CargoToml, ecosystem: Ecosystem::Cargo, artifact: "target" },
    ProjectRule { anchor: ManifestKind::PackageJson, ecosystem: Ecosystem::Node, artifact: "node_modules" },
    ProjectRule { anchor: ManifestKind::PackageJson, ecosystem: Ecosystem::Node, artifact: "dist" },
    ProjectRule { anchor: ManifestKind::PackageJson, ecosystem: Ecosystem::Node, artifact: "build" },
    ProjectRule { anchor: ManifestKind::PackageJson, ecosystem: Ecosystem::Node, artifact: ".next" },
    ProjectRule { anchor: ManifestKind::PackageJson, ecosystem: Ecosystem::Node, artifact: ".turbo" },
    ProjectRule { anchor: ManifestKind::PyProject, ecosystem: Ecosystem::Python, artifact: ".venv" },
    ProjectRule { anchor: ManifestKind::PyProject, ecosystem: Ecosystem::Python, artifact: "venv" },
    ProjectRule { anchor: ManifestKind::Gradle, ecosystem: Ecosystem::Gradle, artifact: "build" },
    ProjectRule { anchor: ManifestKind::Gradle, ecosystem: Ecosystem::Gradle, artifact: ".gradle" },
    ProjectRule { anchor: ManifestKind::Maven, ecosystem: Ecosystem::Maven, artifact: "target" },
    ProjectRule { anchor: ManifestKind::Gemfile, ecosystem: Ecosystem::Bundler, artifact: "vendor/bundle" },
    ProjectRule { anchor: ManifestKind::Nuget, ecosystem: Ecosystem::Nuget, artifact: "obj" },
    ProjectRule { anchor: ManifestKind::Nuget, ecosystem: Ecosystem::Nuget, artifact: "bin" },
];

/// Directory names the project walk never descends into. They are either
/// artifacts themselves or repositories of unrelated projects.
const SKIP_DESCEND: &[&str] =
    &[".git", "node_modules", "target", "dist", "build", ".next", ".turbo", ".venv", "venv", "vendor", ".gradle", "obj", "bin"];

/// Names that can never become a candidate even if a rule is added later.
const PROTECTED_NAMES: &[&str] = &[
    ".git",
    ".github",
    ".cargo",
    ".rustup",
    "cargo.toml",
    "cargo.lock",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "pyproject.toml",
    "go.mod",
    "go.sum",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "gemfile",
    "gemfile.lock",
    "rust-toolchain.toml",
    "rustfmt.toml",
];

pub fn should_skip_descend(name: &OsStr) -> bool {
    match name.to_str() {
        Some(text) => SKIP_DESCEND.iter().any(|candidate| text.eq_ignore_ascii_case(candidate)),
        None => {
            let text = name.to_string_lossy();
            SKIP_DESCEND.iter().any(|candidate| text.eq_ignore_ascii_case(candidate))
        }
    }
}

/// Reject paths that must never be deleted: repositories, manifests,
/// lockfiles, toolchains and SDK roots.
pub fn is_protected(path: &Path) -> bool {
    path.components().any(|component| match component {
        Component::Normal(name) => {
            let lower = name.to_string_lossy().to_ascii_lowercase();
            lower == ".git" || lower == ".rustup" || PROTECTED_NAMES.contains(&lower.as_str())
        }
        _ => false,
    })
}

/// Detect manifests in one directory. Order is stable so report output is
/// deterministic.
pub fn detect_manifests(dir: &Path) -> Vec<ManifestKind> {
    let Ok(read) = fs::read_dir(dir)
    else {
        return Vec::new();
    };
    let mut found = std::collections::BTreeSet::new();
    for item in read.flatten() {
        let Ok(file_type) = item.file_type()
        else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }
        if let Some(kind) = ManifestKind::from_os_name(&item.file_name()) {
            found.insert(kind);
        }
    }
    // BTreeSet ordering is by enum declaration order (derive Ord), which matches
    // the table order above.
    found.into_iter().collect()
}

pub fn project_rules(anchor: ManifestKind) -> impl Iterator<Item = &'static ProjectRule> {
    PROJECT_RULES.iter().filter(move |rule| rule.anchor == anchor)
}

/// Join a relative artifact path (which may contain `/`).
pub fn artifact_path(root: &Path, artifact: &str) -> PathBuf {
    let mut path = root.to_path_buf();
    for part in artifact.split('/') {
        path.push(part);
    }
    path
}

/// Match only the trailing artifact name(s), ignoring the anchor manifest.
///
/// Execution-time verification uses this to distinguish "the path no longer
/// looks like an artifact" from "the manifest disappeared".
pub fn match_rule_suffix(candidate: &Path) -> Option<(&'static ProjectRule, PathBuf)> {
    if !candidate.is_absolute() {
        return None;
    }
    for rule in PROJECT_RULES {
        let parts: Vec<&str> = rule.artifact.split('/').collect();
        let tail = candidate.components().rev().take(parts.len()).collect::<Vec<_>>();
        if tail.len() != parts.len() {
            continue;
        }
        let matches = tail.iter().rev().zip(parts.iter()).all(|(component, expected)| match component {
            Component::Normal(name) => name.to_string_lossy().eq_ignore_ascii_case(expected),
            _ => false,
        });
        if !matches {
            continue;
        }

        let mut root = candidate.to_path_buf();
        for _ in parts {
            root.pop();
        }
        return Some((rule, root));
    }
    None
}

/// Re-derive the owning project root and rule for an existing candidate.
///
/// Used at execution time so a caller cannot hand in an arbitrary path.
pub fn resolve_project_artifact(candidate: &Path) -> Option<(&'static ProjectRule, PathBuf)> {
    let (rule, root) = match_rule_suffix(candidate)?;
    let manifests = detect_manifests(&root);
    if manifests.contains(&rule.anchor) { Some((rule, root)) } else { None }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn fixture(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("open-cleaner-rules-{}-{name}", std::process::id()));
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

    #[test]
    fn recognizes_rules_only_with_their_anchor() {
        let root = fixture("anchor");
        touch(&root.join("Cargo.toml"), 8);
        touch(&root.join("package.json"), 8);
        touch(&root.join("go.mod"), 8);
        touch(&root.join("pyproject.toml"), 8);
        touch(&root.join("pom.xml"), 8);
        touch(&root.join("Gemfile"), 8);

        let manifests = detect_manifests(&root);
        assert!(manifests.contains(&ManifestKind::CargoToml));
        assert!(manifests.contains(&ManifestKind::GoMod));
        assert!(!manifests.contains(&ManifestKind::PnpmLock));
        assert!(!manifests.contains(&ManifestKind::Nuget));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn same_name_without_manifest_is_not_a_candidate() {
        let root = fixture("no-anchor");
        fs::create_dir_all(root.join("target")).unwrap();
        fs::create_dir_all(root.join("node_modules")).unwrap();

        assert!(resolve_project_artifact(&root.join("target")).is_none());
        assert!(resolve_project_artifact(&root.join("node_modules")).is_none());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn manifest_makes_candidate_resolvable() {
        let root = fixture("with-anchor");
        touch(&root.join("Cargo.toml"), 8);
        fs::create_dir_all(root.join("target")).unwrap();

        let (rule, resolved_root) = resolve_project_artifact(&root.join("target")).unwrap();
        assert_eq!(rule.artifact, "target");
        assert_eq!(rule.ecosystem, Ecosystem::Cargo);
        assert_eq!(resolved_root, root);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn nested_artifact_path_requires_full_suffix() {
        let root = fixture("vendor");
        touch(&root.join("Gemfile"), 8);
        fs::create_dir_all(root.join("vendor").join("bundle")).unwrap();

        let (rule, _) = resolve_project_artifact(&root.join("vendor").join("bundle")).unwrap();
        assert_eq!(rule.artifact, "vendor/bundle");
        assert!(resolve_project_artifact(&root.join("vendor")).is_none());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn protected_names_reject_lockfiles_git_and_config() {
        let root = fixture("protected");
        for name in ["Cargo.lock", "package.json", ".git", "pnpm-lock.yaml", "pyproject.toml"] {
            assert!(is_protected(&root.join(name)), "{name} should be protected");
        }
        assert!(is_protected(&root.join("source").join(".git").join("config")));
        assert!(!is_protected(&root.join("target")));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn skip_descend_covers_artifact_directories() {
        assert!(should_skip_descend(OsStr::new("node_modules")));
        assert!(should_skip_descend(OsStr::new(".git")));
        assert!(!should_skip_descend(OsStr::new("packages")));
    }
}
