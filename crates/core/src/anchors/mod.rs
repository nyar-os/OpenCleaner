//! Config-declared build roots.
//!
//! A shared build directory has no project manifest, so no heuristic may claim
//! it. The only accepted evidence is an operator-declared absolute path in a
//! plain-text config, one path per line. The config path and line number travel
//! with every entry so an audit record can name the exact authorization.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    Error, Result,
    locations::base_dirs,
    safety::{self, RECENT_WRITE_MS},
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BuildRootOptions {
    pub config: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BuildRootCleanOptions {
    pub config: Option<String>,
    pub paths: Vec<String>,
    pub confirm: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BuildRootDeclaration {
    pub path: String,
    pub line: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BuildRootConfig {
    pub config_path: String,
    pub exists: bool,
    pub declarations: Vec<BuildRootDeclaration>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BuildRootEntry {
    pub path: String,
    pub line: u64,
    pub bytes: u64,
    pub files: u64,
    pub removable: bool,
    pub skip_reason: Option<String>,
    /// Human-readable proof of authorization, for example
    /// `line 3 of C:\...\build-roots.conf`.
    pub authorization: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BuildRootPlan {
    pub config_path: String,
    pub config_exists: bool,
    pub entries: Vec<BuildRootEntry>,
    pub total_bytes: u64,
    pub removable_bytes: u64,
    pub warnings: Vec<String>,
    pub scanned_at_unix_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BuildRootCleanItem {
    pub path: String,
    pub line: u64,
    pub bytes: u64,
    pub files: u64,
    pub status: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BuildRootCleanReport {
    pub config_path: String,
    pub executed: bool,
    pub items: Vec<BuildRootCleanItem>,
    pub deleted_dirs: u64,
    pub freed_bytes: u64,
    pub warnings: Vec<String>,
    pub finished_at_unix_ms: u64,
}

/// Config file used when the caller does not pass one.
pub fn default_build_root_config() -> Option<PathBuf> {
    base_dirs().data_dir.map(|dir| dir.join("open-cleaner").join("build-roots.conf"))
}

fn resolve_config(config: Option<&str>) -> Result<PathBuf> {
    match config {
        Some(value) if !value.trim().is_empty() => Ok(PathBuf::from(value.trim())),
        _ => {
            default_build_root_config().ok_or_else(|| Error::Message("build-roots: no config path and no platform data directory".to_string()))
        }
    }
}

/// Parse the line-oriented config. Blank lines and `#` comments are ignored,
/// and every other line is returned with its 1-based line number.
pub fn parse_build_root_config(text: &str, config_path: &str) -> BuildRootConfig {
    let mut config = BuildRootConfig { config_path: config_path.to_string(), exists: true, ..BuildRootConfig::default() };
    for (index, raw) in text.lines().enumerate() {
        let line = index as u64 + 1;
        let value = raw.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        config.declarations.push(BuildRootDeclaration { path: value.to_string(), line });
    }
    config
}

/// Read the config without touching any directory.
pub fn build_root_config(options: BuildRootOptions) -> Result<BuildRootConfig> {
    let path = resolve_config(options.config.as_deref())?;
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BuildRootConfig {
                config_path: path.display().to_string(),
                exists: false,
                declarations: Vec::new(),
                warnings: vec![format!("config file not found: {}", path.display())],
            });
        }
        Err(error) => return Err(Error::Io { path: path.display().to_string(), source: error }),
    };
    Ok(parse_build_root_config(&text, &path.display().to_string()))
}

fn authorization_label(config_path: &str, line: u64) -> String {
    format!("line {line} of {config_path}")
}

/// Full safety evaluation of one declared path. The checks are identical for a
/// plan and for an execution so a directory cannot become removable in between.
fn evaluate(path: &Path) -> std::result::Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("not an absolute path: {}", path.display()));
    }
    let meta = safety::ensure_cleanup_root(path, "build-roots").map_err(|error| error.to_string())?;
    if !meta.is_dir() {
        return Err(format!("not a directory: {}", path.display()));
    }
    safety::ensure_not_install_root(path, "build-roots").map_err(|error| error.to_string())?;
    Ok(())
}

pub fn build_root_plan(options: BuildRootOptions) -> Result<BuildRootPlan> {
    let config = build_root_config(options)?;
    let mut plan = BuildRootPlan {
        config_path: config.config_path.clone(),
        config_exists: config.exists,
        warnings: config.warnings,
        scanned_at_unix_ms: safety::now_unix_ms(),
        ..BuildRootPlan::default()
    };
    let mut seen: Vec<(String, u64)> = Vec::new();
    for declaration in &config.declarations {
        let path = PathBuf::from(&declaration.path);
        let authorization = authorization_label(&config.config_path, declaration.line);
        let mut entry = BuildRootEntry {
            path: declaration.path.clone(),
            line: declaration.line,
            authorization,
            removable: false,
            ..BuildRootEntry::default()
        };
        let key = safety::path_key(&path);
        let skip_reason = if let Some((_, first_line)) = seen.iter().find(|(value, _)| *value == key) {
            Some(format!("duplicate declaration, first declared at line {first_line}"))
        }
        else {
            seen.push((key, declaration.line));
            evaluate(&path).err()
        };
        if let Some(reason) = skip_reason {
            entry.skip_reason = Some(reason);
            plan.entries.push(entry);
            continue;
        }
        let usage = safety::collect_usage(&path);
        if usage.errors > 0 {
            entry.skip_reason = Some(format!("{} entries under this root could not be read", usage.errors));
            plan.entries.push(entry);
            continue;
        }
        entry.bytes = usage.bytes;
        entry.files = usage.files;
        plan.total_bytes = plan.total_bytes.saturating_add(usage.bytes);
        if safety::probe_dir_in_use(&path) {
            entry.skip_reason = Some("a process holds this directory open".to_string());
        }
        else if usage.newest_unix_ms.is_some_and(|stamp| safety::now_unix_ms().saturating_sub(stamp) < RECENT_WRITE_MS) {
            entry.skip_reason = Some("written within the last 10 minutes".to_string());
        }
        else {
            entry.removable = true;
            plan.removable_bytes = plan.removable_bytes.saturating_add(usage.bytes);
        }
        plan.entries.push(entry);
    }
    Ok(plan)
}

pub fn build_root_clean(options: BuildRootCleanOptions) -> Result<BuildRootCleanReport> {
    if !options.confirm {
        return Err(Error::Message("build-roots: refusing to delete without confirm".to_string()));
    }
    if options.paths.is_empty() {
        return Err(Error::Message("build-roots: no declared path selected for removal".to_string()));
    }
    let config_path = resolve_config(options.config.as_deref())?;
    let text = std::fs::read_to_string(&config_path).map_err(|error| Error::Io { path: config_path.display().to_string(), source: error })?;
    let config = parse_build_root_config(&text, &config_path.display().to_string());
    let mut report = BuildRootCleanReport {
        config_path: config.config_path.clone(),
        executed: true,
        finished_at_unix_ms: safety::now_unix_ms(),
        ..BuildRootCleanReport::default()
    };
    for requested in &options.paths {
        let path = PathBuf::from(requested);
        let key = safety::path_key(&path);
        let Some(declaration) = config.declarations.iter().find(|item| safety::path_key(Path::new(&item.path)) == key)
        else {
            report.items.push(BuildRootCleanItem {
                path: requested.clone(),
                line: 0,
                status: "skipped".to_string(),
                reason: Some(format!("not declared in {}", config.config_path)),
                ..BuildRootCleanItem::default()
            });
            continue;
        };
        let mut item = BuildRootCleanItem {
            path: declaration.path.clone(),
            line: declaration.line,
            status: "skipped".to_string(),
            ..BuildRootCleanItem::default()
        };
        if let Err(reason) = evaluate(&path) {
            item.reason = Some(reason);
            report.items.push(item);
            continue;
        }
        let usage = safety::collect_usage(&path);
        item.bytes = usage.bytes;
        item.files = usage.files;
        if usage.errors > 0 {
            item.reason = Some(format!("{} entries under this root could not be read", usage.errors));
            report.items.push(item);
            continue;
        }
        if safety::probe_dir_in_use(&path) {
            item.reason = Some("a process holds this directory open".to_string());
            report.items.push(item);
            continue;
        }
        if usage.newest_unix_ms.is_some_and(|stamp| safety::now_unix_ms().saturating_sub(stamp) < RECENT_WRITE_MS) {
            item.reason = Some("written within the last 10 minutes".to_string());
            report.items.push(item);
            continue;
        }
        match std::fs::remove_dir_all(&path) {
            Ok(()) => {
                item.status = "deleted".to_string();
                report.deleted_dirs += 1;
                report.freed_bytes = report.freed_bytes.saturating_add(usage.bytes);
            }
            Err(error) => item.reason = Some(error.to_string()),
        }
        report.items.push(item);
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_and_blank_lines_are_ignored_with_line_numbers_kept() {
        let config = parse_build_root_config("# shared build caches\n\nC:\\cargo-target\nC:\\_build\n", "C:\\conf\\build-roots.conf");
        assert_eq!(config.declarations.len(), 2);
        assert_eq!(config.declarations[0].line, 3);
        assert_eq!(config.declarations[0].path, r"C:\cargo-target");
        assert_eq!(config.declarations[1].line, 4);
    }

    #[test]
    fn relative_paths_are_rejected_by_evaluation() {
        let reason = evaluate(Path::new("cargo-target")).unwrap_err();
        assert!(reason.contains("absolute"), "{reason}");
    }

    #[test]
    fn drive_roots_are_rejected_by_evaluation() {
        let reason = evaluate(Path::new(r"C:\")).unwrap_err();
        assert!(reason.contains("drive root"), "{reason}");
    }

    #[test]
    fn clean_requires_confirmation_and_a_selection() {
        let error = build_root_clean(BuildRootCleanOptions::default()).unwrap_err();
        assert!(error.to_string().contains("confirm"), "{error}");
        let error = build_root_clean(BuildRootCleanOptions { confirm: true, ..BuildRootCleanOptions::default() }).unwrap_err();
        assert!(error.to_string().contains("no declared path"), "{error}");
    }
}
