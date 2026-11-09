//! Controlled synthetic-tree benchmark for the developer-artifact pipeline.
//!
//! The corpus is deterministic and small (tens of MB, thousands of files): many
//! small files, a few large ones, deep trees, anchored projects and name-only
//! distractors that must never become candidates. Nothing outside the corpus is
//! scanned and no global cache is included.
//!
//! Run with profiling enabled:
//!
//! ```text
//! OPEN_CLEANER_PROFILE=1 cargo run --release -p open-cleaner-core --example dev_bench -- --phase all
//! ```
//!
//! Flags: `--root <dir>` reuses an existing corpus, `--keep` keeps a generated
//! corpus, `--concurrency <n>` sets the clean worker count, `--baseline <scan|none>`
//! selects whether the delete reuses the scan-time size or measures every tree
//! again, `--phase scan` stops after the dry-run plan.

use std::{
    env,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use open_cleaner_core::{DeleteMode, DevCleanOptions, DevScanOptions, dev_clean, dev_plan, dev_scan};

const SMALL: usize = 512;

fn main() {
    let args = args();
    let phase = args.get("--phase").cloned().unwrap_or_else(|| "all".to_string());
    let concurrency = args.get("--concurrency").and_then(|value| value.parse::<usize>().ok());
    let baseline_mode = args.get("--baseline").cloned().unwrap_or_else(|| "scan".to_string());
    let keep = args.contains_key("--keep");

    let generated = !args.contains_key("--root");
    let root = match args.get("--root") {
        Some(path) => PathBuf::from(path),
        // The generated corpus stays under the build directory: a benchmark
        // must not write into the user's temp directory it may also be cleaning.
        None => std::env::current_exe()
            .ok()
            .and_then(|exe| {
                exe.parent().and_then(|examples| examples.parent()).map(|profile| profile.join("test-tmp").join("open-cleaner-bench"))
            })
            .unwrap_or_else(|| env::temp_dir().join("open-cleaner-bench")),
    };

    if generated {
        if root.exists() {
            fs::remove_dir_all(&root).expect("clear previous corpus");
        }
        fs::create_dir_all(&root).expect("create corpus root");
        let started = std::time::Instant::now();
        build_corpus(&root).expect("build corpus");
        println!("corpus: generated {} in {:.1}s", root.display(), started.elapsed().as_secs_f64());
        println!("corpus: on-disk {}", dir_size_bytes(&root).unwrap_or(0));
    }

    let symlink_anchor = root.join("link-project");
    println!("symlink gate corpus: {}", if symlink_anchor.exists() { "present" } else { "absent" });

    let scan = dev_scan(DevScanOptions { roots: vec![root.display().to_string()], include_global: false, max_depth: None, limit: None })
        .expect("scan");
    report_scan(&scan, &root);

    let plan = dev_plan(
        DevScanOptions { roots: vec![root.display().to_string()], include_global: false, max_depth: None, limit: None },
        DeleteMode::Permanent,
    )
    .expect("plan");
    report_plan(&plan);
    if phase == "scan" {
        if generated && !keep {
            let _ = fs::remove_dir_all(&root);
        }
        return;
    }

    let selected: Vec<open_cleaner_core::DevCleanTarget> = plan
        .items
        .iter()
        .filter(|item| item.removable)
        .map(|item| open_cleaner_core::DevCleanTarget {
            path: item.artifact.path.clone(),
            baseline: if baseline_mode == "none" { None } else { item.artifact.baseline.clone() },
        })
        .collect();
    let planned_bytes: u64 = plan.items.iter().filter(|item| item.removable).map(|item| item.artifact.bytes).sum();
    let report = dev_clean(DevCleanOptions { targets: selected, mode: DeleteMode::Permanent, confirm: true, concurrency }).expect("clean");
    report_clean(&report, planned_bytes, &baseline_mode);

    if generated && keep {
        println!("corpus kept at {}", root.display());
    }
    else if generated {
        let _ = fs::remove_dir_all(&root);
    }
}

fn args() -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let mut argv = env::args().skip(1);
    while let Some(arg) = argv.next() {
        if let Some(value) = argv.next()
            && !value.starts_with("--")
        {
            out.insert(arg, value);
            continue;
        }
        out.insert(arg, String::new());
    }
    out
}

fn report_scan(report: &open_cleaner_core::DevScanReport, root: &Path) {
    println!("\n== scan ==");
    println!("projects: {}  artifacts: {}  anchors: {:?}", report.scanned_projects, report.artifacts.len(), report.anchors);
    println!("artifact checksum: {:016x}", checksum(report, root));
    let bytes: u64 = report.artifacts.iter().map(|artifact| artifact.bytes).sum();
    println!("artifact bytes: {bytes}");
    if let Some(profile) = &report.profile {
        stages(profile);
        let scan_ms = stage_ms(profile, "scan");
        let measure_ms = stage_ms(profile, "measurement");
        println!(
            "dirs: {} listed  {} measured  files: {}  bytes: {}",
            profile.dirs_visited, profile.measured_dirs, profile.files_visited, profile.bytes_measured
        );
        println!(
            "rates: {:.1} dirs/s (walk)  {:.1} files/s  {}/s (measure)",
            per_second(profile.dirs_visited, scan_ms),
            per_second(profile.files_visited, measure_ms),
            human(per_second(profile.bytes_measured, measure_ms))
        );
        println!("peak working set: {}  peak handles: {}", opt_bytes(profile.peak_working_set_bytes), opt_num(profile.peak_handle_count));
    }
}

fn report_plan(plan: &open_cleaner_core::DevPlan) {
    println!("\n== plan ==");
    let removable = plan.items.iter().filter(|item| item.removable).count();
    println!("removable: {removable} of {}  bytes: {}  skipped: {}", plan.items.len(), plan.removable_bytes, plan.skipped_bytes);
    for item in &plan.items {
        if let Some(reason) = item.skip_reason {
            println!("skip: {}  {}", reason.as_str(), item.artifact.path);
        }
    }
    if let Some(profile) = &plan.profile {
        stages(profile);
        println!("peak working set: {}  peak handles: {}", opt_bytes(profile.peak_working_set_bytes), opt_num(profile.peak_handle_count));
    }
}

fn report_clean(report: &open_cleaner_core::DevCleanReport, planned_bytes: u64, baseline_mode: &str) {
    println!("\n== clean ==");
    let deleted = report.items.iter().filter(|item| matches!(item.status, open_cleaner_core::CleanStatus::Deleted)).count();
    let skipped = report.items.iter().filter(|item| matches!(item.status, open_cleaner_core::CleanStatus::Skipped)).count();
    let failed = report.items.iter().filter(|item| matches!(item.status, open_cleaner_core::CleanStatus::Failed)).count();
    println!("deleted {deleted}  skipped {skipped}  failed {failed}  freed {}", report.freed_bytes);
    println!(
        "policy: baseline={baseline_mode}  freed scanned {}  freed remeasured {}",
        report.freed_bytes_scanned, report.freed_bytes_remeasured
    );
    println!(
        "freed vs plan bytes: {} (freed {} / plan {planned_bytes})",
        if report.freed_bytes == planned_bytes { "PASS" } else { "FAIL" },
        report.freed_bytes
    );
    for item in &report.items {
        if matches!(item.status, open_cleaner_core::CleanStatus::Failed | open_cleaner_core::CleanStatus::Skipped) {
            println!("{:?}: {}  {}", item.status, item.path, item.reason.clone().unwrap_or_default());
        }
    }
    if let Some(profile) = &report.profile {
        stages(profile);
        let delete_ms = stage_ms(profile, "delete");
        println!(
            "delete: {}/s  {:.1} items/s",
            human(report.freed_bytes as f64 / (delete_ms / 1000.0).max(f64::EPSILON)),
            per_second(deleted as u64, delete_ms)
        );
        println!("peak working set: {}  peak handles: {}", opt_bytes(profile.peak_working_set_bytes), opt_num(profile.peak_handle_count));
    }
}

fn stages(profile: &open_cleaner_core::DevProfile) {
    for stage in &profile.stages {
        println!("stage {:<12} {:>10.1} ms", stage.name, stage.elapsed_ms);
    }
}

fn stage_ms(profile: &open_cleaner_core::DevProfile, name: &str) -> f64 {
    profile.stages.iter().filter(|stage| stage.name == name).map(|stage| stage.elapsed_ms).sum()
}

fn checksum(report: &open_cleaner_core::DevScanReport, root: &Path) -> u64 {
    let mut rows: Vec<(String, u64)> = report
        .artifacts
        .iter()
        .map(|artifact| {
            let relative = Path::new(&artifact.path).strip_prefix(root).unwrap_or(Path::new(&artifact.path));
            (relative.display().to_string(), artifact.bytes)
        })
        .collect();
    rows.sort();
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for (path, bytes) in rows {
        for byte in path.as_bytes().iter().copied().chain(bytes.to_le_bytes()) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    }
    hash
}

fn per_second(count: u64, ms: f64) -> f64 {
    if ms <= 0.0 { 0.0 } else { count as f64 / (ms / 1000.0) }
}

fn human(bytes: f64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < units.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.2} {}", units[unit])
}

fn opt_bytes(value: Option<u64>) -> String {
    value.map(|bytes| human(bytes as f64)).unwrap_or_else(|| "n/a".to_string())
}

fn opt_num(value: Option<u32>) -> String {
    value.map(|count| count.to_string()).unwrap_or_else(|| "n/a".to_string())
}

// ---------------------------------------------------------------- corpus ----

fn build_corpus(root: &Path) -> std::io::Result<()> {
    for project in 0..40 {
        let dir = root.join(format!("crate-{project:02}"));
        write(&dir.join("Cargo.toml"), 48)?;
        write(&dir.join("src").join("main.rs"), 96)?;
        let mut module = dir.join("src");
        for depth in 0..6 {
            module = module.join(format!("mod{depth}"));
            write(&module.join("mod.rs"), 128)?;
        }
        let target = dir.join("target");
        small_tree(&target.join("debug"), 60, 1_024)?;
        small_tree(&target.join("deps"), 40, 2_048)?;
        small_tree(&target.join("incremental").join(format!("s{project}")), 30, SMALL)?;
        write(&target.join("build").join("out.bin"), 4_096)?;
        if project % 8 == 0 {
            write(&target.join("debug").join("big.rlib"), 3_000_000)?;
        }
    }

    for project in 0..20 {
        let dir = root.join(format!("node-{project:02}"));
        write(&dir.join("package.json"), 40)?;
        write(&dir.join("src").join("index.js"), 80)?;
        dependency_tree(&dir.join("node_modules"), 0, 3, 4, 256)?;
        write(&dir.join("dist").join("bundle.js"), 2_048)?;
    }

    // Name-only distractors: no manifest, so no artifact may be reported.
    for project in 0..10 {
        let dir = root.join(format!("scratch-{project:02}"));
        write(&dir.join("target").join("debug").join("data.bin"), 4_096)?;
        write(&dir.join("node_modules").join("dep").join("index.js"), 4_096)?;
        write(&dir.join("build").join("out.bin"), 1_024)?;
    }

    // Deep chain without a manifest, exercising project-tree depth.
    let mut deep = root.join("deep");
    for depth in 0..18 {
        deep = deep.join(format!("d{depth}"));
        write(&deep.join("index.js"), 64)?;
    }

    // A linked artifact directory must be ignored and never descended.
    let real = root.join("link-store");
    write(&real.join("data.bin"), 8_192)?;
    let link_project = root.join("link-project");
    write(&link_project.join("Cargo.toml"), 48)?;
    let _ = link_dir(&real, &link_project.join("target"));
    Ok(())
}

fn small_tree(dir: &Path, count: usize, size: usize) -> std::io::Result<()> {
    for bucket in 0..count / 10 {
        let bucket = dir.join(format!("b{bucket:02}"));
        for index in 0..10 {
            write(&bucket.join(format!("f{index:02}.bin")), size)?;
        }
    }
    Ok(())
}

fn dependency_tree(base: &Path, level: usize, fanout: usize, depth: usize, size: usize) -> std::io::Result<()> {
    for index in 0..fanout {
        let package = base.join(format!("dep-{level}-{index}"));
        write(&package.join("package.json"), 32)?;
        write(&package.join("index.js"), size)?;
        write(&package.join("lib").join("util.js"), size)?;
        if level + 1 < depth {
            dependency_tree(&package.join("node_modules"), level + 1, fanout, depth, size)?;
        }
    }
    Ok(())
}

fn write(path: &Path, bytes: usize) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = File::create(path)?;
    file.write_all(&vec![b'x'; bytes])
}

#[cfg(windows)]
fn link_dir(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_dir(target, link)
}

#[cfg(not(windows))]
fn link_dir(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

fn dir_size_bytes(root: &Path) -> std::io::Result<u64> {
    let mut total = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for item in fs::read_dir(&dir)?.flatten() {
            let Ok(meta) = fs::symlink_metadata(item.path())
            else {
                continue;
            };
            if meta.is_dir() && !platform_link(&meta) {
                stack.push(item.path());
            }
            else if meta.is_file() {
                total += meta.len();
            }
        }
    }
    Ok(total)
}

#[cfg(windows)]
fn platform_link(meta: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn platform_link(meta: &fs::Metadata) -> bool {
    meta.file_type().is_symlink()
}
