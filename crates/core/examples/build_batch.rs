//! Build-output domain report and cleaning entry point for real drives.
//!
//! Probes the given roots for Cargo build output proven by markers
//! (`CACHEDIR.TAG` next to `.rustc_info.json` or `*/debug/.fingerprint`),
//! never by a directory name. Relocated `CARGO_TARGET_DIR` trees that live in
//! the temp directory are invisible to the manifest-anchored dev domain and to
//! the temp file rules, so this domain is what reclaims them.
//!
//! Dry plan:
//!
//! ```text
//! cargo run --release -p open-cleaner-core --example build_batch -- --root <dir>
//! ```
//!
//! Flags: `--root <dir>` may repeat, `--min-bytes <n>` raises the size floor,
//! `--clean` deletes the removable items the plan proved.

use open_cleaner_core::{BuildDirCleanOptions, BuildDirCleanTarget, BuildDirOptions, DeleteMode, build_dir_clean, build_dir_plan};

fn main() {
    let mut args = std::env::args().skip(1).peekable();
    let mut roots: Vec<String> = Vec::new();
    let mut min_bytes: u64 = 0;
    let mut clean = false;
    while let Some(arg) = args.next() {
        let value = match args.peek() {
            Some(next) if !next.starts_with("--") => args.next(),
            _ => None,
        };
        match arg.as_str() {
            "--root" => {
                if let Some(root) = value {
                    roots.push(root);
                }
            }
            "--min-bytes" => min_bytes = value.and_then(|value| value.parse().ok()).unwrap_or(0),
            "--clean" => clean = true,
            other => eprintln!("unknown flag: {other}"),
        }
    }
    if roots.is_empty() {
        roots.push(std::env::temp_dir().display().to_string());
    }

    let options = BuildDirOptions { cwd: None, roots: roots.clone(), min_bytes, depth: 0 };
    let plan = build_dir_plan(options, DeleteMode::Permanent).expect("build dir plan");
    println!("roots: {}", plan.roots.join(" "));
    for root in &plan.depth_by_root {
        println!("depth: {} => {}", root.path, root.depth);
    }
    println!("total {} B  removable {} B  skipped {} B", plan.total_bytes, plan.removable_bytes, plan.skipped_bytes);
    for item in &plan.items {
        if item.removable {
            println!("delete: {:>16} B  {}  owner={:?}", item.bytes, item.path, item.owner);
        }
        else {
            println!("skip:   {:>16} B  {}  {:?} {}", item.bytes, item.path, item.skip_reason, item.skip_detail.clone().unwrap_or_default());
        }
    }
    for warning in plan.warnings.iter().take(10) {
        println!("warn: {warning}");
    }

    if !clean {
        return;
    }
    let targets: Vec<BuildDirCleanTarget> = plan
        .items
        .iter()
        .filter(|item| item.removable)
        .map(|item| BuildDirCleanTarget { path: item.path.clone(), owner: item.owner })
        .collect();
    if targets.is_empty() {
        println!("\nnothing removable");
        return;
    }
    let report =
        build_dir_clean(BuildDirCleanOptions { cwd: None, targets, mode: DeleteMode::Permanent, confirm: true }).expect("build dir clean");
    println!("\n== clean ==");
    println!("executed: {}  freed {} B", report.executed, report.freed_bytes);
    for item in &report.items {
        println!("{:?}: {}  {}", item.status, item.path, item.reason.clone().unwrap_or_default());
    }
}
