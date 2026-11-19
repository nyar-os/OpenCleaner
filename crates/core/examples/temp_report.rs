//! Temp-domain report and cleaning entry point for real drives.
//!
//! Dry plan over the process temp directory:
//!
//! ```text
//! cargo run --release -p open-cleaner-core --example temp_report
//! ```
//!
//! Flags: `--root <dir>` picks another tree, `--days <n>` sets the age
//! threshold, `--clean` executes the removal with the plan's cutoff so the same
//! file set is covered. Recent, in-use, symlinked and protected files always
//! stay, so a clean run only deletes what the plan already listed.

use open_cleaner_core::{TempCleanOptions, TempOptions, temp_clean, temp_plan};

fn main() {
    let mut args = std::env::args().skip(1);
    let mut root: Option<String> = None;
    let mut days: Option<u64> = None;
    let mut clean = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => root = args.next(),
            "--days" => days = args.next().and_then(|value| value.parse().ok()),
            "--clean" => clean = true,
            other => eprintln!("unknown flag: {other}"),
        }
    }

    let started = std::time::Instant::now();
    let plan = temp_plan(TempOptions { root: root.clone(), older_than_days: days, sample_limit: Some(15) }).expect("temp plan");
    let elapsed = started.elapsed();

    println!("root: {}", plan.root);
    println!("older_than_days: {}", plan.older_than_days);
    println!("walk: {:.1} s", elapsed.as_secs_f64());
    println!("scanned: {} files  {} bytes", plan.scanned_files, plan.scanned_bytes);
    println!("candidates: {} files  {} bytes", plan.candidate_files, plan.candidate_bytes);

    let skips = &plan.skipped;
    println!(
        "skips: recent {} ({} B)  dir_recent {} ({} B)  in_use {} ({} B)  symlink {} ({} B)  protected {} ({} B)  build_root {} ({} B)  unreadable {} ({} B)",
        skips.recent,
        skips.recent_bytes,
        skips.dir_recent,
        skips.dir_recent_bytes,
        skips.in_use,
        skips.in_use_bytes,
        skips.symlink,
        skips.symlink_bytes,
        skips.protected,
        skips.protected_bytes,
        skips.build_root,
        skips.build_root_bytes,
        skips.unreadable,
        skips.unreadable_bytes
    );
    println!(
        "shields: cwd {}  process_temp {}  program {}  dev_root {}",
        skips.cwd_shielded, skips.process_temp, skips.program_shielded, skips.dev_root
    );

    println!("age groups:");
    for group in &plan.age_groups {
        println!("  {:<14} {:>8} files {:>16} bytes", group.label, group.files, group.bytes);
    }
    println!("largest extensions:");
    for group in plan.extension_groups.iter().take(12) {
        println!("  {:<14} {:>8} files {:>16} bytes", group.label, group.files, group.bytes);
    }
    println!("samples:");
    for file in &plan.samples {
        println!("  {}  {} B  {} d", file.path, file.bytes, file.age_days);
    }
    if !plan.warnings.is_empty() {
        println!("warnings: {}", plan.warnings.len());
        for warning in plan.warnings.iter().take(10) {
            println!("  {warning}");
        }
    }

    if !clean {
        return;
    }

    let report = temp_clean(TempCleanOptions { root, older_than_days: days, cutoff_unix_ms: Some(plan.cutoff_unix_ms), confirm: true })
        .expect("temp clean");
    println!("\n== clean ==");
    println!(
        "executed: {}  candidates {}  deleted {}  freed {} bytes",
        report.executed, report.candidate_files, report.deleted_files, report.freed_bytes
    );
    if !report.failures.is_empty() {
        println!("failures: {}", report.failures.len());
        for failure in report.failures.iter().take(10) {
            println!("  {}: {}", failure.path, failure.reason);
        }
    }
}
