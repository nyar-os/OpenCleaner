//! Test fixtures live under the build directory, never in the user's temp.
//!
//! A fixture that leaks into the platform temp directory couples the test
//! suite with the machine: a failed assertion leaves files exactly where the
//! temp domain itself looks, and a real cleanup run then deletes the tool's
//! own leftovers. `CARGO_TARGET_TMPDIR` is cargo's fixture area for test
//! binaries; unit tests do not always receive it, so the fallback derives the
//! build profile directory from the test binary path. Either way the result
//! lives under `target/`, where `cargo clean` removes it.

use std::path::PathBuf;

pub(crate) fn fixture_dir(label: &str) -> PathBuf {
    let base = match std::env::var_os("CARGO_TARGET_TMPDIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().and_then(|deps| deps.parent()).map(|profile| profile.join("test-tmp")))
            .unwrap_or_else(std::env::temp_dir),
    };
    let dir = base.join(format!("open-cleaner-{label}-{}-{}", std::process::id(), crate::safety::now_unix_ms()));
    std::fs::create_dir_all(&dir).expect("create fixture directory");
    dir
}
