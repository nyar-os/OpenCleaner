//! Filesystem guards shared by path-scoped cleanup rules.
//!
//! Every rule that removes user-visible state goes through the same invariants:
//! the root must be an absolute, existing directory, reparse points are never
//! followed, installation roots are never entered, and a candidate is skipped
//! when a process holds it or when it sits inside a process working directory.

use std::{
    fs::Metadata,
    path::{Component, Path, PathBuf},
};

use crate::{
    Error, Result,
    locations::{BaseDirs, base_dirs},
    platform,
};

/// Components that mark a path as installation or system state. Name-only
/// matching is intentional: every one of these is a fixed Windows well-known
/// directory, not a guess about a project layout.
const PROTECTED_COMPONENTS: &[&str] =
    &["windows", "program files", "program files (x86)", "programdata", "system volume information", "$recycle.bin", "$mft", "$extend"];

/// Days used when a caller does not choose a threshold for file age.
pub(crate) const DEFAULT_AGE_DAYS: u64 = 7;

/// Length of one day in milliseconds. Defined once so every age and freshness
/// computation compares the same unit.
pub(crate) const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// Window that decides whether a directory is still receiving writes. One
/// definition shared by every rule that needs directory freshness; a directory
/// with a newer direct entry is treated as active.
pub(crate) const FRESHNESS_DAYS: u64 = 30;

pub(crate) fn freshness_window_ms() -> u64 {
    FRESHNESS_DAYS * DAY_MS
}

/// True when a timestamp lies inside the freshness window ending at `now_ms`.
pub(crate) fn is_fresh(stamp_unix_ms: u64, now_ms: u64) -> bool {
    stamp_unix_ms.saturating_add(freshness_window_ms()) > now_ms
}

/// Newest modification time among the direct entries of a directory. Reparse
/// points are ignored rather than followed, and an unreadable directory has no
/// timestamp at all.
pub(crate) fn newest_entry_unix_ms(path: &Path) -> Option<u64> {
    let read = std::fs::read_dir(path).ok()?;
    let mut newest: Option<u64> = None;
    for entry in read.flatten() {
        let Ok(meta) = entry.metadata()
        else {
            continue;
        };
        if platform::is_link_like(&meta) || meta.file_type().is_symlink() {
            continue;
        }
        let Some(stamp) =
            meta.modified().ok().and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok()).map(|elapsed| elapsed.as_millis() as u64)
        else {
            continue;
        };
        newest = Some(newest.map_or(stamp, |current| current.max(stamp)));
    }
    newest
}

/// A directory is considered still being written when its newest file is
/// younger than this. Build tools keep their outputs warm for a while.
pub(crate) const RECENT_WRITE_MS: u64 = 10 * 60 * 1000;

pub(crate) fn now_unix_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|elapsed| elapsed.as_millis() as u64).unwrap_or(0)
}

/// Case-insensitive key used for containment and deduplication.
pub(crate) fn path_key(path: &Path) -> String {
    let text = path.to_string_lossy().replace('/', "\\");
    let trimmed = text.trim_end_matches('\\');
    let base = if trimmed.is_empty() { text.as_str() } else { trimmed };
    base.to_ascii_lowercase()
}

/// True when `candidate` is `root` or lies below it.
pub(crate) fn is_within(root: &Path, candidate: &Path) -> bool {
    let root_key = path_key(root);
    let candidate_key = path_key(candidate);
    if candidate_key == root_key {
        return true;
    }
    let prefix = if root_key.ends_with('\\') { root_key } else { format!("{root_key}\\") };
    candidate_key.starts_with(&prefix)
}

pub(crate) fn has_protected_component(path: &Path) -> bool {
    path.components().any(|component| match component {
        Component::Normal(name) => {
            let lower = name.to_string_lossy().to_ascii_lowercase();
            PROTECTED_COMPONENTS.contains(&lower.as_str())
        }
        _ => false,
    })
}

fn is_volume_root(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let mut rooted = false;
    let mut normal_components = 0usize;
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => rooted = true,
            Component::Normal(_) => normal_components += 1,
            _ => {}
        }
    }
    rooted && normal_components == 0
}

fn is_base_dir(path: &Path, dirs: &BaseDirs) -> bool {
    let key = path_key(path);
    [
        dirs.home.as_ref(),
        dirs.local_app_data.as_ref(),
        dirs.app_data.as_ref(),
        dirs.program_data.as_ref(),
        dirs.program_files.as_ref(),
        dirs.cache_dir.as_ref(),
        dirs.data_dir.as_ref(),
        dirs.cargo_home.as_ref(),
    ]
    .into_iter()
    .flatten()
    .any(|dir| path_key(dir) == key)
}

/// Validate a cleanup root. Rejections are messages, never silent skips.
pub(crate) fn ensure_cleanup_root(path: &Path, capability: &'static str) -> Result<Metadata> {
    if !path.is_absolute() {
        return Err(Error::Message(format!("{capability}: root must be absolute, got {}", path.display())));
    }
    let meta = std::fs::symlink_metadata(path).map_err(|error| Error::Io { path: path.display().to_string(), source: error })?;
    if platform::is_link_like(&meta) || meta.file_type().is_symlink() {
        return Err(Error::Message(format!("{capability}: root is a symbolic link or junction: {}", path.display())));
    }
    if !meta.is_dir() {
        return Err(Error::Message(format!("{capability}: root is not a directory: {}", path.display())));
    }
    if is_volume_root(path) {
        return Err(Error::Message(format!("{capability}: a filesystem root is never used as a cleanup root: {}", path.display())));
    }
    if has_protected_component(path) {
        return Err(Error::Message(format!("{capability}: root contains a protected component: {}", path.display())));
    }
    if is_base_dir(path, &base_dirs()) {
        return Err(Error::Message(format!("{capability}: root is a shared platform directory: {}", path.display())));
    }
    Ok(meta)
}

/// Reject roots that belong to installed software. Used by the declared
/// build-root rule, which otherwise trusts an operator-supplied path.
pub(crate) fn ensure_not_install_root(path: &Path, capability: &'static str) -> Result<()> {
    let mut roots: Vec<PathBuf> = Vec::new();
    for key in ["ProgramFiles", "ProgramFiles(x86)", "ProgramData", "SystemRoot", "windir"] {
        if let Ok(value) = std::env::var(key) {
            let value = value.trim();
            if !value.is_empty() {
                roots.push(PathBuf::from(value));
            }
        }
    }
    for root in roots {
        if is_within(&root, path) {
            return Err(Error::Message(format!(
                "{capability}: declared root is inside installed software ({}) and is not removed",
                root.display()
            )));
        }
    }
    Ok(())
}

/// Rename probe: a directory that another process holds open cannot be renamed
/// on Windows. The original name is restored immediately and no data is touched.
pub(crate) fn probe_dir_in_use(path: &Path) -> bool {
    let Some(parent) = path.parent()
    else {
        return true;
    };
    let Some(name) = path.file_name()
    else {
        return true;
    };
    let probe = parent.join(format!(".{}.open-cleaner-{}.probe", name.to_string_lossy(), std::process::id()));
    if probe.exists() {
        return true;
    }
    if std::fs::rename(path, &probe).is_err() {
        return true;
    }
    std::fs::rename(&probe, path).is_err()
}

/// Per-file occupancy probe. It asks for `DELETE` access, so a file that a
/// program holds open without delete sharing is reported as in use instead of
/// failing later inside the delete batch.
#[cfg(windows)]
pub(crate) fn probe_file_in_use(path: &Path) -> bool {
    let wide = file_sys::wide(path);
    // SAFETY: `wide` is NUL-terminated and the handle is closed below.
    let handle = unsafe {
        file_sys::CreateFileW(
            wide.as_ptr(),
            file_sys::DELETE_ACCESS,
            0,
            std::ptr::null(),
            file_sys::OPEN_EXISTING,
            file_sys::FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle.is_null() || handle as isize == file_sys::INVALID_HANDLE_VALUE {
        return true;
    }
    // SAFETY: `handle` was just opened and is not used afterwards.
    unsafe { file_sys::CloseHandle(handle) };
    false
}

#[cfg(windows)]
mod file_sys {
    use std::{ffi::c_void, os::windows::ffi::OsStrExt};

    pub const DELETE_ACCESS: u32 = 0x0001_0000;
    pub const OPEN_EXISTING: u32 = 3;
    pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    pub const INVALID_HANDLE_VALUE: isize = -1;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            security: *const c_void,
            creation: u32,
            flags: u32,
            template: *mut c_void,
        ) -> *mut c_void;
        pub fn CloseHandle(handle: *mut c_void) -> i32;
    }

    pub fn wide(path: &std::path::Path) -> Vec<u16> {
        let mut units: Vec<u16> = path.as_os_str().encode_wide().collect();
        units.push(0);
        units
    }
}

#[cfg(not(windows))]
pub(crate) fn probe_file_in_use(_path: &Path) -> bool {
    false
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Usage {
    pub bytes: u64,
    pub files: u64,
    pub dirs: u64,
    pub newest_unix_ms: Option<u64>,
    pub errors: u64,
}

/// Recursive usage of one directory. Reparse points are never followed.
pub(crate) fn collect_usage(root: &Path) -> Usage {
    let mut usage = Usage::default();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(read) = std::fs::read_dir(&dir)
        else {
            usage.errors += 1;
            continue;
        };
        usage.dirs += 1;
        for entry in read {
            let Ok(entry) = entry
            else {
                usage.errors += 1;
                continue;
            };
            let Ok(meta) = entry.metadata()
            else {
                usage.errors += 1;
                continue;
            };
            if platform::is_link_like(&meta) || meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                stack.push(entry.path());
                continue;
            }
            usage.files += 1;
            usage.bytes = usage.bytes.saturating_add(meta.len());
            let modified =
                meta.modified().ok().and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok()).map(|elapsed| elapsed.as_millis() as u64);
            if let Some(stamp) = modified {
                usage.newest_unix_ms = Some(usage.newest_unix_ms.map_or(stamp, |current| current.max(stamp)));
            }
        }
    }
    usage
}

/// Working directories and per-process temp directories of running processes.
/// Names are never guessed: a process that cannot be read is counted as
/// unresolved instead.
#[derive(Debug, Clone, Default)]
pub(crate) struct ProcessPaths {
    pub supported: bool,
    pub processes: u32,
    pub resolved: u32,
    pub failed: u32,
    /// Current working directories.
    pub dirs: Vec<PathBuf>,
    /// Values of `TEMP` / `TMP` from each process environment block.
    pub temp_dirs: Vec<PathBuf>,
    /// Parent directories of the executable image of each running process.
    pub image_dirs: Vec<PathBuf>,
}

#[cfg(windows)]
pub(crate) fn process_paths() -> ProcessPaths {
    use std::ffi::c_void;

    mod sys {
        use std::ffi::c_void;

        #[repr(C)]
        pub struct ProcessEntry32W {
            pub dw_size: u32,
            pub cnt_usage: u32,
            pub th32_process_id: u32,
            pub th32_default_heap_id: usize,
            pub th32_module_id: u32,
            pub cnt_threads: u32,
            pub th32_parent_process_id: u32,
            pub pc_pri_class_base: i32,
            pub dw_flags: u32,
            pub sz_exe_file: [u16; 260],
        }

        #[repr(C)]
        pub struct ProcessBasicInformation {
            pub exit_status: usize,
            pub peb_base_address: *mut c_void,
            pub affinity_mask: usize,
            pub base_priority: i32,
            pub unique_process_id: usize,
            pub inherited_from_unique_process_id: usize,
        }

        #[link(name = "kernel32")]
        unsafe extern "system" {
            pub fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> *mut c_void;
            pub fn Process32FirstW(snapshot: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
            pub fn Process32NextW(snapshot: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
            pub fn OpenProcess(access: u32, inherit: i32, process_id: u32) -> *mut c_void;
            pub fn CloseHandle(handle: *mut c_void) -> i32;
            pub fn ReadProcessMemory(process: *mut c_void, base: *const c_void, buffer: *mut c_void, size: usize, read: *mut usize) -> i32;
            pub fn IsWow64Process(process: *mut c_void, wow64: *mut i32) -> i32;
        }

        #[link(name = "ntdll")]
        unsafe extern "system" {
            pub fn NtQueryInformationProcess(process: *mut c_void, class: u32, info: *mut c_void, size: u32, ret: *mut u32) -> i32;
        }
    }

    const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const PROCESS_VM_READ: u32 = 0x0010;
    const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;
    const PEB_PROCESS_PARAMETERS: usize = 0x20;
    const PARAMS_CURRENT_DIRECTORY: usize = 0x38;
    const PARAMS_IMAGE_PATH: usize = 0x60;
    const PARAMS_ENVIRONMENT: usize = 0x80;
    /// Environment blocks are read in 4 KiB chunks and capped at 32 KiB, which
    /// is far above the size any real process uses.
    const ENV_CHUNK_UNITS: usize = 2048;
    const ENV_MAX_UNITS: usize = 16_384;

    struct Handle(*mut c_void);

    impl Handle {
        fn valid(&self) -> bool {
            !self.0.is_null() && self.0 as isize != -1
        }
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            if self.valid() {
                // SAFETY: handle was returned by `OpenProcess`/snapshot and is closed once.
                unsafe {
                    sys::CloseHandle(self.0);
                }
            }
        }
    }

    /// # Safety
    /// `handle` must be a live process handle with `PROCESS_VM_READ`.
    unsafe fn read_usize(handle: *mut c_void, address: usize) -> Option<usize> {
        let mut value = 0usize;
        let mut read = 0usize;
        let size = std::mem::size_of::<usize>();
        // SAFETY: reads one pointer-sized value into a local buffer.
        let ok = unsafe { sys::ReadProcessMemory(handle, address as *const c_void, &mut value as *mut usize as *mut c_void, size, &mut read) };
        (ok != 0 && read == size).then_some(value)
    }

    /// # Safety
    /// `handle` must be a live process handle with `PROCESS_VM_READ`.
    unsafe fn read_wide(handle: *mut c_void, address: usize, units: usize) -> Option<String> {
        let mut buffer = vec![0u16; units];
        let mut read = 0usize;
        let size = units.checked_mul(std::mem::size_of::<u16>())?;
        // SAFETY: buffer length matches `size`, and the source is a remote buffer.
        let ok = unsafe { sys::ReadProcessMemory(handle, address as *const c_void, buffer.as_mut_ptr().cast(), size, &mut read) };
        if ok == 0 || read < size {
            return None;
        }
        Some(String::from_utf16_lossy(&buffer))
    }

    /// # Safety
    /// `handle` must be a live process handle with query and read rights.
    unsafe fn process_parameters(handle: *mut c_void) -> Option<usize> {
        let mut wow64 = 0i32;
        // SAFETY: `wow64` is a caller-owned out parameter.
        if unsafe { sys::IsWow64Process(handle, &mut wow64) } == 0 || wow64 != 0 {
            // A 32-bit process on 64-bit Windows uses a different PEB layout, so
            // reading it here would produce a wrong path. Count it as unresolved.
            return None;
        }
        let mut info = std::mem::MaybeUninit::<sys::ProcessBasicInformation>::zeroed();
        let mut returned = 0u32;
        let size = std::mem::size_of::<sys::ProcessBasicInformation>() as u32;
        // SAFETY: the out buffer matches `size` and is initialised on success.
        let status =
            unsafe { sys::NtQueryInformationProcess(handle, PROCESS_BASIC_INFORMATION_CLASS, info.as_mut_ptr().cast(), size, &mut returned) };
        if status != 0 {
            return None;
        }
        // SAFETY: `status == 0` guarantees the structure was written.
        let info = unsafe { info.assume_init() };
        unsafe { read_usize(handle, info.peb_base_address as usize + PEB_PROCESS_PARAMETERS) }
    }

    /// # Safety
    /// `handle` must be a live process handle with `PROCESS_VM_READ`, and
    /// `address` must point at a `UNICODE_STRING` inside the target process.
    unsafe fn unicode_path(handle: *mut c_void, address: usize) -> Option<PathBuf> {
        let mut raw = [0u8; 16];
        let mut read = 0usize;
        // SAFETY: reads the 16-byte `UNICODE_STRING` header.
        let ok = unsafe { sys::ReadProcessMemory(handle, address as *const c_void, raw.as_mut_ptr().cast(), raw.len(), &mut read) };
        if ok == 0 || read < raw.len() {
            return None;
        }
        let length = u16::from_ne_bytes([raw[0], raw[1]]) as usize;
        let buffer = usize::from_ne_bytes([raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]]);
        if !(4..=0x8000).contains(&length) {
            return None;
        }
        let text = unsafe { read_wide(handle, buffer, length / 2)? };
        let path = PathBuf::from(text);
        if !path.is_absolute() {
            return None;
        }
        Some(path)
    }

    /// # Safety
    /// `handle` must be a live process handle with `PROCESS_VM_READ`.
    unsafe fn environment(handle: *mut c_void, parameters: usize) -> Option<Vec<(String, String)>> {
        let block = unsafe { read_usize(handle, parameters + PARAMS_ENVIRONMENT) }?;
        if block == 0 {
            return None;
        }
        let mut units: Vec<u16> = Vec::new();
        let mut offset = 0usize;
        while offset < ENV_MAX_UNITS {
            let take = ENV_CHUNK_UNITS.min(ENV_MAX_UNITS - offset);
            let mut buffer = vec![0u16; take];
            let mut read = 0usize;
            let size = take * std::mem::size_of::<u16>();
            // SAFETY: the buffer matches `size` and belongs to this thread.
            let ok =
                unsafe { sys::ReadProcessMemory(handle, (block + offset * 2) as *const c_void, buffer.as_mut_ptr().cast(), size, &mut read) };
            let got = read / 2;
            if got == 0 && ok == 0 {
                break;
            }
            units.extend_from_slice(&buffer[..got]);
            // The block terminates with two consecutive NULs.
            if units.len() >= 2 && units[units.len() - 1] == 0 && units[units.len() - 2] == 0 {
                break;
            }
            if got < take {
                break;
            }
            offset += got;
        }
        let text = String::from_utf16_lossy(&units);
        let mut pairs: Vec<(String, String)> = Vec::new();
        for entry in text.split('\0') {
            let Some((name, value)) = entry.split_once('=')
            else {
                continue;
            };
            let name = name.trim().to_ascii_uppercase();
            if name.is_empty() || pairs.iter().any(|(known, _)| *known == name) {
                continue;
            }
            pairs.push((name, value.to_string()));
        }
        Some(pairs)
    }

    /// # Safety
    /// `handle` must be a live process handle with query and read rights.
    unsafe fn cwd_of(handle: *mut c_void) -> Option<PathBuf> {
        let parameters = unsafe { process_parameters(handle)? };
        unsafe { unicode_path(handle, parameters + PARAMS_CURRENT_DIRECTORY) }
    }

    /// # Safety
    /// `handle` must be a live process handle with query and read rights.
    unsafe fn image_dir_of(handle: *mut c_void) -> Option<PathBuf> {
        let parameters = unsafe { process_parameters(handle)? };
        let image = unsafe { unicode_path(handle, parameters + PARAMS_IMAGE_PATH) }?;
        image.parent().map(Path::to_path_buf)
    }

    /// Resolves `TEMP` and `TMP` for one process. Values are expanded against
    /// the process's own environment, so `%USERPROFILE%` yields the right
    /// directory for services and other users too.
    fn expand(value: &str, pairs: &[(String, String)]) -> String {
        let mut text = value.to_string();
        for _ in 0..4 {
            let mut changed = false;
            let mut output = String::new();
            let mut rest = text.as_str();
            while let Some(open) = rest.find('%') {
                let Some(close) = rest[open + 1..].find('%').map(|index| index + open + 1)
                else {
                    break;
                };
                output.push_str(&rest[..open]);
                let name = rest[open + 1..close].to_ascii_uppercase();
                match pairs.iter().find(|(known, _)| *known == name) {
                    Some((_, resolved)) => {
                        output.push_str(resolved);
                        changed = true;
                    }
                    None => output.push_str(&rest[open..=close]),
                }
                rest = &rest[close + 1..];
            }
            output.push_str(rest);
            text = output;
            if !changed {
                break;
            }
        }
        text
    }

    fn temp_dirs_of(handle: *mut c_void) -> Vec<PathBuf> {
        // SAFETY: `handle` is opened with query and read rights for this call.
        let parameters = unsafe { process_parameters(handle) };
        let Some(parameters) = parameters
        else {
            return Vec::new();
        };
        // SAFETY: same handle, and the pointer came from the target process.
        let Some(pairs) = (unsafe { environment(handle, parameters) })
        else {
            return Vec::new();
        };
        let mut dirs = Vec::new();
        for name in ["TEMP", "TMP"] {
            let Some((_, raw)) = pairs.iter().find(|(known, _)| known == name)
            else {
                continue;
            };
            let expanded = expand(raw, &pairs);
            let path = PathBuf::from(expanded.trim());
            if !path.is_absolute() {
                continue;
            }
            if !dirs.iter().any(|known: &PathBuf| path_key(known) == path_key(&path)) {
                dirs.push(path);
            }
        }
        dirs
    }

    let mut result = ProcessPaths { supported: true, ..ProcessPaths::default() };
    // SAFETY: the snapshot handle is closed by `Handle`'s destructor.
    let snapshot = Handle(unsafe { sys::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) });
    if !snapshot.valid() {
        result.supported = false;
        return result;
    }

    let mut entry = sys::ProcessEntry32W {
        dw_size: std::mem::size_of::<sys::ProcessEntry32W>() as u32,
        cnt_usage: 0,
        th32_process_id: 0,
        th32_default_heap_id: 0,
        th32_module_id: 0,
        cnt_threads: 0,
        th32_parent_process_id: 0,
        pc_pri_class_base: 0,
        dw_flags: 0,
        sz_exe_file: [0; 260],
    };

    // SAFETY: snapshot is valid and `entry` matches the documented layout.
    let mut has_entry = unsafe { sys::Process32FirstW(snapshot.0, &mut entry) } != 0;
    while has_entry {
        result.processes += 1;
        let pid = entry.th32_process_id;
        if pid != 0 && pid != std::process::id() {
            // SAFETY: opens a process with the minimum rights needed for the PEB read.
            let process = Handle(unsafe { sys::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) });
            match process.valid().then(|| unsafe { cwd_of(process.0) }).flatten() {
                Some(dir) => {
                    result.resolved += 1;
                    if !result.dirs.iter().any(|known| path_key(known) == path_key(&dir)) {
                        result.dirs.push(dir);
                    }
                }
                None => result.failed += 1,
            }
            for dir in temp_dirs_of(process.0) {
                if !result.temp_dirs.iter().any(|known| path_key(known) == path_key(&dir)) {
                    result.temp_dirs.push(dir);
                }
            }
            if let Some(dir) = unsafe { image_dir_of(process.0) }
                && !result.image_dirs.iter().any(|known| path_key(known) == path_key(&dir))
            {
                result.image_dirs.push(dir);
            }
        }
        // SAFETY: same snapshot and entry buffer as the first call.
        has_entry = unsafe { sys::Process32NextW(snapshot.0, &mut entry) } != 0;
    }

    if let Ok(current) = std::env::current_dir() {
        result.resolved += 1;
        if !result.dirs.iter().any(|known| path_key(known) == path_key(&current)) {
            result.dirs.push(current);
        }
    }
    let temp = std::env::temp_dir();
    if !result.temp_dirs.iter().any(|known| path_key(known) == path_key(&temp)) {
        result.temp_dirs.push(temp);
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        result.image_dirs.push(dir.to_path_buf());
    }
    result
}

#[cfg(not(windows))]
pub(crate) fn process_paths() -> ProcessPaths {
    ProcessPaths::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn containment_is_case_insensitive_and_component_aware() {
        let root = Path::new(r"C:\Users\dev\AppData\Local\Temp");
        assert!(is_within(root, Path::new(r"c:\users\dev\appdata\local\temp\a\b.txt")));
        assert!(is_within(root, root));
        assert!(!is_within(root, Path::new(r"C:\Users\dev\AppData\Local\Temp2")));
        assert!(!is_within(root, Path::new(r"C:\Users\dev\AppData\Local")));
    }

    /// The protected component names are Windows well-known directories, so the
    /// guard only has meaning on Windows path grammar.
    #[cfg(windows)]
    #[test]
    fn install_roots_are_protected_by_component() {
        assert!(has_protected_component(Path::new(r"C:\Program Files\App\node_modules")));
        assert!(has_protected_component(Path::new(r"C:\Windows\Temp")));
        assert!(!has_protected_component(Path::new(r"C:\Users\dev\AppData\Local\Temp\build")));
    }

    #[test]
    fn volume_roots_are_rejected() {
        let root = if cfg!(windows) { Path::new(r"C:\") } else { Path::new("/") };
        let error = ensure_cleanup_root(root, "temp-plan").unwrap_err();
        assert!(error.to_string().contains("filesystem root"), "{error}");
    }
}
