//! Windows recycle-bin deletion via `SHFileOperationW` (raw FFI, matching the
//! existing registry module style — no extra crates).

use std::{
    ffi::c_void,
    io,
    path::Path,
};

use crate::Result;

const FO_DELETE: u32 = 3;
const FOF_ALLOWUNDO: u16 = 0x0040;
const FOF_NOCONFIRMATION: u16 = 0x0010;
const FOF_SILENT: u16 = 0x0004;
const FOF_NOERRORUI: u16 = 0x0400;
const ERROR_CANCELLED: u32 = 1223;

#[repr(C)]
struct ShFileOpStructW {
    hwnd: *mut c_void,
    w_func: u32,
    p_from: *const u16,
    p_to: *const u16,
    f_flags: u16,
    f_any_operations_aborted: i32,
    h_name_mappings: *mut c_void,
    lpsz_progress_title: *const u16,
}

#[link(name = "shell32")]
unsafe extern "system" {
    fn SHFileOperationW(fileop: *const ShFileOpStructW) -> u32;
}

pub(super) fn trash_path(path: &Path) -> Result<()> {
    let absolute = std::path::absolute(path).map_err(|source| crate::Error::Io { path: path.display().to_string(), source })?;

    // `SHFileOperationW` requires a double-NUL-terminated list and prefers
    // backslash separators.
    let text = absolute.to_string_lossy().replace('/', r"\");
    let mut from: Vec<u16> = text.encode_utf16().collect();
    from.push(0);
    from.push(0);

    let operation = ShFileOpStructW {
        hwnd: std::ptr::null_mut(),
        w_func: FO_DELETE,
        p_from: from.as_ptr(),
        p_to: std::ptr::null(),
        f_flags: FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI,
        f_any_operations_aborted: 0,
        h_name_mappings: std::ptr::null_mut(),
        lpsz_progress_title: std::ptr::null(),
    };

    // SAFETY: `operation` matches the `SHFILEOPSTRUCTW` layout and `from` is a
    // valid double-NUL-terminated UTF-16 buffer that outlives the call.
    let code = unsafe { SHFileOperationW(&operation) };
    if operation.f_any_operations_aborted != 0 || code == ERROR_CANCELLED {
        return Err(crate::Error::Message(format!("recycle bin refused {}", absolute.display())));
    }
    if code != 0 {
        return Err(crate::Error::Io {
            path: absolute.display().to_string(),
            source: io::Error::from_raw_os_error(code as i32),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn moves_a_probe_directory_into_the_recycle_bin() {
        let dir = std::env::temp_dir().join(format!("open-cleaner-trash-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("payload.txt"), b"fixture").unwrap();

        trash_path(&dir).unwrap();
        assert!(!dir.exists(), "fixture should be gone from its original path");
    }
}
