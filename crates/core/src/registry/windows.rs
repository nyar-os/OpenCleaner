//! Read-only Windows registry inspection.
//!
//! This is the only module in the core that touches Win32. It enumerates the
//! per-machine and per-user `Uninstall` keys and reports entries whose
//! `InstallLocation` no longer exists. Nothing is deleted.

use std::{
    ffi::c_void,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use super::{RegistryEntry, RegistryOptions, RegistryReport};
use crate::Result;

type Hkey = *mut c_void;
type Status = u32;

const HKEY_CURRENT_USER: Hkey = 0x8000_0001usize as Hkey;
const HKEY_LOCAL_MACHINE: Hkey = 0x8000_0002usize as Hkey;

const KEY_READ: u32 = 0x20019;
const KEY_WOW64_64KEY: u32 = 0x0100;

const ERROR_SUCCESS: Status = 0;
const ERROR_NO_MORE_ITEMS: Status = 259;

const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_DWORD: u32 = 4;

const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegOpenKeyExW(hkey: Hkey, lpsubkey: *const u16, uloptions: u32, samdesired: u32, phkresult: *mut Hkey) -> Status;
    fn RegCloseKey(hkey: Hkey) -> Status;
    fn RegEnumKeyExW(
        hkey: Hkey,
        dwindex: u32,
        lpname: *mut u16,
        lpcchname: *mut u32,
        lpreserved: *mut u32,
        lpclass: *mut u16,
        lpcchclass: *mut u32,
        lpftlastwritetime: *mut u64,
    ) -> Status;
    fn RegQueryValueExW(
        hkey: Hkey,
        lpvaluename: *const u16,
        lpreserved: *mut u32,
        lptype: *mut u32,
        lpdata: *mut u8,
        lpcbdata: *mut u32,
    ) -> Status;
}

struct OwnedKey(Hkey);

impl OwnedKey {
    fn open(parent: Hkey, path: &str, sam: u32) -> Option<Self> {
        let wide = wide(path);
        let mut out: Hkey = std::ptr::null_mut();
        // SAFETY: `wide` is a valid NUL-terminated UTF-16 buffer and `out` is a
        // writable pointer. The returned handle is owned by `OwnedKey`.
        let status = unsafe { RegOpenKeyExW(parent, wide.as_ptr(), 0, sam, &mut out) };
        if status == ERROR_SUCCESS && !out.is_null() { Some(Self(out)) } else { None }
    }

    fn subkeys(&self) -> Vec<String> {
        let mut names = Vec::new();
        let mut index = 0u32;
        loop {
            let mut buf = vec![0u16; 512];
            let mut len = buf.len() as u32;
            // SAFETY: `self.0` is a live key handle and `buf`/`len` are valid
            // writable buffers for this call. `lpReserved` must be NULL.
            let status = unsafe {
                RegEnumKeyExW(
                    self.0,
                    index,
                    buf.as_mut_ptr(),
                    &mut len,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if status == ERROR_NO_MORE_ITEMS || status != ERROR_SUCCESS {
                break;
            }
            names.push(String::from_utf16_lossy(&buf[..len as usize]));
            index += 1;
        }
        names
    }

    fn value(&self, name: &str) -> Option<RegValue> {
        let wide_name = wide(name);
        let mut ty = 0u32;
        let mut size = 0u32;
        // SAFETY: querying size with a null data pointer is allowed by the
        // registry API for this call.
        let status = unsafe { RegQueryValueExW(self.0, wide_name.as_ptr(), std::ptr::null_mut(), &mut ty, std::ptr::null_mut(), &mut size) };
        if status != ERROR_SUCCESS || size == 0 {
            return None;
        }
        let mut data = vec![0u8; size as usize];
        // SAFETY: `data` has the length reported by the previous call and
        // `size` is a writable out-parameter.
        let status = unsafe { RegQueryValueExW(self.0, wide_name.as_ptr(), std::ptr::null_mut(), &mut ty, data.as_mut_ptr(), &mut size) };
        if status != ERROR_SUCCESS {
            return None;
        }
        data.truncate(size as usize);
        Some(RegValue { ty, data })
    }
}

impl Drop for OwnedKey {
    fn drop(&mut self) {
        // SAFETY: `self.0` was returned by `RegOpenKeyExW` and is closed once.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

struct RegValue {
    ty: u32,
    data: Vec<u8>,
}

fn wide(value: &str) -> Vec<u16> {
    let mut buffer: Vec<u16> = value.encode_utf16().collect();
    buffer.push(0);
    buffer
}

fn string_value(value: &RegValue) -> Option<String> {
    if value.ty != REG_SZ && value.ty != REG_EXPAND_SZ {
        return None;
    }
    let utf16: Vec<u16> = value.data.as_chunks::<2>().0.iter().map(|chunk| u16::from_le_bytes(*chunk)).collect();
    let end = utf16.iter().position(|&unit| unit == 0).unwrap_or(utf16.len());
    let text = String::from_utf16_lossy(&utf16[..end]).trim().to_string();
    (!text.is_empty()).then_some(text)
}

fn dword_value(value: &RegValue) -> Option<u32> {
    if value.ty != REG_DWORD || value.data.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([value.data[0], value.data[1], value.data[2], value.data[3]]))
}

fn hive_label(hive: Hkey) -> &'static str {
    if hive == HKEY_LOCAL_MACHINE { "HKLM" } else { "HKCU" }
}

pub(super) fn scan(options: RegistryOptions) -> Result<RegistryReport> {
    let limit = options.limit.unwrap_or(100).max(1);
    let mut entries = Vec::new();
    let mut scanned_keys = 0usize;

    for (hive, sam) in [(HKEY_LOCAL_MACHINE, KEY_READ | KEY_WOW64_64KEY), (HKEY_CURRENT_USER, KEY_READ)] {
        let Some(root) = OwnedKey::open(hive, UNINSTALL, sam)
        else {
            continue;
        };

        for name in root.subkeys() {
            scanned_keys += 1;
            let subkey = format!("{UNINSTALL}\\{name}");
            let Some(key) = OwnedKey::open(hive, &subkey, sam)
            else {
                continue;
            };
            if let Some(flag) = key.value("SystemComponent").as_ref().and_then(dword_value)
                && flag == 1
            {
                continue;
            }

            let display_name = key.value("DisplayName").as_ref().and_then(string_value);
            let install_location = key.value("InstallLocation").as_ref().and_then(string_value);
            let version = key.value("DisplayVersion").as_ref().and_then(string_value);

            let Some(location) = install_location
            else {
                continue;
            };
            let location = location.trim_matches('"').trim().to_string();
            if location.is_empty() || Path::new(&location).exists() {
                continue;
            }

            entries.push(RegistryEntry {
                key: format!("{}\\{subkey}", hive_label(hive)),
                display_name,
                install_location: Some(location),
                version,
                reason: "install-location-missing".to_string(),
            });
        }
    }

    entries.sort_by(|a, b| a.key.cmp(&b.key));
    entries.truncate(limit);

    Ok(RegistryReport {
        platform: crate::platform::name().to_string(),
        scanned_keys,
        entries,
        scanned_at_unix_ms: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0),
    })
}
