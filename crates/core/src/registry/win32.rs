//! Shared Win32 registry primitives (raw FFI, no extra crates).
//!
//! `registry::windows` and `env::windows` both build on these helpers, so the
//! unsafe surface exists exactly once in the core.

#![cfg(windows)]

use std::ffi::c_void;

use super::model::{RegistryValue, RegistryValueKind};

pub(crate) type Hkey = *mut c_void;
type Status = u32;

pub(crate) const HKEY_CURRENT_USER: Hkey = 0x8000_0001usize as Hkey;
pub(crate) const HKEY_LOCAL_MACHINE: Hkey = 0x8000_0002usize as Hkey;

pub(crate) const KEY_READ: u32 = 0x20019;
pub(crate) const KEY_SET_VALUE: u32 = 0x0002;
pub(crate) const KEY_WOW64_64KEY: u32 = 0x0100;

const ERROR_SUCCESS: Status = 0;
const ERROR_MORE_DATA: Status = 234;
const ERROR_NO_MORE_ITEMS: Status = 259;

const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_DWORD: u32 = 4;

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
    fn RegEnumValueW(
        hkey: Hkey,
        dwindex: u32,
        lpvaluename: *mut u16,
        lpcchvaluename: *mut u32,
        lpreserved: *mut u32,
        lptype: *mut u32,
        lpdata: *mut u8,
        lpcbdata: *mut u32,
    ) -> Status;
    fn RegSetValueExW(hkey: Hkey, lpvaluename: *const u16, lpreserved: u32, dwtype: u32, lpdata: *const u8, cbdata: u32) -> Status;
}

/// A registry handle that is closed on drop.
pub(crate) struct OwnedKey(Hkey);

impl OwnedKey {
    pub(crate) fn open(parent: Hkey, path: &str, sam: u32) -> Option<Self> {
        let wide = wide(path);
        let mut out: Hkey = std::ptr::null_mut();
        // SAFETY: `wide` is a valid NUL-terminated UTF-16 buffer and `out` is a
        // writable pointer. The returned handle is owned by `OwnedKey`.
        let status = unsafe { RegOpenKeyExW(parent, wide.as_ptr(), 0, sam, &mut out) };
        if status == ERROR_SUCCESS && !out.is_null() { Some(Self(out)) } else { None }
    }

    /// Open for writing. Reading is not implied: callers that need both open
    /// twice or pass `KEY_READ | KEY_SET_VALUE`.
    pub(crate) fn open_for_write(parent: Hkey, path: &str) -> Option<Self> {
        Self::open(parent, path, KEY_READ | KEY_SET_VALUE)
    }

    pub(crate) fn subkeys(&self) -> Vec<String> {
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

    pub(crate) fn value(&self, name: &str) -> Option<RegValue> {
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

    /// Enumerate every value of this key. Names are read first, then each
    /// value is queried by name so multi-segment data is not truncated.
    pub(crate) fn values(&self) -> Vec<(String, RegValue)> {
        let mut out = Vec::new();
        let mut index = 0u32;
        loop {
            let mut name = vec![0u16; 512];
            let mut name_len = name.len() as u32;
            let mut ty = 0u32;
            let mut size = 0u32;
            // SAFETY: `self.0` is a live handle. `lpData` is NULL on purpose so
            // the call only reports the value name and data size.
            let status = unsafe {
                RegEnumValueW(self.0, index, name.as_mut_ptr(), &mut name_len, std::ptr::null_mut(), &mut ty, std::ptr::null_mut(), &mut size)
            };
            if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
                break;
            }
            let value_name = String::from_utf16_lossy(&name[..name_len as usize]);
            if let Some(value) = self.value(&value_name) {
                out.push((value_name, value));
            }
            index += 1;
        }
        out
    }

    /// Replace a value with an expandable string (`REG_EXPAND_SZ`).
    pub(crate) fn set_expand_string(&self, name: &str, data: &str) -> bool {
        let wide_name = wide(name);
        let mut buffer: Vec<u16> = data.encode_utf16().collect();
        buffer.push(0);
        let bytes: Vec<u8> = buffer.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        // SAFETY: `wide_name` is NUL-terminated and `bytes` outlives the call.
        // The byte length is exact for a UTF-16LE buffer including the terminator.
        let status = unsafe { RegSetValueExW(self.0, wide_name.as_ptr(), 0, REG_EXPAND_SZ, bytes.as_ptr(), bytes.len() as u32) };
        status == ERROR_SUCCESS
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

pub(crate) struct RegValue {
    pub(crate) ty: u32,
    pub(crate) data: Vec<u8>,
}

pub(crate) fn wide(value: &str) -> Vec<u16> {
    let mut buffer: Vec<u16> = value.encode_utf16().collect();
    buffer.push(0);
    buffer
}

pub(crate) fn string_value(value: &RegValue) -> Option<String> {
    if value.ty != REG_SZ && value.ty != REG_EXPAND_SZ {
        return None;
    }
    let utf16: Vec<u16> = value.data.as_chunks::<2>().0.iter().map(|chunk| u16::from_le_bytes(*chunk)).collect();
    let end = utf16.iter().position(|&unit| unit == 0).unwrap_or(utf16.len());
    let text = String::from_utf16_lossy(&utf16[..end]).trim().to_string();
    (!text.is_empty()).then_some(text)
}

pub(crate) fn dword_value(value: &RegValue) -> Option<u32> {
    if value.ty != REG_DWORD || value.data.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([value.data[0], value.data[1], value.data[2], value.data[3]]))
}

pub(crate) fn hive_label(hive: Hkey) -> &'static str {
    if hive == HKEY_LOCAL_MACHINE { "HKLM" } else { "HKCU" }
}

pub(crate) fn map_value(value: &RegValue) -> RegistryValue {
    match value.ty {
        REG_SZ => RegistryValue { kind: RegistryValueKind::String, data: string_value(value).unwrap_or_default() },
        REG_EXPAND_SZ => RegistryValue { kind: RegistryValueKind::ExpandString, data: string_value(value).unwrap_or_default() },
        REG_DWORD => {
            RegistryValue { kind: RegistryValueKind::Dword, data: dword_value(value).map(|flag| flag.to_string()).unwrap_or_default() }
        }
        _ => RegistryValue { kind: RegistryValueKind::Other, data: format!("reg-type-{}", value.ty) },
    }
}
