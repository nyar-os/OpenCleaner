//! Platform-neutral registry snapshot and `.reg` export parser.
//!
//! The Windows implementation fills the same snapshot from live registry
//! reads. Analysis then runs anywhere, so fixtures can be unit tests.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RegistryValueKind {
    String,
    ExpandString,
    Dword,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryValue {
    pub kind: RegistryValueKind,
    /// Textual data. DWORD values are stored as decimal.
    pub data: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegistryKey {
    /// Normalized path, e.g. `HKCU\Software\Microsoft\...`.
    pub path: String,
    pub values: BTreeMap<String, RegistryValue>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegistrySnapshot {
    /// `windows-registry` or `fixture.reg`.
    pub source: String,
    pub keys: Vec<RegistryKey>,
    pub warnings: Vec<String>,
}

impl RegistrySnapshot {
    pub fn insert(&mut self, path: impl Into<String>) {
        let path = normalize_key_path(&path.into());
        if self.key(&path).is_none() {
            self.keys.push(RegistryKey { path, values: BTreeMap::new() });
        }
    }
    pub fn key(&self, path: &str) -> Option<&RegistryKey> {
        let wanted = normalize_key_path(path).to_ascii_lowercase();
        self.keys.iter().find(|key| key.path.to_ascii_lowercase() == wanted)
    }

    pub fn value(&self, path: &str, name: &str) -> Option<&RegistryValue> {
        let key = self.key(path)?;
        key.values.iter().find(|(value_name, _)| value_name.eq_ignore_ascii_case(name)).map(|(_, value)| value)
    }

    pub fn set_value(&mut self, path: &str, name: &str, value: RegistryValue) {
        let normalized = normalize_key_path(path);
        if let Some(index) = self.keys.iter().position(|key| key.path.eq_ignore_ascii_case(&normalized)) {
            // Registry value names are case-insensitive. Keep the spelling
            // from the first occurrence so reports stay faithful.
            let existing = self.keys[index].values.keys().find(|key| key.eq_ignore_ascii_case(name)).cloned();
            let key_name = existing.unwrap_or_else(|| name.to_string());
            self.keys[index].values.insert(key_name, value);
        }
    }
}

/// Normalize hive aliases and trim separators.
pub fn normalize_key_path(path: &str) -> String {
    let trimmed = path.trim().trim_end_matches('\\');
    for (alias, canonical) in [
        ("HKEY_CURRENT_USER", "HKCU"),
        ("HKEY_LOCAL_MACHINE", "HKLM"),
        ("HKEY_CLASSES_ROOT", "HKCR"),
        ("HKEY_USERS", "HKU"),
        ("HKEY_CURRENT_CONFIG", "HKCC"),
    ] {
        if let Some(rest) = trimmed.strip_prefix(alias) {
            return format!("{canonical}{rest}");
        }
    }
    trimmed.to_string()
}

/// Parse an exported `.reg` text (`Windows Registry Editor Version 5.00` or
/// `REGEDIT4`).
pub fn parse_reg(text: &str, source: &str) -> RegistrySnapshot {
    let mut snapshot = RegistrySnapshot { source: source.to_string(), keys: Vec::new(), warnings: Vec::new() };
    let mut current: Option<String> = None;

    let mut logical_lines: Vec<String> = Vec::new();
    let mut buffer = String::new();
    for raw in text.lines() {
        let line = raw.trim_end_matches('\r');
        // Continuation lines end with a single backslash.
        if let Some(rest) = line.strip_suffix('\\') {
            buffer.push_str(rest);
            continue;
        }
        buffer.push_str(line);
        logical_lines.push(std::mem::take(&mut buffer));
    }
    if !buffer.is_empty() {
        logical_lines.push(buffer);
    }

    for line in logical_lines {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if line.starts_with("Windows Registry Editor") || line.eq_ignore_ascii_case("REGEDIT4") {
            continue;
        }
        if let Some(inner) = line.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
            let deletion = inner.starts_with('-');
            let path = normalize_key_path(inner.trim_start_matches('-'));
            if deletion {
                snapshot.warnings.push(format!("ignored key deletion directive [{inner}]"));
                current = None;
            }
            else {
                snapshot.insert(path.clone());
                current = Some(path);
            }
            continue;
        }
        let Some(path) = current.as_ref()
        else {
            continue;
        };
        if line.starts_with('-') {
            snapshot.warnings.push(format!("ignored value deletion directive {line}"));
            continue;
        }
        match parse_value_line(line) {
            Some((name, value)) => {
                let name = name.unwrap_or_default();
                snapshot.set_value(path, &name, value);
            }
            None => snapshot.warnings.push(format!("ignored unsupported line {line}")),
        }
    }

    snapshot
}

fn parse_value_line(line: &str) -> Option<(Option<String>, RegistryValue)> {
    let (name_part, data_part) = split_assignment(line)?;
    let name = if name_part == "@" { None } else { Some(unescape_string(name_part.strip_prefix('"')?.strip_suffix('"')?)) };
    let value = if let Some(rest) = data_part.strip_prefix('"') {
        RegistryValue { kind: RegistryValueKind::String, data: unescape_string(rest.strip_suffix('"')?) }
    }
    else if let Some(hex) = data_part.strip_prefix("dword:") {
        let parsed = u32::from_str_radix(hex.trim(), 16).ok()?;
        RegistryValue { kind: RegistryValueKind::Dword, data: parsed.to_string() }
    }
    else if let Some(hex) = data_part.strip_prefix("hex(2):") {
        RegistryValue { kind: RegistryValueKind::ExpandString, data: decode_utf16_hex(hex)? }
    }
    else {
        RegistryValue { kind: RegistryValueKind::Other, data: data_part.to_string() }
    };
    Some((name, value))
}

fn split_assignment(line: &str) -> Option<(String, &str)> {
    let bytes = line.as_bytes();
    let mut in_quotes = false;
    let mut escape = false;
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'\\' if in_quotes && !escape => escape = true,
            b'"' if !escape => in_quotes = !in_quotes,
            b'=' if !in_quotes => {
                let name = line[..index].trim().to_string();
                let rest = line[index + 1..].trim();
                return (!name.is_empty()).then_some((name, rest));
            }
            _ => escape = false,
        }
        if *byte != b'\\' {
            escape = false;
        }
    }
    None
}

fn unescape_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => match chars.next() {
                Some(next @ ('\\' | '"')) => out.push(next),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            },
            _ => out.push(ch),
        }
    }
    out
}

/// `hex(2)` expand strings are UTF-16LE byte runs; keep the first segment.
fn decode_utf16_hex(rest: &str) -> Option<String> {
    let mut bytes = Vec::new();
    for chunk in rest.split(',') {
        let chunk = chunk.trim();
        if chunk.is_empty() {
            continue;
        }
        bytes.push(u8::from_str_radix(chunk, 16).ok()?);
    }
    let utf16: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|chunk| u16::from_le_bytes(*chunk)).collect();
    let end = utf16.iter().position(|&unit| unit == 0).unwrap_or(utf16.len());
    Some(String::from_utf16_lossy(&utf16[..end]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\Gone App]
"DisplayName"="Gone App"
"DisplayVersion"="1.2.3"
"InstallLocation"="C:\\Program Files\\Gone App"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{ABCD}]
"DisplayName"="Vendor Tool"
"SystemComponent"=dword:00000001
"InstallLocation"="C:\\Program Files\\Vendor Tool"

[HKEY_CURRENT_USER\Software\Classes\gonefile\shell\open\command]
@="\"C:\\Program Files\\Gone App\\gone.exe\" \"%1\""

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
"GoneAgent"="\"C:\\Program Files\\Gone App\\agent.exe\" /run"

[HKEY_CURRENT_USER\Environment]
"Path"=hex(2):25,00,55,00,53,00,45,00,52,00,50,00,52,00,4f,00,46,00,49,00,4c,00,45,00,25,00,5c,00,62,00,69,00,6e,00,00,00
"#;

    #[test]
    fn parses_keys_strings_dwords_and_expand_strings() {
        let snapshot = parse_reg(FIXTURE, "fixture.reg");
        assert_eq!(snapshot.source, "fixture.reg");
        assert_eq!(snapshot.keys.len(), 5);

        let uninstall = snapshot.key(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Gone App").expect("uninstall key");
        assert_eq!(snapshot.value(&uninstall.path, "DisplayName").expect("display name").data, "Gone App");
        assert_eq!(snapshot.value(&uninstall.path, "InstallLocation").expect("install location").kind, RegistryValueKind::String);

        let component = snapshot.key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{ABCD}").expect("component key");
        assert_eq!(snapshot.value(&component.path, "SystemComponent").expect("system component").data, "1");

        let association = snapshot.key(r"HKCU\Software\Classes\gonefile\shell\open\command").expect("association");
        assert_eq!(snapshot.value(&association.path, "").expect("default value").data, r#""C:\Program Files\Gone App\gone.exe" "%1""#);

        let path = snapshot.value(r"HKCU\Environment", "Path").expect("path value");
        assert_eq!(path.kind, RegistryValueKind::ExpandString);
        assert_eq!(path.data, r"%USERPROFILE%\bin");
        assert!(snapshot.warnings.is_empty(), "{:?}", snapshot.warnings);
    }

    #[test]
    fn normalizes_hive_aliases_and_lookup_is_case_insensitive() {
        assert_eq!(normalize_key_path(r"HKEY_CURRENT_USER\Software"), r"HKCU\Software");
        assert_eq!(normalize_key_path("HKLM\\Software\\"), "HKLM\\Software");

        let snapshot = parse_reg("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Vendor]\n\"Name\"=\"value\"\n", "x");
        assert!(snapshot.value(r"HKLM\software\vendor", "name").is_some());
    }

    #[test]
    fn records_warnings_for_unsupported_directives() {
        let snapshot = parse_reg("[HKEY_CURRENT_USER\\Software\\X]\n\"Bin\"=hex:01,02\n", "x");
        assert_eq!(snapshot.keys.len(), 1);
        let value = snapshot.value(r"HKCU\Software\X", "Bin").expect("bin value");
        assert_eq!(value.kind, RegistryValueKind::Other);
    }
}
