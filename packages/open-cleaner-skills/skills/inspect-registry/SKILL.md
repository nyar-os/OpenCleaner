---
name: inspect-registry
description: Inspect Windows uninstall entries for broken install locations. Windows only, read-only.
---

# Inspect Windows registry entries

Use when the user asks about orphaned uninstall entries or stale installed-program records.

## Platform check

1. Read the capability contract:

   `open-cleaner capabilities`

   - `registryScan: true` only on Windows. `registryClean` is `false` in this build.
   - On macOS and Linux `registryScan` is `false`. The CLI exits non-zero with a
     `registry-scan` unsupported message. Report that instead of inventing results.

2. Scan uninstall entries on Windows:

   `open-cleaner registry --limit <n>`

   `--limit` defaults to 100 and must be at least 1.

3. Read the output:

   ```text
   platform: windows
   scanned keys: <count of uninstall subkeys inspected>
   <reason>  <display name or key>  <install location>
   ```

   `install-location-missing` means the row is orphaned: its recorded `InstallLocation`
   no longer exists and the same install evidence chain the `software` command uses finds
   no executable, no running image, no installer registration and no recently written
   matching directory. A missing install path alone is not enough to report a row.
   Absent `DisplayName`, `InstallLocation`, or version fields mean the registry value was
   missing or empty.

## What this checks

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` (64-bit view)
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
- Entries marked `SystemComponent`, update packages (`ParentKeyName` or an update
  `ReleaseType`), and rows whose install evidence still proves the product is present are
  skipped.

## Safety

- The command is read-only. Nothing is deleted.
- Do not run `reg delete`, do not edit the registry by hand, and do not claim a cleanup
  succeeded. Registry deletion is not implemented in this build.
- Do not present macOS or Linux results as registry data. Those platforms have no registry
  capability and must fail explicitly.
- Do not publish packages locally and do not bypass CI.
