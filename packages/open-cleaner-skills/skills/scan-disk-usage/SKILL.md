---
name: scan-disk-usage
description: Measure directory and disk usage with the read-only OpenCleaner scan command, then rank the largest entries.
---

# Scan disk usage

Use when the user asks what occupies space in a folder or wants a ranked list of large
files before deciding what to remove.

## Steps

1. Check the platform contract:

   `open-cleaner capabilities`

   Read `fileScan`. It is `true` on every supported platform. If the addon cannot load,
   stop and report the missing platform package instead of guessing sizes.

2. Scan a bounded directory:

   `open-cleaner scan --root <absolute-path> --limit <n>`

   `--root` defaults to the process temporary directory. Always pass an absolute path.
   `--limit` defaults to 50 and must be at least 1.

3. Read the output:

   ```text
   root: <scanned root>
   total: <bytes summed over all files below the root>
       size  kind    path
   ```

   Rows are sorted largest first. `kind` is one of `cache`, `temp`, `log`, or `file`.
   The returned rows are truncated by `--limit`, but `total` covers the whole scan.

## Limits

- Traversal stops at depth 8.
- Windows junctions and reparse points are not followed.
- Symbolic links are not followed on macOS and Linux.
- Sizes are file sizes, not allocated blocks.

## Safety

- `scan` is read-only and is the preview step for cleanup work.
- Never treat a truncated list as the full inventory. `total` is authoritative for bytes.
- Do not delete anything from a scan result without a separate confirmed cleanup step.
- Never scan or delete a volume root, user home root, repository root without an explicit
  user request naming that path.
