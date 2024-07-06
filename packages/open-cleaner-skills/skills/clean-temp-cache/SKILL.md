---
name: clean-temp-cache
description: Locate temporary and cache files with OpenCleaner and remove only the exact paths the user confirms.
---

# Clean temporary and cache files

Use when the user wants to reclaim space from temporary directories or cache folders.

## Steps

1. Confirm the platform supports file scanning:

   `open-cleaner capabilities`

   `fileScan` must be `true`. If it is not, stop.

2. Preview with the read-only scan:

   `open-cleaner scan --root <temp-or-cache-path> --limit <n>`

   Choose the root from the user's request. When no root is given, use the platform
   temporary directory and say which path was used.

3. Select candidates by the output:

   - `kind: temp` for temporary files
   - `kind: cache` for cache files
   - `kind: log` for log files that the user explicitly agreed to remove

   Show the exact paths and sizes. Do not delete anything in the same step.

4. Ask for explicit confirmation per path or per validated directory.

5. Delete only the confirmed, resolved, absolute paths with a single non-recursive delete
   when the target is a file. Use a directory delete only for a directory the user named and
   that passed a path check.

## This build

There is no delete command and no `--dry-run` flag in this CLI build. `scan` is the preview.
If a future build exposes a cleanup command, run its dry-run preview first and only then ask
for confirmation.

## Safety

- Never delete a path that contains `*`, `?`, an unexpanded variable, or a trailing separator
  used as a root.
- Never recursively delete a volume root, the user home root, a repository root, or the
  current working directory.
- Never delete files outside the root the user named.
- Do not batch delete unrelated paths to save a confirmation round.
- Do not publish packages locally and do not bypass CI.
