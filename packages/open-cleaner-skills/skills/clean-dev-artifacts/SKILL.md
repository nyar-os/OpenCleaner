---
name: clean-dev-artifacts
description: Find build outputs such as target directories, node_modules, and package stores, then clean them with the owning tool after confirmation.
---

# Clean development artifacts

Use when the user wants to reclaim space from build outputs without touching sources.

## Steps

1. Preview the repository with the read-only scan:

   `open-cleaner scan --root <repository-path> --limit <n>`

   Build outputs are reported as ordinary `file` rows unless the path itself contains
   `cache` or `temp`. Identify artifacts by the path prefix, not by `kind`.

2. Recognise the usual artifacts:

   - `target/` for Rust builds
   - `node_modules/` for Node installs
   - `dist/`, `build/`, `.cache/` for generated front-end output
   - package-manager stores named `pnpm`, `yarn`, `npm`, or `cargo` in the user's cache root

3. Prefer the owning tool over manual deletion:

   - Rust build output in the current package: `cargo clean`
   - Unreferenced packages in the pnpm store: `pnpm store prune`

   Run the tool only after the user confirms. Show which directory it will remove.

4. For anything without a tool command, delete only an exact directory the user named and
   verified. Never delete a store or repository root.

## Limits

- Scan depth is 8, so very deep artifact trees appear partially. Use a narrower root when a
  count looks wrong.
- A scan row is a file. Empty directories and directory totals do not appear as rows.

## Safety

- Preview first with `scan`. There is no delete command and no `--dry-run` flag in this CLI
  build, so deletion is always a separate confirmed action.
- Never delete `node_modules` or `target` at a workspace root when the user only named one
  project.
- Never run `cargo clean` from a directory the user did not name.
- Do not run `pnpm store prune` without confirmation, and never as part of a CI job.
- Do not publish packages locally and do not bypass CI.
