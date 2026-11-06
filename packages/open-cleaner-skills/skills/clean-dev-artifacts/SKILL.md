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

## Risk tiers

Classify every candidate before proposing a deletion, and never move an item up a tier to
reclaim more bytes. The test is operational, not nominal: a path is only S when the build can
be reproduced from source that stays on disk, without downloading anything again.

| Tier | Test | Examples |
| --- | --- | --- |
| S | Reproduced from on-disk sources with no network and no loss of user data | `target/`, `dist/`, `build/`, `.next/`, `.turbo/`, `obj/`, `bin/` in a user project |
| A | Regenerated only after a network fetch, or the loss is a cache hit / diagnostic record | `node_modules/`, `.venv/`, `venv/`, `vendor/bundle/`, package manager stores, browser caches, prefetch, crash dumps, logs |
| B | Needs a system service, elevation, or installer state to undo | system temp roots, update downloads, package caches used for repair and uninstall, portable databases, recovery images |
| X | User data or system-owned state that this tool never removes | recycle bin contents, `WinSxS`, page and swap files, restore points and volume snapshots, MSI store, user documents and application data |

### The S set

`open-cleaner dev` selects S candidates. Run the dry-run plan first, then confirm:

`open-cleaner dev --root <project-root> --only target,dist --mode permanent --yes --actor-id <id> --actor-kind agent`

The gates below must all hold, and a skipped item is reported with its reason rather than retried:

- a manifest anchor in the owning project root (`Cargo.toml`, `package.json`, `pyproject.toml`,
  `build.gradle`, `pom.xml`, `Gemfile`, a `*.csproj` or `*.sln`) and the exact artifact suffix
- not a protected path, symbolic link, junction, or reparse point
- the rename probe succeeds, so the directory is not held open by another process

Dependency trees (`node_modules/`, `.venv/`, `venv/`, `vendor/bundle/`) and every global cache
are A, not S: reinstalling them needs the network again.

### Installing software is never S

The rule table matches a `package.json` next to a `node_modules/` or `dist/` directory wherever
that directory happens to live, so installed programs and editor extensions match as well. A
deletion there breaks a working program instead of a rebuildable build. Before adding a path
to an S plan, reject any candidate below an installation or application root:

- `Program Files`, `Program Files (x86)`, `ProgramData`, `Windows`
- application data roots that hold packaged extensions, for example `AppData` extension folders
- any path whose manifest belongs to a shipped product rather than the user's project

Report those as B and leave them alone. A directory name alone is never evidence.

### Temp directory reclamation

`open-cleaner temp` reclaims the temp root at file granularity. Nothing here removes a whole
directory, because one temp root mixes hundreds of thousands of files owned by unrelated
programs.

- Only files older than the threshold are candidates. The default is 7 days and
  `--older-than-days` changes it, so a file a program wrote today is never touched.
- Every candidate gets its own occupancy probe before it is selected, and the same probe runs
  again inside the executing pass. The probe asks for delete access, which is the only test that
  predicts whether removal will actually succeed: a file another process holds open is counted
  and skipped, never deleted and never retried later in the batch.
- Directories are still excluded as subtrees: a running process's working directory, a running
  process's own `TEMP`/`TMP` value, a symbolic link or junction, and any protected component.
- Each failure is printed with its path and reason. There is no aggregate "partial failure" row
  to hide an individual file.
- The plan prints the candidate count, the total bytes, and the distribution by age and by
  extension before the first deletion.

Temp files are A, not S. A stale temp file can be the only copy of a build artifact, an installer
payload, or a diagnostic capture: reclaiming it may cost a rebuild or lose evidence, which is
exactly the A test. Age, occupancy and exclusion are what make the rule safe, not a tier
promotion.

### Declared build roots

A shared build directory such as a central cargo target has no project manifest, so no
heuristic rule may claim it. `open-cleaner build-roots` accepts it only through an explicit
declaration in a plain-text config, one absolute path per line, with `#` comments:

```
# shared build outputs
C:\cargo-target
C:\_build
```

- A directory name is never evidence. Only a listed absolute path is eligible, and the same
  name elsewhere stays rejected.
- The plan prints the config path and the line number that authorized each path. The audit
  record carries the config path plus every `path`/`line` pair, so a later reviewer can find
  the exact line that allowed the deletion.
- Every declared root still passes the full gate set: absolute path, an existing directory, not
  a drive root, no protected component, not a shared platform directory, outside installed
  software, and not a symbolic link or junction.
- A root is skipped when a process holds it open or when any file under it changed within the
  last 10 minutes, so the tool never races a running build.
- Duplicate declarations are reported with the first line instead of counted twice.
- The default config is `open-cleaner/build-roots.conf` in the user data directory. A missing
  config is reported as missing, not as an empty list of removable roots.

This does not loosen the manifest requirement for `dev`: a config declaration is the only
additional route, and it is explicit, logged, and revocable by editing one line.

## Safety

- Preview first with `scan` or `dev` without `--yes`. Deletion is always a separate, confirmed
  action and is permanent unless `--mode trash` is requested.
- Never delete `node_modules` or `target` at a workspace root when the user only named one
  project.
- Never run `cargo clean` from a directory the user did not name.
- Do not run `pnpm store prune` without confirmation, and never as part of a CI job.
- Do not publish packages locally and do not bypass CI.
