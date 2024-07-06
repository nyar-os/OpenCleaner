# `@wae/open-cleaner-skills`

Agent skills for `@wae/open-cleaner`. This package is the family shape for Open app skill bundles:
copy the directory layout, replace `skills/*`, and keep the same metadata rules.

```text
packages/open-cleaner-skills/
  package.json          # files: only skills + README, license MPL-2.0
  README.md
  skills/
    <skill-name>/
      SKILL.md          # frontmatter name + description, then when/how
      references/       # optional supporting notes
```

Rules:

- The package version always matches the owning app package. Do not introduce a separate version line.
- Each skill directory name equals the frontmatter `name`.
- Skill bodies describe agent actions: real commands, real flags, and how to read the output.
- Skills never link internal decision documents. Only the workspace root `AGENTS.md` is a valid index.
- Every skill carries a `## Safety` section: preview first, explicit user confirmation, no unvalidated recursive deletion, no local publishing or CI bypass.

Skills in this package:

| Skill | Purpose |
|-------|---------|
| `scan-disk-usage` | Measure what occupies a directory and rank the entries |
| `clean-temp-cache` | Find temporary and cache files, then delete only confirmed paths |
| `clean-dev-artifacts` | Locate build outputs such as `target/`, `node_modules/`, and package stores |
| `inspect-registry` | Inspect Windows uninstall entries for broken install locations |

Validation: `pnpm run build:ts` then `pnpm run check:skills`. The check parses every
frontmatter and verifies that each referenced `open-cleaner` command and flag exists in the
real CLI command tree.
