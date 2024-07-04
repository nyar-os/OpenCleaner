# `@wae/open-cleaner`

Disk scanner with an optional WebView2 GUI. Built on the WAE meta toolkit:

- Rust addon via facade crate `wae` from `doki-land/wae-framework` (Cargo git rev)
- TypeScript CLI via npm `@wae/commander`
- WebView UI via npm `@vmz/ui` / `@vmz/vmz`

```text
crates/                 # Rust (core + napi cdylib)
packages/
  open-cleaner/         # TS meta package (library + CLI + locales)
    dist/               # publish root (JS + gui/)
      gui/              # staged from open-cleaner-ui dist/static
  open-cleaner-ui/      # @vmz/ui WebView application
  open-cleaner-win32-x64/   # platform package (.node)
  open-cleaner-darwin-arm64/
  open-cleaner-darwin-x64/
  open-cleaner-linux-x64/
  open-cleaner-linux-arm64/
```

```bash
pnpm install
pnpm --filter @wae/open-cleaner-ui run design:init
pnpm run build
pnpm run gui
```

```js
import { capabilities, registryScan, scan, runGui } from '@wae/open-cleaner';
console.log(scan({ limit: 10 }).totalBytes);
console.log(capabilities());
// Windows only. Rejects with a structured error on macOS and Linux.
console.log(registryScan({ limit: 10 }).entries);
await runGui({ title: 'Open Cleaner' });
```

```bash
pnpm --filter @wae/open-cleaner exec node ./dist/cli.js scan --limit 5
pnpm --filter @wae/open-cleaner exec node ./dist/cli.js capabilities
pnpm --filter @wae/open-cleaner exec node ./dist/cli.js registry --limit 5
pnpm --filter @wae/open-cleaner exec node ./dist/cli.js --help
```

Platform support: file and disk scanning is portable. Windows registry inspection and the
WebView2 GUI are Windows-only. Registry cleaning is not implemented in this build, so
`capabilities().registryClean` is `false` everywhere. Cross-target staging uses
`OPEN_CLEANER_TARGET=<rust-triple> pnpm run stage:native`.
