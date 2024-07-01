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
  open-cleaner-win32-x64/  # platform package (.node)
```

```bash
pnpm install
pnpm --filter @wae/open-cleaner-ui run design:init
pnpm run build
pnpm run gui
```

```js
import { scan, runGui } from '@wae/open-cleaner';
console.log(scan({ limit: 10 }).totalBytes);
await runGui({ title: 'Open Cleaner' });
```

```bash
pnpm --filter @wae/open-cleaner exec node ./dist/cli.js scan --limit 5
pnpm --filter @wae/open-cleaner exec node ./dist/cli.js --help
```
