# `@wae/open-cleaner-ui`

WebView UI for Open Cleaner, implemented with [`@vmz/ui`](https://www.npmjs.com/package/@vmz/ui).

## Develop

```bash
pnpm install
pnpm --filter @wae/open-cleaner-ui run design:init
pnpm --filter @wae/open-cleaner-ui run check
pnpm --filter @wae/open-cleaner-ui run build
pnpm --filter @wae/open-cleaner-ui run stage
```

`stage` copies `dist/static` into `packages/open-cleaner/dist/gui` for the native WebView2 host.

```bash
pnpm run gui
```
