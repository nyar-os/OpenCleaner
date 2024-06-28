#!/usr/bin/env node
/** Copy release cdylib into packages/open-cleaner-win32-x64 as .node */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const release = path.join(root, 'target', 'release');
const candidates = [
    path.join(release, 'open_cleaner_napi.dll'),
    path.join(release, 'open_cleaner_napi.node'),
    path.join(release, 'libopen_cleaner_napi.so'),
    path.join(release, 'libopen_cleaner_napi.dylib'),
];
const src = candidates.find((p) => fs.existsSync(p));
if (!src) {
    console.error('native artifact not found under target/release');
    process.exit(1);
}
const destDir = path.join(root, 'packages', 'open-cleaner-win32-x64');
fs.mkdirSync(destDir, { recursive: true });
const dest = path.join(destDir, 'open-cleaner.win32-x64.node');
fs.copyFileSync(src, dest);
console.log(`staged ${src} -> ${dest}`);
