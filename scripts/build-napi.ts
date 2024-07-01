#!/usr/bin/env node
/** cargo build open-cleaner-napi → stage into packages/open-cleaner-win32-x64 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function run(cmd: string, args: string[]): void {
    // Avoid shell:true — Node 22+ warns DEP0190 when args + shell are combined.
    const r = spawnSync(cmd, args, { cwd: root, stdio: 'inherit', shell: false });
    if ((r.status ?? 1) !== 0) {
        process.exit(r.status ?? 1);
    }
}

run('cargo', ['build', '-p', 'open-cleaner-napi', '--release']);

const release = path.join(root, 'target', 'release');
const candidates = [
    path.join(release, 'open_cleaner_napi.dll'),
    path.join(release, 'open_cleaner_napi.node'),
    path.join(release, 'libopen_cleaner_napi.so'),
    path.join(release, 'libopen_cleaner_napi.dylib'),
];
const artifact = candidates.find((p) => fs.existsSync(p));
if (!artifact) {
    console.error('native artifact not found under target/release');
    process.exit(1);
}

const destDir = path.join(root, 'packages', 'open-cleaner-win32-x64');
fs.mkdirSync(destDir, { recursive: true });
const dest = path.join(destDir, 'open-cleaner.win32-x64.node');
fs.copyFileSync(artifact, dest);
console.log(`staged ${artifact} -> ${dest}`);
