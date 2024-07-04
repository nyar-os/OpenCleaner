#!/usr/bin/env node
/** cargo build open-cleaner-napi → stage into the matching platform package */
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveTarget, stageNative, usesExplicitTarget } from './platform.ts';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const target = resolveTarget();

function run(cmd: string, args: string[]): void {
    // Avoid shell:true — Node 22+ warns DEP0190 when args + shell are combined.
    const r = spawnSync(cmd, args, { cwd: root, stdio: 'inherit', shell: false });
    if ((r.status ?? 1) !== 0) {
        process.exit(r.status ?? 1);
    }
}

const args = ['build', '-p', 'open-cleaner-napi', '--release'];
if (usesExplicitTarget()) {
    args.push('--target', target.triple);
}
run('cargo', args);

const { src, dest } = stageNative(root, target);
console.log(`staged ${src} -> ${dest}`);
