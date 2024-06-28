/**
 * Copy VMZ static delivery into the Open Cleaner WebView content root.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const uiRoot = path.resolve(here, '..');
const from = path.join(uiRoot, 'dist', 'static');
const to = path.resolve(uiRoot, '..', 'open-cleaner', 'dist', 'gui');

function copyDir(src: string, dest: string): void {
    fs.mkdirSync(dest, { recursive: true });
    for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
        const s = path.join(src, entry.name);
        const d = path.join(dest, entry.name);
        if (entry.isDirectory()) copyDir(s, d);
        else fs.copyFileSync(s, d);
    }
}

if (!fs.existsSync(path.join(from, 'index.html'))) {
    console.error(`missing static delivery at ${from} (run vmz build first)`);
    process.exit(1);
}

fs.rmSync(to, { recursive: true, force: true });
copyDir(from, to);
console.log(`staged ${from} → ${to}`);
