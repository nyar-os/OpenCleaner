import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export type ScanEntry = {
    path: string;
    bytes: number;
    kind: string;
};

export type ScanReport = {
    root: string;
    totalBytes: number;
    scannedAtUnixMs: number;
    entries: ScanEntry[];
};

export type ScanOptions = {
    root?: string;
    limit?: number;
};

export type OpenGuiOptions = {
    title?: string;
    /** Local folder containing index.html (served via https://app.local/). */
    contentDir?: string;
    /** Escape hatch; prefer contentDir. */
    entryUrl?: string;
};

type NativeBinding = {
    scan(options?: ScanOptions): ScanReport;
    version(): string;
    openGui(options?: OpenGuiOptions): void;
    pumpEvents(): boolean;
    closeGui(): void;
    isGuiOpen(): boolean;
};

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));

function platformPackageName(): string {
    const { platform, arch } = process;
    if (platform === 'win32' && arch === 'x64') return '@wae/open-cleaner-win32-x64';
    throw new Error(
        `Unsupported platform ${platform}-${arch}. Install a matching @wae/open-cleaner-* package.`,
    );
}

function candidateNodePaths(): string[] {
    const pkg = platformPackageName();
    const names = ['open-cleaner.win32-x64.node', 'open_cleaner_napi.node'];
    const paths: string[] = [];

    try {
        const pkgJson = require.resolve(`${pkg}/package.json`);
        const root = path.dirname(pkgJson);
        for (const name of names) {
            paths.push(path.join(root, name));
        }
    } catch {
        // optional dependency may be missing during monorepo dev
    }

    // packages/open-cleaner/dist → ../../open-cleaner-win32-x64
    paths.push(
        path.resolve(here, '../../open-cleaner-win32-x64/open-cleaner.win32-x64.node'),
        path.resolve(here, '../../../target/release/open_cleaner_napi.node'),
    );
    return paths;
}

let cached: NativeBinding | null = null;

export function loadNative(): NativeBinding {
    if (cached) return cached;
    const tried: string[] = [];
    for (const candidate of candidateNodePaths()) {
        tried.push(candidate);
        if (!fs.existsSync(candidate)) continue;
        cached = require(candidate) as NativeBinding;
        return cached;
    }
    throw new Error(
        `Failed to load open-cleaner native addon. Tried:\n${tried.map((p) => `  - ${p}`).join('\n')}`,
    );
}

/** GUI assets ship inside the published/built `dist/gui` tree. */
export function defaultGuiContentDir(): string {
    const dir = path.resolve(here, 'gui');
    if (!fs.existsSync(path.join(dir, 'index.html'))) {
        throw new Error(`GUI folder missing at ${dir} (expected packages/open-cleaner/dist/gui)`);
    }
    return dir;
}
