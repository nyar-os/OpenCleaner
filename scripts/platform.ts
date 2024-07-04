import fs from 'node:fs';
import path from 'node:path';

export type Platform = 'win32' | 'darwin' | 'linux';
export type Arch = 'x64' | 'arm64';

export type Target = {
    platform: Platform;
    arch: Arch;
    triple: string;
};

const TARGETS: Record<string, Target> = {
    'x86_64-pc-windows-msvc': { platform: 'win32', arch: 'x64', triple: 'x86_64-pc-windows-msvc' },
    'x86_64-apple-darwin': { platform: 'darwin', arch: 'x64', triple: 'x86_64-apple-darwin' },
    'aarch64-apple-darwin': { platform: 'darwin', arch: 'arm64', triple: 'aarch64-apple-darwin' },
    'x86_64-unknown-linux-gnu': { platform: 'linux', arch: 'x64', triple: 'x86_64-unknown-linux-gnu' },
    'aarch64-unknown-linux-gnu': { platform: 'linux', arch: 'arm64', triple: 'aarch64-unknown-linux-gnu' },
};

function hostTriple(): string {
    switch (`${process.platform}-${process.arch}`) {
        case 'win32-x64':
            return 'x86_64-pc-windows-msvc';
        case 'darwin-x64':
            return 'x86_64-apple-darwin';
        case 'darwin-arm64':
            return 'aarch64-apple-darwin';
        case 'linux-x64':
            return 'x86_64-unknown-linux-gnu';
        case 'linux-arm64':
            return 'aarch64-unknown-linux-gnu';
        default:
            throw new Error(
                `Unsupported host ${process.platform}-${process.arch}. Supported targets: ${Object.keys(TARGETS).join(', ')}`,
            );
    }
}

/**
 * `OPEN_CLEANER_TARGET` selects an explicit Rust target triple (CI cross builds).
 * Without it the host triple is used.
 */
export function resolveTarget(): Target {
    const triple = process.env.OPEN_CLEANER_TARGET ?? hostTriple();
    const target = TARGETS[triple];
    if (!target) {
        throw new Error(`Unsupported Rust target ${triple}. Supported targets: ${Object.keys(TARGETS).join(', ')}`);
    }
    return target;
}

export function usesExplicitTarget(): boolean {
    return Boolean(process.env.OPEN_CLEANER_TARGET);
}

export function packageName(target: Target): string {
    return `open-cleaner-${target.platform}-${target.arch}`;
}

export function nodeFileName(target: Target): string {
    return `open-cleaner.${target.platform}-${target.arch}.node`;
}

export function packageDir(root: string, target: Target): string {
    return path.join(root, 'packages', packageName(target));
}

function cdylibName(target: Target): string {
    switch (target.platform) {
        case 'win32':
            return 'open_cleaner_napi.dll';
        case 'darwin':
            return 'libopen_cleaner_napi.dylib';
        case 'linux':
            return 'libopen_cleaner_napi.so';
    }
}

function artifactCandidates(root: string, target: Target): string[] {
    const base = usesExplicitTarget() ? path.join(root, 'target', target.triple, 'release') : path.join(root, 'target', 'release');
    return [path.join(base, cdylibName(target)), path.join(base, 'open_cleaner_napi.node')];
}

export function findNativeArtifact(root: string, target: Target): string {
    const candidates = artifactCandidates(root, target);
    const found = candidates.find((candidate) => fs.existsSync(candidate));
    if (!found) {
        throw new Error(`native artifact not found for ${target.triple}. Tried:\n${candidates.map((p) => `  - ${p}`).join('\n')}`);
    }
    return found;
}

export function stageNative(root: string, target: Target): { src: string; dest: string } {
    const src = findNativeArtifact(root, target);
    const destDir = packageDir(root, target);
    fs.mkdirSync(destDir, { recursive: true });
    const dest = path.join(destDir, nodeFileName(target));
    fs.copyFileSync(src, dest);
    return { src, dest };
}
