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

export type RegistryOptions = {
    limit?: number;
};

export type RegistryEntry = {
    key: string;
    displayName?: string;
    installLocation?: string;
    version?: string;
    reason: string;
};

export type RegistryReport = {
    platform: string;
    scannedKeys: number;
    scannedAtUnixMs: number;
    entries: RegistryEntry[];
};

export type Capabilities = {
    platform: string;
    arch: string;
    fileScan: boolean;
    registryScan: boolean;
    registryClean: boolean;
    gui: boolean;
    notes: string[];
};

export type OpenGuiOptions = {
    title?: string;
    /** Local folder containing index.html (served via https://app.local/). */
    contentDir?: string;
    /** Escape hatch; prefer contentDir. */
    entryUrl?: string;
};

export type ActorKind = 'user' | 'agent';

export type AuditActor = {
    kind: ActorKind;
    id: string;
    source: string;
};

/** One append-only record from the shared `wae.audit/v0` history. */
export type AuditRecord = {
    schema: string;
    timestampMs: number;
    actor: AuditActor;
    app: string;
    appVersion: string;
    capability: string;
    mode: 'dry_run' | 'execute';
    params: unknown;
    targets: {
        count: number;
        summary: string;
    };
    result: 'success' | 'failure' | 'rejected';
    errorCode?: string;
    durationMs: number;
    host: string;
    session: string;
};

export type AuditConfigureOptions = {
    actorKind?: ActorKind;
    actorId?: string;
    actorSource?: string;
    session?: string;
    host?: string;
};

export type AuditQueryOptions = {
    actorKind?: ActorKind;
    actorId?: string;
    /** Inclusive lower bound, Unix milliseconds. */
    fromMs?: number;
    /** Inclusive upper bound, Unix milliseconds. */
    toMs?: number;
    capability?: string;
    limit?: number;
};

type NativeBinding = {
    scan(options?: ScanOptions): ScanReport;
    capabilities(): Capabilities;
    registryScan(options?: RegistryOptions): RegistryReport;
    version(): string;
    openGui(options?: OpenGuiOptions): void;
    pumpEvents(): boolean;
    closeGui(): void;
    isGuiOpen(): boolean;
    configureAudit(options?: AuditConfigureOptions): void;
    auditQuery(options?: AuditQueryOptions): AuditRecord[];
};

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));

type PlatformArch = 'win32-x64' | 'darwin-x64' | 'darwin-arm64' | 'linux-x64' | 'linux-arm64';

const PLATFORM_PACKAGES: Record<PlatformArch, string> = {
    'win32-x64': '@wae/open-cleaner-win32-x64',
    'darwin-x64': '@wae/open-cleaner-darwin-x64',
    'darwin-arm64': '@wae/open-cleaner-darwin-arm64',
    'linux-x64': '@wae/open-cleaner-linux-x64',
    'linux-arm64': '@wae/open-cleaner-linux-arm64',
};

export function supportedPlatforms(): PlatformArch[] {
    return Object.keys(PLATFORM_PACKAGES) as PlatformArch[];
}

function currentPlatformArch(): PlatformArch | null {
    const key = `${process.platform}-${process.arch}`;
    return (Object.hasOwn(PLATFORM_PACKAGES, key) ? key : null) as PlatformArch | null;
}

function platformPackageName(pa: PlatformArch): string {
    return PLATFORM_PACKAGES[pa];
}

function candidateNodePaths(): string[] {
    const pa = currentPlatformArch();
    if (!pa) {
        throw new Error(
            `Unsupported platform ${process.platform}-${process.arch}. Supported: ${supportedPlatforms().join(', ')}. ` +
                'Install a matching @wae/open-cleaner-* package.',
        );
    }

    const pkg = platformPackageName(pa);
    const fileName = `open-cleaner.${pa}.node`;
    const paths: string[] = [];

    try {
        const pkgJson = require.resolve(`${pkg}/package.json`);
        const root = path.dirname(pkgJson);
        paths.push(path.join(root, fileName));
    } catch {
        // optional dependency may be missing during monorepo dev
    }

    // packages/open-cleaner/dist → ../../open-cleaner-<platform>-<arch>
    paths.push(
        path.resolve(here, `../../open-cleaner-${pa}/${fileName}`),
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
