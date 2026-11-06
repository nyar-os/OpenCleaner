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

export type RegistryResidueKind = 'uninstall-residue' | 'file-association' | 'startup-item';

/** One registry residue hit, always anchored on a concrete key path. */
export type RegistryFinding = {
    kind: RegistryResidueKind;
    keyPath: string;
    valueName?: string | null;
    displayName?: string | null;
    target: string;
    evidence: string;
    safety: string;
};

export type RegistryResidueOptions = {
    limit?: number;
};

export type RegistryResidueReport = {
    platform: string;
    source: string;
    scannedKeys: number;
    findings: RegistryFinding[];
    warnings: string[];
    scannedAtUnixMs: number;
};

export type DevRiskLevel = 'project-local' | 'global-cache';

/** A developer artifact candidate; every hit carries its rule and anchor. */
export type DevArtifact = {
    path: string;
    bytes: number;
    level: 1 | 2;
    risk: DevRiskLevel;
    ecosystem: string;
    rule: string;
    anchor: string;
    projectRoot?: string | null;
    volume?: string | null;
    crossVolume: boolean;
    warnings: string[];
};

export type DevScanOptions = {
    /** Directories searched for projects. Empty = current working directory. */
    roots?: string[];
    /** Include level-2 global caches. Level 2 is never selected by default. */
    includeGlobal?: boolean;
    maxDepth?: number;
    limit?: number;
};

export type DevScanReport = {
    roots: string[];
    scannedProjects: number;
    anchors: string[];
    artifacts: DevArtifact[];
    warnings: string[];
    scannedAtUnixMs: number;
};

export type DeleteMode = 'trash' | 'permanent';

export type DevSkipReason =
    | 'symlink-not-followed'
    | 'protected-path'
    | 'manifest-missing'
    | 'rule-mismatch'
    | 'not-found'
    | 'not-a-directory'
    | 'in-use-or-locked';

export type DevPlanItem = {
    artifact: DevArtifact;
    removable: boolean;
    skipReason?: DevSkipReason | null;
};

export type DevPlan = {
    roots: string[];
    mode: DeleteMode;
    modeSupported: boolean;
    items: DevPlanItem[];
    totalBytes: number;
    removableBytes: number;
    skippedBytes: number;
    warnings: string[];
    scannedAtUnixMs: number;
};

export type DevCleanOptions = {
    /** Paths taken from a dry-run plan; each is re-validated before deletion. */
    paths: string[];
    mode?: DeleteMode;
    confirm: boolean;
};

export type DevCleanStatus = 'deleted' | 'trashed' | 'skipped' | 'failed';

export type DevCleanItem = {
    path: string;
    bytes: number;
    status: DevCleanStatus;
    reason?: string | null;
};

export type DevCleanReport = {
    mode: DeleteMode;
    executed: boolean;
    items: DevCleanItem[];
    freedBytes: number;
    warnings: string[];
};

export type PathScope = 'user' | 'machine';

export type PathIssue = 'empty' | 'unresolved' | 'duplicate' | 'missing' | 'shadowed';

export type EnvPathEntry = {
    scope: PathScope;
    keyPath: string;
    index: number;
    raw: string;
    expanded?: string | null;
    issue?: PathIssue | null;
    evidence: string;
    safety: string;
    removable: boolean;
    /** PATH is high risk: this is always false in the current build. */
    defaultSelected: boolean;
    relatedIndex?: number | null;
};

export type EnvPathScopeReport = {
    scope: PathScope;
    keyPath: string;
    present: boolean;
    entries: EnvPathEntry[];
    issues: number;
    removable: number;
};

export type EnvPathOptions = {
    limit?: number;
};

export type EnvPathReport = {
    platform: string;
    scopes: EnvPathScopeReport[];
    /** Directory that will hold the next rollback pair, when available. */
    backupDir?: string | null;
    warnings: string[];
    scannedAtUnixMs: number;
};

export type EnvPathSelection = {
    index: number;
    /** Raw value from the dry-run report; must still match when cleaning. */
    raw: string;
};

export type EnvPathCleanOptions = {
    scope: PathScope;
    selections: EnvPathSelection[];
    confirm: boolean;
    backupDir?: string;
};

export type EnvPathCleanStatus = 'removed' | 'skipped' | 'failed';

export type EnvPathCleanItem = {
    index: number;
    raw: string;
    status: EnvPathCleanStatus;
    reason?: string | null;
};

export type EnvPathBackup = {
    jsonPath: string;
    regPath: string;
    original: string;
    restoreRegText: string;
};

export type EnvPathCleanReport = {
    scope: PathScope;
    keyPath: string;
    executed: boolean;
    items: EnvPathCleanItem[];
    removed: number;
    original?: string | null;
    newValue?: string | null;
    backup?: EnvPathBackup | null;
    warnings: string[];
};

export type SoftwareKind = 'install-directory' | 'config-directory';

export type SoftwareFinding = {
    id: string;
    kind: SoftwareKind;
    path: string;
    bytes: number;
    displayName: string;
    /** Uninstall key that anchors this candidate. */
    registryKey: string;
    installLocation?: string | null;
    rule: string;
    evidence: string;
    safety: string;
    removable: boolean;
};

export type SoftwareSkip = {
    registryKey: string;
    displayName?: string | null;
    /** `still-installed`, `system-component`, `update-package`, `no-display-name` or `user-data`. */
    reason: string;
};

export type SoftwareOptions = {
    limit?: number;
};

export type SoftwareReport = {
    platform: string;
    source: string;
    uninstallKeys: number;
    findings: SoftwareFinding[];
    skipped: SoftwareSkip[];
    warnings: string[];
    scannedAtUnixMs: number;
};

export type Capabilities = {
    platform: string;
    arch: string;
    fileScan: boolean;
    devScan: boolean;
    devClean: boolean;
    /** Whether deletion routes through the OS recycle bin. */
    trash: boolean;
    registryScan: boolean;
    registryClean: boolean;
    envPathScan: boolean;
    envPathClean: boolean;
    softwareScan: boolean;
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
    /** JSON-encoded options; see `devScan` in the facade for the typed API. */
    devScan(optionsJson?: string): DevScanReport;
    devPlan(optionsJson?: string, mode?: DeleteMode): DevPlan;
    devClean(optionsJson: string): DevCleanReport;
    registryResidueScan(optionsJson?: string): RegistryResidueReport;
    envPathScan(optionsJson?: string): EnvPathReport;
    envPathClean(optionsJson: string): EnvPathCleanReport;
    softwareResidueScan(optionsJson?: string): SoftwareReport;
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
