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
    /**
     * Directories whose listing was denied. Their subtrees are skipped instead
     * of failing the scan, and their bytes are not in `totalBytes`.
     */
    unreadableDirs: number;
    /** The denied directory at the top of each skipped subtree. */
    unreadablePaths: string[];
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

/**
 * What `bytes` was measured from. A later delete reuses the number while the
 * artifact directory still matches this snapshot and measures again otherwise.
 */
export type DevSizeBaseline = {
    bytes: number;
    entries: number;
    /** Hex digest of the directory listing, kept as text to stay exact. */
    stamp: string;
};

/** One path handed to `devClean`, with its optional scan-time measurement. */
export type DevCleanTarget = {
    path: string;
    baseline?: DevSizeBaseline | null;
};

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
    /** Level 2 caches are never preselected: rebuilding them downloads again. */
    defaultSelected: boolean;
    baseline?: DevSizeBaseline | null;
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

export type DevStageTiming = {
    name: string;
    elapsedMs: number;
};

/** Opt-in measurements, present only when `OPEN_CLEANER_PROFILE` is set. */
export type DevProfile = {
    stages: DevStageTiming[];
    /** Directories listed by the project walk. */
    dirsVisited: number;
    /** Directories listed again while sizing artifact subtrees. */
    measuredDirs: number;
    /** Files sized inside artifact subtrees. */
    filesVisited: number;
    bytesMeasured: number;
    peakWorkingSetBytes?: number | null;
    peakHandleCount?: number | null;
};

export type DevScanReport = {
    roots: string[];
    scannedProjects: number;
    anchors: string[];
    artifacts: DevArtifact[];
    warnings: string[];
    scannedAtUnixMs: number;
    profile?: DevProfile | null;
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
    profile?: DevProfile | null;
};

export type DevCleanOptions = {
    /** Targets taken from a dry-run plan; each is re-validated before deletion. */
    targets: DevCleanTarget[];
    mode?: DeleteMode;
    confirm: boolean;
    /** Cleanup workers. Defaults to 1 (serial), clamped to 1..=8. */
    concurrency?: number;
};

export type DevCleanStatus = 'deleted' | 'trashed' | 'skipped' | 'failed';

/** Where an item's byte count came from. */
export type DevSizeSource = 'scanned' | 'remeasured' | 'not-measured';

export type DevCleanItem = {
    path: string;
    bytes: number;
    status: DevCleanStatus;
    reason?: string | null;
    sizeSource: DevSizeSource;
};

export type DevCleanReport = {
    mode: DeleteMode;
    executed: boolean;
    items: DevCleanItem[];
    freedBytes: number;
    /** Part of `freedBytes` reused from the scan-time measurement. */
    freedBytesScanned: number;
    /** Part of `freedBytes` measured again right before deletion. */
    freedBytesRemeasured: number;
    warnings: string[];
    profile?: DevProfile | null;
};

export type PathScope = 'user' | 'machine';

export type PathIssue = 'empty' | 'unresolved' | 'duplicate' | 'missing';

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

export type TempSkips = {
    recent: number;
    symlink: number;
    protected: number;
    inUse: number;
    cwdShielded: number;
    processTemp: number;
    /** Directories hosting the image of a running process. */
    programShielded: number;
    /** Old files whose path holds a directory with newer content. */
    dirRecent: number;
    /** Directories excluded because they hold a project manifest anchor. */
    devRoot: number;
    /** Files inside an operator-declared build root. */
    buildRoot: number;
    unreadable: number;
};

export type TempGroup = {
    label: string;
    files: number;
    bytes: number;
};

export type TempFile = {
    path: string;
    bytes: number;
    ageDays: number;
};

export type TempCwdProbe = {
    supported: boolean;
    processes: number;
    resolved: number;
    failed: number;
    /** In-root process temp directories excluded from the walk. */
    tempDirs: number;
    /** In-root directories hosting a running process image. */
    programDirs: number;
};

export type TempOptions = {
    root?: string;
    olderThanDays?: number;
    sampleLimit?: number;
};

export type TempCleanOptions = {
    root?: string;
    olderThanDays?: number;
    /** Timestamp printed by the plan; candidates are derived from it. */
    cutoffUnixMs: number;
    confirm: true;
};

export type TempPlan = {
    root: string;
    olderThanDays: number;
    cutoffUnixMs: number;
    scannedFiles: number;
    scannedBytes: number;
    candidateFiles: number;
    candidateBytes: number;
    skipped: TempSkips;
    ageGroups: TempGroup[];
    extensionGroups: TempGroup[];
    samples: TempFile[];
    samplesTruncated: boolean;
    cwdProbe: TempCwdProbe;
    warnings: string[];
    scannedAtUnixMs: number;
};

export type TempFailure = {
    path: string;
    reason: string;
};

/** One file that reached the removal pass. */
export type TempCleanItem = {
    path: string;
    bytes: number;
    status: "deleted" | "skipped" | "failed";
    /** Empty for deleted files. */
    reason: string;
};

export type TempCleanReport = {
    root: string;
    olderThanDays: number;
    cutoffUnixMs: number;
    executed: boolean;
    candidateFiles: number;
    deletedFiles: number;
    freedBytes: number;
    skipped: TempSkips;
    /** Per-file outcomes for every file that reached the removal pass. */
    items: TempCleanItem[];
    failures: TempFailure[];
    warnings: string[];
    finishedAtUnixMs: number;
};

export type BuildRootOptions = {
    config?: string;
};

export type BuildRootDeclaration = {
    path: string;
    line: number;
};

export type BuildRootEntry = {
    path: string;
    line: number;
    bytes: number;
    files: number;
    removable: boolean;
    skipReason?: string | null;
    authorization: string;
};

export type BuildRootPlan = {
    configPath: string;
    configExists: boolean;
    entries: BuildRootEntry[];
    totalBytes: number;
    removableBytes: number;
    warnings: string[];
    scannedAtUnixMs: number;
};

export type BuildRootCleanOptions = {
    config?: string;
    paths: string[];
    confirm: true;
};

export type BuildRootCleanItem = {
    path: string;
    line: number;
    bytes: number;
    files: number;
    status: string;
    reason?: string | null;
};

export type BuildRootCleanReport = {
    configPath: string;
    executed: boolean;
    items: BuildRootCleanItem[];
    deletedDirs: number;
    freedBytes: number;
    warnings: string[];
    finishedAtUnixMs: number;
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
    tempPlan(optionsJson?: string): TempPlan;
    tempClean(optionsJson: string): TempCleanReport;
    buildRootPlan(optionsJson?: string): BuildRootPlan;
    buildRootClean(optionsJson: string): BuildRootCleanReport;
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

/**
 * Specifiers to try: the optional platform package (via `package.json#main`),
 * then the sibling checkout package directory. Never concatenate the `.node`
 * filename — that lives only in the platform package's `main`.
 */
function candidateSpecifiers(): string[] {
    const pa = currentPlatformArch();
    if (!pa) {
        throw new Error(
            `Unsupported platform ${process.platform}-${process.arch}. Supported: ${supportedPlatforms().join(', ')}. ` +
                'Install a matching @wae/open-cleaner-* package.',
        );
    }

    const pkg = platformPackageName(pa);
    // packages/open-cleaner/dist → ../../open-cleaner-<platform>-<arch>
    return [pkg, path.resolve(here, `../../open-cleaner-${pa}`)];
}

let cached: NativeBinding | null = null;

export function loadNative(): NativeBinding {
    if (cached) return cached;
    const tried: string[] = [];
    for (const candidate of candidateSpecifiers()) {
        tried.push(candidate);
        try {
            cached = require(candidate) as NativeBinding;
            return cached;
        } catch {
            // try the next specifier
        }
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
