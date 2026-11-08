import {
    defaultGuiContentDir,
    loadNative,
    type AuditConfigureOptions,
    type AuditQueryOptions,
    type AuditRecord,
    type Capabilities,
    type DeleteMode,
    type DevCleanOptions,
    type DevCleanReport,
    type DevCleanTarget,
    type DevPlan,
    type DevScanOptions,
    type DevScanReport,
    type DevSizeBaseline,
    type DevSizeSource,
    type EnvPathCleanOptions,
    type EnvPathCleanReport,
    type EnvPathOptions,
    type EnvPathReport,
    type OpenGuiOptions,
    type RegistryOptions,
    type RegistryReport,
    type RegistryResidueOptions,
    type RegistryResidueReport,
    type ScanOptions,
    type ScanReport,
    type SoftwareOptions,
    type SoftwareReport,
    type BuildDirOptions,
    type BuildDirReport,
    type BuildRootCleanOptions,
    type BuildRootCleanReport,
    type BuildRootOptions,
    type BuildRootPlan,
    type TempCleanOptions,
    type TempCleanReport,
    type TempOptions,
    type TempPlan,
} from './native.js';

export type {
    ActorKind,
    AuditActor,
    AuditConfigureOptions,
    AuditQueryOptions,
    AuditRecord,
    Capabilities,
    DeleteMode,
    DevArtifact,
    DevCleanItem,
    DevCleanOptions,
    DevCleanReport,
    DevCleanStatus,
    DevCleanTarget,
    DevPlan,
    DevPlanItem,
    DevProfile,
    DevRiskLevel,
    DevScanOptions,
    DevScanReport,
    DevSizeBaseline,
    DevSizeSource,
    DevSkipReason,
    DevStageTiming,
    EnvPathBackup,
    EnvPathCleanItem,
    EnvPathCleanOptions,
    EnvPathCleanReport,
    EnvPathCleanStatus,
    EnvPathEntry,
    EnvPathOptions,
    EnvPathReport,
    EnvPathScopeReport,
    EnvPathSelection,
    OpenGuiOptions,
    PathIssue,
    PathScope,
    RegistryEntry,
    RegistryFinding,
    RegistryOptions,
    RegistryReport,
    RegistryResidueKind,
    RegistryResidueOptions,
    RegistryResidueReport,
    ScanEntry,
    ScanOptions,
    ScanReport,
    SoftwareFinding,
    SoftwareKind,
    SoftwareOptions,
    SoftwareReport,
    SoftwareSkip,
} from './native.js';
export { supportedPlatforms } from './native.js';

export function scan(options: ScanOptions = {}): ScanReport {
    return loadNative().scan(options);
}

/** Report which sinks are available on the current build target. */
export function capabilities(): Capabilities {
    return loadNative().capabilities();
}

/**
 * Inspect Windows uninstall entries for broken install locations.
 * Rejects with a structured error on every other platform.
 */
export function registryScan(options: RegistryOptions = {}): RegistryReport {
    return loadNative().registryScan(options);
}

/** Dry-run scan for developer artifacts (manifest-anchored, never name-only). */
export function devScan(options: DevScanOptions = {}): DevScanReport {
    return loadNative().devScan(JSON.stringify(options));
}

/**
 * Inspectable plan for developer artifacts. `trash` keeps a recycle-bin copy
 * where the platform supports it.
 */
export function devPlan(options: DevScanOptions = {}, mode: DeleteMode = 'trash'): DevPlan {
    return loadNative().devPlan(JSON.stringify(options), mode);
}

/** Delete explicitly listed paths; each is re-validated against the filesystem. */
export function devClean(options: DevCleanOptions): DevCleanReport {
    return loadNative().devClean(JSON.stringify(options));
}

/**
 * Inspect Windows registry residue: orphan uninstall rows, dead file
 * associations, and failing startup entries.
 */
export function registryResidueScan(options: RegistryResidueOptions = {}): RegistryResidueReport {
    return loadNative().registryResidueScan(JSON.stringify(options));
}

/** Read-only PATH inspection. Nothing is selected by default. */
export function envPathScan(options: EnvPathOptions = {}): EnvPathReport {
    return loadNative().envPathScan(JSON.stringify(options));
}

/**
 * Remove explicitly selected PATH entries. Requires `confirm: true` and
 * writes a JSON backup plus a `.reg` restore script before touching the key.
 */
export function envPathClean(options: EnvPathCleanOptions): EnvPathCleanReport {
    return loadNative().envPathClean(JSON.stringify(options));
}

/** Inspect leftover install and config directories anchored on uninstall keys. */
export function softwareResidueScan(options: SoftwareOptions = {}): SoftwareReport {
    return loadNative().softwareResidueScan(JSON.stringify(options));
}

/**
 * Read-only temp plan. Every candidate file is age-checked and occupancy
 * probed individually, and the report groups them by age and extension.
 */
export function tempPlan(options: TempOptions = {}): TempPlan {
    return loadNative().tempPlan(JSON.stringify(options));
}

/** Delete the files selected by a plan cutoff; every file is re-probed first. */
export function tempClean(options: TempCleanOptions): TempCleanReport {
    return loadNative().tempClean(JSON.stringify(options));
}

/** Read-only plan for build roots declared in the config file, one per line. */
export function buildRootPlan(options: BuildRootOptions = {}): BuildRootPlan {
    return loadNative().buildRootPlan(JSON.stringify(options));
}

/**
 * Read-only discovery of explicit Cargo target directories: the
 * `CARGO_TARGET_DIR` variable and `build.target-dir` in Cargo config files.
 * There is no plan or delete counterpart for this report.
 */
export function buildDirScan(options: BuildDirOptions = {}): BuildDirReport {
    return loadNative().buildDirScan(JSON.stringify(options));
}

/** Delete declared build roots; each path must still be declared at clean time. */
export function buildRootClean(options: BuildRootCleanOptions): BuildRootCleanReport {
    return loadNative().buildRootClean(JSON.stringify(options));
}

export type {
    BuildDirDeclaration,
    BuildDirOptions,
    BuildDirReport,
    BuildOutputProbe,
    UncoveredDirectory,
} from './native.js';

export type {
    BuildRootCleanItem,
    BuildRootCleanOptions,
    BuildRootCleanReport,
    BuildRootDeclaration,
    BuildRootEntry,
    BuildRootOptions,
    BuildRootPlan,
    TempCleanOptions,
    TempCleanItem,
    TempCleanReport,
    TempCwdProbe,
    TempFailure,
    TempFile,
    TempGroup,
    TempOptions,
    TempPlan,
    TempSkips,
} from './native.js';

export function version(): string {
    return loadNative().version();
}

export function openGui(options: OpenGuiOptions = {}): void {
    const native = loadNative();
    native.openGui({
        title: options.title ?? 'Open Cleaner',
        contentDir: options.contentDir ?? (options.entryUrl ? undefined : defaultGuiContentDir()),
        entryUrl: options.entryUrl,
    });
}

/** Pump Win32/WebView2 messages. Returns false when the GUI has closed. */
export function pumpEvents(): boolean {
    return loadNative().pumpEvents();
}

export function closeGui(): void {
    loadNative().closeGui();
}

export function isGuiOpen(): boolean {
    return loadNative().isGuiOpen();
}

/**
 * Tag subsequent capability calls with an explicit actor. Without an override
 * `WAE_ACTOR_KIND` / `WAE_ACTOR_ID` / `WAE_ACTOR_SOURCE` supply the identity.
 */
export function configureAudit(options: AuditConfigureOptions = {}): void {
    loadNative().configureAudit(options);
}

/** Read the append-only capability history written by the shared auditor. */
export function auditQuery(options: AuditQueryOptions = {}): AuditRecord[] {
    return loadNative().auditQuery(options);
}

export function runGui(options: OpenGuiOptions = {}, intervalMs = 16): Promise<void> {
    openGui(options);
    return new Promise((resolve, reject) => {
        let frames = 0;
        const timer = setInterval(() => {
            try {
                frames += 1;
                if (frames === 1 && !isGuiOpen()) {
                    clearInterval(timer);
                    reject(new Error('GUI failed to stay open after openGui()'));
                    return;
                }
                if (!pumpEvents()) {
                    clearInterval(timer);
                    resolve();
                }
            } catch (err) {
                clearInterval(timer);
                reject(err);
            }
        }, intervalMs);
    });
}
