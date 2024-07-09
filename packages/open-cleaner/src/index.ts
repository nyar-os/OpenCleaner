import {
    defaultGuiContentDir,
    loadNative,
    type AuditConfigureOptions,
    type AuditQueryOptions,
    type AuditRecord,
    type Capabilities,
    type OpenGuiOptions,
    type RegistryOptions,
    type RegistryReport,
    type ScanOptions,
    type ScanReport,
} from './native.js';

export type {
    ActorKind,
    AuditActor,
    AuditConfigureOptions,
    AuditQueryOptions,
    AuditRecord,
    Capabilities,
    OpenGuiOptions,
    RegistryEntry,
    RegistryOptions,
    RegistryReport,
    ScanEntry,
    ScanOptions,
    ScanReport,
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
