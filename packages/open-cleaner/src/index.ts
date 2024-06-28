import {
    defaultGuiContentDir,
    loadNative,
    type OpenGuiOptions,
    type ScanOptions,
    type ScanReport,
} from './native.js';

export type { OpenGuiOptions, ScanEntry, ScanOptions, ScanReport } from './native.js';

export function scan(options: ScanOptions = {}): ScanReport {
    return loadNative().scan(options);
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
