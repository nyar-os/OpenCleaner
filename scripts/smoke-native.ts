#!/usr/bin/env node
/**
 * Load the staged native addon and assert the platform capability contract.
 * Runs on every CI platform; failures are real, not warnings.
 */
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { nodeFileName, packageDir, resolveTarget } from './platform.ts';

const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const target = resolveTarget();
const addon = path.join(packageDir(root, target), nodeFileName(target));

const native = require(addon) as {
    version(): string;
    capabilities(): {
        platform: string;
        arch: string;
        fileScan: boolean;
        registryScan: boolean;
        registryClean: boolean;
        gui: boolean;
    };
    registryScan(options?: { limit?: number }): { platform: string; scannedKeys: number; entries: unknown[] };
};

const version = native.version();
if (!version) throw new Error('version() returned an empty string');

const rustPlatform = target.platform === 'win32' ? 'windows' : target.platform === 'darwin' ? 'macos' : 'linux';
const rustArch = target.arch === 'x64' ? 'x86_64' : 'aarch64';

const caps = native.capabilities();
const failures: string[] = [];
if (caps.platform !== rustPlatform) failures.push(`platform ${caps.platform} != ${rustPlatform}`);
if (caps.arch !== rustArch) failures.push(`arch ${caps.arch} != ${rustArch}`);
if (!caps.fileScan) failures.push('fileScan must be available everywhere');
if (caps.registryClean) failures.push('registryClean must stay unavailable in this build');
const registrySupported = caps.registryScan && target.platform === 'win32';
if (caps.registryScan !== (target.platform === 'win32')) failures.push('registryScan does not match the platform');

if (registrySupported) {
    const report = native.registryScan({ limit: 5 });
    if (report.platform !== 'windows') failures.push(`registry report platform ${report.platform}`);
    if (!Array.isArray(report.entries)) failures.push('registry report entries is not an array');
} else {
    try {
        native.registryScan({ limit: 5 });
        failures.push('registryScan must fail outside Windows');
    } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (!message.includes(rustPlatform) || !message.includes('registry-scan')) {
            failures.push(`unexpected registry error: ${message}`);
        }
    }
}

if (failures.length > 0) {
    console.error(`native smoke failed for ${target.triple}:`);
    for (const failure of failures) console.error(`  - ${failure}`);
    process.exit(1);
}

console.log(`native smoke ok for ${target.triple}: version=${version} platform=${caps.platform} registryScan=${caps.registryScan}`);
