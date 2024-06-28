#!/usr/bin/env node
/**
 * Open Cleaner CLI — command tree via `@wae/commander`.
 */
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCli } from '@wae/commander';
import { runGui, scan, version } from './index.js';

function formatBytes(n: number): string {
    if (n < 1024) return `${n} B`;
    if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
    return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

const here = path.dirname(fileURLToPath(import.meta.url));
const localesDir = path.join(here, '..', 'locales');

const cli = createCli('open-cleaner').locales(localesDir).intro('cli.intro');

cli.command('scan', 'cli.cmd.scan')
    .option('--root <path>', 'cli.opt.root')
    .option('--limit <n>', 'cli.opt.limit', {
        coerce: (raw) => {
            const n = Number(raw);
            if (!Number.isFinite(n) || n < 1) throw new Error(`invalid --limit: ${raw}`);
            return String(Math.floor(n));
        },
    })
    .actionCtx(async (options) => {
        const root = typeof options.root === 'string' ? options.root : undefined;
        const limitRaw = typeof options.limit === 'string' ? options.limit : undefined;
        const limit = limitRaw ? Number(limitRaw) : undefined;
        const report = scan({ root, limit });
        console.log(`root: ${report.root}`);
        console.log(`total: ${formatBytes(report.totalBytes)}`);
        for (const entry of report.entries) {
            console.log(`${formatBytes(entry.bytes).padStart(10)}  ${entry.kind.padEnd(6)}  ${entry.path}`);
        }
        return 0;
    });

cli.command('gui', 'cli.cmd.gui')
    .option('--title <text>', 'cli.opt.title', { default: 'Open Cleaner' })
    .actionCtx(async (options) => {
        const title = typeof options.title === 'string' ? options.title : 'Open Cleaner';
        await runGui({ title });
        return 0;
    });

cli.command('version', 'cli.cmd.version').actionCtx(async () => {
    console.log(version());
    return 0;
});

const code = await cli.parse(process.argv);
process.exitCode = code;
