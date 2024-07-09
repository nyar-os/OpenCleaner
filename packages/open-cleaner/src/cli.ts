#!/usr/bin/env node
/**
 * Open Cleaner CLI — command tree via `@wae/commander`.
 */
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCli } from '@wae/commander';
import { auditQuery, capabilities, configureAudit, registryScan, runGui, scan, version } from './index.js';
import type { ActorKind } from './index.js';

function formatBytes(n: number): string {
    if (n < 1024) return `${n} B`;
    if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
    return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

const here = path.dirname(fileURLToPath(import.meta.url));
const localesDir = path.join(here, '..', 'locales');

const cli = createCli('open-cleaner')
    .locales(localesDir)
    .intro('cli.intro')
    .option('--actor-id <id>', 'cli.opt.actorId')
    .option('--actor-kind <kind>', 'cli.opt.actorKind')
    .option('--actor-source <source>', 'cli.opt.actorSource');

type Options = Record<string, string | boolean | string[]>;

function text(options: Options, key: string): string | undefined {
    const value = options[key];
    return typeof value === 'string' ? value : undefined;
}

/** Attribute every capability call in this run to an explicit actor. */
function applyActor(options: Options): void {
    const kindRaw = text(options, 'actor-kind');
    const actorKind: ActorKind | undefined =
        kindRaw === 'user' || kindRaw === 'agent' ? kindRaw : undefined;
    configureAudit({
        actorId: text(options, 'actor-id'),
        actorKind,
        actorSource: text(options, 'actor-source') ?? 'cli',
    });
}

const limitOption = {
    coerce: (raw: string | boolean | string[]): unknown => {
        const n = Number(raw);
        if (!Number.isFinite(n) || n < 1) throw new Error(`invalid --limit: ${String(raw)}`);
        return String(Math.floor(n));
    },
};

cli.command('scan', 'cli.cmd.scan')
    .option('--root <path>', 'cli.opt.root')
    .option('--limit <n>', 'cli.opt.limit', limitOption)
    .actionCtx(async (options) => {
        applyActor(options);
        const root = text(options, 'root');
        const limitRaw = text(options, 'limit');
        const limit = limitRaw ? Number(limitRaw) : undefined;
        const report = scan({ root, limit });
        console.log(`root: ${report.root}`);
        console.log(`total: ${formatBytes(report.totalBytes)}`);
        for (const entry of report.entries) {
            console.log(`${formatBytes(entry.bytes).padStart(10)}  ${entry.kind.padEnd(6)}  ${entry.path}`);
        }
        return 0;
    });

cli.command('capabilities', 'cli.cmd.capabilities').actionCtx(async (options) => {
    applyActor(options);
    console.log(JSON.stringify(capabilities(), null, 2));
    return 0;
});

cli.command('registry', 'cli.cmd.registry')
    .option('--limit <n>', 'cli.opt.limit', limitOption)
    .actionCtx(async (options) => {
        applyActor(options);
        const limitRaw = text(options, 'limit');
        try {
            const report = registryScan({ limit: limitRaw ? Number(limitRaw) : undefined });
            console.log(`platform: ${report.platform}`);
            console.log(`scanned keys: ${report.scannedKeys}`);
            for (const entry of report.entries) {
                console.log(`${entry.reason}  ${entry.displayName ?? entry.key}  ${entry.installLocation ?? ''}`);
            }
            return 0;
        } catch (err) {
            console.error(err instanceof Error ? err.message : String(err));
            return 1;
        }
    });

cli.command('audit', 'cli.cmd.audit')
    .option('--actor <id>', 'cli.opt.actorFilter')
    .option('--since <ms>', 'cli.opt.since')
    .option('--capability <name>', 'cli.opt.capability')
    .option('--limit <n>', 'cli.opt.limit', limitOption)
    .actionCtx(async (options) => {
        applyActor(options);
        const sinceRaw = text(options, 'since');
        const since = sinceRaw ? Number(sinceRaw) : undefined;
        if (since !== undefined && (!Number.isFinite(since) || since < 0)) {
            throw new Error(`invalid --since: ${sinceRaw}`);
        }
        const limitRaw = text(options, 'limit');
        const entries = auditQuery({
            actorId: text(options, 'actor'),
            fromMs: since,
            capability: text(options, 'capability'),
            limit: limitRaw ? Number(limitRaw) : undefined,
        });
        for (const entry of entries) {
            console.log(JSON.stringify(entry));
        }
        return 0;
    });

cli.command('gui', 'cli.cmd.gui')
    .option('--title <text>', 'cli.opt.title', { default: 'Open Cleaner' })
    .actionCtx(async (options) => {
        applyActor(options);
        const title = typeof options.title === 'string' ? options.title : 'Open Cleaner';
        await runGui({ title });
        return 0;
    });

cli.command('version', 'cli.cmd.version').actionCtx(async (options) => {
    applyActor(options);
    console.log(version());
    return 0;
});

const code = await cli.parse(process.argv);
process.exitCode = code;
