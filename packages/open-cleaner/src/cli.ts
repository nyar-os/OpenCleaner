#!/usr/bin/env node
/**
 * Open Cleaner CLI — command tree via `@wae/commander`.
 *
 * Destructive commands are dry-run by default. `--yes` is required before any
 * filesystem or registry mutation, and PATH edits always print the rollback
 * artifacts.
 */
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCli } from '@wae/commander';
import {
    auditQuery,
    buildDirScan,
    buildRootClean,
    buildRootPlan,
    capabilities,
    configureAudit,
    devClean,
    devPlan,
    envPathClean,
    envPathScan,
    registryResidueScan,
    registryScan,
    runGui,
    scan,
    softwareResidueScan,
    tempClean,
    tempPlan,
    version,
} from './index.js';
import type { ActorKind, DeleteMode, DevProfile, PathScope } from './index.js';

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

function list(options: Options, key: string): string[] {
    const value = options[key];
    if (Array.isArray(value)) return value;
    return typeof value === 'string' ? [value] : [];
}

function flag(options: Options, key: string): boolean {
    return options[key] === true || options[key] === 'true';
}

function numberOption(options: Options, key: string): number | undefined {
    const raw = text(options, key);
    if (!raw) return undefined;
    const n = Number(raw);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : undefined;
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

/**
 * Numeric options fail on invalid input instead of falling back to a default.
 * A silently defaulted threshold would change which files a `--yes` run deletes.
 */
function integerOption(key: string, minimum: number) {
    return {
        coerce: (raw: string | boolean | string[]): unknown => {
            const text = typeof raw === 'string' ? raw.trim() : '';
            const value = Number(text);
            if (!text || !Number.isInteger(value) || value < minimum) {
                throw new Error(`\`--${key}\` must be an integer >= ${minimum}, got \`${String(raw)}\``);
            }
            return String(value);
        },
    };
}

function deleteMode(raw: string | undefined, trashAvailable: boolean): DeleteMode {
    if (raw === 'permanent' || raw === 'trash') return raw;
    return trashAvailable ? 'trash' : 'permanent';
}

function reportError(err: unknown): number {
    console.error(err instanceof Error ? err.message : String(err));
    return 1;
}

function basename(value: string): string {
    return value.replace(/[\\/]+$/, '').split(/[\\/]/).pop() ?? '';
}

function rate(value: number, ms: number): string {
    return ms <= 0 ? 'n/a' : (value / (ms / 1000)).toFixed(1);
}

function byteRate(bytes: number, ms: number): string {
    return ms <= 0 ? 'n/a' : `${formatBytes(bytes / (ms / 1000))}/s`;
}

/** Print side-channel timings captured during the run. No-op when profiling is off. */
function printProfile(label: string, profile: DevProfile | null | undefined, totals?: { bytes?: number; items?: number }): void {
    if (!profile) return;
    const stages = profile.stages.map((stage) => `${stage.name}=${stage.elapsedMs.toFixed(0)}ms`).join('  ');
    const scanMs = profile.stages.find((stage) => stage.name === 'scan')?.elapsedMs ?? 0;
    const measureMs = profile.stages.find((stage) => stage.name === 'measurement')?.elapsedMs ?? 0;
    const deleteMs = profile.stages.find((stage) => stage.name === 'delete')?.elapsedMs ?? 0;
    console.log(`profile[${label}]: ${stages}`);
    if (scanMs > 0) {
        console.log(`  scan: ${rate(profile.dirsVisited, scanMs)} dirs/s  (${profile.dirsVisited} listed dirs)`);
    }
    if (measureMs > 0) {
        console.log(
            `  measure: ${rate(profile.filesVisited, measureMs)} files/s  ${byteRate(profile.bytesMeasured, measureMs)}  (${profile.filesVisited} files, ${profile.measuredDirs} dirs)`,
        );
    }
    if (deleteMs > 0 && totals?.bytes !== undefined) {
        console.log(`  delete: ${byteRate(totals.bytes, deleteMs)}  ${rate(totals.items ?? 0, deleteMs)} items/s`);
    }
    if (profile.peakWorkingSetBytes) console.log(`  peak working set: ${formatBytes(profile.peakWorkingSetBytes)}`);
    if (profile.peakHandleCount) console.log(`  peak handles: ${profile.peakHandleCount}`);
}

cli.command('scan', 'cli.cmd.scan')
    .option('--root <path>', 'cli.opt.root')
    .option('--limit <n>', 'cli.opt.limit', limitOption)
    .actionCtx(async (options) => {
        applyActor(options);
        const root = text(options, 'root');
        const limit = numberOption(options, 'limit');
        const report = scan({ root, limit });
        console.log(`root: ${report.root}`);
        console.log(`total: ${formatBytes(report.totalBytes)}${report.unreadableDirs ? ' (lower bound: unreadable subtrees excluded)' : ''}`);
        if (report.unreadableDirs) {
            console.log(`unreadable dirs: ${report.unreadableDirs} (skipped, not measured)`);
            for (const path of report.unreadablePaths) console.log(`  skipped: ${path}`);
        }
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

cli.command('dev', 'cli.cmd.dev')
    .option('--root <path>...', 'cli.opt.devRoot')
    .option('--include-global', 'cli.opt.includeGlobal')
    .option('--only <name>...', 'cli.opt.only')
    .option('--max-depth <n>', 'cli.opt.maxDepth', integerOption('max-depth', 0))
    .option('--limit <n>', 'cli.opt.limit', limitOption)
    .option('--mode <mode>', 'cli.opt.mode', { enum: ['trash', 'permanent'] })
    .option('--concurrency <n>', 'cli.opt.concurrency', integerOption('concurrency', 1))
    .option('--yes', 'cli.opt.yes')
    .actionCtx(async (options) => {
        applyActor(options);
        const roots = list(options, 'root');
        const includeGlobal = flag(options, 'include-global');
        const only = list(options, 'only')
            .flatMap((name) => name.split(','))
            .map((name) => name.trim().toLowerCase())
            .filter(Boolean);
        const matchesOnly = (artifactPath: string): boolean => only.length === 0 || only.includes(basename(artifactPath).toLowerCase());
        const mode = deleteMode(text(options, 'mode'), capabilities().trash);
        try {
            const plan = devPlan({ roots, includeGlobal, maxDepth: numberOption(options, 'max-depth'), limit: numberOption(options, 'limit') }, mode);
            console.log(`roots: ${plan.roots.join(', ')}`);
            console.log(`mode: ${plan.mode}${plan.modeSupported ? '' : ' (unsupported on this platform)'}`);
            console.log(`total: ${formatBytes(plan.totalBytes)}  removable: ${formatBytes(plan.removableBytes)}  skipped: ${formatBytes(plan.skippedBytes)}`);
            for (const warning of plan.warnings) console.log(`warning: ${warning}`);

            for (const item of plan.items) {
                const matches = matchesOnly(item.artifact.path);
                const chosen = only.length > 0 && matches;
                const selected = item.removable && matches && (item.artifact.level === 1 || includeGlobal) && (item.artifact.defaultSelected || chosen);
                const state = item.removable
                    ? !matches
                        ? 'filtered'
                        : selected
                            ? 'SELECT'
                            : item.artifact.level === 2 && !includeGlobal
                                ? 'level-2'
                                : 'default-off'
                    : `skip:${item.skipReason}`;
                const owner = item.artifact.projectRoot ?? '-';
                console.log(
                    `${formatBytes(item.artifact.bytes).padStart(10)}  L${item.artifact.level}  ${state.padEnd(18)}  ${item.artifact.ecosystem.padEnd(10)}  ${item.artifact.path}`,
                );
                console.log(`            rule: ${item.artifact.rule}  anchor: ${item.artifact.anchor}  project: ${owner}`);
            }
            printProfile('plan', plan.profile);

            const selected = plan.items.filter(
                (item) =>
                    item.removable &&
                    matchesOnly(item.artifact.path) &&
                    (item.artifact.level === 1 || includeGlobal) &&
                    (item.artifact.defaultSelected || only.length > 0),
            );
            if (!includeGlobal && plan.items.some((item) => item.removable && item.artifact.level === 2)) {
                console.log('level-2 global caches are not selected. Pass --include-global to include them: they can be rebuilt but must be downloaded again.');
            }
            if (includeGlobal && plan.items.some((item) => item.removable && item.artifact.level === 2 && !item.artifact.defaultSelected && matchesOnly(item.artifact.path))) {
                console.log('level-2 caches stay unchecked by default: rebuilding them downloads again. Pass --only <name> to select one explicitly.');
            }
            if (!flag(options, 'yes')) {
                console.log('dry run only. Re-run with --yes to delete the selected paths.');
                return 0;
            }
            if (!plan.modeSupported) {
                console.error(`delete mode ${plan.mode} is not available on this platform. Use --mode permanent or omit --mode.`);
                return 1;
            }
            if (!selected.length) {
                console.log('nothing selected.');
                return 0;
            }
            const report = devClean({
                targets: selected.map((item) => ({ path: item.artifact.path, baseline: item.artifact.baseline })),
                mode: plan.mode,
                confirm: true,
                concurrency: numberOption(options, 'concurrency'),
            });
            for (const item of report.items) {
                const note = item.sizeSource === 'remeasured' ? '  [remeasured]' : '';
                console.log(
                    `${item.status.padEnd(9)}  ${formatBytes(item.bytes).padStart(10)}  ${item.path}${item.reason ? `  (${item.reason})` : ''}${note}`,
                );
            }
            console.log(
                `freed: ${formatBytes(report.freedBytes)}  (scan-time ${formatBytes(report.freedBytesScanned)}, remeasured ${formatBytes(report.freedBytesRemeasured)})`,
            );
            for (const warning of report.warnings) console.log(`warning: ${warning}`);
            const deleted = report.items.filter((item) => item.status === 'deleted' || item.status === 'trashed').length;
            printProfile('clean', report.profile, { bytes: report.freedBytes, items: deleted });
            return report.items.some((item) => item.status === 'failed') ? 1 : 0;
        } catch (err) {
            return reportError(err);
        }
    });

cli.command('registry', 'cli.cmd.registry')
    .option('--limit <n>', 'cli.opt.limit', limitOption)
    .option('--legacy', 'cli.opt.legacy')
    .actionCtx(async (options) => {
        applyActor(options);
        const limit = numberOption(options, 'limit');
        try {
            if (flag(options, 'legacy')) {
                const report = registryScan({ limit });
                console.log(`platform: ${report.platform}`);
                console.log(`scanned keys: ${report.scannedKeys}`);
                for (const entry of report.entries) {
                    console.log(`${entry.reason}  ${entry.displayName ?? entry.key}  ${entry.installLocation ?? ''}`);
                }
                return 0;
            }
            const report = registryResidueScan({ limit });
            console.log(`platform: ${report.platform}  source: ${report.source}`);
            console.log(`scanned keys: ${report.scannedKeys}  findings: ${report.findings.length}`);
            for (const finding of report.findings) {
                console.log(`${finding.kind}  ${finding.keyPath}${finding.valueName ? `\\${finding.valueName}` : ''}`);
                console.log(`  target: ${finding.target}`);
                console.log(`  evidence: ${finding.evidence}`);
                console.log(`  safety: ${finding.safety}`);
            }
            for (const warning of report.warnings) console.log(`warning: ${warning}`);
            return 0;
        } catch (err) {
            return reportError(err);
        }
    });

cli.command('env', 'cli.cmd.env')
    .option('--scope <scope>', 'cli.opt.scope', { enum: ['user', 'machine'], default: 'user' })
    .option('--index <n>...', 'cli.opt.index')
    .option('--backup-dir <dir>', 'cli.opt.backupDir')
    .option('--limit <n>', 'cli.opt.limit', limitOption)
    .option('--yes', 'cli.opt.yes')
    .actionCtx(async (options) => {
        applyActor(options);
        const scopeRaw = text(options, 'scope');
        const scope: PathScope = scopeRaw === 'machine' ? 'machine' : 'user';
        const indexes = list(options, 'index').map((value) => Number(value));
        try {
            const report = envPathScan({ limit: numberOption(options, 'limit') });
            console.log(`platform: ${report.platform}`);
            if (report.backupDir) console.log(`backup dir: ${report.backupDir}`);
            for (const warning of report.warnings) console.log(`warning: ${warning}`);
            for (const scopeReport of report.scopes) {
                console.log(`\n[${scopeReport.scope}] ${scopeReport.keyPath}  present=${scopeReport.present}  issues=${scopeReport.issues}`);
                for (const entry of scopeReport.entries) {
                    const issue = entry.issue ?? 'ok';
                    const marker = entry.removable ? 'removable' : 'report-only';
                    console.log(`  #${entry.index}  ${issue.padEnd(10)}  ${marker.padEnd(11)}  ${entry.raw}`);
                    if (entry.issue) console.log(`      ${entry.evidence}`);
                }
            }

            if (!indexes.length) {
                console.log('\nPATH edits are never pre-selected. Review the entries above, then pass --scope, --index and --yes.');
                return 0;
            }
            if (indexes.some((n) => !Number.isInteger(n) || n < 0)) {
                console.error(`invalid --index: ${indexes.join(', ')}`);
                return 1;
            }

            const selectedScope = report.scopes.find((item) => item.scope === scope);
            if (!selectedScope) {
                console.error(`scope ${scope} not found in the scan`);
                return 1;
            }
            const picks = selectedScope.entries.filter((entry) => indexes.includes(entry.index));
            if (!picks.length) {
                console.error(`no entries matched indexes ${indexes.join(', ')} in scope ${scope}`);
                return 1;
            }
            console.log(`\nselected ${picks.length} entr${picks.length === 1 ? 'y' : 'ies'}:`);
            for (const entry of picks) {
                console.log(`  #${entry.index}  ${entry.issue ?? 'ok'}  ${entry.raw}`);
            }
            if (!flag(options, 'yes')) {
                console.log('preview only. Re-run with --yes to write the new PATH value. A JSON backup and a .reg restore script will be written first.');
                return 0;
            }
            const cleanReport = envPathClean({
                scope,
                selections: picks.map((entry) => ({ index: entry.index, raw: entry.raw })),
                confirm: true,
                backupDir: text(options, 'backup-dir'),
            });
            for (const item of cleanReport.items) {
                console.log(`${item.status.padEnd(9)}  #${item.index}  ${item.raw}${item.reason ? `  (${item.reason})` : ''}`);
            }
            console.log(`removed: ${cleanReport.removed}`);
            if (cleanReport.backup) {
                console.log(`backup json: ${cleanReport.backup.jsonPath}`);
                console.log(`restore reg: ${cleanReport.backup.regPath}`);
            }
            for (const warning of cleanReport.warnings) console.log(`warning: ${warning}`);
            return cleanReport.items.some((item) => item.status === 'failed') ? 1 : 0;
        } catch (err) {
            return reportError(err);
        }
    });

cli.command('software', 'cli.cmd.software')
    .option('--limit <n>', 'cli.opt.limit', limitOption)
    .actionCtx(async (options) => {
        applyActor(options);
        try {
            const report = softwareResidueScan({ limit: numberOption(options, 'limit') });
            console.log(`platform: ${report.platform}  source: ${report.source}`);
            console.log(`uninstall keys: ${report.uninstallKeys}  candidates: ${report.findings.length}`);
            for (const finding of report.findings) {
                console.log(`\n${finding.kind}  ${formatBytes(finding.bytes)}  ${finding.path}`);
                console.log(`  product: ${finding.displayName}`);
                console.log(`  key: ${finding.registryKey}`);
                console.log(`  rule: ${finding.rule}`);
                console.log(`  evidence: ${finding.evidence}`);
                console.log(`  safety: ${finding.safety}`);
            }
            for (const skip of report.skipped) {
                console.log(`skip: ${skip.reason}  ${skip.displayName ?? skip.registryKey}`);
            }
            for (const warning of report.warnings) console.log(`warning: ${warning}`);
            console.log('\nsoftware residue is reported only in this build. No directory is removed.');
            return 0;
        } catch (err) {
            return reportError(err);
        }
    });

cli.command('temp', 'cli.cmd.temp')
    .option('--root <path>', 'cli.opt.root')
    .option('--older-than-days <n>', 'cli.opt.olderThanDays', integerOption('older-than-days', 1))
    .option('--sample <n>', 'cli.opt.sample', integerOption('sample', 0))
    .option('--yes', 'cli.opt.yes')
    .actionCtx(async (options) => {
        applyActor(options);
        const root = text(options, 'root');
        const olderThanDays = numberOption(options, 'older-than-days');
        try {
            const plan = tempPlan({ root, olderThanDays, sampleLimit: numberOption(options, 'sample') ?? 50 });
            console.log(`root: ${plan.root}`);
            console.log(`threshold: older than ${plan.olderThanDays} day(s), cutoff ${new Date(plan.cutoffUnixMs).toISOString()}`);
            console.log(`scanned: ${plan.scannedFiles} files / ${formatBytes(plan.scannedBytes)}`);
            console.log(`candidates: ${plan.candidateFiles} files / ${formatBytes(plan.candidateBytes)}`);
            console.log(
                `skipped: recent=${plan.skipped.recent} dir-recent=${plan.skipped.dirRecent} dev-root=${plan.skipped.devRoot} build-root=${plan.skipped.buildRoot} in-use=${plan.skipped.inUse} symlink=${plan.skipped.symlink} protected=${plan.skipped.protected} cwd-shielded=${plan.skipped.cwdShielded} process-temp=${plan.skipped.processTemp} program-shielded=${plan.skipped.programShielded} unreadable=${plan.skipped.unreadable}`,
            );
            console.log(
                `cwd probe: supported=${plan.cwdProbe.supported} processes=${plan.cwdProbe.processes} resolved=${plan.cwdProbe.resolved} unresolved=${plan.cwdProbe.failed} process-temp-dirs=${plan.cwdProbe.tempDirs} program-dirs=${plan.cwdProbe.programDirs}`,
            );
            console.log('\nage distribution:');
            for (const group of plan.ageGroups) {
                console.log(`  ${group.label.padEnd(18)} ${String(group.files).padStart(7)} files  ${formatBytes(group.bytes).padStart(10)}`);
            }
            console.log('\nextension distribution:');
            for (const group of plan.extensionGroups.slice(0, 15)) {
                console.log(`  ${group.label.padEnd(18)} ${String(group.files).padStart(7)} files  ${formatBytes(group.bytes).padStart(10)}`);
            }
            const scope = plan.samplesTruncated ? `${plan.samples.length} of ${plan.candidateFiles}` : String(plan.samples.length);
            console.log(`\nsamples (${scope}):`);
            for (const file of plan.samples) {
                console.log(`  ${formatBytes(file.bytes).padStart(10)}  ${String(file.ageDays).padStart(3)}d  ${file.path}`);
            }
            for (const warning of plan.warnings) console.log(`warning: ${warning}`);
            if (!flag(options, 'yes')) {
                console.log('\npreview only. Re-run with --yes to delete exactly the candidates above.');
                return 0;
            }
            if (plan.candidateFiles === 0) {
                console.log('nothing selected.');
                return 0;
            }
            const report = tempClean({
                root: plan.root,
                olderThanDays: plan.olderThanDays,
                cutoffUnixMs: plan.cutoffUnixMs,
                confirm: true,
            });
            console.log(`\nevaluated: ${report.candidateFiles}  deleted: ${report.deletedFiles} files  freed: ${formatBytes(report.freedBytes)}`);
            console.log(`skipped during execution: in-use=${report.skipped.inUse} recent=${report.skipped.recent} dir-recent=${report.skipped.dirRecent} dev-root=${report.skipped.devRoot} build-root=${report.skipped.buildRoot} symlink=${report.skipped.symlink} protected=${report.skipped.protected} program-shielded=${report.skipped.programShielded}`);
            if (report.failures.length) {
                console.log(`\nfailures (${report.failures.length}):`);
                for (const failure of report.failures) console.log(`  ${failure.path}  (${failure.reason})`);
            }
            for (const warning of report.warnings) console.log(`warning: ${warning}`);
            return report.failures.length ? 1 : 0;
        } catch (err) {
            return reportError(err);
        }
    });

cli.command('build-roots', 'cli.cmd.buildRoots')
    .option('--config <path>', 'cli.opt.config')
    .option('--yes', 'cli.opt.yes')
    .actionCtx(async (options) => {
        applyActor(options);
        try {
            const plan = buildRootPlan({ config: text(options, 'config') });
            console.log(`config: ${plan.configPath}  exists=${plan.configExists}`);
            for (const entry of plan.entries) {
                console.log(`\n${(entry.removable ? 'removable' : 'skip').padEnd(9)}  line ${entry.line}  ${formatBytes(entry.bytes).padStart(10)}  ${entry.path}`);
                console.log(`  authorized by: ${entry.authorization}`);
                if (entry.skipReason) console.log(`  reason: ${entry.skipReason}`);
            }
            console.log(`\ntotal: ${formatBytes(plan.totalBytes)}  removable: ${formatBytes(plan.removableBytes)}`);
            for (const warning of plan.warnings) console.log(`warning: ${warning}`);
            if (!flag(options, 'yes')) {
                console.log('\npreview only. Re-run with --yes to delete the removable declarations.');
                return 0;
            }
            const selected = plan.entries.filter((entry) => entry.removable);
            if (!selected.length) {
                console.log('nothing selected.');
                return 0;
            }
            const report = buildRootClean({ config: plan.configPath, paths: selected.map((entry) => entry.path), confirm: true });
            for (const item of report.items) {
                console.log(`${item.status.padEnd(9)}  line ${item.line}  ${formatBytes(item.bytes).padStart(10)}  ${item.path}${item.reason ? `  (${item.reason})` : ''}`);
            }
            console.log(`deleted: ${report.deletedDirs} roots  freed: ${formatBytes(report.freedBytes)}`);
            for (const warning of report.warnings) console.log(`warning: ${warning}`);
            return report.items.some((item) => item.status !== 'deleted') ? 1 : 0;
        } catch (err) {
            return reportError(err);
        }
    });

cli.command('build-dirs', 'cli.cmd.buildDirs')
    .option('--cwd <path>', 'cli.opt.cwd')
    .option('--root <path>...', 'cli.opt.probeRoot')
    .option('--min-bytes <n>', 'cli.opt.minBytes', integerOption('min-bytes', 1))
    .option('--depth <n>', 'cli.opt.depth', integerOption('depth', 1))
    .actionCtx(async (options) => {
        applyActor(options);
        try {
            const report = buildDirScan({
                cwd: text(options, 'cwd'),
                roots: list(options, 'root'),
                minBytes: numberOption(options, 'min-bytes'),
                depth: numberOption(options, 'depth'),
            });
            console.log(`cwd: ${report.cwd}`);
            const accepted = report.declarations.filter((item) => item.accepted).length;
            const valid = report.declarations.filter((item) => item.valid).length;
            console.log(`declarations: ${report.declarations.length}  accepted: ${accepted}  valid: ${valid}`);
            if (!report.declarations.length) {
                console.log('no explicit declaration found: neither CARGO_TARGET_DIR nor build.target-dir');
            }
            for (const item of report.declarations) {
                console.log(`\n[${item.origin}] ${item.source}  ${item.key} = "${item.raw}"`);
                console.log(`  resolved: ${item.resolved}${item.effective ? '  (effective)' : ''}`);
                if (item.relative) console.log(`  relative to: ${item.base}`);
                if (item.shadowedBy) console.log(`  shadowed by: ${item.shadowedBy}`);
                if (item.reason) console.log(`  invalid: ${item.reason}`);
            }
            if (report.effectivePath) console.log(`\neffective target dir: ${report.effectivePath}  (${report.effectiveSource})`);
            if (report.matches.length) {
                console.log('\nmarker-proven build output:');
                for (const item of report.matches) {
                    console.log(`  ${formatBytes(item.bytes).padStart(10)}  ${item.path}  [${item.attribution}]`);
                    for (const path of item.evidence) console.log(`              evidence: ${path}`);
                    if (item.coveredByDeclaration) console.log(`              declared by: ${item.coveredByDeclaration}`);
                    if (item.alsoInBuildRoots) console.log('              also counted by build-roots (not added twice)');
                }
            } else if (report.roots.length) {
                console.log('\nno directory under the probe roots carries CACHEDIR.TAG plus a Cargo-specific marker.');
            }
            if (report.rejected.length) {
                console.log('\nmarker-proven but refused by the location rules:');
                for (const item of report.rejected) {
                    console.log(`  ${item.path}  (${item.reason})`);
                    for (const path of item.evidence) console.log(`              evidence: ${path}`);
                }
            }
            if (report.uncovered.length) {
                console.log('\nuncovered directories:');
                for (const item of report.uncovered) {
                    console.log(`  ${formatBytes(item.bytes).padStart(10)}  ${item.path}${item.alsoInBuildRoots ? '  (already declared in build-roots)' : ''}`);
                    console.log(`              ${item.reason}`);
                    for (const path of item.evidence) console.log(`              marker: ${path}`);
                }
                console.log('\nnothing here is selected and nothing is deleted.');
            } else if (report.roots.length) {
                console.log('\nno uncovered directory at or above the size floor.');
            }
            if (report.buildRoots.length) {
                console.log(`\nbuild-roots overlap (compared with ${report.buildRootConfig ?? 'the build-root config'}):`);
                for (const item of report.buildRoots) {
                    const size = item.bytes === null || item.bytes === undefined ? 'unmeasured' : formatBytes(item.bytes);
                    console.log(`  line ${item.line}  ${size.padStart(10)}  ${item.path}  ${item.matchedByMarkers ? 'matched' : 'no marker match'}`);
                    console.log(`              ${item.note}`);
                }
            }
            console.log(
                `\nmatched: ${formatBytes(report.matchedBytes)}  in build-roots: ${formatBytes(report.matchedBytesInBuildRoots)}  unique: ${formatBytes(report.uniqueMatchedBytes)}`,
            );
            for (const warning of report.warnings) console.log(`warning: ${warning}`);
            return 0;
        } catch (err) {
            return reportError(err);
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
        const entries = auditQuery({
            actorId: text(options, 'actor'),
            fromMs: since,
            capability: text(options, 'capability'),
            limit: numberOption(options, 'limit'),
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
