#!/usr/bin/env node
/**
 * Validate agent skills against the real CLI command tree.
 *
 * Checks:
 * - every `skills/<name>/SKILL.md` has parseable frontmatter with `name` and `description`
 * - `name` matches the directory and is kebab-case
 * - each skill has a `## Safety` section
 * - each skill contains at least one backticked `open-cleaner <command>` invocation
 * - every referenced command exists in `open-cleaner --help`
 * - every referenced flag exists in `<command> --help`
 * - no link or path in a skill leaves the published skills tree
 * - the skills package version matches the owning app package and uses `MPL-2.0`
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const skillsRoot = path.join(root, 'packages', 'open-cleaner-skills', 'skills');
const skillsPackage = path.join(root, 'packages', 'open-cleaner-skills', 'package.json');
const appPackage = path.join(root, 'packages', 'open-cleaner', 'package.json');
const cli = path.join(root, 'packages', 'open-cleaner', 'dist', 'cli.js');

function fail(message: string): never {
    console.error(`check-skills failed: ${message}`);
    process.exit(1);
}

/**
 * Published skills may link to the network or to files inside the skills
 * package. Everything else is rejected by shape: filesystem paths (absolute,
 * drive-letter, home, file URL), parent traversal, and local targets that do
 * not resolve to a packaged file. No directory name list is kept here.
 */
function assertNoOutOfPackageReferences(source: string, file: string, dir: string): void {
    for (const match of source.matchAll(/\]\(([^)\s]+)(?:\s+[^)]*)?\)/g)) {
        const target = match[1];
        if (/^(?:https?:|mailto:)/i.test(target) || target.startsWith('#')) continue;
        if (/^(?:[a-z]:[\\/]|[\\/]|~[\\/]|file:)/i.test(target) || target.includes('..')) {
            fail(`${file}: link target \`${target}\` must stay inside the skills package`);
        }
        const resolved = path.resolve(dir, target.split('#')[0]);
        const relative = path.relative(skillsRoot, resolved);
        if (relative.startsWith('..') || path.isAbsolute(relative) || !fs.existsSync(resolved)) {
            fail(`${file}: link target \`${target}\` is not a file inside the skills package`);
        }
    }
    for (const match of source.matchAll(/(?:^|[\s`"'(（])((?:[a-z]:[\\/]|~[\\/]|file:\/\/)[^\s`"'()）]+)/gi)) {
        fail(`${file}: filesystem path \`${match[1]}\` must not appear in a published skill`);
    }
}

function runCli(args: string[]): string {
    return execFileSync(process.execPath, [cli, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function commandTree(): Set<string> {
    const lines = runCli(['--help']).split(/\r?\n/);
    const start = lines.findIndex((line) => line.trim() === 'Commands:');
    if (start < 0) fail('could not find the `Commands:` section in `open-cleaner --help`');
    const commands = new Set<string>();
    for (let i = start + 1; i < lines.length; i += 1) {
        const line = lines[i];
        if (!line.trim()) break;
        const match = line.match(/^\s{2,}([a-z][a-z0-9-]*)\s{2,}/);
        if (match) commands.add(match[1]);
    }
    if (commands.size === 0) fail('no commands parsed from `open-cleaner --help`');
    return commands;
}

const flagCache = new Map<string, Set<string>>();
function flagsFor(command: string): Set<string> {
    const cached = flagCache.get(command);
    if (cached) return cached;
    const lines = runCli([command, '--help']).split(/\r?\n/);
    const start = lines.findIndex((line) => line.trim() === 'Options:');
    if (start < 0) fail(`could not find the \`Options:\` section in \`open-cleaner ${command} --help\``);
    const flags = new Set<string>(['--help']);
    for (let i = start + 1; i < lines.length; i += 1) {
        const line = lines[i];
        if (!line.trim() || /^\s{2,}[a-z][a-z0-9-]*\s{2,}/.test(line)) break;
        const match = line.match(/^\s+(--[a-z0-9-]+)/);
        if (match) flags.add(match[1]);
    }
    flagCache.set(command, flags);
    return flags;
}

type Frontmatter = Record<string, string>;

function parseFrontmatter(source: string, file: string): { meta: Frontmatter; body: string } {
    const lines = source.split(/\r?\n/);
    if (lines[0]?.trim() !== '---') fail(`${file}: frontmatter must start on line 1 with \`---\``);
    const end = lines.findIndex((line, index) => index > 0 && line.trim() === '---');
    if (end < 0) fail(`${file}: frontmatter is not closed with \`---\``);
    const meta: Frontmatter = {};
    for (const line of lines.slice(1, end)) {
        if (!line.trim()) continue;
        const match = line.match(/^([a-zA-Z][a-zA-Z0-9_-]*):\s*(.*)$/);
        if (!match) fail(`${file}: cannot parse frontmatter line \`${line}\``);
        meta[match[1]] = match[2].trim().replace(/^['"]|['"]$/g, '');
    }
    return { meta, body: lines.slice(end + 1).join('\n') };
}

function readJson(file: string): Record<string, unknown> {
    return JSON.parse(fs.readFileSync(file, 'utf8')) as Record<string, unknown>;
}

if (!fs.existsSync(cli)) {
    fail('CLI build missing. Run `pnpm run build:ts` first.');
}
if (!fs.existsSync(skillsRoot)) {
    fail('`packages/open-cleaner-skills/skills` is missing');
}

const commands = commandTree();
const app = readJson(appPackage);
const skillsPackageJson = readJson(skillsPackage);
if (skillsPackageJson.license !== 'MPL-2.0') fail('skills package `license` must be `MPL-2.0`');
if (skillsPackageJson.version !== app.version) {
    fail(`skills package version \`${skillsPackageJson.version}\` must match the app version \`${app.version}\``);
}
const files = skillsPackageJson.files;
if (!Array.isArray(files) || !files.includes('skills') || files.length > 2) {
    fail('skills package `files` must contain `skills` plus at most one readme');
}

const skillDirs = fs
    .readdirSync(skillsRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
if (skillDirs.length === 0) fail('no skill directories found');

let checkedInvocations = 0;
for (const dir of skillDirs) {
    const file = path.join(skillsRoot, dir, 'SKILL.md');
    if (!fs.existsSync(file)) fail(`${dir}: missing SKILL.md`);
    const source = fs.readFileSync(file, 'utf8');

    const { meta, body } = parseFrontmatter(source, `skills/${dir}/SKILL.md`);
    if (!meta.name) fail(`${dir}: frontmatter is missing \`name\``);
    if (!meta.description) fail(`${dir}: frontmatter is missing \`description\``);
    if (!/^[a-z0-9][a-z0-9-]*$/.test(meta.name)) fail(`${dir}: \`name\` must be kebab-case`);
    if (meta.name !== dir) fail(`${dir}: frontmatter \`name\` does not match the directory`);

    if (!/^##\s+Safety\b/m.test(body)) fail(`${dir}: missing a \`## Safety\` section`);
    assertNoOutOfPackageReferences(source, `skills/${dir}/SKILL.md`, path.join(skillsRoot, dir));

    const invocations = [...source.matchAll(/`(open-cleaner [^`\n]+)`/g)].map((match) => match[1].trim());
    if (invocations.length === 0) fail(`${dir}: no backticked \`open-cleaner\` invocation found`);

    for (const invocation of invocations) {
        const tokens = invocation.split(/\s+/);
        const command = tokens[1];
        if (!commands.has(command)) fail(`${dir}: unknown command \`${command}\` in \`${invocation}\``);
        const allowed = flagsFor(command);
        for (let index = 2; index < tokens.length; index += 1) {
            const token = tokens[index];
            if (token.startsWith('<')) continue;
            if (!token.startsWith('--')) {
                fail(`${dir}: unexpected positional token \`${token}\` in \`${invocation}\``);
            }
            const flag = token.split('=')[0];
            if (!allowed.has(flag)) fail(`${dir}: flag \`${flag}\` is not defined for \`${command}\``);
            // A flag that is written without `=` consumes the value tokens that follow it,
            // so `--only target` and `--root <path>` are both argument values, not positionals.
            if (!token.includes('=')) {
                while (index + 1 < tokens.length && !tokens[index + 1].startsWith('--') && !tokens[index + 1].startsWith('<')) index += 1;
            }
        }
        checkedInvocations += 1;
    }

    console.log(`ok ${dir}: ${invocations.length} invocation(s)`);
}

console.log(`check-skills ok: ${skillDirs.length} skills, ${checkedInvocations} CLI invocations, ${commands.size} commands`);
