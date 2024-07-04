#!/usr/bin/env node
/** Copy the release cdylib into the matching platform package as `.node` */
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveTarget, stageNative } from './platform.ts';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const target = resolveTarget();
const { src, dest } = stageNative(root, target);
console.log(`staged ${src} -> ${dest}`);
