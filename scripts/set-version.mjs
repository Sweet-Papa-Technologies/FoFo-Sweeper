#!/usr/bin/env node
/**
 * Syncs version into package.json during releases.
 * Usage: node scripts/set-version.mjs 0.1.0
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const version = process.argv[2];
if (!version || !/^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$/.test(version)) {
  console.error(`Usage: node scripts/set-version.mjs <semver> (got: ${version ?? ''})`);
  process.exit(1);
}

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const pkgPath = join(root, 'package.json');
const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
pkg.version = version;
writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n', 'utf8');
console.log(`Synced version to ${version} in package.json`);
