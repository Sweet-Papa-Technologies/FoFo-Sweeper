#!/usr/bin/env node
/**
 * Bundles fcsweep into a single zero-dependency CJS file (dist/bundle.cjs)
 * with version and data/triage-prompt.md embedded cleanly for Node SEA.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import esbuild from 'esbuild';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const triagePrompt = readFileSync(join(root, 'data', 'triage-prompt.md'), 'utf8');

await esbuild.build({
  entryPoints: [join(root, 'src', 'index.ts')],
  bundle: true,
  platform: 'node',
  target: 'node22',
  format: 'cjs',
  outfile: join(root, 'dist', 'bundle.cjs'),
  define: {
    __FCSWEEP_VERSION__: JSON.stringify(pkg.version),
    __FCSWEEP_TRIAGE_PROMPT__: JSON.stringify(triagePrompt),
  },
  logLevel: 'info',
});
