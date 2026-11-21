#!/usr/bin/env node
/**
 * Build script for creating a Single Executable Application (SEA) binary for fcsweep.
 *
 * Requirements:
 * - Node.js 22+
 * - `npm run build:bundle` must run first (produces dist/bundle.cjs)
 */

import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, existsSync, readdirSync, unlinkSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, '..');
const distDir = join(rootDir, 'dist');
const isWindows = process.platform === 'win32';
const isMac = process.platform === 'darwin';

const outputName = isWindows ? 'fcsweep.exe' : 'fcsweep';
const outputPath = join(distDir, outputName);
const blobPath = join(distDir, 'sea-prep.blob');
const bundlePath = join(distDir, 'bundle.cjs');

function run(cmd, args, options = {}) {
  console.log(`> ${cmd} ${args.join(' ')}`);
  const res = spawnSync(cmd, args, {
    stdio: 'inherit',
    cwd: rootDir,
    shell: isWindows && cmd.endsWith('.cmd'),
    ...options,
  });
  if (res.status !== 0 && !options.ignoreError) {
    console.error(`Command failed (exit ${res.status}): ${cmd} ${args.join(' ')}`);
    process.exit(res.status || 1);
  }
  return res.status === 0;
}

function findSigntool() {
  const whereRes = spawnSync('where.exe', ['signtool.exe'], { encoding: 'utf8' });
  if (whereRes.status === 0 && whereRes.stdout.trim()) {
    return whereRes.stdout.trim().split(/\r?\n/)[0];
  }
  const sdkRoot = 'C:\\Program Files (x86)\\Windows Kits\\10\\bin';
  if (existsSync(sdkRoot)) {
    try {
      for (const ver of readdirSync(sdkRoot).sort().reverse()) {
        const candidate = join(sdkRoot, ver, 'x64', 'signtool.exe');
        if (existsSync(candidate)) return candidate;
      }
    } catch {
      // ignore
    }
  }
  return null;
}

function main() {
  console.log(`Building fcsweep Single Executable Application (${process.platform}/${process.arch})...\n`);

  if (!existsSync(bundlePath)) {
    console.error('Error: dist/bundle.cjs not found. Run `npm run build:bundle` first.');
    process.exit(1);
  }

  // 1. Generate SEA blob
  console.log('[1/4] Generating SEA preparation blob...');
  run(process.execPath, ['--experimental-sea-config', 'sea-config.json']);
  if (!existsSync(blobPath)) {
    console.error('Error: Failed to generate dist/sea-prep.blob');
    process.exit(1);
  }

  // 2. Copy Node binary
  console.log('[2/4] Copying Node.js executable...');
  if (existsSync(outputPath)) {
    unlinkSync(outputPath);
  }
  copyFileSync(process.execPath, outputPath);

  // 3. Remove original Node signature before blob injection
  console.log('[3/4] Removing existing Node.js signature...');
  if (isWindows) {
    const signtool = findSigntool();
    if (signtool) {
      console.log(`  Using signtool: ${signtool}`);
      run(signtool, ['remove', '/s', outputPath], { ignoreError: true });
    } else {
      console.warn('  Warning: signtool.exe not found; skipping signature removal');
    }
  } else if (isMac) {
    run('codesign', ['--remove-signature', outputPath], { ignoreError: true });
  }

  // 4. Inject SEA blob via local postject
  console.log('[4/4] Injecting SEA blob with postject...');
  const postjectBin = join(
    rootDir,
    'node_modules',
    '.bin',
    isWindows ? 'postject.cmd' : 'postject'
  );
  const postjectArgs = [
    outputPath,
    'NODE_SEA_BLOB',
    blobPath,
    '--sentinel-fuse',
    'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2',
  ];
  if (isMac) {
    postjectArgs.push('--macho-segment-name', 'NODE_SEA');
  }
  run(postjectBin, postjectArgs);

  if (!isWindows) {
    chmodSync(outputPath, 0o755);
  }

  // Re-sign ad-hoc on macOS so local binary executes cleanly before release signing
  if (isMac) {
    console.log('\nApplying local ad-hoc signature (release workflow replaces with Developer ID + notarization)...');
    run('codesign', [
      '--force',
      '--sign',
      '-',
      '--entitlements',
      join(rootDir, 'scripts', 'entitlements.mac.plist'),
      outputPath,
    ]);
  }

  // Quick smoke check
  console.log('\nVerifying built SEA binary...');
  const out = execFileSync(outputPath, ['--version'], { encoding: 'utf8' }).trim();
  console.log(`  Verified: ${out}`);
  console.log(`  Output:   ${outputPath}`);
}

main();
