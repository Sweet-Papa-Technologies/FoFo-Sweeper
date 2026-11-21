#!/usr/bin/env node
/**
 * Build script for creating a Single Executable Application (SEA) binary for fcsweep.
 *
 * Requirements:
 * - Node.js 22+
 * - `npm run build:bundle` must run first (produces dist/bundle.cjs)
 *
 * On Windows, embeds assets/fcsweep.ico and PE VersionInfo (Product Name, Company,
 * Description, FileVersion) BEFORE postject injects NODE_SEA_BLOB so Explorer and
 * Properties display the FoFo Care Sweep icon and Sweet Papa Technologies metadata.
 */

import { execFileSync, spawnSync } from 'node:child_process';
import {
  chmodSync,
  copyFileSync,
  existsSync,
  readdirSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
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
const icoPath = join(rootDir, 'assets', 'fcsweep.ico');
const pkg = JSON.parse(readFileSync(join(rootDir, 'package.json'), 'utf8'));

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

async function embedWindowsIconAndMetadata(exePath) {
  if (!existsSync(icoPath)) {
    console.warn('  Warning: assets/fcsweep.ico not found; skipping Windows icon embedding');
    return;
  }
  try {
    const ResEdit = await import('resedit');
    const exeBuf = readFileSync(exePath);
    const exe = ResEdit.NtExecutable.from(exeBuf, { ignoreCert: true });
    const res = ResEdit.NtExecutableResource.from(exe);

    // Replace icon group #1 (Node's default icon) with FoFo Care Sweep icon
    const iconFile = ResEdit.Data.IconFile.from(readFileSync(icoPath));
    ResEdit.Resource.IconGroupEntry.replaceIconsForResource(
      res.entries,
      1,
      1033,
      iconFile.icons.map((item) => item.data)
    );

    // Update PE VersionInfo strings (Product Name, Company, Description, Version)
    const verTuple = String(pkg.version || '0.1.0')
      .split('-')[0]
      .split('.')
      .map((n) => Number(n) || 0);
    while (verTuple.length < 4) verTuple.push(0);

    const viList = ResEdit.Resource.VersionInfo.fromEntries(res.entries);
    const vi = viList[0] ?? ResEdit.Resource.VersionInfo.createEmpty();
    vi.setFileVersion(verTuple[0], verTuple[1], verTuple[2], verTuple[3], 1033);
    vi.setProductVersion(verTuple[0], verTuple[1], verTuple[2], verTuple[3], 1033);
    vi.setStringValues(
      { lang: 1033, codepage: 1200 },
      {
        CompanyName: 'Sweet Papa Technologies',
        FileDescription: 'FoFo Care Sweep — Malware & Adware Cleanup CLI',
        FileVersion: `${pkg.version}`,
        InternalName: 'fcsweep',
        LegalCopyright: 'Copyright © 2026 Sweet Papa Technologies',
        OriginalFilename: 'fcsweep.exe',
        ProductName: 'FoFo Care Sweep',
        ProductVersion: `${pkg.version}`,
      }
    );
    vi.outputToResourceEntries(res.entries);

    res.outputResource(exe);
    const outBuf = Buffer.from(exe.generate());
    writeFileSync(exePath, outBuf);
    console.log(`  Embedded assets/fcsweep.ico and VersionInfo (${pkg.version}) into ${exePath}`);
  } catch (err) {
    console.warn(`  Warning: failed to embed Windows PE icon/metadata: ${err instanceof Error ? err.message : String(err)}`);
  }
}

async function main() {
  console.log(`Building fcsweep Single Executable Application (${process.platform}/${process.arch})...\n`);

  if (!existsSync(bundlePath)) {
    console.error('Error: dist/bundle.cjs not found. Run `npm run build:bundle` first.');
    process.exit(1);
  }

  // 1. Generate SEA blob
  console.log('[1/5] Generating SEA preparation blob...');
  run(process.execPath, ['--experimental-sea-config', 'sea-config.json']);
  if (!existsSync(blobPath)) {
    console.error('Error: Failed to generate dist/sea-prep.blob');
    process.exit(1);
  }

  // 2. Copy Node binary
  console.log('[2/5] Copying Node.js executable...');
  if (existsSync(outputPath)) {
    unlinkSync(outputPath);
  }
  copyFileSync(process.execPath, outputPath);

  // 3. Remove original Node signature before resource editing / blob injection
  console.log('[3/5] Removing existing Node.js signature...');
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

  // 4. Embed Windows app icon & VersionInfo metadata (before postject)
  console.log('[4/5] Applying platform executable branding...');
  if (isWindows) {
    await embedWindowsIconAndMetadata(outputPath);
  } else {
    console.log('  macOS CLI binary (icons stored in assets/fcsweep.icns & assets/icon.png)');
  }

  // 5. Inject SEA blob via local postject
  console.log('[5/5] Injecting SEA blob with postject...');
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
