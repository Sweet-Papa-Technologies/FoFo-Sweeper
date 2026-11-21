import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSafe } from '../../platform/exec.js';
import { classifyPath, hashFileSha256 } from '../../platform/file-facts.js';
import type { CollectedItem, CollectorRunResult, FileFacts, SigStatus } from '../../types.js';

interface MacCodeSignInfo {
  sig_status: SigStatus;
  signer: string | null;
  notarized: boolean | null;
}

const signCache = new Map<string, MacCodeSignInfo>();

async function inspectMacBinarySignature(filePath: string): Promise<MacCodeSignInfo> {
  const cached = signCache.get(filePath);
  if (cached) return cached;

  const cs = await execFileSafe('codesign', ['-dv', '--verbose=4', filePath], { timeoutMs: 8_000 });
  const combined = `${cs.stdout}\n${cs.stderr}`;

  let sigStatus: SigStatus = 'NotSigned';
  let signer: string | null = null;
  let notarized: boolean | null = null;

  if (/permission denied|operation not permitted/i.test(combined)) {
    sigStatus = 'NotApplicable';
    signer = null;
    notarized = null;
  } else if (/code object is not signed at all/i.test(combined)) {
    sigStatus = 'NotSigned';
    notarized = false;
  } else if (cs.exitCode === 0) {
    const isAdHoc = /Signature=adhoc/i.test(combined) || /flags=0x[0-9a-f]+\(adhoc\)/i.test(combined);
    const authMatches = Array.from(combined.matchAll(/^Authority=(.+)$/gm)).map((m) => m[1].trim());
    const authUnavailable = authMatches.some((a) => a === '(unavailable)');
    if (isAdHoc || authMatches.length === 0) {
      sigStatus = 'AdHoc';
      signer = 'adhoc';
      notarized = false;
    } else if (authUnavailable) {
      // Restricted/sandboxed environment where Security daemon cannot return certificate chain
      sigStatus = 'NotApplicable';
      signer = null;
      notarized = null;
    } else {
      sigStatus = 'Valid';
      signer = authMatches[0];
      // Verify integrity & notarization with codesign --verify and spctl
      const verify = await execFileSafe('codesign', ['--verify', '--strict', filePath], { timeoutMs: 8_000 });
      if (verify.exitCode !== 0) {
        sigStatus = 'HashMismatch';
        notarized = false;
      } else if (
        authMatches.some((a) => /Apple Root CA|Software Signing|Apple Code Signing/i.test(a)) &&
        (filePath.startsWith('/System/') || filePath.startsWith('/usr/') || filePath.startsWith('/Library/Apple/'))
      ) {
        notarized = true;
      } else {
        // For binaries inside a .app bundle, evaluate the .app bundle with spctl
        const appBundleMatch = filePath.match(/^(.+?\.app)\/Contents\/MacOS\//);
        const assessTarget = appBundleMatch ? appBundleMatch[1] : filePath;
        const sp = await execFileSafe('spctl', ['--assess', '--type', 'exec', '-vv', assessTarget], {
          timeoutMs: 8_000,
        });
        const spOut = `${sp.stdout}\n${sp.stderr}`;
        if (sp.exitCode === 0 && /accepted/i.test(spOut)) {
          notarized = true;
        } else if (/the code is valid but does not seem to be an app/i.test(spOut)) {
          // Standalone Mach-O CLI binaries (e.g. node, Developer ID tools) cannot be assessed as .app bundles by spctl
          notarized = null;
        } else if (/rejected/i.test(spOut)) {
          notarized = false;
        }
      }
    }
  } else {
    sigStatus = 'UnknownError';
  }

  const info: MacCodeSignInfo = { sig_status: sigStatus, signer, notarized };
  signCache.set(filePath, info);
  return info;
}

async function readPlistAsJson(
  plistPath: string
): Promise<{ data: Record<string, any> | null; permissionDenied: boolean }> {
  const res = await execFileSafe('plutil', ['-convert', 'json', '-o', '-', plistPath], {
    timeoutMs: 5_000,
  });
  const errText = `${res.stdout}\n${res.stderr}`;
  if (/permission denied|couldn.t be opened because you don.t have permission/i.test(errText)) {
    return { data: null, permissionDenied: true };
  }
  if (res.exitCode !== 0 || !res.stdout.trim()) return { data: null, permissionDenied: false };
  try {
    return { data: JSON.parse(res.stdout) as Record<string, any>, permissionDenied: false };
  } catch {
    return { data: null, permissionDenied: false };
  }
}

export async function collectMacosLaunchItems(timeoutMs: number): Promise<CollectorRunResult> {
  const start = Date.now();
  const warnings: string[] = [];
  const items: CollectedItem[] = [];

  const dirs: string[] = [
    path.join(os.homedir(), 'Library', 'LaunchAgents'),
    '/Library/LaunchAgents',
    '/Library/LaunchDaemons',
  ];

  // If elevated, also scan other users' LaunchAgents
  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    try {
      for (const entry of fs.readdirSync('/Users', { withFileTypes: true })) {
        if (!entry.isDirectory() || entry.name === 'Shared' || entry.name.startsWith('.')) continue;
        const d = path.join('/Users', entry.name, 'Library', 'LaunchAgents');
        if (!dirs.includes(d)) dirs.push(d);
      }
    } catch {
      // ignore
    }
  }

  const deadline = start + timeoutMs - 2_000;

  for (const dir of dirs) {
    if (!fs.existsSync(dir)) continue;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (err) {
      warnings.push(`Cannot read ${dir}: ${err instanceof Error ? err.message : String(err)}`);
      continue;
    }

    for (const entry of entries) {
      if (Date.now() > deadline) {
        warnings.push('Launch items scan reached timeout budget; results may be partial');
        break;
      }
      if (!entry.name.endsWith('.plist')) continue;
      const plistPath = path.join(dir, entry.name);
      const parsedPlist = await readPlistAsJson(plistPath);
      if (!parsedPlist.data) {
        warnings.push(
          parsedPlist.permissionDenied
            ? `Unreadable without root: ${plistPath}`
            : `Failed to parse plist: ${plistPath}`
        );
        continue;
      }
      const plist = parsedPlist.data;

      const label = typeof plist.Label === 'string' ? plist.Label : entry.name.replace(/\.plist$/, '');
      const progArgs: string[] = Array.isArray(plist.ProgramArguments)
        ? plist.ProgramArguments.map(String)
        : [];
      const program =
        typeof plist.Program === 'string' ? plist.Program : progArgs[0] ?? null;
      const cmdLine = progArgs.length > 0 ? progArgs.join(' ') : program ?? '';
      const runAtLoad = Boolean(plist.RunAtLoad);

      const fileFacts: FileFacts = {
        target_path: program,
        file_exists: false,
        path_class: program ? classifyPath(program, 'macos') : undefined,
      };

      let plistCreated: string | null = null;
      try {
        plistCreated = fs.statSync(plistPath).birthtime.toISOString();
      } catch {
        // ignore
      }

      if (program && fs.existsSync(program)) {
        try {
          const st = fs.statSync(program);
          if (st.isFile()) {
            fileFacts.file_exists = true;
            fileFacts.file_size = st.size;
            fileFacts.file_created = st.birthtime.toISOString();
            fileFacts.file_modified = st.mtime.toISOString();
            fileFacts.sha256 = hashFileSha256(program);
            fileFacts.hidden_attr = path.basename(program).startsWith('.');
            const cs = await inspectMacBinarySignature(program);
            fileFacts.sig_status = cs.sig_status;
            fileFacts.signer = cs.signer;
            fileFacts.notarized = cs.notarized;
          }
        } catch {
          // ignore
        }
      }

      items.push({
        collector: 'launch_items',
        kind: 'launch_item',
        location: `${plistPath} (${label})`,
        facts: {
          ...fileFacts,
          entry_created: plistCreated,
          runs_as: dir.includes('LaunchDaemons') ? 'root' : os.userInfo().username,
          run_at_load: runAtLoad,
        },
        untrusted: {
          label,
          name: label,
          command_line: cmdLine || null,
        },
        command_inspect: cmdLine || null,
      });
    }
  }

  return {
    collector: 'launch_items',
    status: warnings.length > 0 ? 'partial' : 'ok',
    duration_ms: Date.now() - start,
    item_count: items.length,
    items,
    warnings,
  };
}
