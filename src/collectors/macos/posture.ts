import fs from 'node:fs';
import { execFileSafe } from '../../platform/exec.js';
import type { CollectedItem, CollectorRunResult } from '../../types.js';

async function readPlistKey(plistPath: string, key: string): Promise<string | null> {
  if (!fs.existsSync(plistPath)) return null;
  const res = await execFileSafe('defaults', ['read', plistPath, key], { timeoutMs: 5_000 });
  return res.exitCode === 0 ? res.stdout.trim() : null;
}

export async function collectMacosPosture(timeoutMs: number): Promise<CollectorRunResult> {
  const start = Date.now();
  const items: CollectedItem[] = [];

  const [gkRes, sipRes, xpVer, xprVer, pendingUpdates] = await Promise.all([
    execFileSafe('spctl', ['--status'], { timeoutMs: 5_000 }),
    execFileSafe('csrutil', ['status'], { timeoutMs: 5_000 }),
    readPlistKey('/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist', 'CFBundleShortVersionString'),
    readPlistKey('/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist', 'CFBundleShortVersionString'),
    readPlistKey('/Library/Preferences/com.apple.SoftwareUpdate.plist', 'RecommendedUpdates'),
  ]);

  const gkOut = `${gkRes.stdout} ${gkRes.stderr}`.trim();
  const gatekeeperEnabled = /assessments enabled/i.test(gkOut);

  const sipOut = `${sipRes.stdout} ${sipRes.stderr}`.trim();
  const sipEnabled = /enabled/i.test(sipOut) && !/disabled/i.test(sipOut);

  items.push({
    collector: 'posture',
    kind: 'posture',
    location: 'macOS:SecurityPosture',
    facts: {
      gatekeeper_enabled: gatekeeperEnabled,
      sip_enabled: sipEnabled,
      xprotect_version: xpVer,
      xprotect_remediator_version: xprVer,
      has_pending_updates: Boolean(pendingUpdates && pendingUpdates !== '(\n)' && pendingUpdates !== '()'),
    },
    untrusted: {
      name: 'macOS Security Posture',
      raw_value: `Gatekeeper=${gkOut}; SIP=${sipOut}; XProtect=${xpVer ?? 'unknown'}; XProtectRemediator=${xprVer ?? 'unknown'}`,
    },
  });

  void timeoutMs;
  return {
    collector: 'posture',
    status: 'ok',
    duration_ms: Date.now() - start,
    item_count: items.length,
    items,
    warnings: [],
  };
}
