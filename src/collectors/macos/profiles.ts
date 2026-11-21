import { execFileSafe } from '../../platform/exec.js';
import type { CollectedItem, CollectorRunResult, PreflightResult } from '../../types.js';

const SUSPICIOUS_PAYLOAD_TYPES = [
  'com.google.chrome',
  'com.microsoft.edge',
  'com.brave.browser',
  'org.mozilla.firefox',
  'com.apple.safari',
  'com.apple.systemconfiguration',
  'com.apple.proxy.http.global',
  'com.apple.dnssettings.managed',
  'com.apple.managedclient.preferences',
];

const SUSPICIOUS_PAYLOAD_KEYS = [
  'homepagelocation',
  'defaultsearchprovidersearchurl',
  'extensioninstallforcelist',
  'restoreonstartupurls',
  'httpproxy',
  'httpsproxy',
  'proxyautoconfigurlstring',
  'dnssettings',
  'newtabpagelocation',
];

export function analyzeProfilePayload(profile: Record<string, any>): {
  setsBrowserOrNet: boolean;
  payloadTypes: string[];
  matchedReasons: string[];
} {
  const payloadTypes: string[] = [];
  const matchedReasons: string[] = [];

  const items = Array.isArray(profile.ProfileItems) ? profile.ProfileItems : [];
  for (const pi of items) {
    const pType = String(pi.PayloadType || '').toLowerCase();
    if (pType) payloadTypes.push(pi.PayloadType);
    const contentStr = JSON.stringify(pi.PayloadContent ?? pi ?? '').toLowerCase();

    if (SUSPICIOUS_PAYLOAD_TYPES.some((t) => pType.includes(t))) {
      matchedReasons.push(`payload_type=${pi.PayloadType}`);
    }
    for (const k of SUSPICIOUS_PAYLOAD_KEYS) {
      if (contentStr.includes(k)) {
        matchedReasons.push(`key=${k}`);
      }
    }
  }

  return {
    setsBrowserOrNet: matchedReasons.length > 0,
    payloadTypes,
    matchedReasons: Array.from(new Set(matchedReasons)),
  };
}

export async function collectMacosProfiles(
  timeoutMs: number,
  preflight?: PreflightResult
): Promise<CollectorRunResult> {
  const start = Date.now();
  const res = await execFileSafe('profiles', ['show', '-output', 'stdout-xml'], {
    timeoutMs: Math.min(timeoutMs, 30_000),
  });
  const durationMs = Date.now() - start;

  if (res.exitCode !== 0 || !res.stdout.trim()) {
    // No profiles installed or permission issue
    if (/no configuration profiles/i.test(`${res.stdout}\n${res.stderr}`)) {
      return {
        collector: 'profiles',
        status: 'ok',
        duration_ms: durationMs,
        item_count: 0,
        items: [],
        warnings: [],
      };
    }
    return {
      collector: 'profiles',
      status: 'partial',
      duration_ms: durationMs,
      item_count: 0,
      items: [],
      warnings: [res.stderr.trim() || 'profiles show returned no XML output'],
    };
  }

  // Convert XML plist to JSON via plutil using stdin
  const jsonRes = await execFileSafe('python3', [
    '-c',
    'import plistlib, json, sys; print(json.dumps(plistlib.loads(sys.stdin.buffer.read()), default=str))',
  ], { timeoutMs: 10_000 }).catch(() => null);
  // Actually avoid piping issues by writing to a temp buffer via node or parsing via plutil on /dev/stdin!
  // Let's write a small inline XML-to-JSON via plutil on a temp file in os.tmpdir!
  void jsonRes;

  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const tmpFile = path.join(os.tmpdir(), `fcsweep-profiles-${process.pid}-${Date.now()}.plist`);
  let parsed: Record<string, any> | null = null;
  try {
    fs.writeFileSync(tmpFile, res.stdout, 'utf8');
    const pl = await execFileSafe('plutil', ['-convert', 'json', '-o', '-', tmpFile], { timeoutMs: 8_000 });
    if (pl.exitCode === 0 && pl.stdout.trim()) {
      parsed = JSON.parse(pl.stdout) as Record<string, any>;
    }
  } catch {
    parsed = null;
  } finally {
    try {
      fs.unlinkSync(tmpFile);
    } catch {
      // ignore
    }
  }

  if (!parsed) {
    return {
      collector: 'profiles',
      status: 'partial',
      duration_ms: Date.now() - start,
      item_count: 0,
      items: [],
      warnings: ['Could not parse configuration profiles XML output'],
    };
  }

  const mdmEnrolled = Boolean(preflight?.mdm_enrolled);
  const items: CollectedItem[] = [];

  for (const [scopeKey, profList] of Object.entries(parsed)) {
    if (!Array.isArray(profList)) continue;
    for (const prof of profList) {
      if (!prof || typeof prof !== 'object') continue;
      const id = String(prof.ProfileIdentifier || prof.ProfileUUID || 'unknown-profile');
      const displayName = String(prof.ProfileDisplayName || id);
      const org = prof.ProfileOrganization ? String(prof.ProfileOrganization) : null;
      const installDate = prof.ProfileInstallDate ? String(prof.ProfileInstallDate) : null;
      const analysis = analyzeProfilePayload(prof);

      items.push({
        collector: 'profiles',
        kind: 'config_profile',
        location: `Profile:${scopeKey}:${id}`,
        facts: {
          domain_or_mdm_joined: mdmEnrolled,
          profile_sets_browser_or_net: analysis.setsBrowserOrNet && !mdmEnrolled,
          entry_created: installDate,
        },
        untrusted: {
          name: displayName,
          publisher: org,
          description: prof.ProfileDescription ? String(prof.ProfileDescription) : null,
          raw_value: analysis.matchedReasons.join(', ') || analysis.payloadTypes.join(', '),
        },
      });
    }
  }

  return {
    collector: 'profiles',
    status: 'ok',
    duration_ms: Date.now() - start,
    item_count: items.length,
    items,
    warnings: [],
  };
}
