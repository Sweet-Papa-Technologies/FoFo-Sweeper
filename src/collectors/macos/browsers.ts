import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSafe } from '../../platform/exec.js';
import type { CollectedItem, CollectorRunResult, PreflightResult } from '../../types.js';

const MAC_CHROMIUM_BROWSERS = [
  { name: 'Chrome', baseDir: path.join('Library', 'Application Support', 'Google', 'Chrome') },
  { name: 'Edge', baseDir: path.join('Library', 'Application Support', 'Microsoft Edge') },
  { name: 'Brave', baseDir: path.join('Library', 'Application Support', 'BraveSoftware', 'Brave-Browser') },
];

const BUILTIN_EXT_IDS = new Set([
  'nmmhkkegccagdldgiimedpiccmgmieda',
  'pkedcjkdefgpdelpbcmbmeomcjbeemfm',
  'ghbmnnjooekpmoecnnnilnnbdlolhkhi',
  'aapocclcgogkmnckokdopfmhonfmgoek',
  'aohghmighlieiainnegkcijnfilokake',
  'felcaaldnbdncclmgdcncolpebgiejap',
]);

export async function collectMacosBrowsers(
  timeoutMs: number,
  preflight?: PreflightResult
): Promise<CollectorRunResult> {
  const start = Date.now();
  const warnings: string[] = [];
  const items: CollectedItem[] = [];
  const home = os.homedir();
  const mdmEnrolled = Boolean(preflight?.mdm_enrolled);

  // 1. Safari extensions (requires Full Disk Access for ~/Library/Safari)
  const safariExtPlist = path.join(home, 'Library', 'Safari', 'Extensions', 'Extensions.plist');
  try {
    if (fs.existsSync(safariExtPlist)) {
      const pl = await execFileSafe('plutil', ['-convert', 'json', '-o', '-', safariExtPlist], { timeoutMs: 5_000 });
      if (pl.exitCode === 0 && pl.stdout.trim()) {
        const parsed = JSON.parse(pl.stdout) as { 'Installed Extensions'?: Array<Record<string, any>> };
        for (const ext of parsed['Installed Extensions'] ?? []) {
          const id = String(ext['Archive File Name'] || ext['Bundle Identifier'] || 'safari-ext');
          items.push({
            collector: 'browsers',
            kind: 'browser_extension',
            location: `Safari:extension:${id}`,
            facts: {
              browser: 'Safari',
              extension_id: id,
              force_installed: false,
              domain_or_mdm_joined: mdmEnrolled,
            },
            untrusted: {
              name: String(ext['Bundle Identifier'] || id),
              raw_value: JSON.stringify(ext).slice(0, 240),
            },
          });
        }
      }
    }
  } catch {
    warnings.push(
      'Could not read Safari extensions (Full Disk Access required: System Settings -> Privacy & Security -> Full Disk Access).'
    );
  }

  // Safari App Extensions via pluginkit (works even without FDA)
  const pk = await execFileSafe('pluginkit', ['-m', '-v', '-p', 'com.apple.Safari.web-extension'], {
    timeoutMs: Math.min(timeoutMs, 10_000),
  });
  if (pk.exitCode === 0 && pk.stdout.trim()) {
    for (const line of pk.stdout.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const m = trimmed.match(/^([+-]?)\s*([^\s(]+)\(([^)]+)\)\s+(.+)$/);
      if (!m) continue;
      const bundleId = m[2];
      const version = m[3];
      const rest = m[4].trim();
      if (bundleId.startsWith('com.apple.')) continue;
      items.push({
        collector: 'browsers',
        kind: 'browser_extension',
        location: `Safari:webext:${bundleId}`,
        facts: {
          browser: 'Safari',
          extension_id: bundleId,
          force_installed: false,
          domain_or_mdm_joined: mdmEnrolled,
        },
        untrusted: {
          name: bundleId,
          version,
          raw_value: rest,
        },
      });
    }
  }

  // 2. Chromium-based browsers (Chrome, Edge, Brave)
  for (const b of MAC_CHROMIUM_BROWSERS) {
    const root = path.join(home, b.baseDir);
    if (!fs.existsSync(root)) continue;
    let dirs: fs.Dirent[] = [];
    try {
      dirs = fs.readdirSync(root, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const d of dirs) {
      if (!d.isDirectory() || (d.name !== 'Default' && !d.name.startsWith('Profile '))) continue;
      const profDir = path.join(root, d.name);
      const prefsPath = path.join(profDir, 'Preferences');
      let prefs: Record<string, any> | null = null;
      if (fs.existsSync(prefsPath)) {
        try {
          prefs = JSON.parse(fs.readFileSync(prefsPath, 'utf8'));
        } catch {
          prefs = null;
        }
      }

      const extDir = path.join(profDir, 'Extensions');
      const extSettings = prefs?.extensions?.settings ?? {};
      if (fs.existsSync(extDir)) {
        try {
          for (const ee of fs.readdirSync(extDir, { withFileTypes: true })) {
            if (!ee.isDirectory() || BUILTIN_EXT_IDS.has(ee.name.toLowerCase())) continue;
            const extId = ee.name;
            const setting = extSettings[extId] ?? {};
            if (setting.location === 5 || setting.location === 10) continue;

            const versions = fs
              .readdirSync(path.join(extDir, extId), { withFileTypes: true })
              .filter((v) => v.isDirectory())
              .map((v) => v.name)
              .sort()
              .reverse();
            if (versions.length === 0) continue;

            let manifest: Record<string, any> = {};
            const mp = path.join(extDir, extId, versions[0], 'manifest.json');
            try {
              if (fs.existsSync(mp)) manifest = JSON.parse(fs.readFileSync(mp, 'utf8'));
            } catch {
              // ignore
            }

            let installSource = 'webstore';
            if (setting.location === 4) installSource = 'unpacked';
            else if (setting.location === 2 || setting.location === 3) installSource = 'sideloaded';
            else if (setting.location === 6 || setting.location === 8) installSource = 'policy_forced';

            items.push({
              collector: 'browsers',
              kind: 'browser_extension',
              location: `${b.name}:${d.name}:extension:${extId}`,
              facts: {
                browser: b.name,
                extension_id: extId,
                force_installed: installSource === 'policy_forced',
                install_source: installSource,
                domain_or_mdm_joined: mdmEnrolled,
              },
              untrusted: {
                name: String(manifest.name || extId),
                version: String(manifest.version || versions[0]),
              },
            });
          }
        } catch {
          // ignore
        }
      }

      // Notification permissions
      const notifMap = prefs?.profile?.content_settings?.exceptions?.notifications;
      if (notifMap && typeof notifMap === 'object') {
        for (const [originKey, entry] of Object.entries(notifMap as Record<string, any>)) {
          if (!entry || entry.setting !== 1) continue;
          const clean = originKey.replace(/,\*$/, '');
          if (/google\.com|github\.com|slack\.com|discord\.com|localhost|127\.0\.0\.1/i.test(clean)) {
            continue;
          }
          items.push({
            collector: 'browsers',
            kind: 'browser_notification',
            location: `${b.name}:${d.name}:notification:${clean}`,
            facts: { browser: b.name },
            untrusted: { origin: clean, name: clean },
          });
        }
      }
    }
  }

  // 3. Firefox extensions
  const ffRoot = path.join(home, 'Library', 'Application Support', 'Firefox', 'Profiles');
  if (fs.existsSync(ffRoot)) {
    try {
      for (const prof of fs.readdirSync(ffRoot, { withFileTypes: true })) {
        if (!prof.isDirectory()) continue;
        const extJson = path.join(ffRoot, prof.name, 'extensions.json');
        if (!fs.existsSync(extJson)) continue;
        try {
          const parsed = JSON.parse(fs.readFileSync(extJson, 'utf8'));
          for (const addon of Array.isArray(parsed.addons) ? parsed.addons : []) {
            if (addon.type !== 'extension' || addon.location === 'app-builtin' || addon.location === 'app-system-defaults') {
              continue;
            }
            items.push({
              collector: 'browsers',
              kind: 'browser_extension',
              location: `Firefox:${prof.name}:extension:${addon.id}`,
              facts: {
                browser: 'Firefox',
                extension_id: String(addon.id),
                force_installed: false,
                install_source: addon.location === 'app-profile' ? 'amo_or_profile' : 'sideloaded',
                domain_or_mdm_joined: mdmEnrolled,
              },
              untrusted: {
                name: String(addon.defaultLocale?.name || addon.id),
                version: String(addon.version || ''),
              },
            });
          }
        } catch {
          // ignore
        }
      }
    } catch {
      // ignore
    }
  }

  return {
    collector: 'browsers',
    status: warnings.length > 0 ? 'partial' : 'ok',
    duration_ms: Date.now() - start,
    item_count: items.length,
    items,
    warnings,
  };
}
