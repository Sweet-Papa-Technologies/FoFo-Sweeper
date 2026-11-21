import fs from 'node:fs';
import path from 'node:path';
import { ensureArray, runPowerShellJson } from '../../platform/powershell.js';
import type { CollectedItem, CollectorRunResult, PreflightResult } from '../../types.js';
import { PS_FILE_FACTS_HELPER } from './ps-common.js';

interface RawPolicyEntry {
  browser: string;
  hive: string;
  key_path: string;
  value_name: string;
  raw_value: string;
  is_forcelist: boolean;
}

const CHROMIUM_BROWSERS = [
  {
    name: 'Chrome',
    relUserData: path.join('AppData', 'Local', 'Google', 'Chrome', 'User Data'),
    extPage: 'chrome://extensions',
  },
  {
    name: 'Edge',
    relUserData: path.join('AppData', 'Local', 'Microsoft', 'Edge', 'User Data'),
    extPage: 'edge://extensions',
  },
  {
    name: 'Brave',
    relUserData: path.join('AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data'),
    extPage: 'brave://extensions',
  },
];

// Built-in Chromium component extensions & Microsoft/Google defaults not worth cluttering
const BUILTIN_EXTENSION_IDS = new Set([
  'nmmhkkegccagdldgiimedpiccmgmieda', // Chrome Web Store Payments
  'pkedcjkdefgpdelpbcmbmeomcjbeemfm', // Chrome Media Router
  'ghbmnnjooekpmoecnnnilnnbdlolhkhi', // Google Docs Offline
  'aapocclcgogkmnckokdopfmhonfmgoek', // Google Slides
  'aohghmighlieiainnegkcijnfilokake', // Google Docs
  'felcaaldnbdncclmgdcncolpebgiejap', // Google Sheets
  'jmjflgjpcpepeafmmgdpfkogkghcpiha', // Edge PDF/built-in
]);

const WELL_KNOWN_NOTIFICATION_ORIGINS = [
  'mail.google.com',
  'calendar.google.com',
  'chat.google.com',
  'meet.google.com',
  'outlook.live.com',
  'outlook.office.com',
  'teams.microsoft.com',
  'discord.com',
  'slack.com',
  'app.slack.com',
  'web.whatsapp.com',
  'messages.google.com',
  'github.com',
  'youtube.com',
  'www.youtube.com',
];

function resolveLocalizedName(extVersionDir: string, rawName: string): string {
  const m = rawName.match(/^__MSG_(.+)__$/);
  if (!m) return rawName;
  const msgKey = m[1];
  for (const locale of ['en', 'en_US', 'en_GB']) {
    const msgFile = path.join(extVersionDir, '_locales', locale, 'messages.json');
    if (!fs.existsSync(msgFile)) continue;
    try {
      const parsed = JSON.parse(fs.readFileSync(msgFile, 'utf8')) as Record<string, { message?: string }>;
      const direct = parsed[msgKey]?.message;
      if (direct) return direct;
      const ciKey = Object.keys(parsed).find((k) => k.toLowerCase() === msgKey.toLowerCase());
      if (ciKey && parsed[ciKey]?.message) return parsed[ciKey].message!;
    } catch {
      // ignore
    }
  }
  return rawName;
}

function readChromiumProfiles(
  userDir: string,
  browser: (typeof CHROMIUM_BROWSERS)[number],
  forceInstalledIds: Set<string>,
  domainOrMdmJoined: boolean
): CollectedItem[] {
  const items: CollectedItem[] = [];
  const userDataDir = path.join(userDir, browser.relUserData);
  if (!fs.existsSync(userDataDir)) return items;

  let subdirs: fs.Dirent[] = [];
  try {
    subdirs = fs.readdirSync(userDataDir, { withFileTypes: true });
  } catch {
    return items;
  }

  const profileDirs = subdirs
    .filter((d) => d.isDirectory() && (d.name === 'Default' || d.name.startsWith('Profile ')))
    .map((d) => ({ name: d.name, fullPath: path.join(userDataDir, d.name) }));

  for (const prof of profileDirs) {
    const prefsPath = path.join(prof.fullPath, 'Preferences');
    let prefs: Record<string, any> | null = null;
    if (fs.existsSync(prefsPath)) {
      try {
        prefs = JSON.parse(fs.readFileSync(prefsPath, 'utf8'));
      } catch {
        prefs = null;
      }
    }

    // 1. Extensions
    const extSettings = prefs?.extensions?.settings ?? {};
    const extDir = path.join(prof.fullPath, 'Extensions');
    const seenIds = new Set<string>();

    if (fs.existsSync(extDir)) {
      try {
        for (const extEntry of fs.readdirSync(extDir, { withFileTypes: true })) {
          if (!extEntry.isDirectory()) continue;
          const extId = extEntry.name;
          if (BUILTIN_EXTENSION_IDS.has(extId.toLowerCase())) continue;
          seenIds.add(extId);

          const versions = fs
            .readdirSync(path.join(extDir, extId), { withFileTypes: true })
            .filter((v) => v.isDirectory())
            .map((v) => v.name)
            .sort()
            .reverse();
          if (versions.length === 0) continue;

          const verDir = path.join(extDir, extId, versions[0]);
          const manifestPath = path.join(verDir, 'manifest.json');
          let manifest: Record<string, any> = {};
          try {
            if (fs.existsSync(manifestPath)) {
              manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
            }
          } catch {
            // ignore
          }

          const setting = extSettings[extId] ?? {};
          // Chromium location codes: 1=INTERNAL (webstore), 2=EXTERNAL_PREF, 3=EXTERNAL_REG, 4=LOAD(unpacked), 5=COMPONENT, 6=EXTERNAL_POLICY, 8=EXTERNAL_POLICY_DOWNLOAD
          const locCode = setting.location;
          if (locCode === 5 || locCode === 10) continue; // built-in component
          let installSource = 'webstore';
          if (locCode === 4) installSource = 'unpacked';
          else if (locCode === 2 || locCode === 3) installSource = 'sideloaded';
          else if (locCode === 6 || locCode === 8 || forceInstalledIds.has(extId.toLowerCase())) {
            installSource = 'policy_forced';
          }

          const isForced = installSource === 'policy_forced' || forceInstalledIds.has(extId.toLowerCase());
          const extName = resolveLocalizedName(verDir, String(manifest.name || setting.manifest?.name || extId));
          const perms = [
            ...(Array.isArray(manifest.permissions) ? manifest.permissions : []),
            ...(Array.isArray(manifest.host_permissions) ? manifest.host_permissions : []),
          ].map(String);

          let createdIso: string | null = null;
          try {
            createdIso = fs.statSync(verDir).birthtime.toISOString();
          } catch {
            // ignore
          }

          items.push({
            collector: 'browsers',
            kind: 'browser_extension',
            location: `${browser.name}:${prof.name}:extension:${extId}`,
            facts: {
              browser: browser.name,
              extension_id: extId,
              force_installed: isForced,
              install_source: installSource,
              domain_or_mdm_joined: domainOrMdmJoined,
              entry_created: createdIso,
              permissions_count: perms.length,
            },
            untrusted: {
              name: extName,
              version: String(manifest.version || versions[0] || ''),
              description: typeof manifest.description === 'string' ? manifest.description : null,
              raw_value: perms.slice(0, 12).join(', '),
            },
            remediation_meta: {
              browser: browser.name,
              profile_path: prof.fullPath,
              extension_id: extId,
              extension_page_url: browser.extPage,
            },
          });
        }
      } catch {
        // ignore
      }
    }

    // 2. Notification permissions (setting === 1 means Allowed)
    const notifMap = prefs?.profile?.content_settings?.exceptions?.notifications;
    if (notifMap && typeof notifMap === 'object') {
      for (const [originKey, entry] of Object.entries(notifMap as Record<string, any>)) {
        if (!entry || entry.setting !== 1) continue;
        const cleanOrigin = originKey.replace(/,\*$/, '');
        let host = cleanOrigin;
        try {
          host = new URL(cleanOrigin).hostname.toLowerCase();
        } catch {
          host = cleanOrigin.toLowerCase();
        }
        if (
          WELL_KNOWN_NOTIFICATION_ORIGINS.some((w) => host === w || host.endsWith('.' + w)) ||
          host === 'localhost' ||
          host === '127.0.0.1'
        ) {
          continue;
        }
        items.push({
          collector: 'browsers',
          kind: 'browser_notification',
          location: `${browser.name}:${prof.name}:notification:${cleanOrigin}`,
          facts: {
            browser: browser.name,
          },
          untrusted: {
            origin: cleanOrigin,
            name: host,
          },
          remediation_meta: {
            browser: browser.name,
            profile_path: prof.fullPath,
            preferences_path: prefsPath,
            notification_origin: originKey,
          },
        });
      }
    }

    // 3. Homepage / Startup URLs / Default search (recorded in snapshot for context)
    if (prefs) {
      const homepage = typeof prefs.homepage === 'string' ? prefs.homepage : null;
      const startupUrls: string[] = Array.isArray(prefs.session?.startup_urls)
        ? prefs.session.startup_urls.map(String)
        : [];
      if (homepage || startupUrls.length > 0) {
        items.push({
          collector: 'browsers',
          kind: 'browser_settings',
          location: `${browser.name}:${prof.name}:settings`,
          facts: {
            browser: browser.name,
          },
          untrusted: {
            name: `${browser.name} (${prof.name}) homepage/startup`,
            raw_value: [homepage ? `homepage=${homepage}` : '', startupUrls.length ? `startup=${startupUrls.join(',')}` : '']
              .filter(Boolean)
              .join(' | '),
          },
        });
      }
    }
  }

  return items;
}

function readFirefoxProfiles(userDir: string, domainOrMdmJoined: boolean): CollectedItem[] {
  const items: CollectedItem[] = [];
  const ffRoot = path.join(userDir, 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles');
  if (!fs.existsSync(ffRoot)) return items;

  let profiles: fs.Dirent[] = [];
  try {
    profiles = fs.readdirSync(ffRoot, { withFileTypes: true });
  } catch {
    return items;
  }

  for (const prof of profiles) {
    if (!prof.isDirectory()) continue;
    const profPath = path.join(ffRoot, prof.name);
    const extJsonPath = path.join(profPath, 'extensions.json');
    if (fs.existsSync(extJsonPath)) {
      try {
        const parsed = JSON.parse(fs.readFileSync(extJsonPath, 'utf8'));
        for (const addon of Array.isArray(parsed.addons) ? parsed.addons : []) {
          if (addon.type !== 'extension' || addon.location === 'app-builtin' || addon.location === 'app-system-defaults') {
            continue;
          }
          const installSource = addon.location === 'app-profile' ? 'amo_or_profile' : 'sideloaded';
          items.push({
            collector: 'browsers',
            kind: 'browser_extension',
            location: `Firefox:${prof.name}:extension:${addon.id}`,
            facts: {
              browser: 'Firefox',
              extension_id: String(addon.id),
              force_installed: false,
              install_source: installSource,
              domain_or_mdm_joined: domainOrMdmJoined,
            },
            untrusted: {
              name: String(addon.defaultLocale?.name || addon.id),
              version: String(addon.version || ''),
              description: addon.defaultLocale?.description ? String(addon.defaultLocale.description) : null,
            },
            remediation_meta: {
              browser: 'Firefox',
              profile_path: profPath,
              extension_id: String(addon.id),
              extension_page_url: 'about:addons',
            },
          });
        }
      } catch {
        // ignore
      }
    }
  }

  return items;
}

export async function collectWindowsBrowsers(
  timeoutMs: number,
  preflight?: PreflightResult
): Promise<CollectorRunResult> {
  const start = Date.now();
  const domainOrMdmJoined = Boolean(preflight?.domain_joined || preflight?.mdm_enrolled);

  // 1. Collect browser policy keys across HKLM and all loaded user hives via PowerShell
  const policyScript = `
${PS_FILE_FACTS_HELPER}

$policies = @()
$browserSpecs = @(
  @{ browser = 'Chrome'; base = 'SOFTWARE\\Policies\\Google\\Chrome' },
  @{ browser = 'Edge'; base = 'SOFTWARE\\Policies\\Microsoft\\Edge' },
  @{ browser = 'Brave'; base = 'SOFTWARE\\Policies\\BraveSoftware\\Brave' },
  @{ browser = 'Firefox'; base = 'SOFTWARE\\Policies\\Mozilla\\Firefox' }
)
$interestingValues = @(
  'HomepageLocation', 'HomepageIsNewTabPage', 'NewTabPageLocation',
  'RestoreOnStartup', 'DefaultSearchProviderEnabled',
  'DefaultSearchProviderName', 'DefaultSearchProviderSearchURL',
  'ExtensionSettings'
)
$listSubkeys = @('ExtensionInstallForcelist', 'RestoreOnStartupURLs', 'Extensions\\Install')

function Inspect-BrowserPolicy([string]$browser, [string]$hiveLabel, [string]$psPrefix, [string]$baseKey) {
  $fullBase = $psPrefix + '\\' + $baseKey
  if (-not (Test-Path -LiteralPath $fullBase)) { return }
  try {
    $k = Get-Item -LiteralPath $fullBase -ErrorAction Stop
    foreach ($vn in $k.GetValueNames()) {
      if ($interestingValues -contains $vn) {
        $val = [string]$k.GetValue($vn)
        $script:policies += [ordered]@{
          browser = $browser
          hive = $hiveLabel
          key_path = $baseKey
          value_name = $vn
          raw_value = $val
          is_forcelist = ($vn -eq 'ExtensionSettings' -and $val -match 'force_installed')
        }
      }
    }
  } catch {}

  foreach ($sub in $listSubkeys) {
    $subPath = $fullBase + '\\' + $sub
    if (-not (Test-Path -LiteralPath $subPath)) { continue }
    try {
      $sk = Get-Item -LiteralPath $subPath -ErrorAction Stop
      foreach ($vn in $sk.GetValueNames()) {
        if ([string]::IsNullOrEmpty($vn)) { continue }
        $val = [string]$sk.GetValue($vn)
        $script:policies += [ordered]@{
          browser = $browser
          hive = $hiveLabel
          key_path = ($baseKey + '\\' + $sub)
          value_name = $vn
          raw_value = $val
          is_forcelist = ($sub -like '*Forcelist*' -or $sub -like '*Install*')
        }
      }
    } catch {}
  }
}

$userSids = Get-LoadedUserHives
foreach ($b in $browserSpecs) {
  Inspect-BrowserPolicy $b.browser 'HKLM' 'Registry::HKEY_LOCAL_MACHINE' $b.base
  if ($userSids.Count -eq 0) {
    Inspect-BrowserPolicy $b.browser 'HKCU' 'Registry::HKEY_CURRENT_USER' $b.base
  } else {
    foreach ($sid in $userSids) {
      Inspect-BrowserPolicy $b.browser ('HKU\\' + $sid) ('Registry::HKEY_USERS\\' + $sid) $b.base
    }
  }
}

ConvertTo-Json -InputObject @($policies) -Depth 5 -Compress
`;

  const polRes = await runPowerShellJson<RawPolicyEntry[]>(policyScript, {
    timeoutMs: Math.min(timeoutMs, 60_000),
  });
  const warnings: string[] = [];
  if (!polRes.ok) {
    warnings.push(`Browser policy query failed: ${polRes.error ?? 'unknown'}`);
  }

  const items: CollectedItem[] = [];
  const forceInstalledIds = new Set<string>();

  for (const p of ensureArray(polRes.data)) {
    if (p.is_forcelist && p.raw_value) {
      const extId = p.raw_value.split(';')[0].trim().toLowerCase();
      if (extId) forceInstalledIds.add(extId);
    }
    items.push({
      collector: 'browsers',
      kind: 'browser_policy',
      location: `${p.hive}\\${p.key_path}\\${p.value_name}`,
      facts: {
        browser: p.browser,
        policy_key: p.key_path,
        force_installed: Boolean(p.is_forcelist),
        domain_or_mdm_joined: domainOrMdmJoined,
      },
      untrusted: {
        name: `${p.browser} policy ${p.value_name}`,
        raw_value: p.raw_value,
      },
      remediation_meta: {
        browser: p.browser,
        policy_hive: p.hive,
        policy_key: p.key_path,
        policy_value_name: p.value_name,
      },
    });
  }

  // 2. Enumerate every user profile directory for Chrome, Edge, Brave, Firefox
  const sysDrive = process.env.SystemDrive || 'C:';
  const usersRoot = path.join(sysDrive + '\\', 'Users');
  try {
    const userEntries = fs.readdirSync(usersRoot, { withFileTypes: true });
    for (const ue of userEntries) {
      if (!ue.isDirectory()) continue;
      if (['Default', 'Default User', 'All Users', 'Public'].includes(ue.name)) continue;
      const userDir = path.join(usersRoot, ue.name);
      for (const b of CHROMIUM_BROWSERS) {
        items.push(...readChromiumProfiles(userDir, b, forceInstalledIds, domainOrMdmJoined));
      }
      items.push(...readFirefoxProfiles(userDir, domainOrMdmJoined));
    }
  } catch (err) {
    warnings.push(`Could not enumerate user browser profiles: ${err instanceof Error ? err.message : String(err)}`);
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
