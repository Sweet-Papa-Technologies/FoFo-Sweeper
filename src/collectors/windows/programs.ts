import { loadProgramsCatalog } from '../../data-loader.js';
import { ensureArray, runPowerShellJson } from '../../platform/powershell.js';
import type { CollectedItem, CollectorRunResult } from '../../types.js';
import { PS_FILE_FACTS_HELPER } from './ps-common.js';

interface RawProgram {
  source: 'uninstall' | 'appx';
  location: string;
  display_name: string;
  publisher?: string | null;
  version?: string | null;
  install_date?: string | null;
  install_location?: string | null;
  uninstall_string?: string | null;
}

function normalizeInstallDate(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const s = raw.trim();
  // Registry InstallDate is typically YYYYMMDD
  if (/^\d{8}$/.test(s)) {
    return `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T00:00:00Z`;
  }
  const ts = Date.parse(s);
  return Number.isNaN(ts) ? null : new Date(ts).toISOString();
}

export async function collectWindowsPrograms(timeoutMs: number): Promise<CollectorRunResult> {
  const start = Date.now();
  const script = `
${PS_FILE_FACTS_HELPER}

$items = @()
$seen = @{}

function Read-UninstallKey([string]$hiveLabel, [string]$psPath) {
  if (-not (Test-Path -LiteralPath $psPath)) { return }
  foreach ($k in (Get-ChildItem -LiteralPath $psPath -ErrorAction SilentlyContinue)) {
    try {
      $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop
      $name = [string]$p.DisplayName
      if ([string]::IsNullOrWhiteSpace($name)) { continue }
      if ($p.SystemComponent -eq 1) { continue }
      $dedupe = ($name.ToLowerInvariant() + '|' + [string]$p.DisplayVersion)
      if ($script:seen.ContainsKey($dedupe)) { continue }
      $script:seen[$dedupe] = $true
      $script:items += [ordered]@{
        source = 'uninstall'
        location = ($hiveLabel + '\\' + $k.PSChildName)
        display_name = $name
        publisher = [string]$p.Publisher
        version = [string]$p.DisplayVersion
        install_date = [string]$p.InstallDate
        install_location = [string]$p.InstallLocation
        uninstall_string = if ($p.UninstallString) { [string]$p.UninstallString } else { [string]$p.QuietUninstallString }
      }
    } catch {}
  }
}

Read-UninstallKey 'HKLM\\Uninstall' 'Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
Read-UninstallKey 'HKLM\\WOW6432Node\\Uninstall' 'Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall'

$userSids = Get-LoadedUserHives
if ($userSids.Count -eq 0) {
  Read-UninstallKey 'HKCU\\Uninstall' 'Registry::HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
} else {
  foreach ($sid in $userSids) {
    Read-UninstallKey ('HKU\\' + $sid + '\\Uninstall') ('Registry::HKEY_USERS\\' + $sid + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall')
  }
}

# Appx packages (non-framework, non-Microsoft built-in noise)
try {
  $appx = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue
  if (-not $appx) { $appx = Get-AppxPackage -ErrorAction SilentlyContinue }
  foreach ($a in @($appx)) {
    if (-not $a -or $a.IsFramework -or $a.SignatureKind -eq 'System') { continue }
    $items += [ordered]@{
      source = 'appx'
      location = ('Appx:' + [string]$a.Name)
      display_name = [string]$a.Name
      publisher = [string]$a.Publisher
      version = [string]$a.Version
      install_date = $null
      install_location = [string]$a.InstallLocation
      uninstall_string = $null
    }
  }
} catch {}

ConvertTo-Json -InputObject @($items) -Depth 5 -Compress
`;

  const res = await runPowerShellJson<RawProgram[]>(script, { timeoutMs });
  const durationMs = Date.now() - start;
  if (!res.ok) {
    return {
      collector: 'programs',
      status: 'error',
      duration_ms: durationMs,
      item_count: 0,
      items: [],
      warnings: [],
      error: res.error || res.stderr || 'programs collector failed',
    };
  }

  const catalog = loadProgramsCatalog();
  const items: CollectedItem[] = ensureArray(res.data).map((r) => {
    const haystack = `${r.display_name} ${r.publisher ?? ''} ${r.install_location ?? ''}`.toLowerCase();
    let programTag: 'remote_access_tool' | 'bundleware' | null = null;
    let programTagName: string | null = null;

    for (const rat of catalog.remote_access_tools) {
      if (rat.patterns.some((pat) => haystack.includes(pat))) {
        programTag = 'remote_access_tool';
        programTagName = rat.name;
        break;
      }
    }
    if (!programTag) {
      for (const pup of catalog.bundleware) {
        if (pup.patterns.some((pat) => haystack.includes(pat))) {
          programTag = 'bundleware';
          programTagName = pup.name;
          break;
        }
      }
    }

    return {
      collector: 'programs',
      kind: 'installed_program',
      location: r.location,
      facts: {
        program_tag: programTag,
        program_tag_name: programTagName,
        install_date: normalizeInstallDate(r.install_date),
      },
      untrusted: {
        name: r.display_name,
        publisher: r.publisher ?? null,
        version: r.version ?? null,
        raw_value: r.uninstall_string ?? null,
      },
      remediation_meta: r.uninstall_string
        ? { uninstall_string: r.uninstall_string }
        : undefined,
    };
  });

  return {
    collector: 'programs',
    status: 'ok',
    duration_ms: durationMs,
    item_count: items.length,
    items,
    warnings: [],
  };
}
