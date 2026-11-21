import { ensureArray, runPowerShellJson } from '../../platform/powershell.js';
import type { CollectedItem, CollectorRunResult } from '../../types.js';
import { mapPsFileFacts, PS_FILE_FACTS_HELPER, type RawPsFileFacts } from './ps-common.js';

interface RawAutorun {
  kind: 'autorun_registry' | 'autorun_startup';
  hive?: string;
  key_path?: string;
  value_name?: string;
  raw_value?: string;
  startup_file_path?: string;
  location: string;
  file_facts?: RawPsFileFacts | null;
}

export async function collectWindowsAutoruns(timeoutMs: number): Promise<CollectorRunResult> {
  const start = Date.now();
  const script = `
${PS_FILE_FACTS_HELPER}

$items = @()
$runSubkeys = @(
  'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
  'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices',
  'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce',
  'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run'
)
$wowSubkeys = @(
  'SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
  'SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServices',
  'SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run'
)

function Read-RunKey([string]$hiveLabel, [string]$psPrefix, [string]$subkey) {
  $fullPsPath = $psPrefix + '\\' + $subkey
  if (-not (Test-Path -LiteralPath $fullPsPath)) { return }
  try {
    $k = Get-Item -LiteralPath $fullPsPath -ErrorAction Stop
    foreach ($valName in $k.GetValueNames()) {
      if ([string]::IsNullOrEmpty($valName)) { continue }
      $val = [string]$k.GetValue($valName, '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
      $expandedVal = [string]$k.GetValue($valName)
      $resolved = Resolve-TargetPath $expandedVal
      $ff = Get-FileFacts $resolved
      $script:items += [ordered]@{
        kind = 'autorun_registry'
        hive = $hiveLabel
        key_path = $subkey
        value_name = $valName
        raw_value = $val
        location = ($hiveLabel + '\\' + $subkey + '\\' + $valName)
        file_facts = $ff
      }
    }
  } catch {}
}

foreach ($sk in $runSubkeys) { Read-RunKey 'HKLM' 'Registry::HKEY_LOCAL_MACHINE' $sk }
foreach ($sk in $wowSubkeys) { Read-RunKey 'HKLM' 'Registry::HKEY_LOCAL_MACHINE' $sk }

$userSids = Get-LoadedUserHives
if ($userSids.Count -eq 0) {
  foreach ($sk in $runSubkeys) { Read-RunKey 'HKCU' 'Registry::HKEY_CURRENT_USER' $sk }
} else {
  foreach ($sid in $userSids) {
    foreach ($sk in $runSubkeys) {
      Read-RunKey ('HKU\\' + $sid) ('Registry::HKEY_USERS\\' + $sid) $sk
    }
  }
}

# Startup folders (All Users + every user profile)
$startupDirs = @()
if ($env:ProgramData) {
  $startupDirs += (Join-Path $env:ProgramData 'Microsoft\\Windows\\Start Menu\\Programs\\StartUp')
}
try {
  $sysDrive = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }
  $usersRoot = Join-Path $sysDrive 'Users'
  foreach ($ud in (Get-ChildItem -LiteralPath $usersRoot -Directory -ErrorAction SilentlyContinue)) {
    if ($ud.Name -in @('Default','Default User','All Users','Public')) { continue }
    $startupDirs += (Join-Path $ud.FullName 'AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup')
  }
} catch {}

$shellCom = $null
try { $shellCom = New-Object -ComObject WScript.Shell } catch {}

foreach ($dir in ($startupDirs | Select-Object -Unique)) {
  if (-not (Test-Path -LiteralPath $dir)) { continue }
  try {
    foreach ($f in (Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue)) {
      if ($f.Name -ieq 'desktop.ini') { continue }
      $cmd = $f.FullName
      $target = $f.FullName
      if ($f.Extension -ieq '.lnk' -and $shellCom) {
        try {
          $lnk = $shellCom.CreateShortcut($f.FullName)
          if ($lnk.TargetPath) {
            $target = Resolve-TargetPath $lnk.TargetPath
            $cmd = ($lnk.TargetPath + ' ' + $lnk.Arguments).Trim()
          }
        } catch {}
      }
      $ff = Get-FileFacts $target
      $items += [ordered]@{
        kind = 'autorun_startup'
        startup_file_path = $f.FullName
        raw_value = $cmd
        location = $f.FullName
        file_facts = $ff
      }
    }
  } catch {}
}

ConvertTo-Json -InputObject @($items) -Depth 6 -Compress
`;

  const res = await runPowerShellJson<RawAutorun[]>(script, { timeoutMs });
  const durationMs = Date.now() - start;
  if (!res.ok) {
    return {
      collector: 'autoruns',
      status: 'error',
      duration_ms: durationMs,
      item_count: 0,
      items: [],
      warnings: [],
      error: res.error || res.stderr || 'autoruns collector failed',
    };
  }

  const rawItems = ensureArray(res.data);
  const items: CollectedItem[] = rawItems.map((r) => {
    const fileFacts = mapPsFileFacts(r.file_facts);
    return {
      collector: 'autoruns',
      kind: r.kind,
      location: r.location,
      facts: {
        ...fileFacts,
      },
      untrusted: {
        name: r.value_name ?? null,
        command_line: r.raw_value ?? null,
      },
      command_inspect: r.raw_value ?? null,
      remediation_meta:
        r.kind === 'autorun_registry'
          ? {
              registry_hive: r.hive,
              registry_key: r.key_path,
              registry_value_name: r.value_name,
              target_file_path: fileFacts.target_path ?? undefined,
            }
          : {
              startup_file_path: r.startup_file_path,
              target_file_path: fileFacts.target_path ?? undefined,
            },
    };
  });

  return {
    collector: 'autoruns',
    status: 'ok',
    duration_ms: durationMs,
    item_count: items.length,
    items,
    warnings: [],
  };
}
