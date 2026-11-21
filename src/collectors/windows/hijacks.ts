import { ensureArray, runPowerShellJson } from '../../platform/powershell.js';
import type { CollectedItem, CollectorRunResult, FindingFacts } from '../../types.js';
import { mapPsFileFacts, PS_FILE_FACTS_HELPER, type RawPsFileFacts } from './ps-common.js';

interface RawHijack {
  hijack_type: NonNullable<FindingFacts['hijack_type']>;
  hive: string;
  key_path: string;
  value_name: string;
  raw_value: string;
  default_value?: string | null;
  location: string;
  name?: string | null;
  file_facts?: RawPsFileFacts | null;
}

export async function collectWindowsHijacks(timeoutMs: number): Promise<CollectorRunResult> {
  const start = Date.now();
  const script = `
${PS_FILE_FACTS_HELPER}

$items = @()

# 1. Image File Execution Options (IFEO) Debugger values
foreach ($sub in @(
  'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options',
  'SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options'
)) {
  $psRoot = 'Registry::HKEY_LOCAL_MACHINE\\' + $sub
  if (-not (Test-Path -LiteralPath $psRoot)) { continue }
  foreach ($k in (Get-ChildItem -LiteralPath $psRoot -ErrorAction SilentlyContinue)) {
    try {
      $dbg = (Get-ItemProperty -LiteralPath $k.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
      if (-not [string]::IsNullOrWhiteSpace($dbg)) {
        $resolved = Resolve-TargetPath $dbg
        $items += [ordered]@{
          hijack_type = 'ifeo_debugger'
          hive = 'HKLM'
          key_path = ($sub + '\\' + $k.PSChildName)
          value_name = 'Debugger'
          raw_value = [string]$dbg
          default_value = $null
          location = ('HKLM\\' + $sub + '\\' + $k.PSChildName + '\\Debugger')
          name = $k.PSChildName
          file_facts = (Get-FileFacts $resolved)
        }
      }
    } catch {}
  }
}

# 2. Winlogon Shell & Userinit (HKLM + loaded users)
$winlogonSub = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'
try {
  $wl = Get-ItemProperty -LiteralPath ('Registry::HKEY_LOCAL_MACHINE\\' + $winlogonSub) -ErrorAction SilentlyContinue
  if ($wl) {
    $shellVal = [string]$wl.Shell
    if ($shellVal -and ($shellVal.Trim() -ine 'explorer.exe')) {
      $resolved = Resolve-TargetPath $shellVal
      $items += [ordered]@{
        hijack_type = 'winlogon_shell'
        hive = 'HKLM'
        key_path = $winlogonSub
        value_name = 'Shell'
        raw_value = $shellVal
        default_value = 'explorer.exe'
        location = ('HKLM\\' + $winlogonSub + '\\Shell')
        name = 'Winlogon Shell'
        file_facts = (Get-FileFacts $resolved)
      }
    }
    $uiVal = [string]$wl.Userinit
    $defaultUi = (Join-Path $env:SystemRoot 'system32\\userinit.exe') + ','
    if ($uiVal -and ($uiVal.Trim().TrimEnd(',') -ine (Join-Path $env:SystemRoot 'system32\\userinit.exe'))) {
      $resolved = Resolve-TargetPath ($uiVal -split ',')[0]
      $items += [ordered]@{
        hijack_type = 'winlogon_userinit'
        hive = 'HKLM'
        key_path = $winlogonSub
        value_name = 'Userinit'
        raw_value = $uiVal
        default_value = $defaultUi
        location = ('HKLM\\' + $winlogonSub + '\\Userinit')
        name = 'Winlogon Userinit'
        file_facts = (Get-FileFacts $resolved)
      }
    }
  }
} catch {}

foreach ($sid in (Get-LoadedUserHives)) {
  $uWlPath = 'Registry::HKEY_USERS\\' + $sid + '\\' + $winlogonSub
  if (Test-Path -LiteralPath $uWlPath) {
    try {
      $uWl = Get-ItemProperty -LiteralPath $uWlPath -ErrorAction SilentlyContinue
      if ($uWl -and -not [string]::IsNullOrWhiteSpace($uWl.Shell)) {
        $resolved = Resolve-TargetPath $uWl.Shell
        $items += [ordered]@{
          hijack_type = 'winlogon_shell'
          hive = ('HKU\\' + $sid)
          key_path = $winlogonSub
          value_name = 'Shell'
          raw_value = [string]$uWl.Shell
          default_value = $null
          location = ('HKU\\' + $sid + '\\' + $winlogonSub + '\\Shell')
          name = 'Per-user Winlogon Shell'
          file_facts = (Get-FileFacts $resolved)
        }
      }
    } catch {}
  }
}

# 3. AppInit_DLLs
foreach ($sub in @(
  'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows',
  'SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows'
)) {
  $p = 'Registry::HKEY_LOCAL_MACHINE\\' + $sub
  try {
    $props = Get-ItemProperty -LiteralPath $p -ErrorAction SilentlyContinue
    if ($props -and -not [string]::IsNullOrWhiteSpace($props.AppInit_DLLs)) {
      $dlls = [string]$props.AppInit_DLLs
      $resolved = Resolve-TargetPath ($dlls -split '[,\\s]+')[0]
      $items += [ordered]@{
        hijack_type = 'appinit_dlls'
        hive = 'HKLM'
        key_path = $sub
        value_name = 'AppInit_DLLs'
        raw_value = $dlls
        default_value = ''
        location = ('HKLM\\' + $sub + '\\AppInit_DLLs')
        name = 'AppInit_DLLs'
        file_facts = (Get-FileFacts $resolved)
      }
    }
  } catch {}
}

# 4. Session Manager BootExecute
$smSub = 'SYSTEM\\CurrentControlSet\\Control\\Session Manager'
try {
  $be = (Get-ItemProperty -LiteralPath ('Registry::HKEY_LOCAL_MACHINE\\' + $smSub) -Name BootExecute -ErrorAction SilentlyContinue).BootExecute
  $beArr = @($be | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  $nonDefault = @($beArr | Where-Object { $_.Trim() -ine 'autocheck autochk *' })
  if ($nonDefault.Count -gt 0) {
    $joined = ($beArr -join '; ')
    $items += [ordered]@{
      hijack_type = 'boot_execute'
      hive = 'HKLM'
      key_path = $smSub
      value_name = 'BootExecute'
      raw_value = $joined
      default_value = 'autocheck autochk *'
      location = ('HKLM\\' + $smSub + '\\BootExecute')
      name = 'Session Manager BootExecute'
      file_facts = $null
    }
  }
} catch {}

# 5. Active Setup (only non-Microsoft / user-writable or suspicious StubPath)
foreach ($sub in @(
  'SOFTWARE\\Microsoft\\Active Setup\\Installed Components',
  'SOFTWARE\\WOW6432Node\\Microsoft\\Active Setup\\Installed Components'
)) {
  $root = 'Registry::HKEY_LOCAL_MACHINE\\' + $sub
  if (-not (Test-Path -LiteralPath $root)) { continue }
  foreach ($k in (Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
    try {
      $stub = (Get-ItemProperty -LiteralPath $k.PSPath -Name StubPath -ErrorAction SilentlyContinue).StubPath
      if (-not [string]::IsNullOrWhiteSpace($stub)) {
        $resolved = Resolve-TargetPath $stub
        $ff = Get-FileFacts $resolved
        # Only collect Active Setup entries pointing outside Microsoft-signed Windows system binaries
        $isMsWin = ($ff -and $ff.sig_status -eq 'Valid' -and $ff.signer -match 'Microsoft' -and $ff.target_path -match '^[A-Za-z]:\\\\Windows\\\\')
        if (-not $isMsWin) {
          $items += [ordered]@{
            hijack_type = 'active_setup'
            hive = 'HKLM'
            key_path = ($sub + '\\' + $k.PSChildName)
            value_name = 'StubPath'
            raw_value = [string]$stub
            default_value = $null
            location = ('HKLM\\' + $sub + '\\' + $k.PSChildName + '\\StubPath')
            name = $k.PSChildName
            file_facts = $ff
          }
        }
      }
    } catch {}
  }
}

# 6. Browser Helper Objects (BHO)
foreach ($sub in @(
  'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects',
  'SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects'
)) {
  $root = 'Registry::HKEY_LOCAL_MACHINE\\' + $sub
  if (-not (Test-Path -LiteralPath $root)) { continue }
  foreach ($k in (Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
    $clsid = $k.PSChildName
    $dllPath = $null
    try {
      $inproc = Get-ItemProperty -LiteralPath ('Registry::HKEY_CLASSES_ROOT\\CLSID\\' + $clsid + '\\InprocServer32') -ErrorAction SilentlyContinue
      if ($inproc) { $dllPath = [string]$inproc.'(default)' }
    } catch {}
    $resolved = Resolve-TargetPath $dllPath
    $items += [ordered]@{
      hijack_type = 'bho'
      hive = 'HKLM'
      key_path = ($sub + '\\' + $clsid)
      value_name = ''
      raw_value = if ($dllPath) { $dllPath } else { $clsid }
      default_value = $null
      location = ('HKLM\\' + $sub + '\\' + $clsid)
      name = $clsid
      file_facts = (Get-FileFacts $resolved)
    }
  }
}

ConvertTo-Json -InputObject @($items) -Depth 6 -Compress
`;

  const res = await runPowerShellJson<RawHijack[]>(script, { timeoutMs });
  const durationMs = Date.now() - start;
  if (!res.ok) {
    return {
      collector: 'hijacks',
      status: 'error',
      duration_ms: durationMs,
      item_count: 0,
      items: [],
      warnings: [],
      error: res.error || res.stderr || 'hijacks collector failed',
    };
  }

  const items: CollectedItem[] = ensureArray(res.data).map((r) => {
    const fileFacts = mapPsFileFacts(r.file_facts);
    return {
      collector: 'hijacks',
      kind: 'hijack',
      location: r.location,
      facts: {
        ...fileFacts,
        hijack_type: r.hijack_type,
      },
      untrusted: {
        name: r.name ?? r.hijack_type,
        command_line: r.raw_value ?? null,
      },
      command_inspect: r.raw_value ?? null,
      remediation_meta: {
        registry_hive: r.hive,
        registry_key: r.key_path,
        registry_value_name: r.value_name,
        registry_default_value: r.default_value ?? undefined,
        target_file_path: fileFacts.target_path ?? undefined,
      },
    };
  });

  return {
    collector: 'hijacks',
    status: 'ok',
    duration_ms: durationMs,
    item_count: items.length,
    items,
    warnings: [],
  };
}
