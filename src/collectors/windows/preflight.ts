import os from 'node:os';
import { VERSION } from '../../constants.js';
import { ensureArray, runPowerShellJson } from '../../platform/powershell.js';
import type { AvProductInfo, DefenderStatusInfo, PreflightResult } from '../../types.js';

interface RawWinPreflight {
  os_caption?: string;
  os_version?: string;
  os_build?: string;
  free_disk_bytes?: number | null;
  pending_reboot_reasons?: string[];
  domain_joined?: boolean;
  mdm_enrolled?: boolean;
  av_products?: Array<{
    displayName?: string;
    productState?: number;
    pathToSignedProductExe?: string;
    pathToSignedReportingExe?: string;
  }>;
  defender?: {
    available?: boolean;
    realtime_enabled?: boolean | null;
    antispyware_enabled?: boolean | null;
    antivirus_enabled?: boolean | null;
    tamper_protected?: boolean | null;
    pua_protection?: number | null;
    signature_version?: string | null;
    signature_age_days?: number | null;
    engine_version?: string | null;
    service_status?: string | null;
    disabled_by_policy?: boolean;
    am_running_mode?: string | null;
    error?: string | null;
  };
  ransomware_indicators?: string[];
}

function decodeAvState(productState: number): { enabled: boolean; upToDate: boolean } {
  // SecurityCenter2 productState bitmask:
  // Bits 12-15 (0xF000): 0x1000 = enabled / on
  // Bits 4-7 (0x00F0): 0x0000 = up to date
  const enabledByte = (productState >> 12) & 0xf;
  const sigByte = (productState >> 4) & 0xf;
  return {
    enabled: enabledByte === 0x1 || enabledByte === 0x2,
    upToDate: sigByte === 0x0,
  };
}

export async function runWindowsPreflight(
  elevated: boolean,
  collectorsRequested: string[]
): Promise<PreflightResult> {
  const script = `
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
$cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$sysDrive = $env:SystemDrive
if (-not $sysDrive) { $sysDrive = 'C:' }
$disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='" + $sysDrive + "'") -ErrorAction SilentlyContinue

$rebootReasons = @()
if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending') {
  $rebootReasons += 'CBS RebootPending'
}
if (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired') {
  $rebootReasons += 'WindowsUpdate RebootRequired'
}
try {
  $pfro = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager' -Name PendingFileRenameOperations -ErrorAction Stop).PendingFileRenameOperations
  if ($pfro -and $pfro.Count -gt 0) { $rebootReasons += 'PendingFileRenameOperations' }
} catch {}

# MDM enrollment check
$mdm = $false
try {
  $enrollKeys = Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Enrollments' -ErrorAction SilentlyContinue
  foreach ($ek in $enrollKeys) {
    $props = Get-ItemProperty $ek.PSPath -ErrorAction SilentlyContinue
    if ($props -and $props.UPN -and $props.EnrollmentState -eq 1) { $mdm = $true; break }
  }
} catch {}

# SecurityCenter2 AntiVirusProduct
$avList = @()
try {
  $avs = Get-CimInstance -Namespace 'root\\SecurityCenter2' -ClassName 'AntiVirusProduct' -ErrorAction SilentlyContinue
  foreach ($a in @($avs)) {
    if ($a) {
      $avList += [ordered]@{
        displayName = [string]$a.displayName
        productState = [int]$a.productState
        pathToSignedProductExe = [string]$a.pathToSignedProductExe
        pathToSignedReportingExe = [string]$a.pathToSignedReportingExe
      }
    }
  }
} catch {}

# Microsoft Defender state
$def = [ordered]@{
  available = $false
  realtime_enabled = $null
  antispyware_enabled = $null
  antivirus_enabled = $null
  tamper_protected = $null
  pua_protection = $null
  signature_version = $null
  signature_age_days = $null
  engine_version = $null
  service_status = $null
  disabled_by_policy = $false
  am_running_mode = $null
  error = $null
}

try {
  $svc = Get-Service -Name 'WinDefend' -ErrorAction SilentlyContinue
  if ($svc) { $def.service_status = [string]$svc.Status }
} catch {}

try {
  $pol = Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' -ErrorAction SilentlyContinue
  if ($pol -and ($pol.DisableAntiSpyware -eq 1 -or $pol.DisableAntiVirus -eq 1)) {
    $def.disabled_by_policy = $true
  }
  $rtpPol = Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection' -ErrorAction SilentlyContinue
  if ($rtpPol -and $rtpPol.DisableRealtimeMonitoring -eq 1) {
    $def.disabled_by_policy = $true
  }
} catch {}

try {
  $mp = Get-MpComputerStatus -ErrorAction Stop
  if ($mp) {
    $def.available = $true
    $def.realtime_enabled = [bool]$mp.RealTimeProtectionEnabled
    $def.antispyware_enabled = [bool]$mp.AntispywareEnabled
    $def.antivirus_enabled = [bool]$mp.AntivirusEnabled
    $def.tamper_protected = [bool]$mp.IsTamperProtected
    $def.signature_version = [string]$mp.AntivirusSignatureVersion
    $def.signature_age_days = $mp.AntivirusSignatureAge
    $def.engine_version = [string]$mp.AMEngineVersion
    if ($mp.PSObject.Properties['AMRunningMode']) {
      $def.am_running_mode = [string]$mp.AMRunningMode
    }
  }
} catch {
  $def.error = $_.Exception.Message
}

try {
  $pref = Get-MpPreference -ErrorAction SilentlyContinue
  if ($pref -and $pref.PSObject.Properties['PUAProtection']) {
    $def.pua_protection = $pref.PUAProtection
  }
} catch {}

# Lightweight ransomware indicator check (ransom note filenames on Desktop/Documents/SystemDrive root)
$ransomIndicators = @()
$notePatterns = @(
  '*README_DECRYPT*', '*HOW_TO_DECRYPT*', '*DECRYPT_INSTRUCTIONS*', '*RESTORE_FILES*',
  '*HOW_TO_RESTORE*', '*RECOVERY_INSTRUCTIONS*', '*YOUR_FILES_ARE_ENCRYPTED*', '*FILES_ENCRYPTED*'
)
$checkDirs = @($env:SystemDrive + '\\')
try {
  $userDirs = Get-ChildItem (Join-Path $env:SystemDrive 'Users') -Directory -ErrorAction SilentlyContinue
  foreach ($ud in $userDirs) {
    if ($ud.Name -in @('Default','Default User','All Users','Public')) { continue }
    $d1 = Join-Path $ud.FullName 'Desktop'
    $d2 = Join-Path $ud.FullName 'Documents'
    if (Test-Path $d1) { $checkDirs += $d1 }
    if (Test-Path $d2) { $checkDirs += $d2 }
  }
} catch {}

foreach ($cd in $checkDirs) {
  foreach ($pat in $notePatterns) {
    try {
      $hits = Get-ChildItem -LiteralPath $cd -Filter $pat -File -ErrorAction SilentlyContinue | Select-Object -First 3
      foreach ($h in $hits) {
        $ransomIndicators += ('Ransom note candidate: ' + $h.FullName)
      }
    } catch {}
  }
}

$out = [ordered]@{
  os_caption = if ($os) { [string]$os.Caption } else { 'Windows' }
  os_version = if ($os) { [string]$os.Version } else { '' }
  os_build = if ($os) { [string]$os.BuildNumber } else { '' }
  free_disk_bytes = if ($disk) { [int64]$disk.FreeSpace } else { $null }
  pending_reboot_reasons = @($rebootReasons)
  domain_joined = if ($cs) { [bool]$cs.PartOfDomain } else { $false }
  mdm_enrolled = $mdm
  av_products = @($avList)
  defender = $def
  ransomware_indicators = @($ransomIndicators)
}
$out | ConvertTo-Json -Depth 6 -Compress
`;

  const res = await runPowerShellJson<RawWinPreflight>(script, { timeoutMs: 30_000 });
  const raw = res.data ?? {};

  const avProducts: AvProductInfo[] = ensureArray(raw.av_products).map((a) => {
    const st = decodeAvState(a.productState ?? 0);
    return {
      display_name: a.displayName ?? 'Unknown AV',
      product_state: a.productState ?? 0,
      enabled: st.enabled,
      up_to_date: st.upToDate,
      path_to_signed_product_exe: a.pathToSignedProductExe || null,
      path_to_signed_reporting_exe: a.pathToSignedReportingExe || null,
    };
  });

  const otherActiveAv = avProducts.some(
    (a) => a.enabled && !/windows defender|microsoft defender/i.test(a.display_name)
  );

  const rawDef = raw.defender ?? {};
  let mode: DefenderStatusInfo['mode'] = 'unavailable';
  if (rawDef.available) {
    const runningMode = (rawDef.am_running_mode ?? '').toLowerCase();
    if (runningMode.includes('passive')) {
      mode = 'passive';
    } else if (otherActiveAv && !rawDef.realtime_enabled) {
      mode = 'displaced';
    } else if (rawDef.realtime_enabled) {
      mode = 'active';
    } else {
      mode = 'disabled';
    }
  } else if (otherActiveAv) {
    mode = 'displaced';
  } else if (rawDef.disabled_by_policy || rawDef.service_status?.toLowerCase() === 'stopped') {
    mode = 'disabled';
  }

  const defender: DefenderStatusInfo = {
    available: Boolean(rawDef.available),
    active: mode === 'active',
    mode,
    realtime_enabled: rawDef.realtime_enabled ?? null,
    antispyware_enabled: rawDef.antispyware_enabled ?? null,
    antivirus_enabled: rawDef.antivirus_enabled ?? null,
    tamper_protected: rawDef.tamper_protected ?? null,
    pua_protection: rawDef.pua_protection ?? null,
    signature_version: rawDef.signature_version ?? null,
    signature_age_days: rawDef.signature_age_days ?? null,
    engine_version: rawDef.engine_version ?? null,
    service_status: rawDef.service_status ?? null,
    disabled_by_policy: Boolean(rawDef.disabled_by_policy),
    error: rawDef.error ?? null,
  };

  const pendingReasons = ensureArray(raw.pending_reboot_reasons).filter(Boolean);

  return {
    timestamp: new Date().toISOString(),
    tool_version: VERSION,
    platform: 'windows',
    hostname: os.hostname(),
    os_version: raw.os_caption || `Windows ${os.release()}`,
    os_build: raw.os_build || raw.os_version || os.release(),
    arch: process.arch,
    elevated,
    pending_reboot: pendingReasons.length > 0,
    pending_reboot_reasons: pendingReasons,
    free_disk_bytes: typeof raw.free_disk_bytes === 'number' ? raw.free_disk_bytes : null,
    domain_joined: Boolean(raw.domain_joined),
    mdm_enrolled: Boolean(raw.mdm_enrolled),
    av_products: avProducts,
    defender,
    collectors_requested: collectorsRequested,
    collectors_skipped: [],
    collectors_partial: [],
    ransomware_indicators: ensureArray(raw.ransomware_indicators).filter(Boolean),
  };
}
