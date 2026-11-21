import { ensureArray, runPowerShell, runPowerShellJson } from '../platform/powershell.js';
import type { DefenderDetection, DefenderScanResult } from '../types.js';

interface RawMpDetection {
  threat_id: string;
  threat_name: string;
  severity?: string | null;
  resources?: string[];
  action_taken?: string | null;
  detection_time?: string | null;
}

interface RawMpStatus {
  available: boolean;
  realtime_enabled?: boolean | null;
  antivirus_enabled?: boolean | null;
  antispyware_enabled?: boolean | null;
  tamper_protected?: boolean | null;
  signature_version?: string | null;
  signature_age_days?: number | null;
  engine_version?: string | null;
  quick_scan_end?: string | null;
  full_scan_end?: string | null;
  am_running_mode?: string | null;
  pua_protection?: number | null;
  error?: string | null;
}

export async function getDefenderStatus(): Promise<RawMpStatus> {
  const script = `
$out = [ordered]@{ available = $false; error = $null }
try {
  $st = Get-MpComputerStatus -ErrorAction Stop
  $out.available = $true
  $out.realtime_enabled = [bool]$st.RealTimeProtectionEnabled
  $out.antivirus_enabled = [bool]$st.AntivirusEnabled
  $out.antispyware_enabled = [bool]$st.AntispywareEnabled
  $out.tamper_protected = [bool]$st.IsTamperProtected
  $out.signature_version = [string]$st.AntivirusSignatureVersion
  $out.signature_age_days = $st.AntivirusSignatureAge
  $out.engine_version = [string]$st.AMEngineVersion
  $out.quick_scan_end = if ($st.QuickScanEndTime) { ([DateTime]$st.QuickScanEndTime).ToUniversalTime().ToString('o') } else { $null }
  $out.full_scan_end = if ($st.FullScanEndTime) { ([DateTime]$st.FullScanEndTime).ToUniversalTime().ToString('o') } else { $null }
  if ($st.PSObject.Properties['AMRunningMode']) { $out.am_running_mode = [string]$st.AMRunningMode }
  try {
    $pref = Get-MpPreference -ErrorAction SilentlyContinue
    if ($pref -and $pref.PSObject.Properties['PUAProtection']) { $out.pua_protection = $pref.PUAProtection }
  } catch {}
} catch {
  $out.error = $_.Exception.Message
}
$out | ConvertTo-Json -Depth 4 -Compress
`;
  const res = await runPowerShellJson<RawMpStatus>(script, { timeoutMs: 20_000 });
  return res.data ?? { available: false, error: res.error || 'Get-MpComputerStatus failed' };
}

export async function updateDefenderSignatures(): Promise<{ ok: boolean; signatureVersion?: string | null; error?: string }> {
  const script = `
$ErrorActionPreference = 'Stop'
$res = [ordered]@{ ok = $false; signature_version = $null; error = $null }
try {
  Update-MpSignature -ErrorAction Stop
  $st = Get-MpComputerStatus -ErrorAction SilentlyContinue
  $res.ok = $true
  if ($st) { $res.signature_version = [string]$st.AntivirusSignatureVersion }
} catch {
  $res.error = $_.Exception.Message
}
$res | ConvertTo-Json -Depth 4 -Compress
`;
  const res = await runPowerShellJson<{ ok: boolean; signature_version?: string | null; error?: string }>(script, {
    timeoutMs: 120_000,
  });
  return {
    ok: Boolean(res.data?.ok),
    signatureVersion: res.data?.signature_version ?? null,
    error: res.data?.error ?? res.error,
  };
}

export async function readDefenderDetections(sinceHours: number = 24): Promise<DefenderDetection[]> {
  const script = `
$since = (Get-Date).AddHours(-([int]$FCSWEEP_PARAMS.since_hours))
$threatMap = @{}
try {
  foreach ($t in @(Get-MpThreat -ErrorAction SilentlyContinue)) {
    if ($t) {
      $threatMap[[string]$t.ThreatID] = [ordered]@{
        name = [string]$t.ThreatName
        severity = [string]$t.SeverityID
        resources = @($t.Resources | ForEach-Object { [string]$_ })
      }
    }
  }
} catch {}

$items = @()
try {
  foreach ($d in @(Get-MpThreatDetection -ErrorAction SilentlyContinue)) {
    if (-not $d) { continue }
    $dt = $null
    if ($d.InitialDetectionTime) { $dt = [DateTime]$d.InitialDetectionTime }
    if ($dt -and $dt -lt $since) { continue }
    $tid = [string]$d.ThreatID
    $tinfo = $threatMap[$tid]
    $resList = @()
    if ($d.Resources) { $resList = @($d.Resources | ForEach-Object { [string]$_ }) }
    elseif ($tinfo) { $resList = @($tinfo.resources) }
    $items += [ordered]@{
      threat_id = $tid
      threat_name = if ($tinfo -and $tinfo.name) { $tinfo.name } else { ('ThreatID:' + $tid) }
      severity = if ($tinfo) { $tinfo.severity } else { $null }
      resources = $resList
      action_taken = [string]$d.CleaningActionID
      detection_time = if ($dt) { $dt.ToUniversalTime().ToString('o') } else { $null }
    }
  }
} catch {}

ConvertTo-Json -InputObject @($items) -Depth 5 -Compress
`;

  const res = await runPowerShellJson<RawMpDetection[]>(script, {
    timeoutMs: 30_000,
    params: { since_hours: sinceHours },
  });
  return ensureArray(res.data).map((d) => ({
    threat_id: d.threat_id,
    threat_name: d.threat_name,
    severity: d.severity ?? null,
    resources: ensureArray(d.resources),
    action_taken: d.action_taken ?? null,
    detection_time: d.detection_time ?? null,
    source: 'defender',
  }));
}

export async function runWindowsDefenderScan(
  scanType: 'quick' | 'full',
  options: { updateFirst?: boolean; customPath?: string } = {}
): Promise<DefenderScanResult> {
  const timestamp = new Date().toISOString();
  let signatureUpdated = false;
  let signatureVersion: string | null = null;

  if (options.updateFirst !== false) {
    const upd = await updateDefenderSignatures();
    signatureUpdated = upd.ok;
    signatureVersion = upd.signatureVersion ?? null;
  }

  const mpScanType = scanType === 'full' ? 'FullScan' : 'QuickScan';
  const timeoutMs = scanType === 'full' ? 60 * 60 * 1000 : 15 * 60 * 1000;

  const scanScript = `
$ErrorActionPreference = 'Stop'
$res = [ordered]@{ ok = $false; signature_version = $null; error = $null }
try {
  if ($FCSWEEP_PARAMS.custom_path) {
    Start-MpScan -ScanType CustomScan -ScanPath $FCSWEEP_PARAMS.custom_path -ErrorAction Stop
  } else {
    Start-MpScan -ScanType $FCSWEEP_PARAMS.scan_type -ErrorAction Stop
  }
  $st = Get-MpComputerStatus -ErrorAction SilentlyContinue
  $res.ok = $true
  if ($st) { $res.signature_version = [string]$st.AntivirusSignatureVersion }
} catch {
  $res.error = $_.Exception.Message
}
$res | ConvertTo-Json -Depth 4 -Compress
`;

  const scanRes = await runPowerShellJson<{ ok: boolean; signature_version?: string | null; error?: string }>(
    scanScript,
    {
      timeoutMs,
      params: {
        scan_type: mpScanType,
        custom_path: options.customPath ?? null,
      },
    }
  );

  if (scanRes.data?.signature_version) {
    signatureVersion = scanRes.data.signature_version;
  }

  const detections = await readDefenderDetections(24);
  const ok = Boolean(scanRes.data?.ok);

  return {
    timestamp,
    engine: 'defender',
    scan_type: scanType,
    signature_updated: signatureUpdated,
    signature_version: signatureVersion,
    status: ok ? 'ok' : 'error',
    detections,
    error: ok ? null : scanRes.data?.error ?? scanRes.error ?? 'Start-MpScan failed',
  };
}

export async function runWindowsDefenderOfflineScan(): Promise<{ ok: boolean; error?: string }> {
  const res = await runPowerShell('Start-MpWDOScan -ErrorAction Stop', { timeoutMs: 60_000 });
  if (res.exitCode === 0) {
    return { ok: true };
  }
  return { ok: false, error: res.stderr || res.error || 'Start-MpWDOScan failed' };
}
