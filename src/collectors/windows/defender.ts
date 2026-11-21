import { ensureArray, runPowerShellJson } from '../../platform/powershell.js';
import type { CollectedItem, CollectorRunResult, PreflightResult } from '../../types.js';

interface RawDefenderConfig {
  exclusion_paths?: string[];
  exclusion_processes?: string[];
  exclusion_extensions?: string[];
  exclusion_ips?: string[];
  policy_disables?: Array<{
    key_path: string;
    value_name: string;
    value: unknown;
  }>;
  realtime_enabled?: boolean | null;
  tamper_protected?: boolean | null;
  pua_protection?: number | null;
  access_denied?: boolean;
}

export async function collectWindowsDefender(
  timeoutMs: number,
  preflight?: PreflightResult
): Promise<CollectorRunResult & { exclusions: string[] }> {
  const start = Date.now();
  const script = `
$res = [ordered]@{
  exclusion_paths = @()
  exclusion_processes = @()
  exclusion_extensions = @()
  exclusion_ips = @()
  policy_disables = @()
  realtime_enabled = $null
  tamper_protected = $null
  pua_protection = $null
  access_denied = $false
}

try {
  $pref = Get-MpPreference -ErrorAction Stop
  if ($pref) {
    if ($pref.ExclusionPath) { $res.exclusion_paths = @($pref.ExclusionPath | ForEach-Object { [string]$_ }) }
    if ($pref.ExclusionProcess) { $res.exclusion_processes = @($pref.ExclusionProcess | ForEach-Object { [string]$_ }) }
    if ($pref.ExclusionExtension) { $res.exclusion_extensions = @($pref.ExclusionExtension | ForEach-Object { [string]$_ }) }
    if ($pref.ExclusionIpAddress) { $res.exclusion_ips = @($pref.ExclusionIpAddress | ForEach-Object { [string]$_ }) }
    if ($pref.PSObject.Properties['PUAProtection']) { $res.pua_protection = $pref.PUAProtection }
  }
} catch {
  if ($_.Exception.Message -match 'Access|denied|permission|0x80041003') {
    $res.access_denied = $true
  }
}

try {
  $st = Get-MpComputerStatus -ErrorAction SilentlyContinue
  if ($st) {
    $res.realtime_enabled = [bool]$st.RealTimeProtectionEnabled
    $res.tamper_protected = [bool]$st.IsTamperProtected
  }
} catch {}

# Check Defender policy keys that disable protection
$polChecks = @(
  @{ key = 'SOFTWARE\\Policies\\Microsoft\\Windows Defender'; names = @('DisableAntiSpyware','DisableAntiVirus','DisableRoutinelyTakingAction') },
  @{ key = 'SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection'; names = @('DisableRealtimeMonitoring','DisableBehaviorMonitoring','DisableOnAccessProtection','DisableScanOnRealtimeEnable') }
)
foreach ($pc in $polChecks) {
  $psPath = 'Registry::HKEY_LOCAL_MACHINE\\' + $pc.key
  if (-not (Test-Path -LiteralPath $psPath)) { continue }
  try {
    $props = Get-ItemProperty -LiteralPath $psPath -ErrorAction SilentlyContinue
    foreach ($n in $pc.names) {
      if ($props -and $props.PSObject.Properties[$n] -and $props.$n -eq 1) {
        $res.policy_disables += [ordered]@{
          key_path = $pc.key
          value_name = $n
          value = $props.$n
        }
      }
    }
  } catch {}
}

$res | ConvertTo-Json -Depth 6 -Compress
`;

  const res = await runPowerShellJson<RawDefenderConfig>(script, { timeoutMs });
  const durationMs = Date.now() - start;
  if (!res.ok) {
    return {
      collector: 'defender',
      status: 'error',
      duration_ms: durationMs,
      item_count: 0,
      items: [],
      warnings: [],
      error: res.error || res.stderr || 'defender collector failed',
      exclusions: [],
    };
  }

  const raw = res.data ?? {};
  const items: CollectedItem[] = [];
  const allExclusions: string[] = [];
  const warnings: string[] = [];

  if (raw.access_denied) {
    warnings.push('Defender exclusions require elevated Administrator privileges to read');
  }

  const addExclusions = (
    type: 'ExclusionPath' | 'ExclusionProcess' | 'ExclusionExtension' | 'ExclusionIpAddress',
    values: string[] | undefined
  ) => {
    for (const val of ensureArray(values)) {
      if (!val) continue;
      allExclusions.push(val);
      items.push({
        collector: 'defender',
        kind: 'defender_exclusion',
        location: `Defender:${type}:${val}`,
        facts: {
          exclusion_type: type,
          exclusion_value: val,
        },
        untrusted: {
          name: `${type}: ${val}`,
          raw_value: val,
        },
        remediation_meta: {
          exclusion_type: type,
          exclusion_value: val,
        },
      });
    }
  };

  addExclusions('ExclusionPath', raw.exclusion_paths);
  addExclusions('ExclusionProcess', raw.exclusion_processes);
  addExclusions('ExclusionExtension', raw.exclusion_extensions);
  addExclusions('ExclusionIpAddress', raw.exclusion_ips);

  const hasThirdPartyAv = Boolean(
    preflight?.av_products.some(
      (a) => a.enabled && !/windows defender|microsoft defender/i.test(a.display_name)
    )
  );

  if (!hasThirdPartyAv) {
    for (const pd of ensureArray(raw.policy_disables)) {
      items.push({
        collector: 'defender',
        kind: 'defender_policy',
        location: `HKLM\\${pd.key_path}\\${pd.value_name}`,
        facts: {
          policy_key: pd.key_path,
        },
        untrusted: {
          name: pd.value_name,
          raw_value: String(pd.value),
        },
        remediation_meta: {
          registry_hive: 'HKLM',
          registry_key: pd.key_path,
          registry_value_name: pd.value_name,
        },
      });
    }
  }

  return {
    collector: 'defender',
    status: raw.access_denied ? 'partial' : 'ok',
    duration_ms: durationMs,
    item_count: items.length,
    items,
    warnings,
    exclusions: allExclusions,
  };
}
