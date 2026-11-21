import fs from 'node:fs';
import path from 'node:path';
import { ASR_RULES } from '../constants.js';
import type { EventBus } from '../output/events.js';
import { ensureArray, runPowerShellJson } from '../platform/powershell.js';
import { readJsonFile, writeJsonAtomic } from '../session/manager.js';
import type { HardenManifest, HardenSettingRecord, PreflightResult } from '../types.js';
import { PS_FILE_FACTS_HELPER } from '../collectors/windows/ps-common.js';

export interface HardenBackend {
  applyDefenderRealtime(): Promise<HardenSettingRecord>;
  applyDefenderPua(): Promise<HardenSettingRecord>;
  applyDefenderCloud(): Promise<HardenSettingRecord>;
  applyDefenderAsr(): Promise<HardenSettingRecord>;
  applySmartScreen(): Promise<HardenSettingRecord>;
  applyWindowsUpdate(): Promise<HardenSettingRecord>;
  applyShowFileExtensions(): Promise<HardenSettingRecord>;
  checkTamperProtection(): Promise<HardenSettingRecord>;
  checkPendingUpdates(): Promise<HardenSettingRecord>;
  revertSetting(record: HardenSettingRecord): Promise<{ ok: boolean; message: string }>;
}

function nowIso(): string {
  return new Date().toISOString();
}

export function createWindowsHardenBackend(): HardenBackend {
  return {
    async applyDefenderRealtime(): Promise<HardenSettingRecord> {
      const res = await runPowerShellJson<{ ok: boolean; prior: unknown; error?: string }>(
        `
$ErrorActionPreference = 'Stop'
try {
  $pref = Get-MpPreference -ErrorAction Stop
  $prior = $pref.DisableRealtimeMonitoring
  Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
  @{ ok = $true; prior = $prior } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; prior = $null; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { timeoutMs: 20_000 }
      );
      return {
        id: 'defender_realtime',
        name: 'Microsoft Defender Real-Time Protection',
        status: res.ok && res.data?.ok ? 'applied' : 'failed',
        prior_value: res.data?.prior ?? null,
        new_value: false,
        message: res.ok && res.data?.ok ? 'DisableRealtimeMonitoring = false' : res.data?.error || res.error,
        timestamp: nowIso(),
      };
    },

    async applyDefenderPua(): Promise<HardenSettingRecord> {
      const res = await runPowerShellJson<{ ok: boolean; prior: unknown; error?: string }>(
        `
$ErrorActionPreference = 'Stop'
try {
  $pref = Get-MpPreference -ErrorAction Stop
  $prior = $pref.PUAProtection
  Set-MpPreference -PUAProtection Enabled -ErrorAction Stop
  @{ ok = $true; prior = $prior } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; prior = $null; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { timeoutMs: 20_000 }
      );
      return {
        id: 'defender_pua',
        name: 'Potentially Unwanted App (PUA) Blocking',
        status: res.ok && res.data?.ok ? 'applied' : 'failed',
        prior_value: res.data?.prior ?? null,
        new_value: 1,
        message: res.ok && res.data?.ok ? 'PUAProtection = Enabled' : res.data?.error || res.error,
        timestamp: nowIso(),
      };
    },

    async applyDefenderCloud(): Promise<HardenSettingRecord> {
      const res = await runPowerShellJson<{ ok: boolean; prior: unknown; error?: string }>(
        `
$ErrorActionPreference = 'Stop'
try {
  $pref = Get-MpPreference -ErrorAction Stop
  $prior = [ordered]@{ MAPSReporting = $pref.MAPSReporting; SubmitSamplesConsent = $pref.SubmitSamplesConsent }
  Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -ErrorAction Stop
  @{ ok = $true; prior = $prior } | ConvertTo-Json -Depth 4 -Compress
} catch {
  @{ ok = $false; prior = $null; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { timeoutMs: 20_000 }
      );
      return {
        id: 'defender_cloud',
        name: 'Cloud-Delivered Protection & Safe Sample Submission',
        status: res.ok && res.data?.ok ? 'applied' : 'failed',
        prior_value: res.data?.prior ?? null,
        new_value: { MAPSReporting: 'Advanced', SubmitSamplesConsent: 'SendSafeSamples' },
        message:
          res.ok && res.data?.ok
            ? 'MAPSReporting=Advanced, SubmitSamplesConsent=SendSafeSamples'
            : res.data?.error || res.error,
        timestamp: nowIso(),
      };
    },

    async applyDefenderAsr(): Promise<HardenSettingRecord> {
      const ids = ASR_RULES.map((r) => r.id);
      const res = await runPowerShellJson<{ ok: boolean; prior: unknown; error?: string }>(
        `
$ErrorActionPreference = 'Stop'
try {
  $pref = Get-MpPreference -ErrorAction Stop
  $priorIds = @($pref.AttackSurfaceReductionRules_Ids | ForEach-Object { [string]$_ })
  $priorActs = @($pref.AttackSurfaceReductionRules_Actions | ForEach-Object { [int]$_ })
  $prior = [ordered]@{ ids = $priorIds; actions = $priorActs }
  $ruleIds = @($FCSWEEP_PARAMS.ids)
  $actions = @($ruleIds | ForEach-Object { 'Enabled' })
  Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleIds -AttackSurfaceReductionRules_Actions $actions -ErrorAction Stop
  @{ ok = $true; prior = $prior } | ConvertTo-Json -Depth 5 -Compress
} catch {
  @{ ok = $false; prior = $null; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { timeoutMs: 25_000, params: { ids } }
      );
      return {
        id: 'defender_asr',
        name: 'Attack Surface Reduction (ASR) Rules (4 rules)',
        status: res.ok && res.data?.ok ? 'applied' : 'failed',
        prior_value: res.data?.prior ?? null,
        new_value: ids,
        message:
          res.ok && res.data?.ok
            ? `Enabled ${ids.length} ASR rules (${ASR_RULES.map((r) => r.name).join('; ')})`
            : res.data?.error || res.error,
        timestamp: nowIso(),
      };
    },

    async applySmartScreen(): Promise<HardenSettingRecord> {
      const res = await runPowerShellJson<{ ok: boolean; prior: unknown; error?: string }>(
        `
${PS_FILE_FACTS_HELPER}
$ErrorActionPreference = 'Stop'
try {
  $prior = @()
  $targets = @(
    @{ path = 'Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer'; name = 'SmartScreenEnabled'; value = 'RequireAdmin'; type = 'String' }
  )
  $sids = Get-LoadedUserHives
  if ($sids.Count -eq 0) {
    $targets += @{ path = 'Registry::HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Edge'; name = 'SmartScreenEnabled'; value = 1; type = 'DWord' }
    $targets += @{ path = 'Registry::HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Edge'; name = 'SmartScreenPuaEnabled'; value = 1; type = 'DWord' }
    $targets += @{ path = 'Registry::HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost'; name = 'EnableWebContentEvaluation'; value = 1; type = 'DWord' }
  } else {
    foreach ($sid in $sids) {
      $targets += @{ path = ('Registry::HKEY_USERS\\' + $sid + '\\SOFTWARE\\Microsoft\\Edge'); name = 'SmartScreenEnabled'; value = 1; type = 'DWord' }
      $targets += @{ path = ('Registry::HKEY_USERS\\' + $sid + '\\SOFTWARE\\Microsoft\\Edge'); name = 'SmartScreenPuaEnabled'; value = 1; type = 'DWord' }
      $targets += @{ path = ('Registry::HKEY_USERS\\' + $sid + '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost'); name = 'EnableWebContentEvaluation'; value = 1; type = 'DWord' }
    }
  }

  foreach ($t in $targets) {
    $existed = $false
    $oldVal = $null
    if (Test-Path -LiteralPath $t.path) {
      try {
        $p = Get-ItemProperty -LiteralPath $t.path -Name $t.name -ErrorAction Stop
        $existed = $true
        $oldVal = $p.($t.name)
      } catch {}
    } else {
      New-Item -Path $t.path -Force | Out-Null
    }
    $prior += [ordered]@{ path = $t.path; name = $t.name; existed = $existed; value = $oldVal; type = $t.type }
    New-ItemProperty -LiteralPath $t.path -Name $t.name -Value $t.value -PropertyType $t.type -Force | Out-Null
  }
  @{ ok = $true; prior = @($prior) } | ConvertTo-Json -Depth 5 -Compress
} catch {
  @{ ok = $false; prior = $null; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { timeoutMs: 25_000 }
      );
      return {
        id: 'smartscreen',
        name: 'SmartScreen for Apps, Edge, and Store',
        status: res.ok && res.data?.ok ? 'applied' : 'failed',
        prior_value: res.data?.prior ?? null,
        new_value: { Explorer: 'RequireAdmin', Edge: 1, AppHost: 1 },
        message: res.ok && res.data?.ok ? 'SmartScreen enabled for Explorer, Edge, and Store' : res.data?.error || res.error,
        timestamp: nowIso(),
      };
    },

    async applyWindowsUpdate(): Promise<HardenSettingRecord> {
      const res = await runPowerShellJson<{ ok: boolean; prior: unknown; error?: string }>(
        `
$ErrorActionPreference = 'Stop'
try {
  $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='wuauserv'" -ErrorAction Stop
  $uxPath = 'Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings'
  $pauseNames = @('PauseUpdatesExpiryTime','PauseFeatureUpdatesStartTime','PauseFeatureUpdatesEndTime','PauseQualityUpdatesStartTime','PauseQualityUpdatesEndTime')
  $savedPause = @{}
  if (Test-Path -LiteralPath $uxPath) {
    $props = Get-ItemProperty -LiteralPath $uxPath -ErrorAction SilentlyContinue
    foreach ($pn in $pauseNames) {
      if ($props -and $props.PSObject.Properties[$pn]) {
        $savedPause[$pn] = [string]$props.$pn
        Remove-ItemProperty -LiteralPath $uxPath -Name $pn -ErrorAction SilentlyContinue
      }
    }
  }
  $priorStart = [string]$svc.StartMode
  if ($priorStart -eq 'Disabled') {
    Set-Service -Name 'wuauserv' -StartupType Manual -ErrorAction Stop
  }
  @{ ok = $true; prior = @{ start_mode = $priorStart; pause_keys = $savedPause } } | ConvertTo-Json -Depth 5 -Compress
} catch {
  @{ ok = $false; prior = $null; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { timeoutMs: 20_000 }
      );
      return {
        id: 'windows_update',
        name: 'Windows Update Enabled and Unpaused',
        status: res.ok && res.data?.ok ? 'applied' : 'failed',
        prior_value: res.data?.prior ?? null,
        new_value: { wuauserv: 'Manual_or_Auto', paused: false },
        message: res.ok && res.data?.ok ? 'Windows Update service enabled and pause keys cleared' : res.data?.error || res.error,
        timestamp: nowIso(),
      };
    },

    async applyShowFileExtensions(): Promise<HardenSettingRecord> {
      const res = await runPowerShellJson<{ ok: boolean; prior: unknown; error?: string }>(
        `
${PS_FILE_FACTS_HELPER}
$ErrorActionPreference = 'Stop'
try {
  $prior = @()
  $sub = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced'
  $paths = @()
  $sids = Get-LoadedUserHives
  if ($sids.Count -eq 0) {
    $paths += ('Registry::HKEY_CURRENT_USER\\' + $sub)
  } else {
    foreach ($sid in $sids) { $paths += ('Registry::HKEY_USERS\\' + $sid + '\\' + $sub) }
  }
  foreach ($p in $paths) {
    $existed = $false
    $oldVal = $null
    if (Test-Path -LiteralPath $p) {
      try {
        $prop = Get-ItemProperty -LiteralPath $p -Name 'HideFileExt' -ErrorAction Stop
        $existed = $true
        $oldVal = $prop.HideFileExt
      } catch {}
    } else {
      New-Item -Path $p -Force | Out-Null
    }
    $prior += [ordered]@{ path = $p; existed = $existed; value = $oldVal }
    New-ItemProperty -LiteralPath $p -Name 'HideFileExt' -Value 0 -PropertyType DWord -Force | Out-Null
  }
  @{ ok = $true; prior = @($prior) } | ConvertTo-Json -Depth 5 -Compress
} catch {
  @{ ok = $false; prior = $null; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { timeoutMs: 20_000 }
      );
      return {
        id: 'show_file_extensions',
        name: 'Show File Extensions in Explorer (HideFileExt = 0)',
        status: res.ok && res.data?.ok ? 'applied' : 'failed',
        prior_value: res.data?.prior ?? null,
        new_value: 0,
        message: res.ok && res.data?.ok ? 'HideFileExt set to 0 for loaded user profiles' : res.data?.error || res.error,
        timestamp: nowIso(),
      };
    },

    async checkTamperProtection(): Promise<HardenSettingRecord> {
      const res = await runPowerShellJson<{ tamper: boolean | null }>(
        `
try {
  $st = Get-MpComputerStatus -ErrorAction Stop
  @{ tamper = [bool]$st.IsTamperProtected } | ConvertTo-Json -Compress
} catch {
  @{ tamper = $null } | ConvertTo-Json -Compress
}
`,
        { timeoutMs: 15_000 }
      );
      const tp = res.data?.tamper;
      const msg =
        tp === true
          ? 'Tamper Protection is ON.'
          : tp === false
            ? 'Tamper Protection is OFF (cannot be changed by script). Enable it in Windows Security -> Virus & threat protection -> Manage settings -> Tamper Protection.'
            : 'Tamper Protection state unavailable. Check Windows Security -> Virus & threat protection -> Manage settings -> Tamper Protection.';
      return {
        id: 'tamper_protection',
        name: 'Tamper Protection (Report Only)',
        status: 'report_only',
        prior_value: tp ?? null,
        new_value: null,
        message: msg,
        timestamp: nowIso(),
      };
    },

    async checkPendingUpdates(): Promise<HardenSettingRecord> {
      const res = await runPowerShellJson<{ pending_count: number | null; titles: string[] }>(
        `
$count = $null
$titles = @()
try {
  $session = New-Object -ComObject Microsoft.Update.Session
  $searcher = $session.CreateUpdateSearcher()
  $searcher.Online = $false
  $result = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
  $count = $result.Updates.Count
  foreach ($u in $result.Updates) { $titles += [string]$u.Title }
} catch {}
@{ pending_count = $count; titles = @($titles | Select-Object -First 10) } | ConvertTo-Json -Depth 4 -Compress
`,
        { timeoutMs: 25_000 }
      );
      const count = res.data?.pending_count;
      return {
        id: 'pending_updates',
        name: 'Pending Windows Updates (Report Only)',
        status: 'report_only',
        prior_value: count ?? null,
        new_value: null,
        message:
          typeof count === 'number'
            ? count === 0
              ? '0 cached pending Windows updates found. Also verify Chrome/Edge/Firefox are up to date.'
              : `${count} pending Windows update(s) found. Open Windows Update (ms-settings:windowsupdate) to install.`
            : 'Could not query cached Windows Update state; open Settings -> Windows Update to check manually.',
        timestamp: nowIso(),
      };
    },

    async revertSetting(record: HardenSettingRecord): Promise<{ ok: boolean; message: string }> {
      if (record.status !== 'applied') {
        return { ok: true, message: `Skipped revert (status was ${record.status})` };
      }

      switch (record.id) {
        case 'defender_realtime': {
          const priorBool = Boolean(record.prior_value);
          const r = await runPowerShellJson<{ ok: boolean; error?: string }>(
            `try { Set-MpPreference -DisableRealtimeMonitoring ([bool]$FCSWEEP_PARAMS.val) -ErrorAction Stop; @{ ok = $true } | ConvertTo-Json -Compress } catch { @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress }`,
            { timeoutMs: 20_000, params: { val: priorBool } }
          );
          return { ok: Boolean(r.data?.ok), message: r.data?.ok ? `Restored DisableRealtimeMonitoring=${priorBool}` : r.data?.error || 'failed' };
        }

        case 'defender_pua': {
          const priorVal = record.prior_value ?? 0;
          const r = await runPowerShellJson<{ ok: boolean; error?: string }>(
            `try { Set-MpPreference -PUAProtection $FCSWEEP_PARAMS.val -ErrorAction Stop; @{ ok = $true } | ConvertTo-Json -Compress } catch { @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress }`,
            { timeoutMs: 20_000, params: { val: priorVal } }
          );
          return { ok: Boolean(r.data?.ok), message: r.data?.ok ? `Restored PUAProtection=${priorVal}` : r.data?.error || 'failed' };
        }

        case 'defender_cloud': {
          const prior = (record.prior_value ?? {}) as { MAPSReporting?: unknown; SubmitSamplesConsent?: unknown };
          const r = await runPowerShellJson<{ ok: boolean; error?: string }>(
            `
try {
  if ($null -ne $FCSWEEP_PARAMS.maps) { Set-MpPreference -MAPSReporting $FCSWEEP_PARAMS.maps -ErrorAction Stop }
  if ($null -ne $FCSWEEP_PARAMS.consent) { Set-MpPreference -SubmitSamplesConsent $FCSWEEP_PARAMS.consent -ErrorAction Stop }
  @{ ok = $true } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
            {
              timeoutMs: 20_000,
              params: { maps: prior.MAPSReporting ?? null, consent: prior.SubmitSamplesConsent ?? null },
            }
          );
          return { ok: Boolean(r.data?.ok), message: r.data?.ok ? 'Restored MAPSReporting and SubmitSamplesConsent' : r.data?.error || 'failed' };
        }

        case 'defender_asr': {
          const prior = (record.prior_value ?? { ids: [], actions: [] }) as { ids: string[]; actions: number[] };
          const appliedIds = ASR_RULES.map((r) => r.id);
          const r = await runPowerShellJson<{ ok: boolean; error?: string }>(
            `
try {
  $priorIds = @($FCSWEEP_PARAMS.prior_ids)
  $priorActs = @($FCSWEEP_PARAMS.prior_actions)
  if ($priorIds.Count -gt 0) {
    Set-MpPreference -AttackSurfaceReductionRules_Ids $priorIds -AttackSurfaceReductionRules_Actions $priorActs -ErrorAction Stop
  } else {
    Remove-MpPreference -AttackSurfaceReductionRules_Ids @($FCSWEEP_PARAMS.applied_ids) -ErrorAction Stop
  }
  @{ ok = $true } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
            {
              timeoutMs: 25_000,
              params: { prior_ids: prior.ids ?? [], prior_actions: prior.actions ?? [], applied_ids: appliedIds },
            }
          );
          return { ok: Boolean(r.data?.ok), message: r.data?.ok ? 'Restored prior ASR rules' : r.data?.error || 'failed' };
        }

        case 'smartscreen': {
          const items = ensureArray(record.prior_value as any[]);
          const r = await runPowerShellJson<{ ok: boolean; error?: string }>(
            `
try {
  foreach ($t in @($FCSWEEP_PARAMS.items)) {
    if ($t.existed) {
      New-ItemProperty -LiteralPath $t.path -Name $t.name -Value $t.value -PropertyType $t.type -Force | Out-Null
    } else {
      Remove-ItemProperty -LiteralPath $t.path -Name $t.name -ErrorAction SilentlyContinue
    }
  }
  @{ ok = $true } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
            { timeoutMs: 20_000, params: { items } }
          );
          return { ok: Boolean(r.data?.ok), message: r.data?.ok ? 'Restored prior SmartScreen values' : r.data?.error || 'failed' };
        }

        case 'windows_update': {
          const prior = (record.prior_value ?? {}) as { start_mode?: string; pause_keys?: Record<string, string> };
          const r = await runPowerShellJson<{ ok: boolean; error?: string }>(
            `
try {
  $sm = $FCSWEEP_PARAMS.start_mode
  if ($sm -eq 'Disabled') { Set-Service -Name 'wuauserv' -StartupType Disabled -ErrorAction Stop }
  elseif ($sm -eq 'Auto' -or $sm -eq 'Automatic') { Set-Service -Name 'wuauserv' -StartupType Automatic -ErrorAction Stop }
  elseif ($sm -eq 'Manual') { Set-Service -Name 'wuauserv' -StartupType Manual -ErrorAction Stop }
  $uxPath = 'Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings'
  if ($FCSWEEP_PARAMS.pause_keys) {
    if (-not (Test-Path -LiteralPath $uxPath)) { New-Item -Path $uxPath -Force | Out-Null }
    foreach ($p in $FCSWEEP_PARAMS.pause_keys.PSObject.Properties) {
      New-ItemProperty -LiteralPath $uxPath -Name $p.Name -Value ([string]$p.Value) -PropertyType String -Force | Out-Null
    }
  }
  @{ ok = $true } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
            { timeoutMs: 20_000, params: { start_mode: prior.start_mode ?? null, pause_keys: prior.pause_keys ?? {} } }
          );
          return { ok: Boolean(r.data?.ok), message: r.data?.ok ? 'Restored Windows Update service and pause keys' : r.data?.error || 'failed' };
        }

        case 'show_file_extensions': {
          const items = ensureArray(record.prior_value as any[]);
          const r = await runPowerShellJson<{ ok: boolean; error?: string }>(
            `
try {
  foreach ($t in @($FCSWEEP_PARAMS.items)) {
    if ($t.existed) {
      New-ItemProperty -LiteralPath $t.path -Name 'HideFileExt' -Value ([int]$t.value) -PropertyType DWord -Force | Out-Null
    } else {
      Remove-ItemProperty -LiteralPath $t.path -Name 'HideFileExt' -ErrorAction SilentlyContinue
    }
  }
  @{ ok = $true } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
            { timeoutMs: 20_000, params: { items } }
          );
          return { ok: Boolean(r.data?.ok), message: r.data?.ok ? 'Restored prior Explorer HideFileExt values' : r.data?.error || 'failed' };
        }

        default:
          return { ok: true, message: 'No revert action needed' };
      }
    },
  };
}

export async function runHardenApply(params: {
  sessionId: string;
  sessionDir: string;
  preflight?: PreflightResult | null;
  bus: EventBus;
  backend?: HardenBackend;
}): Promise<{ manifest: HardenManifest; failedCount: number }> {
  const { sessionId, sessionDir, preflight, bus } = params;
  const backend = params.backend ?? createWindowsHardenBackend();

  const thirdPartyAvs = (preflight?.av_products ?? [])
    .filter((a) => a.enabled && !/windows defender|microsoft defender/i.test(a.display_name))
    .map((a) => a.display_name);
  const skipDefender = thirdPartyAvs.length > 0;

  const settings: HardenSettingRecord[] = [];
  const manifestPath = path.join(sessionDir, 'harden-manifest.json');

  const manifest: HardenManifest = {
    session_id: sessionId,
    applied_at: nowIso(),
    reverted_at: null,
    third_party_av_detected: skipDefender,
    av_names: thirdPartyAvs,
    settings,
  };

  const runSetting = async (id: string, name: string, fn: () => Promise<HardenSettingRecord>) => {
    bus.emit('action_start', { action: `harden:${id}`, name });
    let rec: HardenSettingRecord;
    try {
      rec = await fn();
    } catch (err) {
      rec = {
        id,
        name,
        status: 'failed',
        prior_value: null,
        new_value: null,
        message: err instanceof Error ? err.message : String(err),
        timestamp: nowIso(),
      };
    }
    settings.push(rec);
    // Persist incrementally so every applied setting can always be reverted
    writeJsonAtomic(manifestPath, manifest);
    bus.emit('action_done', {
      action: `harden:${rec.id}`,
      name: rec.name,
      status: rec.status,
      message: rec.message,
    });
    const icon = rec.status === 'applied' ? '✅' : rec.status === 'report_only' ? 'ℹ️ ' : rec.status === 'skipped' ? '⏭️ ' : '❌';
    bus.info(`  ${icon} ${bus.ui.bold(rec.name)}: ${rec.message ?? ''}`);
  };

  if (skipDefender) {
    const reason = `Skipped because another antivirus is registered and active: ${thirdPartyAvs.join(', ')}`;
    for (const [id, name] of [
      ['defender_realtime', 'Microsoft Defender Real-Time Protection'],
      ['defender_pua', 'Potentially Unwanted App (PUA) Blocking'],
      ['defender_cloud', 'Cloud-Delivered Protection & Safe Sample Submission'],
      ['defender_asr', 'Attack Surface Reduction (ASR) Rules'],
    ]) {
      const rec: HardenSettingRecord = {
        id,
        name,
        status: 'skipped',
        prior_value: null,
        new_value: null,
        message: reason,
        timestamp: nowIso(),
      };
      settings.push(rec);
      bus.info(`[SKIPPED] ${name}: ${reason}`);
    }
    writeJsonAtomic(manifestPath, manifest);
  } else {
    await runSetting('defender_realtime', 'Microsoft Defender Real-Time Protection', () => backend.applyDefenderRealtime());
    await runSetting('defender_pua', 'Potentially Unwanted App (PUA) Blocking', () => backend.applyDefenderPua());
    await runSetting('defender_cloud', 'Cloud-Delivered Protection', () => backend.applyDefenderCloud());
    await runSetting('defender_asr', 'Attack Surface Reduction (ASR) Rules', () => backend.applyDefenderAsr());
  }

  await runSetting('smartscreen', 'SmartScreen for Apps, Edge, and Store', () => backend.applySmartScreen());
  await runSetting('windows_update', 'Windows Update Enabled and Unpaused', () => backend.applyWindowsUpdate());
  await runSetting('show_file_extensions', 'Show File Extensions in Explorer', () => backend.applyShowFileExtensions());
  await runSetting('tamper_protection', 'Tamper Protection (Report Only)', () => backend.checkTamperProtection());
  await runSetting('pending_updates', 'Pending Windows Updates (Report Only)', () => backend.checkPendingUpdates());

  const failedCount = settings.filter((s) => s.status === 'failed').length;
  return { manifest, failedCount };
}

export async function runHardenRevert(params: {
  sessionDir: string;
  bus: EventBus;
  backend?: HardenBackend;
}): Promise<{ manifest: HardenManifest; reverted: number; failed: number }> {
  const { sessionDir, bus } = params;
  const backend = params.backend ?? createWindowsHardenBackend();
  const manifestPath = path.join(sessionDir, 'harden-manifest.json');
  if (!fs.existsSync(manifestPath)) {
    throw new Error(`No harden-manifest.json found in session folder: ${sessionDir}`);
  }

  const manifest = readJsonFile<HardenManifest>(manifestPath);
  let reverted = 0;
  let failed = 0;

  for (const rec of [...manifest.settings].reverse()) {
    if (rec.status !== 'applied') continue;
    bus.emit('action_start', { action: `harden_revert:${rec.id}`, name: rec.name });
    const res = await backend.revertSetting(rec);
    if (res.ok) {
      rec.status = 'reverted';
      rec.message = res.message;
      reverted++;
    } else {
      rec.status = 'revert_failed';
      rec.message = res.message;
      failed++;
    }
    bus.emit('action_done', {
      action: `harden_revert:${rec.id}`,
      name: rec.name,
      status: rec.status,
      message: rec.message,
    });
    bus.info(`[${rec.status.toUpperCase()}] ${rec.name}: ${rec.message}`);
  }

  manifest.reverted_at = nowIso();
  writeJsonAtomic(manifestPath, manifest);
  return { manifest, reverted, failed };
}
