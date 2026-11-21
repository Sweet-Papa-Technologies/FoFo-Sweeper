import fs from 'node:fs';
import path from 'node:path';
import { execFileSafe } from '../platform/exec.js';
import { runPowerShellJson } from '../platform/powershell.js';
import { hardenDirectoryPermissions } from '../session/manager.js';
import { sha256File } from '../session/manifest.js';
import type { ActionType, Finding, InverseSpec, ManifestEntry } from '../types.js';

export interface ActionContext {
  sessionDir: string;
  backupsDir: string;
  quarantineDir: string;
  elevated: boolean;
  /** Optional hook for tests to simulate backup failures or intercept OS execution */
  hooks?: ActionHooks;
}

export interface BackupResult {
  backup_path: string | null;
  backup_sha256: string | null;
  inverse: InverseSpec;
}

export interface ActionHooks {
  onBeforeBackup?: (action: ActionType, finding: Finding) => void;
  /** Optional custom executor override for cross-platform unit testing of Windows OS actions */
  customExecutor?: {
    backup: (action: ActionType, finding: Finding, ctx: ActionContext, seqKey: string) => Promise<BackupResult>;
    apply: (action: ActionType, finding: Finding, backup: BackupResult, ctx: ActionContext) => Promise<string>;
    undo: (entry: ManifestEntry, ctx: ActionContext) => Promise<string>;
  };
}

/**
 * Execution order per Section 4 Step 6:
 * 1. kill_process
 * 2. disable persistence & policies
 * 3. quarantine_file
 * 4. reset network & browser preferences
 * 5. user-guided actions (uninstall_program, guide_extension)
 */
export function getActionOrderPriority(action: ActionType): number {
  switch (action) {
    case 'kill_process':
      return 10;
    case 'disable_autorun':
    case 'disable_task':
    case 'disable_service':
    case 'remove_wmi_subscription':
    case 'remove_hijack':
    case 'remove_policy':
    case 'remove_defender_exclusion':
    case 'remove_root_cert':
      return 20;
    case 'quarantine_file':
      return 30;
    case 'reset_proxy':
    case 'reset_dns':
    case 'clean_hosts':
    case 'remove_notification_permission':
      return 40;
    case 'uninstall_program':
    case 'guide_extension':
      return 50;
    default:
      return 99;
  }
}

function safeFileSlug(input: string): string {
  return input.replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 60) || 'item';
}

function hiveToRegPrefix(hive: string): string {
  if (hive === 'HKLM') return 'HKLM';
  if (hive === 'HKCU') return 'HKCU';
  if (hive.startsWith('HKU\\')) return hive;
  return hive;
}

function hiveToPsPrefix(hive: string): string {
  if (hive === 'HKLM') return 'Registry::HKEY_LOCAL_MACHINE';
  if (hive === 'HKCU') return 'Registry::HKEY_CURRENT_USER';
  if (hive.startsWith('HKU\\')) return `Registry::HKEY_USERS\\${hive.slice(4)}`;
  return `Registry::${hive}`;
}

async function runPsChecked<T = Record<string, unknown>>(
  script: string,
  params: Record<string, unknown>,
  timeoutMs = 30_000
): Promise<T> {
  const res = await runPowerShellJson<{ ok: boolean; error?: string; data?: T }>(script, {
    timeoutMs,
    params,
  });
  if (!res.ok || !res.data?.ok) {
    throw new Error(res.data?.error || res.error || res.stderr || 'PowerShell operation failed');
  }
  return (res.data.data ?? {}) as T;
}

async function exportRegistryKeyBackup(
  hive: string,
  keyPath: string,
  destPath: string
): Promise<void> {
  const regPath = `${hiveToRegPrefix(hive)}\\${keyPath}`;
  const res = await execFileSafe('reg.exe', ['export', regPath, destPath, '/y'], { timeoutMs: 20_000 });
  if (res.exitCode !== 0 || !fs.existsSync(destPath)) {
    throw new Error(`reg.exe export failed for ${regPath}: ${res.stderr || res.error || 'unknown'}`);
  }
}

async function importRegistryKeyBackup(regFilePath: string): Promise<void> {
  if (!fs.existsSync(regFilePath)) {
    throw new Error(`Registry backup file missing: ${regFilePath}`);
  }
  const res = await execFileSafe('reg.exe', ['import', regFilePath], { timeoutMs: 20_000 });
  if (res.exitCode !== 0) {
    throw new Error(`reg.exe import failed for ${regFilePath}: ${res.stderr || res.error || 'unknown'}`);
  }
}

export async function performBackup(
  action: ActionType,
  finding: Finding,
  ctx: ActionContext,
  seqKey: string
): Promise<BackupResult> {
  if (ctx.hooks?.onBeforeBackup) {
    ctx.hooks.onBeforeBackup(action, finding);
  }
  if (ctx.hooks?.customExecutor) {
    return ctx.hooks.customExecutor.backup(action, finding, ctx, seqKey);
  }

  fs.mkdirSync(ctx.backupsDir, { recursive: true });
  fs.mkdirSync(ctx.quarantineDir, { recursive: true });
  const meta = finding.remediation_meta ?? {};
  const prefix = `${seqKey}_${finding.id}_${action}`;

  switch (action) {
    case 'kill_process': {
      return {
        backup_path: null,
        backup_sha256: null,
        inverse: {
          type: 'kill_process',
          reversible: false,
          description: `Process termination for PID ${meta.pid ?? finding.facts.pid ?? 'unknown'} (not reversible; logged only)`,
          params: { pid: meta.pid ?? finding.facts.pid ?? null },
        },
      };
    }

    case 'disable_autorun': {
      if (meta.startup_file_path) {
        const src = meta.startup_file_path;
        if (!fs.existsSync(src)) {
          throw new Error(`Startup shortcut not found for backup: ${src}`);
        }
        const st = fs.statSync(src);
        const qName = `${prefix}_${safeFileSlug(path.basename(src))}.quarantined`;
        const qPath = path.join(ctx.quarantineDir, qName);
        const sddl = await getWindowsFileSddl(src);
        const sha = sha256File(src);
        return {
          backup_path: qPath,
          backup_sha256: sha,
          inverse: {
            type: 'disable_autorun',
            reversible: true,
            description: `Restore Startup file ${src} from quarantine`,
            backup_path: qPath,
            backup_sha256: sha,
            params: {
              mode: 'startup_file',
              original_path: src,
              quarantine_path: qPath,
              sddl,
              atime_ms: st.atimeMs,
              mtime_ms: st.mtimeMs,
            },
          },
        };
      }

      if (!meta.registry_hive || !meta.registry_key || !meta.registry_value_name) {
        throw new Error(`Missing registry metadata for disable_autorun on ${finding.id}`);
      }
      const regFile = path.join(ctx.backupsDir, `${prefix}.reg`);
      await exportRegistryKeyBackup(meta.registry_hive, meta.registry_key, regFile);
      const sha = sha256File(regFile);
      return {
        backup_path: regFile,
        backup_sha256: sha,
        inverse: {
          type: 'disable_autorun',
          reversible: true,
          description: `Re-import registry value ${meta.registry_hive}\\${meta.registry_key}\\${meta.registry_value_name}`,
          backup_path: regFile,
          backup_sha256: sha,
          params: {
            mode: 'registry',
            reg_file: regFile,
            hive: meta.registry_hive,
            key: meta.registry_key,
            value_name: meta.registry_value_name,
          },
        },
      };
    }

    case 'disable_task': {
      const taskPath = meta.task_path ?? '\\';
      const taskName = meta.task_name;
      if (!taskName) throw new Error(`Missing task_name for disable_task on ${finding.id}`);
      const xmlFile = path.join(ctx.backupsDir, `${prefix}_${safeFileSlug(taskName)}.xml`);
      await runPsChecked(
        `
$ErrorActionPreference = 'Stop'
try {
  $xml = Export-ScheduledTask -TaskPath $FCSWEEP_PARAMS.task_path -TaskName $FCSWEEP_PARAMS.task_name -ErrorAction Stop
  [System.IO.File]::WriteAllText($FCSWEEP_PARAMS.out_file, $xml, [System.Text.Encoding]::UTF8)
  @{ ok = $true; data = @{ exported = $true } } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { task_path: taskPath, task_name: taskName, out_file: xmlFile }
      );
      if (!fs.existsSync(xmlFile)) throw new Error(`Task XML export missing: ${xmlFile}`);
      const sha = sha256File(xmlFile);
      return {
        backup_path: xmlFile,
        backup_sha256: sha,
        inverse: {
          type: 'disable_task',
          reversible: true,
          description: `Re-enable scheduled task ${taskPath}${taskName}`,
          backup_path: xmlFile,
          backup_sha256: sha,
          params: { task_path: taskPath, task_name: taskName, xml_file: xmlFile },
        },
      };
    }

    case 'disable_service': {
      const svcName = meta.service_name;
      if (!svcName) throw new Error(`Missing service_name for disable_service on ${finding.id}`);
      const info = await runPsChecked<{ start_mode: string; state: string }>(
        `
$ErrorActionPreference = 'Stop'
try {
  $s = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + ($FCSWEEP_PARAMS.name -replace "'","''") + "'") -ErrorAction Stop
  if (-not $s) { throw "Service not found" }
  @{ ok = $true; data = @{ start_mode = [string]$s.StartMode; state = [string]$s.State } } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { name: svcName }
      );
      const backupFile = path.join(ctx.backupsDir, `${prefix}_${safeFileSlug(svcName)}.json`);
      fs.writeFileSync(backupFile, JSON.stringify({ service_name: svcName, ...info }, null, 2) + '\n');
      const sha = sha256File(backupFile);
      return {
        backup_path: backupFile,
        backup_sha256: sha,
        inverse: {
          type: 'disable_service',
          reversible: true,
          description: `Restore service ${svcName} to StartMode=${info.start_mode}, State=${info.state}`,
          backup_path: backupFile,
          backup_sha256: sha,
          params: { service_name: svcName, start_mode: info.start_mode, state: info.state },
        },
      };
    }

    case 'remove_wmi_subscription': {
      const filterName = meta.wmi_filter_name;
      const consumerName = meta.wmi_consumer_name;
      const consumerClass = meta.wmi_consumer_class || 'CommandLineEventConsumer';
      if (!filterName || !consumerName) {
        throw new Error(`Missing WMI filter/consumer names on ${finding.id}`);
      }
      const backupFile = path.join(ctx.backupsDir, `${prefix}_wmi.json`);
      await runPsChecked(
        `
$ErrorActionPreference = 'Stop'
try {
  $fn = $FCSWEEP_PARAMS.filter_name
  $cn = $FCSWEEP_PARAMS.consumer_name
  $f = Get-CimInstance -Namespace 'root\\subscription' -ClassName '__EventFilter' | Where-Object { $_.Name -eq $fn } | Select-Object -First 1
  $c = Get-CimInstance -Namespace 'root\\subscription' -ClassName '__EventConsumer' | Where-Object { $_.Name -eq $cn } | Select-Object -First 1
  if (-not $f -and -not $c) { throw 'WMI filter and consumer not found' }
  $dump = [ordered]@{
    filter = if ($f) { [ordered]@{ Name = $f.Name; Query = $f.Query; QueryLanguage = $f.QueryLanguage; EventNamespace = $f.EventNamespace } } else { $null }
    consumer_class = if ($c) { [string]$c.CimClass.CimClassName } else { $FCSWEEP_PARAMS.consumer_class }
    consumer = if ($c) {
      $h = [ordered]@{ Name = $c.Name }
      foreach ($p in @('CommandLineTemplate','ExecutablePath','WorkingDirectory','ScriptText','ScriptFileName','ScriptingEngine','RunInteractively')) {
        if ($c.PSObject.Properties[$p] -and $null -ne $c.$p) { $h[$p] = $c.$p }
      }
      $h
    } else { $null }
  }
  [System.IO.File]::WriteAllText($FCSWEEP_PARAMS.out_file, ($dump | ConvertTo-Json -Depth 6), [System.Text.Encoding]::UTF8)
  @{ ok = $true; data = @{ saved = $true } } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        {
          filter_name: filterName,
          consumer_name: consumerName,
          consumer_class: consumerClass,
          out_file: backupFile,
        }
      );
      if (!fs.existsSync(backupFile)) throw new Error(`WMI backup missing: ${backupFile}`);
      const sha = sha256File(backupFile);
      return {
        backup_path: backupFile,
        backup_sha256: sha,
        inverse: {
          type: 'remove_wmi_subscription',
          reversible: true,
          description: `Recreate WMI subscription ${filterName} -> ${consumerName}`,
          backup_path: backupFile,
          backup_sha256: sha,
          params: { backup_file: backupFile, filter_name: filterName, consumer_name: consumerName, consumer_class: consumerClass },
        },
      };
    }

    case 'remove_hijack': {
      if (!meta.registry_hive || !meta.registry_key) {
        throw new Error(`Missing registry metadata for remove_hijack on ${finding.id}`);
      }
      const regFile = path.join(ctx.backupsDir, `${prefix}.reg`);
      await exportRegistryKeyBackup(meta.registry_hive, meta.registry_key, regFile);
      const sha = sha256File(regFile);
      return {
        backup_path: regFile,
        backup_sha256: sha,
        inverse: {
          type: 'remove_hijack',
          reversible: true,
          description: `Re-import hijack registry key ${meta.registry_hive}\\${meta.registry_key}`,
          backup_path: regFile,
          backup_sha256: sha,
          params: {
            reg_file: regFile,
            hive: meta.registry_hive,
            key: meta.registry_key,
            value_name: meta.registry_value_name ?? '',
          },
        },
      };
    }

    case 'quarantine_file': {
      const target = meta.target_file_path ?? finding.facts.target_path;
      if (!target) throw new Error(`Missing target_path for quarantine_file on ${finding.id}`);
      if (!fs.existsSync(target)) throw new Error(`File does not exist for quarantine: ${target}`);
      const st = fs.statSync(target);
      const sha = sha256File(target);
      const sddl = await getWindowsFileSddl(target);
      const qName = `${prefix}_${safeFileSlug(path.basename(target))}.quarantined`;
      const qPath = path.join(ctx.quarantineDir, qName);
      // Record metadata JSON alongside quarantine target
      const metaFile = path.join(ctx.backupsDir, `${prefix}_filemeta.json`);
      fs.writeFileSync(
        metaFile,
        JSON.stringify(
          {
            original_path: target,
            quarantine_path: qPath,
            sha256: sha,
            sddl,
            atime_ms: st.atimeMs,
            mtime_ms: st.mtimeMs,
            birthtime_ms: st.birthtimeMs,
          },
          null,
          2
        ) + '\n'
      );
      return {
        backup_path: qPath,
        backup_sha256: sha,
        inverse: {
          type: 'quarantine_file',
          reversible: true,
          description: `Restore quarantined file back to ${target} with original ACL and timestamps`,
          backup_path: qPath,
          backup_sha256: sha,
          params: {
            original_path: target,
            quarantine_path: qPath,
            meta_file: metaFile,
            sddl,
            atime_ms: st.atimeMs,
            mtime_ms: st.mtimeMs,
          },
        },
      };
    }

    case 'remove_policy': {
      const hive = meta.policy_hive ?? meta.registry_hive;
      const key = meta.policy_key ?? meta.registry_key;
      const valueName = meta.policy_value_name ?? meta.registry_value_name;
      if (!hive || !key) throw new Error(`Missing policy registry key metadata on ${finding.id}`);
      const regFile = path.join(ctx.backupsDir, `${prefix}.reg`);
      await exportRegistryKeyBackup(hive, key, regFile);
      const sha = sha256File(regFile);
      return {
        backup_path: regFile,
        backup_sha256: sha,
        inverse: {
          type: 'remove_policy',
          reversible: true,
          description: `Re-import browser policy key ${hive}\\${key}`,
          backup_path: regFile,
          backup_sha256: sha,
          params: { reg_file: regFile, hive, key, value_name: valueName ?? '' },
        },
      };
    }

    case 'remove_notification_permission': {
      const prefsPath = meta.preferences_path;
      const originKey = meta.notification_origin;
      const browser = meta.browser || finding.facts.browser || '';
      if (!prefsPath || !originKey) {
        throw new Error(`Missing preferences_path or notification_origin on ${finding.id}`);
      }
      if (!fs.existsSync(prefsPath)) {
        throw new Error(`Browser Preferences file not found: ${prefsPath}`);
      }
      // Section 8: browser must be closed before editing Preferences
      const running = await isBrowserRunning(browser);
      if (running) {
        throw new Error(
          `${browser} is currently running. Close ${browser} completely before removing notification permissions so Chromium does not overwrite or reset the profile.`
        );
      }
      const backupFile = path.join(ctx.backupsDir, `${prefix}_Preferences.json`);
      fs.copyFileSync(prefsPath, backupFile);
      const sha = sha256File(backupFile);
      return {
        backup_path: backupFile,
        backup_sha256: sha,
        inverse: {
          type: 'remove_notification_permission',
          reversible: true,
          description: `Restore browser Preferences file ${prefsPath}`,
          backup_path: backupFile,
          backup_sha256: sha,
          params: { preferences_path: prefsPath, backup_file: backupFile, browser, origin_key: originKey },
        },
      };
    }

    case 'reset_proxy': {
      const scope = meta.proxy_scope ?? 'user';
      const userSid = meta.proxy_user_sid ?? 'HKCU';
      const backupFile = path.join(ctx.backupsDir, `${prefix}_proxy.json`);
      if (scope === 'winhttp') {
        const res = await execFileSafe('netsh.exe', ['winhttp', 'show', 'proxy'], { timeoutMs: 10_000 });
        fs.writeFileSync(backupFile, JSON.stringify({ scope: 'winhttp', raw: res.stdout }, null, 2) + '\n');
        const sha = sha256File(backupFile);
        return {
          backup_path: backupFile,
          backup_sha256: sha,
          inverse: {
            type: 'reset_proxy',
            reversible: true,
            description: 'Restore WinHTTP proxy configuration',
            backup_path: backupFile,
            backup_sha256: sha,
            params: { scope: 'winhttp', raw: res.stdout, proxy_server: finding.facts.proxy_server ?? null },
          },
        };
      }
      const hive = userSid === 'HKCU' ? 'HKCU' : `HKU\\${userSid}`;
      const sub = 'Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
      const regFile = path.join(ctx.backupsDir, `${prefix}_proxy.reg`);
      await exportRegistryKeyBackup(hive, sub, regFile);
      const sha = sha256File(regFile);
      return {
        backup_path: regFile,
        backup_sha256: sha,
        inverse: {
          type: 'reset_proxy',
          reversible: true,
          description: `Re-import Internet Settings proxy keys for ${hive}`,
          backup_path: regFile,
          backup_sha256: sha,
          params: { scope: 'user', reg_file: regFile, hive, key: sub },
        },
      };
    }

    case 'reset_dns': {
      const alias = meta.adapter_interface_alias;
      if (!alias) throw new Error(`Missing adapter_interface_alias on ${finding.id}`);
      const prior = await runPsChecked<{ servers: string[] }>(
        `
$ErrorActionPreference = 'Stop'
try {
  $d = Get-DnsClientServerAddress -InterfaceAlias $FCSWEEP_PARAMS.alias -AddressFamily IPv4 -ErrorAction Stop
  @{ ok = $true; data = @{ servers = @($d.ServerAddresses | ForEach-Object { [string]$_ }) } } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { alias }
      );
      const backupFile = path.join(ctx.backupsDir, `${prefix}_dns.json`);
      fs.writeFileSync(backupFile, JSON.stringify({ interface_alias: alias, servers: prior.servers }, null, 2) + '\n');
      const sha = sha256File(backupFile);
      return {
        backup_path: backupFile,
        backup_sha256: sha,
        inverse: {
          type: 'reset_dns',
          reversible: true,
          description: `Restore DNS servers on adapter ${alias}`,
          backup_path: backupFile,
          backup_sha256: sha,
          params: { interface_alias: alias, servers: prior.servers },
        },
      };
    }

    case 'clean_hosts': {
      const sysRoot = process.env.SystemRoot || 'C:\\Windows';
      const hostsPath = path.join(sysRoot, 'System32', 'drivers', 'etc', 'hosts');
      if (!fs.existsSync(hostsPath)) throw new Error(`hosts file not found: ${hostsPath}`);
      const backupFile = path.join(ctx.backupsDir, `${prefix}_hosts.bak`);
      fs.copyFileSync(hostsPath, backupFile);
      const sha = sha256File(backupFile);
      return {
        backup_path: backupFile,
        backup_sha256: sha,
        inverse: {
          type: 'clean_hosts',
          reversible: true,
          description: `Restore original hosts file from ${backupFile}`,
          backup_path: backupFile,
          backup_sha256: sha,
          params: { hosts_path: hostsPath, backup_file: backupFile },
        },
      };
    }

    case 'remove_defender_exclusion': {
      const exType = meta.exclusion_type;
      const exVal = meta.exclusion_value;
      if (!exType || !exVal) throw new Error(`Missing exclusion_type/value on ${finding.id}`);
      const backupFile = path.join(ctx.backupsDir, `${prefix}_exclusion.json`);
      fs.writeFileSync(backupFile, JSON.stringify({ exclusion_type: exType, exclusion_value: exVal }, null, 2) + '\n');
      const sha = sha256File(backupFile);
      return {
        backup_path: backupFile,
        backup_sha256: sha,
        inverse: {
          type: 'remove_defender_exclusion',
          reversible: true,
          description: `Re-add Defender ${exType} exclusion "${exVal}"`,
          backup_path: backupFile,
          backup_sha256: sha,
          params: { exclusion_type: exType, exclusion_value: exVal },
        },
      };
    }

    case 'remove_root_cert': {
      const store = meta.cert_store || 'LocalMachine\\Root';
      const thumbprint = meta.cert_thumbprint;
      if (!thumbprint) throw new Error(`Missing cert_thumbprint on ${finding.id}`);
      const cerFile = path.join(ctx.backupsDir, `${prefix}_${thumbprint}.cer`);
      await runPsChecked(
        `
$ErrorActionPreference = 'Stop'
try {
  $p = 'Cert:\\' + $FCSWEEP_PARAMS.store + '\\' + $FCSWEEP_PARAMS.thumbprint
  $cert = Get-Item -LiteralPath $p -ErrorAction Stop
  $bytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
  [System.IO.File]::WriteAllBytes($FCSWEEP_PARAMS.out_file, $bytes)
  @{ ok = $true; data = @{ exported = $true } } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { store, thumbprint, out_file: cerFile }
      );
      if (!fs.existsSync(cerFile)) throw new Error(`Certificate export missing: ${cerFile}`);
      const sha = sha256File(cerFile);
      return {
        backup_path: cerFile,
        backup_sha256: sha,
        inverse: {
          type: 'remove_root_cert',
          reversible: true,
          description: `Re-import root certificate ${thumbprint} into Cert:\\${store}`,
          backup_path: cerFile,
          backup_sha256: sha,
          params: { store, thumbprint, cer_file: cerFile },
        },
      };
    }

    case 'uninstall_program': {
      return {
        backup_path: null,
        backup_sha256: null,
        inverse: {
          type: 'uninstall_program',
          reversible: false,
          description: 'Opens program uninstaller for the user (not automatic; not reversible by fcsweep)',
          params: { uninstall_string: meta.uninstall_string ?? null },
        },
      };
    }

    case 'guide_extension': {
      return {
        backup_path: null,
        backup_sha256: null,
        inverse: {
          type: 'guide_extension',
          reversible: false,
          description: 'Guided browser extension removal (user removes manually in browser UI)',
          params: {
            browser: meta.browser ?? null,
            extension_id: meta.extension_id ?? null,
            extension_page_url: meta.extension_page_url ?? null,
          },
        },
      };
    }

    default:
      throw new Error(`Unsupported remediation action: ${action}`);
  }
}

export async function performApply(
  action: ActionType,
  finding: Finding,
  backup: BackupResult,
  ctx: ActionContext
): Promise<string> {
  if (ctx.hooks?.customExecutor) {
    return ctx.hooks.customExecutor.apply(action, finding, backup, ctx);
  }

  const meta = finding.remediation_meta ?? {};

  switch (action) {
    case 'kill_process': {
      const pid = meta.pid ?? finding.facts.pid;
      if (!pid) throw new Error(`No PID to terminate for ${finding.id}`);
      const res = await execFileSafe('taskkill.exe', ['/PID', String(pid), '/T', '/F'], { timeoutMs: 15_000 });
      if (res.exitCode !== 0 && !/not found/i.test(`${res.stdout}${res.stderr}`)) {
        throw new Error(`taskkill failed for PID ${pid}: ${res.stderr || res.stdout}`);
      }
      return `Terminated process tree for PID ${pid}`;
    }

    case 'disable_autorun': {
      if (meta.startup_file_path) {
        const qPath = String(backup.inverse.params.quarantine_path);
        await moveFileToQuarantine(meta.startup_file_path, qPath, ctx.elevated);
        return `Moved Startup item to quarantine: ${qPath}`;
      }
      const psKey = `${hiveToPsPrefix(meta.registry_hive!)}\\${meta.registry_key!}`;
      await runPsChecked(
        `
$ErrorActionPreference = 'Stop'
try {
  Remove-ItemProperty -LiteralPath $FCSWEEP_PARAMS.key -Name $FCSWEEP_PARAMS.name -ErrorAction Stop
  @{ ok = $true; data = @{} } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { key: psKey, name: meta.registry_value_name! }
      );
      return `Removed autorun registry value ${meta.registry_hive}\\${meta.registry_key}\\${meta.registry_value_name}`;
    }

    case 'disable_task': {
      await runPsChecked(
        `
$ErrorActionPreference = 'Stop'
try {
  Disable-ScheduledTask -TaskPath $FCSWEEP_PARAMS.task_path -TaskName $FCSWEEP_PARAMS.task_name -ErrorAction Stop | Out-Null
  @{ ok = $true; data = @{} } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { task_path: meta.task_path ?? '\\', task_name: meta.task_name! }
      );
      return `Disabled scheduled task ${meta.task_path ?? '\\'}${meta.task_name}`;
    }

    case 'disable_service': {
      await runPsChecked(
        `
$ErrorActionPreference = 'Stop'
try {
  Stop-Service -Name $FCSWEEP_PARAMS.name -Force -ErrorAction SilentlyContinue
  Set-Service -Name $FCSWEEP_PARAMS.name -StartupType Disabled -ErrorAction Stop
  @{ ok = $true; data = @{} } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { name: meta.service_name! }
      );
      return `Stopped and disabled service ${meta.service_name}`;
    }

    case 'remove_wmi_subscription': {
      await runPsChecked(
        `
$ErrorActionPreference = 'Stop'
try {
  $fn = $FCSWEEP_PARAMS.filter_name
  $cn = $FCSWEEP_PARAMS.consumer_name
  Get-CimInstance -Namespace 'root\\subscription' -ClassName '__FilterToConsumerBinding' |
    Where-Object { ($_.Filter.Name -eq $fn) -or ($_.Consumer.Name -eq $cn) } |
    Remove-CimInstance -ErrorAction Stop
  Get-CimInstance -Namespace 'root\\subscription' -ClassName '__EventFilter' |
    Where-Object { $_.Name -eq $fn } |
    Remove-CimInstance -ErrorAction Stop
  Get-CimInstance -Namespace 'root\\subscription' -ClassName '__EventConsumer' |
    Where-Object { $_.Name -eq $cn } |
    Remove-CimInstance -ErrorAction Stop
  @{ ok = $true; data = @{} } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { filter_name: meta.wmi_filter_name!, consumer_name: meta.wmi_consumer_name! }
      );
      return `Removed WMI event subscription ${meta.wmi_filter_name} -> ${meta.wmi_consumer_name}`;
    }

    case 'remove_hijack': {
      const psKey = `${hiveToPsPrefix(meta.registry_hive!)}\\${meta.registry_key!}`;
      const defVal = meta.registry_default_value;
      await runPsChecked(
        `
$ErrorActionPreference = 'Stop'
try {
  $k = $FCSWEEP_PARAMS.key
  $vn = $FCSWEEP_PARAMS.value_name
  $dv = $FCSWEEP_PARAMS.default_value
  if ([string]::IsNullOrEmpty($vn)) {
    Remove-Item -LiteralPath $k -Recurse -Force -ErrorAction Stop
  } elseif ($null -ne $dv) {
    if ($vn -eq 'BootExecute') {
      Set-ItemProperty -LiteralPath $k -Name $vn -Value @($dv) -ErrorAction Stop
    } else {
      Set-ItemProperty -LiteralPath $k -Name $vn -Value $dv -ErrorAction Stop
    }
  } else {
    Remove-ItemProperty -LiteralPath $k -Name $vn -ErrorAction Stop
  }
  @{ ok = $true; data = @{} } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { key: psKey, value_name: meta.registry_value_name ?? '', default_value: defVal ?? null }
      );
      return `Restored hijack key ${meta.registry_hive}\\${meta.registry_key}`;
    }

    case 'quarantine_file': {
      const src = String(backup.inverse.params.original_path);
      const qPath = String(backup.inverse.params.quarantine_path);
      await moveFileToQuarantine(src, qPath, ctx.elevated);
      return `Quarantined ${src} -> ${qPath}`;
    }

    case 'remove_policy': {
      const hive = meta.policy_hive ?? meta.registry_hive!;
      const key = meta.policy_key ?? meta.registry_key!;
      const valName = meta.policy_value_name ?? meta.registry_value_name ?? '';
      const psKey = `${hiveToPsPrefix(hive)}\\${key}`;
      await runPsChecked(
        `
$ErrorActionPreference = 'Stop'
try {
  $k = $FCSWEEP_PARAMS.key
  $vn = $FCSWEEP_PARAMS.value_name
  if (-not [string]::IsNullOrEmpty($vn)) {
    Remove-ItemProperty -LiteralPath $k -Name $vn -ErrorAction Stop
    # Clean up empty list subkey (e.g. ExtensionInstallForcelist) if no values remain
    $item = Get-Item -LiteralPath $k -ErrorAction SilentlyContinue
    if ($item -and $item.ValueCount -eq 0 -and $item.SubKeyCount -eq 0) {
      Remove-Item -LiteralPath $k -Force -ErrorAction SilentlyContinue
    }
  } else {
    Remove-Item -LiteralPath $k -Recurse -Force -ErrorAction Stop
  }
  @{ ok = $true; data = @{} } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { key: psKey, value_name: valName }
      );
      return `Removed browser policy ${hive}\\${key}${valName ? '\\' + valName : ''}`;
    }

    case 'remove_notification_permission': {
      const prefsPath = meta.preferences_path!;
      const originKey = meta.notification_origin!;
      const parsed = JSON.parse(fs.readFileSync(prefsPath, 'utf8'));
      const notif = parsed?.profile?.content_settings?.exceptions?.notifications;
      if (notif && typeof notif === 'object' && originKey in notif) {
        delete notif[originKey];
        fs.writeFileSync(prefsPath, JSON.stringify(parsed), 'utf8');
        return `Removed notification permission for ${originKey} from ${prefsPath}`;
      }
      return `Notification origin ${originKey} was already absent`;
    }

    case 'reset_proxy': {
      if (meta.proxy_scope === 'winhttp') {
        const res = await execFileSafe('netsh.exe', ['winhttp', 'reset', 'proxy'], { timeoutMs: 10_000 });
        if (res.exitCode !== 0) throw new Error(`netsh winhttp reset proxy failed: ${res.stderr}`);
        return 'Reset WinHTTP system proxy to direct access';
      }
      const hive = String(backup.inverse.params.hive);
      const key = String(backup.inverse.params.key);
      const psKey = `${hiveToPsPrefix(hive)}\\${key}`;
      await runPsChecked(
        `
$ErrorActionPreference = 'Stop'
try {
  Set-ItemProperty -LiteralPath $FCSWEEP_PARAMS.key -Name 'ProxyEnable' -Value 0 -ErrorAction Stop
  Remove-ItemProperty -LiteralPath $FCSWEEP_PARAMS.key -Name 'ProxyServer' -ErrorAction SilentlyContinue
  Remove-ItemProperty -LiteralPath $FCSWEEP_PARAMS.key -Name 'AutoConfigURL' -ErrorAction SilentlyContinue
  @{ ok = $true; data = @{} } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { key: psKey }
      );
      return `Cleared WinINET proxy settings under ${hive}`;
    }

    case 'reset_dns': {
      const alias = meta.adapter_interface_alias!;
      await runPsChecked(
        `
$ErrorActionPreference = 'Stop'
try {
  Set-DnsClientServerAddress -InterfaceAlias $FCSWEEP_PARAMS.alias -ResetServerAddresses -ErrorAction Stop
  @{ ok = $true; data = @{} } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { alias }
      );
      return `Reset DNS servers to automatic (DHCP) on ${alias}`;
    }

    case 'clean_hosts': {
      const hostsPath = String(backup.inverse.params.hosts_path);
      const domain = (meta.hosts_domain ?? '').toLowerCase();
      const origLine = (meta.hosts_line ?? '').trim();
      const lines = fs.readFileSync(hostsPath, 'utf8').split(/\r?\n/);
      const kept = lines.filter((line) => {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) return true;
        if (origLine && trimmed === origLine) return false;
        if (domain) {
          const tokens = trimmed.split('#')[0].trim().split(/\s+/).slice(1).map((t) => t.toLowerCase());
          if (tokens.includes(domain)) return false;
        }
        return true;
      });
      fs.writeFileSync(hostsPath, kept.join('\r\n'), 'utf8');
      return `Removed hosts entry for ${domain || origLine}`;
    }

    case 'remove_defender_exclusion': {
      await runPsChecked(
        `
$ErrorActionPreference = 'Stop'
try {
  $t = $FCSWEEP_PARAMS.ex_type
  $v = $FCSWEEP_PARAMS.ex_value
  switch ($t) {
    'ExclusionPath' { Remove-MpPreference -ExclusionPath $v -ErrorAction Stop }
    'ExclusionProcess' { Remove-MpPreference -ExclusionProcess $v -ErrorAction Stop }
    'ExclusionExtension' { Remove-MpPreference -ExclusionExtension $v -ErrorAction Stop }
    'ExclusionIpAddress' { Remove-MpPreference -ExclusionIpAddress $v -ErrorAction Stop }
    default { throw ("Unknown exclusion type: " + $t) }
  }
  @{ ok = $true; data = @{} } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { ex_type: meta.exclusion_type!, ex_value: meta.exclusion_value! }
      );
      return `Removed Defender ${meta.exclusion_type} exclusion: ${meta.exclusion_value}`;
    }

    case 'remove_root_cert': {
      const store = meta.cert_store || 'LocalMachine\\Root';
      const thumbprint = meta.cert_thumbprint!;
      await runPsChecked(
        `
$ErrorActionPreference = 'Stop'
try {
  $p = 'Cert:\\' + $FCSWEEP_PARAMS.store + '\\' + $FCSWEEP_PARAMS.thumbprint
  Remove-Item -LiteralPath $p -Force -ErrorAction Stop
  @{ ok = $true; data = @{} } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { store, thumbprint }
      );
      return `Removed root certificate ${thumbprint} from Cert:\\${store}`;
    }

    case 'uninstall_program': {
      // Section 8: Does NOT run silently/automatically; opens Settings / Apps & Features or reports uninstall guidance
      const name = finding.untrusted.name || finding.location;
      await execFileSafe('cmd.exe', ['/c', 'start', '', 'ms-settings:appsfeatures'], { timeoutMs: 10_000 });
      return `Opened Windows Installed Apps settings for user-guided uninstall of "${name}" (manual confirmation required)`;
    }

    case 'guide_extension': {
      const extUrl = meta.extension_page_url || 'chrome://extensions';
      const browser = meta.browser || 'Browser';
      const extId = meta.extension_id || finding.location;
      const extName = finding.untrusted.name || extId;
      return `Manual removal required: open ${extUrl} in ${browser} and remove extension "${extName}" (ID: ${extId})`;
    }

    default:
      throw new Error(`Unsupported remediation action: ${action}`);
  }
}

export async function performUndo(entry: ManifestEntry, ctx: ActionContext): Promise<string> {
  if (ctx.hooks?.customExecutor) {
    return ctx.hooks.customExecutor.undo(entry, ctx);
  }

  if (!entry.inverse.reversible) {
    return `Not reversible (${entry.inverse.description})`;
  }

  const p = entry.inverse.params;

  switch (entry.action) {
    case 'disable_autorun': {
      if (p.mode === 'startup_file') {
        await restoreQuarantinedFile(
          String(p.quarantine_path),
          String(p.original_path),
          p.sddl as string | null,
          p.atime_ms as number | undefined,
          p.mtime_ms as number | undefined
        );
        return `Restored Startup file to ${p.original_path}`;
      }
      await importRegistryKeyBackup(String(p.reg_file));
      return `Re-imported autorun registry key from ${p.reg_file}`;
    }

    case 'disable_task': {
      await runPsChecked(
        `
$ErrorActionPreference = 'Stop'
try {
  Enable-ScheduledTask -TaskPath $FCSWEEP_PARAMS.task_path -TaskName $FCSWEEP_PARAMS.task_name -ErrorAction Stop | Out-Null
  @{ ok = $true; data = @{} } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { task_path: String(p.task_path), task_name: String(p.task_name) }
      );
      return `Re-enabled scheduled task ${p.task_path}${p.task_name}`;
    }

    case 'disable_service': {
      const sm = String(p.start_mode || 'Manual');
      const psStartType =
        sm.toLowerCase() === 'auto' || sm.toLowerCase() === 'automatic'
          ? 'Automatic'
          : sm.toLowerCase() === 'disabled'
            ? 'Disabled'
            : 'Manual';
      await runPsChecked(
        `
$ErrorActionPreference = 'Stop'
try {
  Set-Service -Name $FCSWEEP_PARAMS.name -StartupType $FCSWEEP_PARAMS.start_type -ErrorAction Stop
  if ($FCSWEEP_PARAMS.was_running) {
    Start-Service -Name $FCSWEEP_PARAMS.name -ErrorAction SilentlyContinue
  }
  @{ ok = $true; data = @{} } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        {
          name: String(p.service_name),
          start_type: psStartType,
          was_running: String(p.state || '').toLowerCase() === 'running',
        }
      );
      return `Restored service ${p.service_name} to ${psStartType} (prior state: ${p.state})`;
    }

    case 'remove_wmi_subscription': {
      const backupFile = String(p.backup_file);
      if (!fs.existsSync(backupFile)) throw new Error(`WMI backup missing: ${backupFile}`);
      const dump = JSON.parse(fs.readFileSync(backupFile, 'utf8'));
      await runPsChecked(
        `
$ErrorActionPreference = 'Stop'
try {
  $d = $FCSWEEP_PARAMS.dump
  $fObj = $null
  $cObj = $null
  if ($d.filter) {
    $fProps = @{
      Name = [string]$d.filter.Name
      Query = [string]$d.filter.Query
      QueryLanguage = [string]$d.filter.QueryLanguage
      EventNamespace = [string]$d.filter.EventNamespace
    }
    $fObj = New-CimInstance -Namespace 'root\\subscription' -ClassName '__EventFilter' -Property $fProps -ErrorAction Stop
  }
  if ($d.consumer) {
    $cProps = @{}
    foreach ($prop in $d.consumer.PSObject.Properties) {
      if ($null -ne $prop.Value) { $cProps[$prop.Name] = $prop.Value }
    }
    $cObj = New-CimInstance -Namespace 'root\\subscription' -ClassName ([string]$d.consumer_class) -Property $cProps -ErrorAction Stop
  }
  if ($fObj -and $cObj) {
    New-CimInstance -Namespace 'root\\subscription' -ClassName '__FilterToConsumerBinding' -Property @{ Filter = [Ref]$fObj; Consumer = [Ref]$cObj } -ErrorAction Stop | Out-Null
  }
  @{ ok = $true; data = @{} } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { dump }
      );
      return `Recreated WMI event subscription ${p.filter_name} -> ${p.consumer_name}`;
    }

    case 'remove_hijack':
    case 'remove_policy': {
      await importRegistryKeyBackup(String(p.reg_file));
      return `Re-imported registry key from ${p.reg_file}`;
    }

    case 'quarantine_file': {
      await restoreQuarantinedFile(
        String(p.quarantine_path),
        String(p.original_path),
        p.sddl as string | null,
        p.atime_ms as number | undefined,
        p.mtime_ms as number | undefined
      );
      return `Restored file to ${p.original_path}`;
    }

    case 'remove_notification_permission': {
      const browser = String(p.browser || '');
      if (browser && (await isBrowserRunning(browser))) {
        throw new Error(`Close ${browser} before restoring ${p.preferences_path}`);
      }
      const backupFile = String(p.backup_file);
      const prefsPath = String(p.preferences_path);
      if (!fs.existsSync(backupFile)) throw new Error(`Preferences backup missing: ${backupFile}`);
      fs.copyFileSync(backupFile, prefsPath);
      return `Restored browser Preferences to ${prefsPath}`;
    }

    case 'reset_proxy': {
      if (p.scope === 'winhttp') {
        if (p.proxy_server) {
          const res = await execFileSafe('netsh.exe', ['winhttp', 'set', 'proxy', String(p.proxy_server)], {
            timeoutMs: 10_000,
          });
          if (res.exitCode !== 0) throw new Error(`Failed restoring WinHTTP proxy: ${res.stderr}`);
        }
        return 'Restored WinHTTP proxy';
      }
      await importRegistryKeyBackup(String(p.reg_file));
      return `Restored WinINET proxy settings from ${p.reg_file}`;
    }

    case 'reset_dns': {
      const alias = String(p.interface_alias);
      const servers = Array.isArray(p.servers) ? (p.servers as string[]) : [];
      if (servers.length > 0) {
        await runPsChecked(
          `
$ErrorActionPreference = 'Stop'
try {
  Set-DnsClientServerAddress -InterfaceAlias $FCSWEEP_PARAMS.alias -ServerAddresses $FCSWEEP_PARAMS.servers -ErrorAction Stop
  @{ ok = $true; data = @{} } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
          { alias, servers }
        );
      }
      return `Restored DNS servers on ${alias}`;
    }

    case 'clean_hosts': {
      const backupFile = String(p.backup_file);
      const hostsPath = String(p.hosts_path);
      if (!fs.existsSync(backupFile)) throw new Error(`hosts backup missing: ${backupFile}`);
      fs.copyFileSync(backupFile, hostsPath);
      return `Restored hosts file from ${backupFile}`;
    }

    case 'remove_defender_exclusion': {
      await runPsChecked(
        `
$ErrorActionPreference = 'Stop'
try {
  $t = $FCSWEEP_PARAMS.ex_type
  $v = $FCSWEEP_PARAMS.ex_value
  switch ($t) {
    'ExclusionPath' { Add-MpPreference -ExclusionPath $v -ErrorAction Stop }
    'ExclusionProcess' { Add-MpPreference -ExclusionProcess $v -ErrorAction Stop }
    'ExclusionExtension' { Add-MpPreference -ExclusionExtension $v -ErrorAction Stop }
    'ExclusionIpAddress' { Add-MpPreference -ExclusionIpAddress $v -ErrorAction Stop }
    default { throw ("Unknown exclusion type: " + $t) }
  }
  @{ ok = $true; data = @{} } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { ex_type: String(p.exclusion_type), ex_value: String(p.exclusion_value) }
      );
      return `Restored Defender ${p.exclusion_type} exclusion: ${p.exclusion_value}`;
    }

    case 'remove_root_cert': {
      const cerFile = String(p.cer_file);
      const store = String(p.store || 'LocalMachine\\Root');
      if (!fs.existsSync(cerFile)) throw new Error(`Certificate backup missing: ${cerFile}`);
      await runPsChecked(
        `
$ErrorActionPreference = 'Stop'
try {
  Import-Certificate -FilePath $FCSWEEP_PARAMS.cer_file -CertStoreLocation ('Cert:\\' + $FCSWEEP_PARAMS.store) -ErrorAction Stop | Out-Null
  @{ ok = $true; data = @{} } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`,
        { cer_file: cerFile, store }
      );
      return `Re-imported root certificate into Cert:\\${store}`;
    }

    default:
      throw new Error(`No undo handler for action: ${entry.action}`);
  }
}

async function getWindowsFileSddl(filePath: string): Promise<string | null> {
  if (process.platform !== 'win32') return null;
  const res = await runPowerShellJson<{ sddl: string | null }>(
    `
try {
  $acl = Get-Acl -LiteralPath $FCSWEEP_PARAMS.path -ErrorAction Stop
  @{ sddl = $acl.Sddl } | ConvertTo-Json -Compress
} catch {
  @{ sddl = $null } | ConvertTo-Json -Compress
}
`,
    { timeoutMs: 10_000, params: { path: filePath } }
  );
  return res.data?.sddl ?? null;
}

async function setWindowsFileSddl(filePath: string, sddl: string | null): Promise<void> {
  if (process.platform !== 'win32' || !sddl) return;
  await runPowerShellJson(
    `
try {
  $acl = Get-Acl -LiteralPath $FCSWEEP_PARAMS.path -ErrorAction Stop
  $acl.SetSecurityDescriptorSddlForm($FCSWEEP_PARAMS.sddl)
  Set-Acl -LiteralPath $FCSWEEP_PARAMS.path -AclObject $acl -ErrorAction Stop
  @{ ok = $true } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false } | ConvertTo-Json -Compress
}
`,
    { timeoutMs: 10_000, params: { path: filePath, sddl } }
  );
}

async function moveFileToQuarantine(src: string, qPath: string, elevated: boolean): Promise<void> {
  fs.mkdirSync(path.dirname(qPath), { recursive: true });
  try {
    fs.renameSync(src, qPath);
  } catch {
    // Cross-volume fallback: copy + verify hash + unlink
    fs.copyFileSync(src, qPath);
    if (sha256File(src) !== sha256File(qPath)) {
      fs.unlinkSync(qPath);
      throw new Error('Quarantine copy hash mismatch; aborted removal of source file');
    }
    fs.unlinkSync(src);
  }
  if (process.platform === 'win32' && elevated) {
    // Readable by Administrators & SYSTEM only
    await execFileSafe(
      'icacls.exe',
      [qPath, '/inheritance:r', '/grant:r', '*S-1-5-32-544:F', '/grant:r', '*S-1-5-18:F'],
      { timeoutMs: 10_000 }
    );
  } else {
    hardenDirectoryPermissions(path.dirname(qPath), elevated);
    try {
      fs.chmodSync(qPath, 0o600);
    } catch {
      // ignore
    }
  }
}

async function restoreQuarantinedFile(
  qPath: string,
  originalPath: string,
  sddl: string | null,
  atimeMs?: number,
  mtimeMs?: number
): Promise<void> {
  if (!fs.existsSync(qPath)) {
    throw new Error(`Quarantined file missing: ${qPath}`);
  }
  fs.mkdirSync(path.dirname(originalPath), { recursive: true });
  try {
    fs.renameSync(qPath, originalPath);
  } catch {
    fs.copyFileSync(qPath, originalPath);
    fs.unlinkSync(qPath);
  }
  if (sddl) {
    await setWindowsFileSddl(originalPath, sddl);
  }
  if (typeof atimeMs === 'number' && typeof mtimeMs === 'number') {
    try {
      fs.utimesSync(originalPath, new Date(atimeMs), new Date(mtimeMs));
    } catch {
      // ignore
    }
  }
}

async function isBrowserRunning(browser: string): Promise<boolean> {
  if (process.platform !== 'win32') return false;
  const procMap: Record<string, string> = {
    chrome: 'chrome',
    edge: 'msedge',
    brave: 'brave',
    firefox: 'firefox',
  };
  const procName = procMap[browser.toLowerCase()];
  if (!procName) return false;
  const res = await runPowerShellJson<{ running: boolean }>(
    `@{ running = [bool](Get-Process -Name $FCSWEEP_PARAMS.proc -ErrorAction SilentlyContinue) } | ConvertTo-Json -Compress`,
    { timeoutMs: 10_000, params: { proc: procName } }
  );
  return Boolean(res.data?.running);
}
