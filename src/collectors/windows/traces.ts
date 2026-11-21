import fs from 'node:fs';
import path from 'node:path';
import { ensureArray, runPowerShellJson } from '../../platform/powershell.js';
import { matchesTracePasteExec } from '../../scoring/engine.js';
import type { CollectedItem, CollectorRunResult } from '../../types.js';
import { PS_FILE_FACTS_HELPER } from './ps-common.js';

interface RawRunMru {
  hive: string;
  value_name: string;
  command: string;
  location: string;
}

export async function collectWindowsTraces(timeoutMs: number): Promise<CollectorRunResult> {
  const start = Date.now();
  const script = `
${PS_FILE_FACTS_HELPER}

$entries = @()
$sub = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU'

function Read-RunMru([string]$hiveLabel, [string]$psPath) {
  if (-not (Test-Path -LiteralPath $psPath)) { return }
  try {
    $k = Get-Item -LiteralPath $psPath -ErrorAction Stop
    foreach ($vn in $k.GetValueNames()) {
      if ($vn -eq 'MRUList' -or [string]::IsNullOrEmpty($vn)) { continue }
      $val = [string]$k.GetValue($vn)
      if ([string]::IsNullOrWhiteSpace($val)) { continue }
      $clean = $val -replace '\\\\1$', ''
      $script:entries += [ordered]@{
        hive = $hiveLabel
        value_name = $vn
        command = $clean
        location = ($hiveLabel + '\\' + $script:sub + '\\' + $vn)
      }
    }
  } catch {}
}

$userSids = Get-LoadedUserHives
if ($userSids.Count -eq 0) {
  Read-RunMru 'HKCU' ('Registry::HKEY_CURRENT_USER\\' + $sub)
} else {
  foreach ($sid in $userSids) {
    Read-RunMru ('HKU\\' + $sid) ('Registry::HKEY_USERS\\' + $sid + '\\' + $sub)
  }
}

ConvertTo-Json -InputObject @($entries) -Depth 4 -Compress
`;

  const res = await runPowerShellJson<RawRunMru[]>(script, { timeoutMs });
  const warnings: string[] = [];
  if (!res.ok) {
    warnings.push(`RunMRU query error: ${res.error ?? 'unknown'}`);
  }

  const items: CollectedItem[] = [];

  for (const r of ensureArray(res.data)) {
    const matched = matchesTracePasteExec(r.command);
    items.push({
      collector: 'traces',
      kind: 'run_mru',
      location: r.location,
      facts: {
        trace_source: 'Explorer\\RunMRU',
        trace_paste_match: matched,
      },
      untrusted: {
        name: `RunMRU:${r.value_name}`,
        command_line: r.command,
      },
      command_inspect: r.command,
    });
  }

  // Read PowerShell PSReadLine ConsoleHost_history.txt across user profiles
  const sysDrive = process.env.SystemDrive || 'C:';
  const usersRoot = path.join(sysDrive + '\\', 'Users');
  try {
    for (const ue of fs.readdirSync(usersRoot, { withFileTypes: true })) {
      if (!ue.isDirectory()) continue;
      if (['Default', 'Default User', 'All Users', 'Public'].includes(ue.name)) continue;
      const histFile = path.join(
        usersRoot,
        ue.name,
        'AppData',
        'Roaming',
        'Microsoft',
        'Windows',
        'PowerShell',
        'PSReadLine',
        'ConsoleHost_history.txt'
      );
      if (!fs.existsSync(histFile)) continue;
      try {
        const content = fs.readFileSync(histFile, 'utf8');
        const lines = content.split(/\r?\n/);
        // Inspect the last 500 lines and record any paste-exec hits
        const startIdx = Math.max(0, lines.length - 500);
        for (let i = startIdx; i < lines.length; i++) {
          const line = lines[i].trim();
          if (!line) continue;
          if (matchesTracePasteExec(line)) {
            items.push({
              collector: 'traces',
              kind: 'ps_history',
              location: `${histFile}:L${i + 1}`,
              facts: {
                trace_source: 'ConsoleHost_history.txt',
                trace_paste_match: true,
              },
              untrusted: {
                name: `PSReadLine history line ${i + 1}`,
                command_line: line,
              },
              command_inspect: line,
            });
          }
        }
      } catch {
        // ignore unreadable other-user profile if non-elevated
      }
    }
  } catch (err) {
    warnings.push(`PSReadLine history enumeration warning: ${err instanceof Error ? err.message : String(err)}`);
  }

  return {
    collector: 'traces',
    status: warnings.length > 0 ? 'partial' : 'ok',
    duration_ms: Date.now() - start,
    item_count: items.length,
    items,
    warnings,
  };
}
