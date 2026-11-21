import { ensureArray, runPowerShellJson } from '../../platform/powershell.js';
import type { CollectedItem, CollectorRunResult } from '../../types.js';
import { mapPsFileFacts, PS_FILE_FACTS_HELPER, type RawPsFileFacts } from './ps-common.js';

interface RawProcess {
  pid: number;
  ppid: number;
  name: string;
  executable_path?: string | null;
  command_line?: string | null;
  creation_date?: string | null;
  session_id?: number | null;
  listening_ports?: number[];
  file_facts?: RawPsFileFacts | null;
}

export async function collectWindowsProcesses(timeoutMs: number): Promise<CollectorRunResult> {
  const start = Date.now();
  const script = `
${PS_FILE_FACTS_HELPER}

$portsByPid = @{}
try {
  foreach ($c in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
    $pidKey = [int]$c.OwningProcess
    if (-not $portsByPid.ContainsKey($pidKey)) { $portsByPid[$pidKey] = @() }
    if ($portsByPid[$pidKey] -notcontains [int]$c.LocalPort) {
      $portsByPid[$pidKey] += [int]$c.LocalPort
    }
  }
} catch {}
try {
  foreach ($u in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
    $pidKey = [int]$u.OwningProcess
    if ($pidKey -le 4) { continue }
    if (-not $portsByPid.ContainsKey($pidKey)) { $portsByPid[$pidKey] = @() }
    if ($portsByPid[$pidKey] -notcontains [int]$u.LocalPort) {
      $portsByPid[$pidKey] += [int]$u.LocalPort
    }
  }
} catch {}

$items = @()
$procs = Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue
foreach ($p in @($procs)) {
  if (-not $p) { continue }
  $pidVal = [int]$p.ProcessId
  if ($pidVal -le 4) { continue }
  $exe = [string]$p.ExecutablePath
  $cmd = [string]$p.CommandLine
  $resolved = if ($exe) { Resolve-TargetPath $exe } else { Resolve-TargetPath $cmd }
  $ff = Get-FileFacts $resolved

  $created = $null
  if ($p.CreationDate) {
    try { $created = ([DateTime]$p.CreationDate).ToUniversalTime().ToString('o') } catch {}
  }

  $ports = if ($portsByPid.ContainsKey($pidVal)) { @($portsByPid[$pidVal] | Sort-Object) } else { @() }

  $items += [ordered]@{
    pid = $pidVal
    ppid = [int]$p.ParentProcessId
    name = [string]$p.Name
    executable_path = $exe
    command_line = $cmd
    creation_date = $created
    session_id = [int]$p.SessionId
    listening_ports = $ports
    file_facts = $ff
  }
}

ConvertTo-Json -InputObject @($items) -Depth 6 -Compress
`;

  const res = await runPowerShellJson<RawProcess[]>(script, { timeoutMs });
  const durationMs = Date.now() - start;
  if (!res.ok) {
    return {
      collector: 'processes',
      status: 'error',
      duration_ms: durationMs,
      item_count: 0,
      items: [],
      warnings: [],
      error: res.error || res.stderr || 'processes collector failed',
    };
  }

  const items: CollectedItem[] = ensureArray(res.data).map((r) => {
    const fileFacts = mapPsFileFacts(r.file_facts);
    return {
      collector: 'processes',
      kind: 'process',
      location: `pid:${r.pid} (${r.name})`,
      facts: {
        ...fileFacts,
        pid: r.pid,
        ppid: r.ppid,
        session_id: r.session_id ?? null,
        listening_ports: ensureArray(r.listening_ports),
      },
      untrusted: {
        name: r.name,
        command_line: r.command_line ?? null,
      },
      command_inspect: r.command_line ?? null,
      remediation_meta: {
        pid: r.pid,
        target_file_path: fileFacts.target_path ?? undefined,
      },
    };
  });

  return {
    collector: 'processes',
    status: 'ok',
    duration_ms: durationMs,
    item_count: items.length,
    items,
    warnings: [],
  };
}
