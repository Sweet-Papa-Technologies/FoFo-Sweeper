import { ensureArray, runPowerShellJson } from '../../platform/powershell.js';
import type { CollectedItem, CollectorRunResult } from '../../types.js';
import { mapPsFileFacts, PS_FILE_FACTS_HELPER, type RawPsFileFacts } from './ps-common.js';

interface RawService {
  kind: 'service' | 'kernel_driver';
  name: string;
  display_name?: string | null;
  description?: string | null;
  path_name?: string | null;
  service_dll?: string | null;
  start_mode?: string | null;
  state?: string | null;
  start_name?: string | null;
  is_boot_start?: boolean;
  file_facts?: RawPsFileFacts | null;
}

export async function collectWindowsServices(timeoutMs: number): Promise<CollectorRunResult> {
  const start = Date.now();
  const script = `
${PS_FILE_FACTS_HELPER}

$items = @()

# Win32 Services
$svcs = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue
foreach ($s in @($svcs)) {
  if (-not $s) { continue }
  $pathName = [string]$s.PathName
  $svcDll = $null
  try {
    $paramPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\' + $s.Name + '\\Parameters'
    if (Test-Path -LiteralPath $paramPath) {
      $p = Get-ItemProperty -LiteralPath $paramPath -Name ServiceDll -ErrorAction SilentlyContinue
      if ($p -and $p.ServiceDll) {
        $svcDll = [Environment]::ExpandEnvironmentVariables([string]$p.ServiceDll)
      }
    }
  } catch {}

  $targetRaw = if ($svcDll) { $svcDll } else { $pathName }
  $resolved = Resolve-TargetPath $targetRaw
  $ff = Get-FileFacts $resolved

  $items += [ordered]@{
    kind = 'service'
    name = [string]$s.Name
    display_name = [string]$s.DisplayName
    description = [string]$s.Description
    path_name = $pathName
    service_dll = $svcDll
    start_mode = [string]$s.StartMode
    state = [string]$s.State
    start_name = [string]$s.StartName
    is_boot_start = $false
    file_facts = $ff
  }
}

# Kernel Drivers (report-only; protected, except boot-start malicious triggers stop condition)
$drvs = Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction SilentlyContinue
foreach ($d in @($drvs)) {
  if (-not $d) { continue }
  $pathName = [string]$d.PathName
  $resolved = Resolve-TargetPath $pathName
  $ff = Get-FileFacts $resolved
  $sm = [string]$d.StartMode
  $items += [ordered]@{
    kind = 'kernel_driver'
    name = [string]$d.Name
    display_name = [string]$d.DisplayName
    description = [string]$d.Description
    path_name = $pathName
    service_dll = $null
    start_mode = $sm
    state = [string]$d.State
    start_name = 'SYSTEM'
    is_boot_start = ($sm -ieq 'Boot')
    file_facts = $ff
  }
}

ConvertTo-Json -InputObject @($items) -Depth 6 -Compress
`;

  const res = await runPowerShellJson<RawService[]>(script, { timeoutMs });
  const durationMs = Date.now() - start;
  if (!res.ok) {
    return {
      collector: 'services',
      status: 'error',
      duration_ms: durationMs,
      item_count: 0,
      items: [],
      warnings: [],
      error: res.error || res.stderr || 'services collector failed',
    };
  }

  const items: CollectedItem[] = ensureArray(res.data).map((r) => {
    const fileFacts = mapPsFileFacts(r.file_facts);
    const isDriver = r.kind === 'kernel_driver';
    return {
      collector: 'services',
      kind: r.kind,
      location: `HKLM\\SYSTEM\\CurrentControlSet\\Services\\${r.name}`,
      facts: {
        ...fileFacts,
        runs_as: r.start_name ?? null,
        start_mode: r.start_mode ?? null,
        service_state: r.state ?? null,
        is_kernel_driver: isDriver,
        is_boot_start: Boolean(r.is_boot_start),
      },
      untrusted: {
        name: r.display_name ?? r.name ?? null,
        description: r.description ?? null,
        command_line: r.path_name ?? null,
      },
      command_inspect: r.path_name ?? null,
      remediation_meta: isDriver
        ? undefined
        : {
            service_name: r.name,
            service_start_mode: r.start_mode ?? undefined,
            service_state: r.state ?? undefined,
            target_file_path: fileFacts.target_path ?? undefined,
          },
    };
  });

  return {
    collector: 'services',
    status: 'ok',
    duration_ms: durationMs,
    item_count: items.length,
    items,
    warnings: [],
  };
}
