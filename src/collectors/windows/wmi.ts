import { ensureArray, runPowerShellJson } from '../../platform/powershell.js';
import type { CollectedItem, CollectorRunResult } from '../../types.js';
import { mapPsFileFacts, PS_FILE_FACTS_HELPER, type RawPsFileFacts } from './ps-common.js';

interface RawWmiSub {
  filter_name: string;
  filter_query?: string | null;
  consumer_name: string;
  consumer_class: string;
  command_line?: string | null;
  executable_path?: string | null;
  script_text?: string | null;
  binding_path?: string | null;
  file_facts?: RawPsFileFacts | null;
}

export async function collectWindowsWmi(timeoutMs: number): Promise<CollectorRunResult> {
  const start = Date.now();
  const script = `
${PS_FILE_FACTS_HELPER}

$items = @()
$filters = @{}
foreach ($f in @(Get-CimInstance -Namespace 'root\\subscription' -ClassName '__EventFilter' -ErrorAction SilentlyContinue)) {
  if ($f -and $f.Name) { $filters[$f.Name] = $f }
}

$consumers = @{}
foreach ($c in @(Get-CimInstance -Namespace 'root\\subscription' -ClassName '__EventConsumer' -ErrorAction SilentlyContinue)) {
  if ($c -and $c.Name) { $consumers[$c.Name] = $c }
}

$bindings = @(Get-CimInstance -Namespace 'root\\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue)
foreach ($b in $bindings) {
  if (-not $b) { continue }
  $fName = if ($b.Filter -and $b.Filter.Name) { [string]$b.Filter.Name } else { [string]$b.Filter }
  $cName = if ($b.Consumer -and $b.Consumer.Name) { [string]$b.Consumer.Name } else { [string]$b.Consumer }

  # Ignore Windows built-in SCM Event Log Consumer (standard OS component)
  if ($fName -eq 'SCM Event Log Filter' -and $cName -eq 'SCM Event Log Consumer') { continue }

  $fObj = $filters[$fName]
  $cObj = $consumers[$cName]
  $cClass = if ($cObj) { [string]$cObj.CimClass.CimClassName } else { 'UnknownConsumer' }
  $cmdLine = $null
  $exePath = $null
  $scriptText = $null

  if ($cObj) {
    if ($cObj.PSObject.Properties['CommandLineTemplate']) { $cmdLine = [string]$cObj.CommandLineTemplate }
    if ($cObj.PSObject.Properties['ExecutablePath']) { $exePath = [string]$cObj.ExecutablePath }
    if ($cObj.PSObject.Properties['ScriptText']) { $scriptText = [string]$cObj.ScriptText }
    if ($cObj.PSObject.Properties['ScriptFileName'] -and -not $exePath) { $exePath = [string]$cObj.ScriptFileName }
  }

  $targetRaw = if ($exePath) { $exePath } elseif ($cmdLine) { $cmdLine } else { $null }
  $resolved = Resolve-TargetPath $targetRaw
  $ff = Get-FileFacts $resolved

  $items += [ordered]@{
    filter_name = $fName
    filter_query = if ($fObj) { [string]$fObj.Query } else { $null }
    consumer_name = $cName
    consumer_class = $cClass
    command_line = if ($cmdLine) { $cmdLine } elseif ($exePath) { $exePath } else { $scriptText }
    executable_path = $exePath
    script_text = $scriptText
    binding_path = ($fName + ' -> ' + $cName)
    file_facts = $ff
  }
}

ConvertTo-Json -InputObject @($items) -Depth 6 -Compress
`;

  const res = await runPowerShellJson<RawWmiSub[]>(script, { timeoutMs });
  const durationMs = Date.now() - start;
  if (!res.ok) {
    return {
      collector: 'wmi',
      status: 'error',
      duration_ms: durationMs,
      item_count: 0,
      items: [],
      warnings: [],
      error: res.error || res.stderr || 'wmi collector failed',
    };
  }

  const items: CollectedItem[] = ensureArray(res.data).map((r) => {
    const fileFacts = mapPsFileFacts(r.file_facts);
    return {
      collector: 'wmi',
      kind: 'wmi_subscription',
      location: `root\\subscription:${r.filter_name}->${r.consumer_name}`,
      facts: {
        ...fileFacts,
        runs_as: 'SYSTEM',
      },
      untrusted: {
        name: `${r.filter_name} -> ${r.consumer_name}`,
        description: r.filter_query ?? null,
        command_line: r.command_line ?? null,
      },
      command_inspect: r.command_line ?? r.script_text ?? null,
      remediation_meta: {
        wmi_filter_name: r.filter_name,
        wmi_consumer_name: r.consumer_name,
        wmi_consumer_class: r.consumer_class,
        wmi_binding_path: r.binding_path ?? undefined,
        target_file_path: fileFacts.target_path ?? undefined,
      },
    };
  });

  return {
    collector: 'wmi',
    status: 'ok',
    duration_ms: durationMs,
    item_count: items.length,
    items,
    warnings: [],
  };
}
