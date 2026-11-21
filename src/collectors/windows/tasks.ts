import { ensureArray, runPowerShellJson } from '../../platform/powershell.js';
import type { CollectedItem, CollectorRunResult } from '../../types.js';
import { mapPsFileFacts, PS_FILE_FACTS_HELPER, type RawPsFileFacts } from './ps-common.js';

interface RawTask {
  task_path: string;
  task_name: string;
  location: string;
  state: string;
  execute?: string | null;
  arguments?: string | null;
  command_line?: string | null;
  triggers?: string | null;
  runs_as?: string | null;
  run_level?: string | null;
  hidden?: boolean;
  author?: string | null;
  description?: string | null;
  registration_date?: string | null;
  file_facts?: RawPsFileFacts | null;
}

export async function collectWindowsTasks(timeoutMs: number): Promise<CollectorRunResult> {
  const start = Date.now();
  const script = `
${PS_FILE_FACTS_HELPER}

$items = @()
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
foreach ($t in @($tasks)) {
  if (-not $t) { continue }
  $stateStr = [string]$t.State
  if ($stateStr -eq 'Disabled') { continue }
  $execActions = @($t.Actions | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskExecAction' -or $_.Execute })
  if ($execActions.Count -eq 0) { continue }

  $first = $execActions[0]
  $exe = [string]$first.Execute
  $args = [string]$first.Arguments
  $cmdLine = ($exe + ' ' + $args).Trim()
  $resolved = Resolve-TargetPath $exe
  $ff = Get-FileFacts $resolved

  $trigList = @()
  foreach ($tr in @($t.Triggers)) {
    if ($tr -and $tr.CimClass) { $trigList += $tr.CimClass.CimClassName }
  }

  $regDate = $null
  if ($t.Date) {
    try { $regDate = ([DateTime]$t.Date).ToUniversalTime().ToString('o') } catch { $regDate = [string]$t.Date }
  }

  $runsAs = $null
  $runLevel = $null
  if ($t.Principal) {
    $runsAs = if ($t.Principal.UserId) { [string]$t.Principal.UserId } elseif ($t.Principal.GroupId) { [string]$t.Principal.GroupId } else { $null }
    $runLevel = [string]$t.Principal.RunLevel
  }

  $hidden = $false
  if ($t.Settings -and $t.Settings.Hidden) { $hidden = [bool]$t.Settings.Hidden }

  $items += [ordered]@{
    task_path = [string]$t.TaskPath
    task_name = [string]$t.TaskName
    location = ([string]$t.TaskPath + [string]$t.TaskName)
    state = $stateStr
    execute = $exe
    arguments = $args
    command_line = $cmdLine
    triggers = ($trigList -join ',')
    runs_as = $runsAs
    run_level = $runLevel
    hidden = $hidden
    author = [string]$t.Author
    description = [string]$t.Description
    registration_date = $regDate
    file_facts = $ff
  }
}

ConvertTo-Json -InputObject @($items) -Depth 6 -Compress
`;

  const res = await runPowerShellJson<RawTask[]>(script, { timeoutMs });
  const durationMs = Date.now() - start;
  if (!res.ok) {
    return {
      collector: 'tasks',
      status: 'error',
      duration_ms: durationMs,
      item_count: 0,
      items: [],
      warnings: [],
      error: res.error || res.stderr || 'tasks collector failed',
    };
  }

  const items: CollectedItem[] = ensureArray(res.data).map((r) => {
    const fileFacts = mapPsFileFacts(r.file_facts);
    return {
      collector: 'tasks',
      kind: 'scheduled_task',
      location: r.location,
      facts: {
        ...fileFacts,
        runs_as: r.runs_as ?? null,
        hidden_task: Boolean(r.hidden),
        entry_created: r.registration_date ?? null,
      },
      untrusted: {
        name: r.task_name ?? null,
        description: r.description ?? null,
        publisher: r.author ?? null,
        command_line: r.command_line ?? null,
      },
      command_inspect: r.command_line ?? null,
      remediation_meta: {
        task_path: r.task_path,
        task_name: r.task_name,
        target_file_path: fileFacts.target_path ?? undefined,
      },
    };
  });

  return {
    collector: 'tasks',
    status: 'ok',
    duration_ms: durationMs,
    item_count: items.length,
    items,
    warnings: [],
  };
}
