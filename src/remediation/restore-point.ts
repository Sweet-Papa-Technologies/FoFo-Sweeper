import { runPowerShellJson } from '../platform/powershell.js';

export interface RestorePointResult {
  attempted: boolean;
  created: boolean;
  description: string;
  message: string;
  timestamp: string;
}

/**
 * Creates a Windows System Restore point before the first change in a session.
 * If System Protection is off or Windows enforces the 24-hour restore point frequency
 * limit, records that cleanly and allows the manifest-backed fix to proceed.
 */
export async function createSystemRestorePoint(sessionId: string): Promise<RestorePointResult> {
  const description = `FoFo Care Sweep (${sessionId})`;
  const timestamp = new Date().toISOString();

  if (process.platform !== 'win32') {
    return {
      attempted: false,
      created: false,
      description,
      message: 'System Restore points are only supported on Windows',
      timestamp,
    };
  }

  const script = `
$res = [ordered]@{ created = $false; message = '' }
try {
  Checkpoint-Computer -Description $FCSWEEP_PARAMS.desc -RestorePointType 'MODIFY_SETTINGS' -WarningVariable warnVar -ErrorAction Stop
  if ($warnVar -and ($warnVar -join ' ') -match 'already been created|frequency|24') {
    $res.created = $false
    $res.message = ($warnVar -join ' ')
  } else {
    $res.created = $true
    $res.message = 'System Restore point created'
  }
} catch {
  $res.created = $false
  $res.message = $_.Exception.Message
}
$res | ConvertTo-Json -Depth 3 -Compress
`;

  const res = await runPowerShellJson<{ created: boolean; message: string }>(script, {
    timeoutMs: 90_000,
    params: { desc: description },
  });

  if (!res.ok || !res.data) {
    return {
      attempted: true,
      created: false,
      description,
      message: res.error || res.stderr || 'Checkpoint-Computer unavailable (System Protection may be disabled)',
      timestamp,
    };
  }

  return {
    attempted: true,
    created: Boolean(res.data.created),
    description,
    message: res.data.message || (res.data.created ? 'Created' : 'Not created'),
    timestamp,
  };
}
