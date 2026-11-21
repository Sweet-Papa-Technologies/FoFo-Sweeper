import { execFileSafe, type ExecResult } from './exec.js';

export interface PowerShellOptions {
  timeoutMs?: number;
  params?: Record<string, unknown>;
}

const PS_PREAMBLE = [
  '[Console]::InputEncoding = [System.Text.Encoding]::UTF8',
  '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8',
  '$OutputEncoding = [System.Text.Encoding]::UTF8',
  '$ProgressPreference = "SilentlyContinue"',
  '$ErrorActionPreference = "SilentlyContinue"',
  '$FCSWEEP_PARAMS = $null',
  'if ($env:FCSWEEP_PARAMS_B64) {',
  '  $FCSWEEP_PARAMS = ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:FCSWEEP_PARAMS_B64)) | ConvertFrom-Json)',
  '}',
].join('\n');

/**
 * Executes a Windows PowerShell 5.1 script via -EncodedCommand (UTF-16LE Base64).
 * Parameters are passed safely via FCSWEEP_PARAMS_B64 so untrusted machine data
 * is never interpolated into shell/script source.
 */
export async function runPowerShell(
  script: string,
  options: PowerShellOptions = {}
): Promise<ExecResult> {
  const fullScript = `${PS_PREAMBLE}\n${script}`;
  const encoded = Buffer.from(fullScript, 'utf16le').toString('base64');

  const env: NodeJS.ProcessEnv = { ...process.env };
  if (options.params !== undefined) {
    env.FCSWEEP_PARAMS_B64 = Buffer.from(JSON.stringify(options.params), 'utf8').toString('base64');
  } else {
    delete env.FCSWEEP_PARAMS_B64;
  }

  return execFileSafe(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded],
    {
      timeoutMs: options.timeoutMs ?? 60_000,
      env,
    }
  );
}

function cleanPsError(stderr: string, fallback?: string): string {
  const cleaned = (stderr || '')
    .replace(/^#< CLIXML[\r\n]*/i, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/_x000[DA]_/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (cleaned) return cleaned.slice(0, 300);
  return (fallback || 'PowerShell command failed')
    .replace(/-EncodedCommand\s+[A-Za-z0-9+/=]+/g, '-EncodedCommand <redacted>')
    .slice(0, 300);
}

/**
 * Runs a PowerShell script expected to print a single JSON value on stdout.
 * Extracts the JSON cleanly even if PowerShell emitted stray warning lines before it.
 */
export async function runPowerShellJson<T>(
  script: string,
  options: PowerShellOptions = {}
): Promise<{ ok: boolean; data: T | null; stderr: string; error?: string; timedOut: boolean }> {
  const res = await runPowerShell(script, options);
  if (res.timedOut) {
    return { ok: false, data: null, stderr: res.stderr, error: res.error, timedOut: true };
  }
  const raw = res.stdout.replace(/^\uFEFF/, '').trim();
  if (!raw) {
    if (res.exitCode !== 0 && (res.error || res.stderr)) {
      return {
        ok: false,
        data: null,
        stderr: res.stderr,
        error: cleanPsError(res.stderr, res.error),
        timedOut: false,
      };
    }
    return { ok: true, data: null, stderr: res.stderr, timedOut: false };
  }

  try {
    const parsed = JSON.parse(raw) as T;
    return { ok: true, data: parsed, stderr: res.stderr, timedOut: false };
  } catch {
    // Attempt to locate JSON start if PowerShell printed noise ahead of payload
    const firstObj = raw.indexOf('{');
    const firstArr = raw.indexOf('[');
    const starts = [firstObj, firstArr].filter((i) => i >= 0);
    if (starts.length > 0) {
      const idx = Math.min(...starts);
      try {
        const parsed = JSON.parse(raw.slice(idx)) as T;
        return { ok: true, data: parsed, stderr: res.stderr, timedOut: false };
      } catch {
        // fall through
      }
    }
    return {
      ok: false,
      data: null,
      stderr: res.stderr,
      error: `Failed to parse PowerShell JSON output: ${raw.slice(0, 240)}`,
      timedOut: false,
    };
  }
}

export function ensureArray<T>(val: T | T[] | null | undefined): T[] {
  if (val === null || val === undefined) return [];
  return Array.isArray(val) ? val : [val];
}
