import fs from 'node:fs';
import path from 'node:path';
import { MSERT_DOWNLOAD_URL } from '../constants.js';
import { execFileSafe } from '../platform/exec.js';
import { runPowerShellJson } from '../platform/powershell.js';
import { isMicrosoftSigner } from '../scoring/protected.js';
import type { DefenderDetection, DefenderScanResult } from '../types.js';

/**
 * Parses %SystemRoot%\debug\msert.log for threat detections recorded during a
 * Microsoft Safety Scanner detect-only run.
 */
export function parseMsertLog(logContent: string): DefenderDetection[] {
  const detections: DefenderDetection[] = [];
  const lines = logContent.split(/\r?\n/);

  // Only inspect the most recent scan block (starts with "Microsoft Safety Scanner v...")
  let startIdx = 0;
  for (let i = lines.length - 1; i >= 0; i--) {
    if (/Microsoft Safety Scanner v/i.test(lines[i])) {
      startIdx = i;
      break;
    }
  }

  let currentThreat: string | null = null;
  let seq = 0;
  for (let i = startIdx; i < lines.length; i++) {
    const line = lines[i].trim();
    const threatMatch = line.match(/Threat Detected:\s*(.+)$/i);
    if (threatMatch) {
      currentThreat = threatMatch[1].trim();
      seq++;
      detections.push({
        threat_id: `msert-${seq}`,
        threat_name: currentThreat,
        resources: [],
        action_taken: 'DetectedOnly',
        source: 'safety_scanner',
      });
      continue;
    }
    const resourceMatch = line.match(/^(?:file|containerfile|regkey|process|startup):(.+)$/i);
    if (resourceMatch && detections.length > 0) {
      detections[detections.length - 1].resources.push(resourceMatch[1].trim());
    }
  }

  return detections;
}

/**
 * Fallback known-threat scanner when Microsoft Defender is unavailable or displaced.
 * Downloads Microsoft Safety Scanner (msert.exe) from Microsoft, verifies its
 * Authenticode signature is valid Microsoft before running, and runs detect-only (/N /Q).
 */
export async function runSafetyScannerFallback(
  sessionDir: string,
  scanType: 'quick' | 'full'
): Promise<DefenderScanResult> {
  const timestamp = new Date().toISOString();
  const toolsDir = path.join(sessionDir, 'backups');
  fs.mkdirSync(toolsDir, { recursive: true });
  const msertPath = path.join(toolsDir, 'msert.exe');

  // 1. Download msert.exe directly from Microsoft via PowerShell TLS 1.2+
  const dlScript = `
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
$url = $FCSWEEP_PARAMS.url
$dest = $FCSWEEP_PARAMS.dest
Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing -MaximumRedirection 5
$sig = Get-AuthenticodeSignature -LiteralPath $dest
[ordered]@{
  exists = (Test-Path -LiteralPath $dest)
  sig_status = [string]$sig.Status
  signer = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Subject } else { $null }
} | ConvertTo-Json -Depth 3 -Compress
`;

  const dlRes = await runPowerShellJson<{ exists: boolean; sig_status: string; signer: string | null }>(dlScript, {
    timeoutMs: 300_000,
    params: { url: MSERT_DOWNLOAD_URL, dest: msertPath },
  });

  if (!dlRes.ok || !dlRes.data?.exists) {
    return {
      timestamp,
      engine: 'safety_scanner',
      scan_type: scanType,
      signature_updated: false,
      status: 'error',
      detections: [],
      error: `Failed to download Microsoft Safety Scanner: ${dlRes.error || dlRes.stderr || 'unknown error'}`,
    };
  }

  // 2. Fail closed if Authenticode signature is NOT valid Microsoft!
  if (dlRes.data.sig_status !== 'Valid' || !isMicrosoftSigner(dlRes.data.signer)) {
    try {
      fs.unlinkSync(msertPath);
    } catch {
      // ignore
    }
    return {
      timestamp,
      engine: 'safety_scanner',
      scan_type: scanType,
      signature_updated: false,
      status: 'error',
      detections: [],
      msert_signer: dlRes.data.signer,
      error: `Refusing to execute msert.exe: Authenticode verification failed (status=${dlRes.data.sig_status}, signer=${dlRes.data.signer ?? 'none'})`,
    };
  }

  // 3. Run in strictly detect-only quiet mode (/N /Q, or /F /N /Q for full)
  const args = scanType === 'full' ? ['/F', '/N', '/Q'] : ['/N', '/Q'];
  const timeoutMs = scanType === 'full' ? 60 * 60 * 1000 : 20 * 60 * 1000;
  const runRes = await execFileSafe(msertPath, args, { timeoutMs });

  const sysRoot = process.env.SystemRoot || 'C:\\Windows';
  const msertLogPath = path.join(sysRoot, 'debug', 'msert.log');
  let detections: DefenderDetection[] = [];
  if (fs.existsSync(msertLogPath)) {
    try {
      const content = fs.readFileSync(msertLogPath, 'utf8');
      detections = parseMsertLog(content);
    } catch {
      // ignore
    }
  }

  // Note: msert.exe returns non-zero (e.g. 2) when threats are detected in detect-only mode
  const failedHard = runRes.timedOut || (runRes.exitCode !== 0 && runRes.exitCode !== 2 && detections.length === 0);

  return {
    timestamp,
    engine: 'safety_scanner',
    scan_type: scanType,
    signature_updated: true,
    status: failedHard ? 'error' : 'ok',
    detections,
    msert_path: msertPath,
    msert_signer: dlRes.data.signer,
    msert_log: fs.existsSync(msertLogPath) ? msertLogPath : null,
    error: failedHard ? runRes.error || `msert.exe exited with code ${runRes.exitCode}` : null,
  };
}
