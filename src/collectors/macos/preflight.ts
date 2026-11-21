import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { VERSION } from '../../constants.js';
import { execFileSafe } from '../../platform/exec.js';
import type { PreflightResult } from '../../types.js';

export async function runMacosPreflight(
  elevated: boolean,
  collectorsRequested: string[]
): Promise<PreflightResult> {
  const [swVers, swBuild, dfRes, profilesStatus] = await Promise.all([
    execFileSafe('sw_vers', ['-productVersion'], { timeoutMs: 5_000 }),
    execFileSafe('sw_vers', ['-buildVersion'], { timeoutMs: 5_000 }),
    execFileSafe('df', ['-k', '/'], { timeoutMs: 5_000 }),
    execFileSafe('profiles', ['status', '-type', 'enrollment'], { timeoutMs: 8_000 }),
  ]);

  let freeDiskBytes: number | null = null;
  const dfLines = dfRes.stdout.trim().split(/\r?\n/);
  if (dfLines.length >= 2) {
    const cols = dfLines[1].trim().split(/\s+/);
    const availKb = Number(cols[3]);
    if (!Number.isNaN(availKb)) freeDiskBytes = availKb * 1024;
  }

  const mdmEnrolled = /MDM enrollment:\s*Yes/i.test(profilesStatus.stdout);

  // Probe Full Disk Access gently by checking readability of ~/Library/Safari
  let fullDiskAccess: boolean | null = null;
  let fdaGuidance: string | null = null;
  const safariDir = path.join(os.homedir(), 'Library', 'Safari');
  if (fs.existsSync(safariDir)) {
    try {
      fs.readdirSync(safariDir);
      fullDiskAccess = true;
    } catch {
      fullDiskAccess = false;
      fdaGuidance =
        'Full Disk Access is not granted to this terminal/process. Grant Full Disk Access in System Settings -> Privacy & Security -> Full Disk Access to inspect Safari data and protected user locations.';
    }
  }

  return {
    timestamp: new Date().toISOString(),
    tool_version: VERSION,
    platform: 'macos',
    hostname: os.hostname(),
    os_version: `macOS ${swVers.stdout.trim() || os.release()}`,
    os_build: swBuild.stdout.trim() || os.release(),
    arch: process.arch,
    elevated,
    pending_reboot: false,
    pending_reboot_reasons: [],
    free_disk_bytes: freeDiskBytes,
    domain_joined: false,
    mdm_enrolled: mdmEnrolled,
    av_products: [],
    defender: {
      available: false,
      active: false,
      mode: 'unavailable',
    },
    collectors_requested: collectorsRequested,
    collectors_skipped: [],
    collectors_partial: [],
    full_disk_access: fullDiskAccess,
    fda_guidance: fdaGuidance,
    ransomware_indicators: [],
  };
}
