import { spawnSync } from 'node:child_process';

let cachedElevation: boolean | null = null;

export function isElevated(): boolean {
  if (cachedElevation !== null) return cachedElevation;

  if (process.platform === 'win32') {
    try {
      // `fltmc` or PowerShell WindowsPrincipal check; net session is fast and built-in,
      // and PowerShell WindowsPrincipal is definitive even when Server service is stopped.
      const ps = spawnSync(
        'powershell.exe',
        [
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          '([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)',
        ],
        { encoding: 'utf8', windowsHide: true, timeout: 10_000 }
      );
      cachedElevation = ps.stdout?.trim().toLowerCase() === 'true';
    } catch {
      cachedElevation = false;
    }
    return cachedElevation;
  }

  cachedElevation = typeof process.getuid === 'function' ? process.getuid() === 0 : false;
  return cachedElevation;
}

export function resetElevationCache(): void {
  cachedElevation = null;
}
