import type { FileFacts, SigStatus } from '../../types.js';
import { classifyPath } from '../../platform/file-facts.js';

/**
 * Shared Windows PowerShell 5.1 helper functions prepended to collectors that
 * inspect files and loaded user hives.
 *
 * Strictly PowerShell 5.1 compatible (no ternary ?:, no ??, no PS7 parameters).
 */
export const PS_FILE_FACTS_HELPER = `
$script:__fileFactsCache = @{}

function Resolve-TargetPath([string]$raw) {
  if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
  $s = $raw.Trim()
  if ($s.StartsWith('"')) {
    $idx = $s.IndexOf('"', 1)
    if ($idx -gt 1) {
      $s = $s.Substring(1, $idx - 1)
    } else {
      $s = $s.Trim('"')
    }
  } else {
    $m = [regex]::Match($s, '^(.+?\\.(?:exe|dll|sys|scr|com|bat|cmd|vbs|js|ps1|msi|cpl|hta|lnk))(?:\\s|$|,)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($m.Success) {
      $s = $m.Groups[1].Value
    } else {
      $parts = $s -split '\\s+'
      if ($parts.Length -gt 0) { $s = $parts[0] }
    }
  }
  $s = $s.Trim().Trim('"').Trim("'")
  if ($s.StartsWith('\\??\\')) { $s = $s.Substring(4) }
  if ($s.StartsWith('\\\\?\\')) { $s = $s.Substring(4) }
  if ($s -match '^\\\\SystemRoot\\\\') {
    $s = $env:SystemRoot + $s.Substring(11)
  } elseif ($s -match '^System32\\\\') {
    $s = Join-Path $env:SystemRoot $s
  }
  $s = [Environment]::ExpandEnvironmentVariables($s)
  # Resolve bare executable names like svchost.exe or powershell.exe via System32 if needed
  if ($s -notmatch '[\\\\/]' -and $s -match '\\.[A-Za-z0-9]{2,4}$') {
    $cand = Join-Path (Join-Path $env:SystemRoot 'System32') $s
    if (Test-Path -LiteralPath $cand) { $s = $cand }
  }
  return $s
}

function Get-FileFacts([string]$path) {
  if ([string]::IsNullOrWhiteSpace($path)) { return $null }
  $key = $path.ToLowerInvariant()
  if ($script:__fileFactsCache.ContainsKey($key)) {
    return $script:__fileFactsCache[$key]
  }
  $res = [ordered]@{
    target_path = $path
    file_exists = $false
    sha256 = $null
    file_size = $null
    file_created = $null
    file_modified = $null
    sig_status = 'NotApplicable'
    signer = $null
    hidden_attr = $false
    system_attr = $false
  }
  try {
    if (Test-Path -LiteralPath $path -PathType Leaf) {
      $fi = Get-Item -LiteralPath $path -Force -ErrorAction Stop
      $res.target_path = $fi.FullName
      $res.file_exists = $true
      $res.file_size = [int64]$fi.Length
      $res.file_created = $fi.CreationTimeUtc.ToString('o')
      $res.file_modified = $fi.LastWriteTimeUtc.ToString('o')
      $attrs = $fi.Attributes
      $res.hidden_attr = (($attrs -band [System.IO.FileAttributes]::Hidden) -ne 0)
      $res.system_attr = (($attrs -band [System.IO.FileAttributes]::System) -ne 0)
      if ($fi.Length -le 134217728) {
        try {
          $h = Get-FileHash -LiteralPath $fi.FullName -Algorithm SHA256 -ErrorAction Stop
          $res.sha256 = $h.Hash.ToLowerInvariant()
        } catch {}
      }
      try {
        $sig = Get-AuthenticodeSignature -LiteralPath $fi.FullName -ErrorAction Stop
        if ($sig) {
          $st = [string]$sig.Status
          if ($st -eq 'Valid') { $res.sig_status = 'Valid' }
          elseif ($st -eq 'NotSigned') { $res.sig_status = 'NotSigned' }
          elseif ($st -eq 'HashMismatch') { $res.sig_status = 'HashMismatch' }
          elseif ($st -eq 'NotTrusted') { $res.sig_status = 'NotTrusted' }
          else { $res.sig_status = 'UnknownError' }
          if ($sig.SignerCertificate) {
            $res.signer = [string]$sig.SignerCertificate.Subject
          }
        }
      } catch {
        $res.sig_status = 'UnknownError'
      }
    }
  } catch {}
  $script:__fileFactsCache[$key] = $res
  return $res
}

function Get-LoadedUserHives {
  $list = @()
  try {
    $keys = Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue
    foreach ($k in $keys) {
      $name = $k.PSChildName
      if ($name -match '^S-1-5-21-[0-9-]+$' -and ($name -notlike '*_Classes')) {
        $list += $name
      }
    }
  } catch {}
  return $list
}
`;

export interface RawPsFileFacts {
  target_path?: string | null;
  file_exists?: boolean;
  sha256?: string | null;
  file_size?: number | null;
  file_created?: string | null;
  file_modified?: string | null;
  sig_status?: string | null;
  signer?: string | null;
  hidden_attr?: boolean;
  system_attr?: boolean;
}

const VALID_SIG_STATUS = new Set<SigStatus>([
  'Valid',
  'NotSigned',
  'HashMismatch',
  'NotTrusted',
  'UnknownError',
  'AdHoc',
  'NotApplicable',
]);

export function mapPsFileFacts(raw: RawPsFileFacts | null | undefined): FileFacts {
  if (!raw) return {};
  const sig = raw.sig_status && VALID_SIG_STATUS.has(raw.sig_status as SigStatus)
    ? (raw.sig_status as SigStatus)
    : 'NotApplicable';
  return {
    target_path: raw.target_path ?? null,
    file_exists: raw.file_exists,
    sha256: raw.sha256 ?? null,
    file_size: typeof raw.file_size === 'number' ? raw.file_size : null,
    file_created: raw.file_created ?? null,
    file_modified: raw.file_modified ?? null,
    sig_status: sig,
    signer: raw.signer ?? null,
    path_class: raw.target_path ? classifyPath(raw.target_path, 'windows') : undefined,
    hidden_attr: Boolean(raw.hidden_attr),
    system_attr: Boolean(raw.system_attr),
  };
}
