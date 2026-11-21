import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { PathClass, PlatformKind } from '../types.js';

const USER_PERSONAL_FOLDERS = [
  'documents',
  'my documents',
  'pictures',
  'my pictures',
  'desktop',
  'onedrive',
  'dropbox',
  'google drive',
  'my drive',
  'iclouddrive',
  'icloud drive',
  'box',
  'box sync',
  'creative cloud files',
  'nextcloud',
  'owncloud',
];

export function normalizeWindowsPath(raw: string | null | undefined): string | null {
  if (!raw) return null;
  let s = raw.trim();
  if (!s) return null;
  // Strip surrounding quotes
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    s = s.slice(1, -1).trim();
  }
  // Handle NT prefixes like \??\C:\... or \\?\C:\... or \SystemRoot\...
  if (s.startsWith('\\??\\') || s.startsWith('\\\\?\\')) {
    s = s.slice(4);
  }
  const sysRoot = process.env.SystemRoot || 'C:\\Windows';
  if (/^\\SystemRoot\\/i.test(s)) {
    s = sysRoot + s.slice('\\SystemRoot'.length);
  } else if (/^System32\\/i.test(s)) {
    s = path.win32.join(sysRoot, s);
  }
  // Expand %VAR% environment variables when running on Windows
  s = s.replace(/%([^%]+)%/g, (match, varName: string) => {
    const val =
      process.env[varName] ??
      process.env[varName.toUpperCase()] ??
      process.env[varName.toLowerCase()];
    return val ?? match;
  });
  return s;
}

/**
 * Extracts the executable path from a Windows command line (quoted or unquoted).
 */
export function extractExecutableFromCommandLine(cmdLine: string | null | undefined): string | null {
  if (!cmdLine) return null;
  const s = cmdLine.trim();
  if (!s) return null;

  if (s.startsWith('"')) {
    const endQuote = s.indexOf('"', 1);
    if (endQuote > 1) {
      return normalizeWindowsPath(s.slice(1, endQuote));
    }
  }

  // Match up to known executable extensions even if path contains spaces (e.g. C:\Program Files\App\foo.exe -arg)
  const exeMatch = s.match(/^(.+?\.(?:exe|dll|sys|scr|com|bat|cmd|vbs|js|ps1|msi|cpl|hta))(?:\s|$|,)/i);
  if (exeMatch) {
    return normalizeWindowsPath(exeMatch[1]);
  }

  // Fallback to first whitespace-delimited token
  const firstToken = s.split(/\s+/)[0];
  return normalizeWindowsPath(firstToken);
}

export function classifyPath(
  filePath: string | null | undefined,
  platform: PlatformKind
): PathClass {
  if (!filePath) return 'other';
  const normalized = filePath.replace(/\//g, '\\').toLowerCase();

  if (platform === 'windows') {
    // Check user personal & cloud-sync folders FIRST so protected checks align cleanly
    if (isPersonalOrCloudPath(filePath, 'windows')) {
      return 'user_personal';
    }
    if (
      /^[a-z]:\\windows(\\|$)/.test(normalized) ||
      /^[a-z]:\\programdata\\microsoft\\windows defender(\\|$)/.test(normalized) ||
      normalized.startsWith('\\systemroot\\') ||
      normalized.startsWith('%systemroot%\\') ||
      normalized.startsWith('%windir%\\')
    ) {
      return 'windows_system';
    }
    if (
      /^[a-z]:\\program files( \(x86\))?\\/.test(normalized)
    ) {
      return 'program_files';
    }
    if (
      /\\appdata\\/.test(normalized) ||
      /\\temp\\/.test(normalized) ||
      /\\tmp\\/.test(normalized) ||
      /^[a-z]:\\programdata\\/.test(normalized) ||
      /^[a-z]:\\users\\public\\/.test(normalized) ||
      /\\downloads\\/.test(normalized) ||
      /\\\$recycle\.bin\\/.test(normalized) ||
      /^[a-z]:\\windows\\temp\\/.test(normalized) ||
      /^[a-z]:\\windows\\tasks\\/.test(normalized)
    ) {
      return 'user_writable';
    }
    return 'other';
  }

  // macOS / POSIX
  const posix = filePath.replace(/\\/g, '/').toLowerCase();
  if (isPersonalOrCloudPath(filePath, platform)) {
    return 'user_personal';
  }
  if (
    posix.startsWith('/system/') ||
    posix.startsWith('/usr/bin/') ||
    posix.startsWith('/usr/sbin/') ||
    posix.startsWith('/usr/libexec/') ||
    posix.startsWith('/bin/') ||
    posix.startsWith('/sbin/')
  ) {
    return 'macos_system';
  }
  if (posix.startsWith('/applications/') || posix.startsWith('/library/apple/')) {
    return 'macos_applications';
  }
  if (
    posix.startsWith('/tmp/') ||
    posix.startsWith('/private/tmp/') ||
    posix.startsWith('/var/tmp/') ||
    posix.startsWith('/private/var/tmp/') ||
    posix.startsWith('/users/shared/') ||
    /\/users\/[^/]+\/downloads\//.test(posix) ||
    /\/users\/[^/]+\/\./.test(posix) ||
    /\/users\/[^/]+\/library\/application support\//.test(posix) ||
    /\/users\/[^/]+\/library\/caches\//.test(posix) ||
    /\/users\/[^/]+\/library\/launchagents\//.test(posix) ||
    /\/\.[^/]+\//.test(posix)
  ) {
    return 'user_writable';
  }
  return 'other';
}

export function isPersonalOrCloudPath(
  filePath: string | null | undefined,
  platform: PlatformKind
): boolean {
  if (!filePath) return false;
  const segments = filePath
    .replace(/\\/g, '/')
    .toLowerCase()
    .split('/')
    .filter(Boolean);

  if (platform === 'windows') {
    // Match C:\Users\<user>\<PersonalOrCloudFolder>\...
    const usersIdx = segments.indexOf('users');
    if (usersIdx >= 0 && segments.length > usersIdx + 2) {
      const sub = segments[usersIdx + 2];
      if (
        USER_PERSONAL_FOLDERS.includes(sub) ||
        sub.startsWith('onedrive - ') ||
        sub.startsWith('onedrive-')
      ) {
        return true;
      }
      // Also check nested cloud folders like Mobile Documents (iCloud) or Google Drive
      if (sub === 'library' && segments[usersIdx + 3] === 'mobile documents') {
        return true;
      }
    }
    return false;
  }

  // macOS: /Users/<user>/Documents, Desktop, Pictures, Library/Mobile Documents, Library/CloudStorage
  const usersIdx = segments.indexOf('users');
  if (usersIdx >= 0 && segments.length > usersIdx + 2) {
    const sub = segments[usersIdx + 2];
    if (
      USER_PERSONAL_FOLDERS.includes(sub) ||
      sub.startsWith('onedrive - ') ||
      sub.startsWith('onedrive-')
    ) {
      return true;
    }
    if (
      sub === 'library' &&
      (segments[usersIdx + 3] === 'mobile documents' || segments[usersIdx + 3] === 'cloudstorage')
    ) {
      return true;
    }
  }
  return false;
}

export function hashFileSha256(filePath: string): string | null {
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) return null;
    // Cap hashing at 256 MB to stay responsive on huge files
    if (stat.size > 256 * 1024 * 1024) return null;
    const hash = crypto.createHash('sha256');
    const fd = fs.openSync(filePath, 'r');
    const buf = Buffer.allocUnsafe(64 * 1024);
    try {
      let bytesRead = 0;
      while ((bytesRead = fs.readSync(fd, buf, 0, buf.length, null)) > 0) {
        hash.update(buf.subarray(0, bytesRead));
      }
    } finally {
      fs.closeSync(fd);
    }
    return hash.digest('hex');
  } catch {
    return null;
  }
}

export function getBasenameLower(filePath: string | null | undefined): string {
  if (!filePath) return '';
  const cleaned = filePath.replace(/\\/g, '/');
  const idx = cleaned.lastIndexOf('/');
  return (idx >= 0 ? cleaned.slice(idx + 1) : cleaned).toLowerCase();
}
