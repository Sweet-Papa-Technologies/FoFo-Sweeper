import path from 'node:path';
import type { AvProductInfo, CollectedItem, PlatformKind } from '../types.js';
import { isPersonalOrCloudPath } from '../platform/file-facts.js';

export interface ProtectedContext {
  platform: PlatformKind;
  avProducts: AvProductInfo[];
  toolPaths: string[];
  sessionRoot: string;
}

export interface ProtectedCheckOptions {
  /** Persistence entry abusing a Windows LOLBin (e.g. scheduled task running powershell -enc) */
  isLolbinAbuse?: boolean;
}

export interface ProtectedCheckResult {
  protected: boolean;
  reason?: string;
}

function normPath(p: string | null | undefined): string {
  if (!p) return '';
  return p.replace(/\//g, '\\').toLowerCase().replace(/\\+$/, '');
}

function isInsideDir(filePath: string, dirPath: string): boolean {
  const f = normPath(filePath);
  const d = normPath(dirPath);
  if (!f || !d) return false;
  return f === d || f.startsWith(d + '\\');
}

export function isMicrosoftSigner(signer: string | null | undefined): boolean {
  if (!signer) return false;
  const s = signer.toLowerCase();
  return (
    s.includes('o=microsoft corporation') ||
    s.includes('cn=microsoft windows') ||
    s.includes('cn=microsoft corporation') ||
    s.includes('microsoft windows publisher') ||
    s.includes('microsoft windows production')
  );
}

export function isAppleSigner(signer: string | null | undefined): boolean {
  if (!signer) return false;
  const s = signer.toLowerCase();
  return (
    s.includes('software signing') ||
    s.includes('apple code signing') ||
    s.includes('authority=apple root ca') ||
    s.includes('com.apple.')
  );
}

/**
 * Evaluates Section 6 Protected List.
 * A protected item is NEVER actioned, whatever its score or AI verdict.
 *
 * Protected categories:
 * 1. Files with a valid Microsoft signature inside Windows directories (or valid Apple signature inside /System)
 * 2. Registered antivirus products
 * 3. Kernel drivers
 * 4. The tool's own files (binary, bundle, session root)
 * 5. Anything under user Documents, Pictures, Desktop, or cloud-sync folders
 */
export function checkProtected(
  item: CollectedItem,
  ctx: ProtectedContext,
  options: ProtectedCheckOptions = {}
): ProtectedCheckResult {
  const targetPath = item.facts.target_path ?? null;

  // 3. Kernel drivers (always report-only)
  if (item.kind === 'kernel_driver' || item.facts.is_kernel_driver === true) {
    return {
      protected: true,
      reason: 'Kernel drivers are protected and report-only in v0.1',
    };
  }

  // 4. The tool's own files and session folder
  if (targetPath) {
    for (const tp of ctx.toolPaths) {
      if (!tp) continue;
      if (isInsideDir(targetPath, tp) || normPath(targetPath) === normPath(tp)) {
        return {
          protected: true,
          reason: 'Tool binary or working directory is protected',
        };
      }
    }
    if (ctx.sessionRoot && isInsideDir(targetPath, ctx.sessionRoot)) {
      return {
        protected: true,
        reason: 'Sweep session directory is protected',
      };
    }
  }
  if (item.location && ctx.sessionRoot && isInsideDir(item.location, ctx.sessionRoot)) {
    return {
      protected: true,
      reason: 'Sweep session directory is protected',
    };
  }

  // 5. Anything under user Documents, Pictures, Desktop, or cloud-sync folders
  if (targetPath && isPersonalOrCloudPath(targetPath, ctx.platform)) {
    return {
      protected: true,
      reason: 'User personal or cloud-sync folder is protected',
    };
  }

  // 1. Files with a valid Microsoft signature inside Windows directories
  // Note: If a persistence entry (scheduled task, autorun, WMI subscription, hijack) abuses a
  // signed Windows LOLBin like powershell.exe -enc, the entry itself can still be disabled while
  // the Windows binary itself is never quarantined (deriveProposedAction blocks windows_system).
  const isPersistenceAbuse =
    options.isLolbinAbuse &&
    (item.kind === 'scheduled_task' ||
      item.kind === 'autorun_registry' ||
      item.kind === 'autorun_startup' ||
      item.kind === 'wmi_subscription' ||
      item.kind === 'hijack');

  if (ctx.platform === 'windows' && targetPath && !isPersistenceAbuse) {
    const norm = normPath(targetPath);
    const inWindowsDir =
      /^[a-z]:\\windows(\\|$)/.test(norm) &&
      !/^[a-z]:\\windows\\temp(\\|$)/.test(norm) &&
      !/^[a-z]:\\windows\\tasks(\\|$)/.test(norm);

    if (inWindowsDir && item.facts.sig_status === 'Valid' && isMicrosoftSigner(item.facts.signer)) {
      return {
        protected: true,
        reason: 'Valid Microsoft-signed file inside Windows directory',
      };
    }
  }

  if (ctx.platform === 'macos' && targetPath) {
    const posix = targetPath.replace(/\\/g, '/').toLowerCase();
    if (
      (posix.startsWith('/system/') || posix.startsWith('/usr/libexec/') || posix.startsWith('/usr/sbin/')) &&
      item.facts.sig_status === 'Valid' &&
      isAppleSigner(item.facts.signer)
    ) {
      return {
        protected: true,
        reason: 'Valid Apple-signed file inside macOS system directory',
      };
    }
  }

  // 2. Registered antivirus products
  if (targetPath) {
    const norm = normPath(targetPath);
    // Built-in Windows Defender directories
    if (
      /^[a-z]:\\programdata\\microsoft\\windows defender\\/.test(norm) ||
      /^[a-z]:\\program files\\windows defender\\/.test(norm) ||
      /^[a-z]:\\program files \(x86\)\\windows defender\\/.test(norm)
    ) {
      if (item.facts.sig_status === 'Valid' && isMicrosoftSigner(item.facts.signer)) {
        return {
          protected: true,
          reason: 'Registered antivirus product (Microsoft Defender)',
        };
      }
    }

    for (const av of ctx.avProducts) {
      const avPaths = [av.path_to_signed_product_exe, av.path_to_signed_reporting_exe].filter(
        Boolean
      ) as string[];
      for (const avExe of avPaths) {
        const avNorm = normPath(avExe.replace(/^%programfiles%/i, 'C:\\Program Files'));
        if (!avNorm) continue;
        const avDir = path.win32.dirname(avNorm);
        // Guard against matching root or generic C:\Program Files
        const depth = avDir.split('\\').filter(Boolean).length;
        if (norm === avNorm || (depth >= 3 && isInsideDir(norm, avDir))) {
          return {
            protected: true,
            reason: `Registered antivirus product (${av.display_name})`,
          };
        }
      }
    }
  }

  return { protected: false };
}
