import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { SESSION_RETENTION_DAYS } from '../constants.js';
import type { PlatformKind } from '../types.js';

export interface SessionInfo {
  id: string;
  dir: string;
  created_at: Date;
  age_days: number;
  has_findings: boolean;
  has_manifest: boolean;
  has_report: boolean;
  findings_summary?: {
    malicious: number;
    suspicious: number;
    review: number;
    clean: number;
  };
  actions_taken?: number;
  size_bytes: number;
}

export function detectPlatform(): PlatformKind {
  if (process.platform === 'win32') return 'windows';
  if (process.platform === 'darwin') return 'macos';
  return 'linux';
}

export function getDefaultSessionRoot(elevated: boolean): { root: string; fallbackUsed: boolean } {
  const platform = detectPlatform();
  if (platform === 'windows') {
    const programData = process.env.ProgramData || 'C:\\ProgramData';
    const primary = path.join(programData, 'FoFoCare', 'Sweep', 'sessions');
    if (canEnsureDirectory(primary)) {
      return { root: primary, fallbackUsed: false };
    }
    const fallback = path.join(os.homedir(), 'AppData', 'Local', 'FoFoCare', 'Sweep', 'sessions');
    return { root: fallback, fallbackUsed: true };
  }

  if (platform === 'macos') {
    const systemRoot = '/Library/Application Support/FoFoCare/Sweep/sessions';
    if (elevated || canEnsureDirectory(systemRoot)) {
      return { root: systemRoot, fallbackUsed: false };
    }
    const userRoot = path.join(os.homedir(), 'Library', 'Application Support', 'FoFoCare', 'Sweep', 'sessions');
    return { root: userRoot, fallbackUsed: true };
  }

  return {
    root: path.join(os.homedir(), '.local', 'share', 'fcsweep', 'sessions'),
    fallbackUsed: false,
  };
}

function canEnsureDirectory(dirPath: string): boolean {
  try {
    fs.mkdirSync(dirPath, { recursive: true });
    fs.accessSync(dirPath, fs.constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

export function resolveSessionRoot(explicitRoot: string | undefined, elevated: boolean): {
  root: string;
  fallbackUsed: boolean;
} {
  if (explicitRoot) {
    return { root: path.resolve(explicitRoot), fallbackUsed: false };
  }
  return getDefaultSessionRoot(elevated);
}

export function generateSessionId(now: Date = new Date()): string {
  const iso = now
    .toISOString()
    .replace(/\.\d{3}Z$/, 'Z')
    .replace(/:/g, '-');
  const shortId = crypto.randomBytes(3).toString('hex');
  return `${iso}-${shortId}`;
}

export function hardenDirectoryPermissions(dirPath: string, elevated: boolean): void {
  if (process.platform === 'win32') {
    if (!elevated) return;
    // Administrators (*S-1-5-32-544) and SYSTEM (*S-1-5-18) Full Control only
    spawnSync(
      'icacls.exe',
      [
        dirPath,
        '/inheritance:r',
        '/grant:r',
        '*S-1-5-32-544:(OI)(CI)F',
        '/grant:r',
        '*S-1-5-18:(OI)(CI)F',
      ],
      { stdio: 'ignore', windowsHide: true }
    );
  } else {
    try {
      fs.chmodSync(dirPath, 0o700);
    } catch {
      // ignore if filesystem does not support chmod
    }
  }
}

export function createSession(
  sessionRoot: string,
  elevated: boolean,
  explicitId?: string
): { id: string; dir: string; quarantineDir: string; backupsDir: string } {
  const id = explicitId || generateSessionId();
  if (!/^[A-Za-z0-9._-]+$/.test(id)) {
    throw new Error(`Invalid session id: ${id}`);
  }
  fs.mkdirSync(sessionRoot, { recursive: true });
  const dir = path.join(sessionRoot, id);
  const quarantineDir = path.join(dir, 'quarantine');
  const backupsDir = path.join(dir, 'backups');

  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(quarantineDir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(backupsDir, { recursive: true, mode: 0o700 });

  hardenDirectoryPermissions(dir, elevated);
  hardenDirectoryPermissions(quarantineDir, elevated);
  hardenDirectoryPermissions(backupsDir, elevated);

  return { id, dir, quarantineDir, backupsDir };
}

function getDirSizeBytes(dirPath: string): number {
  let total = 0;
  try {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(dirPath, entry.name);
      if (entry.isDirectory()) {
        total += getDirSizeBytes(full);
      } else if (entry.isFile()) {
        try {
          total += fs.statSync(full).size;
        } catch {
          // ignore
        }
      }
    }
  } catch {
    // ignore
  }
  return total;
}

function parseSessionDate(id: string, dirPath: string): Date {
  // Format: 2026-11-21T16-55-00Z-a1b2c3
  const m = id.match(/^(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})Z/);
  if (m) {
    const d = new Date(`${m[1]}T${m[2]}:${m[3]}:${m[4]}Z`);
    if (!Number.isNaN(d.getTime())) return d;
  }
  try {
    return fs.statSync(dirPath).birthtime;
  } catch {
    return new Date(0);
  }
}

export function listSessions(sessionRoot: string): SessionInfo[] {
  if (!fs.existsSync(sessionRoot)) return [];
  const now = Date.now();
  const entries = fs.readdirSync(sessionRoot, { withFileTypes: true });
  const sessions: SessionInfo[] = [];

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const dir = path.join(sessionRoot, entry.name);
    const createdAt = parseSessionDate(entry.name, dir);
    const ageDays = Math.max(0, (now - createdAt.getTime()) / (1000 * 60 * 60 * 24));
    const findingsPath = path.join(dir, 'findings.json');
    const manifestPath = path.join(dir, 'manifest.json');
    const reportPath = path.join(dir, 'report.md');

    let findingsSummary: SessionInfo['findings_summary'];
    if (fs.existsSync(findingsPath)) {
      try {
        const findings = JSON.parse(fs.readFileSync(findingsPath, 'utf8'));
        const list = Array.isArray(findings) ? findings : findings.findings ?? [];
        const counts = { malicious: 0, suspicious: 0, review: 0, clean: 0 };
        for (const f of list) {
          if (f?.tier in counts) counts[f.tier as keyof typeof counts]++;
        }
        findingsSummary = counts;
      } catch {
        // ignore corrupt file in listing
      }
    }

    let actionsTaken: number | undefined;
    if (fs.existsSync(manifestPath)) {
      try {
        const m = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
        actionsTaken = Array.isArray(m.entries)
          ? m.entries.filter((e: { status?: string }) => e.status === 'succeeded').length
          : 0;
      } catch {
        // ignore
      }
    }

    sessions.push({
      id: entry.name,
      dir,
      created_at: createdAt,
      age_days: Math.round(ageDays * 10) / 10,
      has_findings: fs.existsSync(findingsPath),
      has_manifest: fs.existsSync(manifestPath),
      has_report: fs.existsSync(reportPath),
      findings_summary: findingsSummary,
      actions_taken: actionsTaken,
      size_bytes: getDirSizeBytes(dir),
    });
  }

  // Newest first
  sessions.sort((a, b) => b.created_at.getTime() - a.created_at.getTime() || b.id.localeCompare(a.id));
  return sessions;
}

export function resolveExistingSession(
  sessionRoot: string,
  explicitId?: string
): { id: string; dir: string } {
  if (explicitId) {
    // Also allow passing an absolute path directly to a session folder
    if (path.isAbsolute(explicitId) && fs.existsSync(explicitId)) {
      return { id: path.basename(explicitId), dir: explicitId };
    }
    const dir = path.join(sessionRoot, explicitId);
    if (!fs.existsSync(dir)) {
      throw new Error(`Session not found: ${explicitId} (looked in ${sessionRoot})`);
    }
    return { id: explicitId, dir };
  }

  const sessions = listSessions(sessionRoot);
  if (sessions.length === 0) {
    throw new Error(`No sessions found in ${sessionRoot}. Run 'fcsweep scan' first.`);
  }
  return { id: sessions[0].id, dir: sessions[0].dir };
}

export function purgeOldSessions(
  sessionRoot: string,
  olderThanDays: number = SESSION_RETENTION_DAYS
): { purged: string[]; kept: string[]; errors: Array<{ id: string; error: string }> } {
  const sessions = listSessions(sessionRoot);
  const purged: string[] = [];
  const kept: string[] = [];
  const errors: Array<{ id: string; error: string }> = [];

  for (const s of sessions) {
    if (s.age_days > olderThanDays) {
      try {
        fs.rmSync(s.dir, { recursive: true, force: true });
        purged.push(s.id);
      } catch (err) {
        errors.push({ id: s.id, error: err instanceof Error ? err.message : String(err) });
      }
    } else {
      kept.push(s.id);
    }
  }
  return { purged, kept, errors };
}

export function writeJsonAtomic(filePath: string, data: unknown): void {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  const tmpPath = `${filePath}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  const payload = JSON.stringify(data, null, 2) + '\n';
  const fd = fs.openSync(tmpPath, 'w', 0o600);
  try {
    fs.writeSync(fd, payload, 0, 'utf8');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmpPath, filePath);
}

export function readJsonFile<T>(filePath: string): T {
  return JSON.parse(fs.readFileSync(filePath, 'utf8').replace(/^\uFEFF/, '')) as T;
}
