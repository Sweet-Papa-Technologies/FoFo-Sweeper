import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { ActionType, InverseSpec, Manifest, ManifestEntry } from '../types.js';
import { readJsonFile, writeJsonAtomic } from './manager.js';

export function sha256File(filePath: string): string {
  const hash = crypto.createHash('sha256');
  const buf = fs.readFileSync(filePath);
  hash.update(buf);
  return hash.digest('hex');
}

export class ManifestStore {
  readonly filePath: string;
  private manifest: Manifest;

  constructor(sessionId: string, sessionDir: string) {
    this.filePath = path.join(sessionDir, 'manifest.json');
    if (fs.existsSync(this.filePath)) {
      this.manifest = readJsonFile<Manifest>(this.filePath);
    } else {
      this.manifest = {
        session_id: sessionId,
        created_at: new Date().toISOString(),
        entries: [],
      };
    }
  }

  getManifest(): Manifest {
    return this.manifest;
  }

  save(): void {
    writeJsonAtomic(this.filePath, this.manifest);
  }

  setRestorePoint(info: NonNullable<Manifest['restore_point']>): void {
    this.manifest.restore_point = info;
    this.save();
  }

  /**
   * Records an action and its exact inverse to manifest.json and fsyncs to disk
   * BEFORE the destructive action executes (Design Principle #2 & #9: Fail Closed).
   */
  recordPending(params: {
    finding_id: string;
    action: ActionType;
    location: string;
    backup_path: string | null;
    backup_sha256: string | null;
    inverse: InverseSpec;
  }): ManifestEntry {
    const seq = this.manifest.entries.length + 1;
    const actionId = `act-${String(seq).padStart(4, '0')}`;
    const entry: ManifestEntry = {
      action_id: actionId,
      finding_id: params.finding_id,
      action: params.action,
      location: params.location,
      timestamp: new Date().toISOString(),
      backup_path: params.backup_path,
      backup_sha256: params.backup_sha256,
      inverse: params.inverse,
      status: 'pending',
    };
    this.manifest.entries.push(entry);
    // Must succeed and fsync BEFORE action runs
    this.save();
    return entry;
  }

  recordBackupFailure(params: {
    finding_id: string;
    action: ActionType;
    location: string;
    error: string;
  }): ManifestEntry {
    const seq = this.manifest.entries.length + 1;
    const actionId = `act-${String(seq).padStart(4, '0')}`;
    const entry: ManifestEntry = {
      action_id: actionId,
      finding_id: params.finding_id,
      action: params.action,
      location: params.location,
      timestamp: new Date().toISOString(),
      backup_path: null,
      backup_sha256: null,
      inverse: {
        type: params.action,
        reversible: false,
        description: 'Action did not run because backup failed',
        params: {},
      },
      status: 'skipped_backup_failed',
      error: params.error,
      completed_at: new Date().toISOString(),
    };
    this.manifest.entries.push(entry);
    this.save();
    return entry;
  }

  recordOutcome(
    actionId: string,
    status: 'succeeded' | 'failed',
    detail?: string | null,
    error?: string | null
  ): ManifestEntry {
    const entry = this.manifest.entries.find((e) => e.action_id === actionId);
    if (!entry) {
      throw new Error(`Manifest entry not found: ${actionId}`);
    }
    entry.status = status;
    entry.detail = detail ?? null;
    entry.error = error ?? null;
    entry.completed_at = new Date().toISOString();
    this.save();
    return entry;
  }

  recordUndoOutcome(
    actionId: string,
    undoStatus: 'undone' | 'undo_failed' | 'not_reversible',
    undoError?: string | null
  ): ManifestEntry {
    const entry = this.manifest.entries.find((e) => e.action_id === actionId);
    if (!entry) {
      throw new Error(`Manifest entry not found: ${actionId}`);
    }
    entry.undo_status = undoStatus;
    entry.undo_at = new Date().toISOString();
    entry.undo_error = undoError ?? null;
    this.save();
    return entry;
  }
}
