import path from 'node:path';
import type { EventBus } from '../output/events.js';
import { ManifestStore } from '../session/manifest.js';
import type { Plan } from '../types.js';
import { performUndo, type ActionContext, type ActionHooks } from './actions.js';

export interface UndoOptions {
  sessionId: string;
  sessionDir: string;
  itemId?: string;
  elevated: boolean;
  bus: EventBus;
  plan?: Plan | null;
  hooks?: ActionHooks;
}

export interface UndoSummary {
  undone: number;
  not_reversible: number;
  failed: number;
  skipped: number;
  errors: Array<{ action_id: string; finding_id: string; error: string }>;
}

/**
 * Replays manifest.json inverses newest-first (reverse chronological order)
 * and records every outcome.
 */
export async function executeUndo(opts: UndoOptions): Promise<UndoSummary> {
  const { sessionId, sessionDir, itemId, elevated, bus, plan, hooks } = opts;
  const store = new ManifestStore(sessionId, sessionDir);
  const manifest = store.getManifest();

  const ctx: ActionContext = {
    sessionDir,
    backupsDir: path.join(sessionDir, 'backups'),
    quarantineDir: path.join(sessionDir, 'quarantine'),
    elevated,
    hooks,
  };

  // Newest-first replay of succeeded entries not already undone
  const candidates = [...manifest.entries]
    .reverse()
    .filter((e) => {
      if (e.status !== 'succeeded') return false;
      if (e.undo_status === 'undone') return false;
      if (itemId && e.finding_id !== itemId && e.action_id !== itemId) return false;
      return true;
    });

  let undone = 0;
  let notReversible = 0;
  let failed = 0;
  const skipped = 0;
  const errors: UndoSummary['errors'] = [];

  for (const entry of candidates) {
    bus.emit('action_start', {
      action_id: entry.action_id,
      finding_id: entry.finding_id,
      action: `undo:${entry.action}`,
      location: entry.location,
    });

    if (!entry.inverse.reversible) {
      store.recordUndoOutcome(entry.action_id, 'not_reversible', null);
      notReversible++;
      bus.emit('action_done', {
        action_id: entry.action_id,
        finding_id: entry.finding_id,
        action: `undo:${entry.action}`,
        status: 'not_reversible',
        detail: entry.inverse.description,
      });
      bus.info(`[SKIP] ${entry.action_id} (${entry.action}): not reversible (${entry.inverse.description})`);
      continue;
    }

    try {
      const detail = await performUndo(entry, ctx);
      store.recordUndoOutcome(entry.action_id, 'undone', null);
      undone++;
      bus.emit('action_done', {
        action_id: entry.action_id,
        finding_id: entry.finding_id,
        action: `undo:${entry.action}`,
        status: 'undone',
        detail,
      });
      bus.info(`[UNDONE] ${entry.action_id} (${entry.finding_id} · ${entry.action}): ${detail}`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      store.recordUndoOutcome(entry.action_id, 'undo_failed', msg);
      failed++;
      errors.push({ action_id: entry.action_id, finding_id: entry.finding_id, error: msg });
      bus.emit('action_done', {
        action_id: entry.action_id,
        finding_id: entry.finding_id,
        action: `undo:${entry.action}`,
        status: 'undo_failed',
        error: msg,
      });
      bus.warn(`[UNDO FAIL] ${entry.action_id} (${entry.finding_id} · ${entry.action}): ${msg}`);
    }
  }

  // Update plan items whose actions were all undone
  if (plan) {
    const updatedManifest = store.getManifest();
    for (const pi of plan.items) {
      const entriesForItem = updatedManifest.entries.filter(
        (e) => e.finding_id === pi.finding_id && e.status === 'succeeded' && e.inverse.reversible
      );
      if (entriesForItem.length > 0 && entriesForItem.every((e) => e.undo_status === 'undone')) {
        pi.approval_state = 'undone';
      }
    }
    plan.updated_at = new Date().toISOString();
  }

  return {
    undone,
    not_reversible: notReversible,
    failed,
    skipped,
    errors,
  };
}
