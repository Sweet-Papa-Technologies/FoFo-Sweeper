import path from 'node:path';
import readline from 'node:readline';
import type { EventBus } from '../output/events.js';
import { formatUntrustedCode } from '../output/sanitize.js';
import { ManifestStore } from '../session/manifest.js';
import type { ActionType, Finding, Plan } from '../types.js';
import {
  getActionOrderPriority,
  performApply,
  performBackup,
  type ActionContext,
  type ActionHooks,
} from './actions.js';
import { parseProposedActions } from './plan.js';
import { createSystemRestorePoint } from './restore-point.js';

export interface FixExecutionOptions {
  sessionId: string;
  sessionDir: string;
  findings: Finding[];
  plan: Plan;
  elevated: boolean;
  dryRun: boolean;
  interactive: boolean;
  approveIds?: string[];
  bus: EventBus;
  hooks?: ActionHooks;
  skipRestorePoint?: boolean;
}

export interface FixExecutionSummary {
  applied: number;
  failed: number;
  skipped: number;
  dry_run: boolean;
  approved_ids: string[];
  errors: Array<{ finding_id: string; action: ActionType; error: string }>;
}

async function promptLine(rl: readline.Interface, question: string): Promise<string> {
  return new Promise((resolve) => {
    rl.question(question, (answer) => resolve(answer.trim()));
  });
}

async function selectInteractiveApprovals(
  findings: Finding[],
  plan: Plan,
  bus: EventBus
): Promise<string[]> {
  const byId = new Map(findings.map((f) => [f.id, f]));
  // Section 8:
  // Malicious: pre-selected in --interactive; still needs the confirm.
  // Suspicious: listed, not pre-selected.
  // Review: shown in the report only (can be actioned via explicit --approve <id>).
  const candidates = plan.items.filter(
    (p) => !p.protected && p.actions.length > 0 && (p.tier === 'malicious' || p.tier === 'suspicious')
  );

  if (candidates.length === 0) {
    bus.info('No actionable malicious or suspicious findings require confirmation.');
    return [];
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
  const selected: string[] = [];

  try {
    for (const item of candidates) {
      const f = byId.get(item.finding_id);
      if (!f) continue;
      bus.emit('needs_approval', {
        finding_id: f.id,
        tier: f.tier,
        score: f.score,
        location: f.location,
        proposed_action: f.proposed_action,
        default_selected: item.default_selected,
      });

      const defaultHint = item.default_selected ? '[Y/n]' : '[y/N]';
      process.stderr.write(
        `\n[${f.tier.toUpperCase()} · ${f.score}/100] ${f.id} (${f.kind})\n` +
          `  Location: ${f.location}\n` +
          `  Signals:  ${f.signals.join(', ')}\n` +
          `  Action:   ${f.proposed_action}\n` +
          (f.untrusted.name ? `  Label:    ${formatUntrustedCode(f.untrusted.name, 100)}\n` : '')
      );
      const ans = (await promptLine(rl, `  Approve this action? ${defaultHint}: `)).toLowerCase();
      const approved =
        ans === ''
          ? item.default_selected
          : ans === 'y' || ans === 'yes';

      if (approved) {
        selected.push(f.id);
      } else {
        item.approval_state = 'rejected';
      }
    }

    if (selected.length > 0) {
      process.stderr.write(
        `\nAbout to apply remediation for ${selected.length} finding(s): ${selected.join(', ')}\n` +
          'Removal can affect installed software; every reversible change is recorded in manifest.json for `fcsweep undo`.\n'
      );
      const confirm = (await promptLine(rl, 'Proceed with these changes? [y/N]: ')).toLowerCase();
      if (confirm !== 'y' && confirm !== 'yes') {
        bus.info('Aborted by user. No changes were made.');
        return [];
      }
    }
  } finally {
    rl.close();
  }

  return selected;
}

export async function executeFixPlan(opts: FixExecutionOptions): Promise<FixExecutionSummary> {
  const { sessionId, sessionDir, findings, plan, elevated, dryRun, interactive, approveIds, bus, hooks } = opts;
  const byId = new Map(findings.map((f) => [f.id, f]));
  const planById = new Map(plan.items.map((p) => [p.finding_id, p]));

  let targetIds: string[] = [];

  if (approveIds && approveIds.length > 0) {
    targetIds = Array.from(new Set(approveIds));
  } else if (interactive) {
    targetIds = await selectInteractiveApprovals(findings, plan, bus);
  } else if (dryRun) {
    // In dry-run without explicit --approve, preview malicious & suspicious items
    targetIds = plan.items
      .filter((p) => !p.protected && p.actions.length > 0 && (p.tier === 'malicious' || p.tier === 'suspicious'))
      .map((p) => p.finding_id);
  }

  // Expand finding IDs into ordered atomic actions while strictly enforcing the Protected List!
  interface QueuedAction {
    finding: Finding;
    action: ActionType;
    priority: number;
  }

  const queue: QueuedAction[] = [];
  const errors: FixExecutionSummary['errors'] = [];
  let skipped = 0;

  for (const id of targetIds) {
    const f = byId.get(id);
    if (!f) {
      errors.push({ finding_id: id, action: 'report_only', error: `Finding ID not found in session: ${id}` });
      continue;
    }
    if (f.protected) {
      skipped++;
      bus.warn(`Refusing to action protected item ${f.id}: ${f.protected_reason ?? 'Protected list'}`);
      continue;
    }
    const actions = parseProposedActions(f.proposed_action);
    if (actions.length === 0) {
      skipped++;
      bus.warn(`Finding ${f.id} has no automated action (proposed_action=${f.proposed_action})`);
      continue;
    }
    const planItem = planById.get(f.id);
    if (planItem && !dryRun) {
      planItem.approval_state = 'approved';
    }
    for (const action of actions) {
      queue.push({ finding: f, action, priority: getActionOrderPriority(action) });
    }
  }

  // Sort strictly by Section 4 Step 6 dependency order (kill -> disable persistence -> quarantine -> network/browser -> guided)
  queue.sort((a, b) => a.priority - b.priority || a.finding.id.localeCompare(b.finding.id));

  if (dryRun) {
    for (const q of queue) {
      bus.info(`[DRY-RUN] ${q.finding.id} · ${q.action} -> ${q.finding.location}`);
      bus.emit('action_start', {
        finding_id: q.finding.id,
        action: q.action,
        location: q.finding.location,
        dry_run: true,
      });
    }
    return {
      applied: 0,
      failed: errors.length,
      skipped,
      dry_run: true,
      approved_ids: targetIds,
      errors,
    };
  }

  if (queue.length === 0) {
    return {
      applied: 0,
      failed: errors.length,
      skipped,
      dry_run: false,
      approved_ids: targetIds,
      errors,
    };
  }

  const manifestStore = new ManifestStore(sessionId, sessionDir);

  // Create System Restore point before the first change in this session
  if (!opts.skipRestorePoint && !manifestStore.getManifest().restore_point?.attempted) {
    bus.emit('phase_start', { phase: 'restore_point' });
    const rp = await createSystemRestorePoint(sessionId);
    manifestStore.setRestorePoint(rp);
    bus.info(`System Restore point: ${rp.created ? 'created' : rp.message}`);
  }

  const ctx: ActionContext = {
    sessionDir,
    backupsDir: path.join(sessionDir, 'backups'),
    quarantineDir: path.join(sessionDir, 'quarantine'),
    elevated,
    hooks,
  };

  let applied = 0;
  let failed = errors.length;
  const findingFailureCount = new Map<string, number>();

  for (let i = 0; i < queue.length; i++) {
    const { finding, action } = queue[i];
    const seqKey = `s${String(manifestStore.getManifest().entries.length + 1).padStart(4, '0')}`;

    bus.emit('action_start', {
      finding_id: finding.id,
      action,
      location: finding.location,
    });

    // Step A: Backup / export BEFORE any modification (Fail Closed!)
    let backupRes;
    try {
      backupRes = await performBackup(action, finding, ctx, seqKey);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      manifestStore.recordBackupFailure({
        finding_id: finding.id,
        action,
        location: finding.location,
        error: `Backup failed (action aborted — fail closed): ${msg}`,
      });
      failed++;
      findingFailureCount.set(finding.id, (findingFailureCount.get(finding.id) ?? 0) + 1);
      errors.push({ finding_id: finding.id, action, error: `Backup failed: ${msg}` });
      bus.emit('action_done', {
        finding_id: finding.id,
        action,
        status: 'skipped_backup_failed',
        error: msg,
      });
      bus.warn(`FAIL-CLOSED: Backup failed for ${finding.id} (${action}); change NOT applied: ${msg}`);
      continue;
    }

    // Step B: Write & fsync inverse entry to manifest.json BEFORE running the action (Fail Closed!)
    let entry;
    try {
      entry = manifestStore.recordPending({
        finding_id: finding.id,
        action,
        location: finding.location,
        backup_path: backupRes.backup_path,
        backup_sha256: backupRes.backup_sha256,
        inverse: backupRes.inverse,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      failed++;
      findingFailureCount.set(finding.id, (findingFailureCount.get(finding.id) ?? 0) + 1);
      errors.push({ finding_id: finding.id, action, error: `Manifest write failed: ${msg}` });
      bus.emit('action_done', {
        finding_id: finding.id,
        action,
        status: 'failed',
        error: `Manifest write failed (action aborted): ${msg}`,
      });
      continue;
    }

    // Step C: Execute the action
    try {
      const detail = await performApply(action, finding, backupRes, ctx);
      manifestStore.recordOutcome(entry.action_id, 'succeeded', detail, null);
      applied++;
      bus.emit('action_done', {
        action_id: entry.action_id,
        finding_id: finding.id,
        action,
        status: 'succeeded',
        detail,
      });
      bus.raw(bus.ui.actionOk(entry.action_id, finding.id, action, detail));
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      manifestStore.recordOutcome(entry.action_id, 'failed', null, msg);
      failed++;
      findingFailureCount.set(finding.id, (findingFailureCount.get(finding.id) ?? 0) + 1);
      errors.push({ finding_id: finding.id, action, error: msg });
      bus.emit('action_done', {
        action_id: entry.action_id,
        finding_id: finding.id,
        action,
        status: 'failed',
        error: msg,
      });
      bus.raw(bus.ui.actionFail(entry.action_id, finding.id, action, msg));
    }
  }

  // Update plan item approval/execution states
  for (const id of targetIds) {
    const pi = planById.get(id);
    if (!pi || pi.protected) continue;
    pi.approval_state = (findingFailureCount.get(id) ?? 0) > 0 ? 'failed' : 'applied';
  }
  plan.updated_at = new Date().toISOString();

  return {
    applied,
    failed,
    skipped,
    dry_run: false,
    approved_ids: targetIds,
    errors,
  };
}
