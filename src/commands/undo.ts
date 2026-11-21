import fs from 'node:fs';
import path from 'node:path';
import { EXIT_CODES, VERSION, type ExitCode } from '../constants.js';
import type { EventBus } from '../output/events.js';
import { writeSessionReports } from '../output/report-writer.js';
import { isElevated } from '../platform/privilege.js';
import { executeUndo } from '../remediation/undo.js';
import {
  detectPlatform,
  readJsonFile,
  resolveExistingSession,
  resolveSessionRoot,
  writeJsonAtomic,
} from '../session/manager.js';
import { ManifestStore } from '../session/manifest.js';
import type {
  DefenderScanResult,
  Finding,
  GlobalOptions,
  Plan,
  PreflightResult,
} from '../types.js';

export async function runUndoCommand(
  globalOpts: GlobalOptions,
  itemId: string | undefined,
  bus: EventBus
): Promise<ExitCode> {
  const platform = detectPlatform();
  if (platform === 'macos') {
    bus.error('`fcsweep undo` is not supported on macOS in v0.1.');
    return EXIT_CODES.ERROR;
  }

  const elevated = isElevated();
  if (!elevated) {
    bus.error('`fcsweep undo` requires an elevated Administrator terminal (exit code 3).');
    bus.emit('done', { command: 'undo', exit_code: EXIT_CODES.ELEVATION_REQUIRED, error: 'Elevation required' });
    return EXIT_CODES.ELEVATION_REQUIRED;
  }

  const { root: sessionRoot } = resolveSessionRoot(globalOpts.sessionRoot, elevated);
  const session = resolveExistingSession(sessionRoot, globalOpts.session);
  bus.attachSession(session.id, session.dir);

  const manifestPath = path.join(session.dir, 'manifest.json');
  if (!fs.existsSync(manifestPath)) {
    bus.info(`No manifest.json found in session ${session.id}; nothing to undo.`);
    bus.emit('done', { command: 'undo', session_id: session.id, undone: 0, exit_code: EXIT_CODES.OK });
    return EXIT_CODES.OK;
  }

  const planPath = path.join(session.dir, 'plan.json');
  const plan = fs.existsSync(planPath) ? readJsonFile<Plan>(planPath) : null;

  bus.raw(bus.ui.banner(VERSION, `⏪ Reverting Changes · Session ${session.id}${itemId ? ` (item ${itemId})` : ''}`));
  bus.emit('phase_start', { phase: 'undo', item_id: itemId ?? null });
  bus.phase('⏪', 'Replaying Inverses Newest-First');
  const summary = await executeUndo({
    sessionId: session.id,
    sessionDir: session.dir,
    itemId,
    elevated,
    bus,
    plan,
  });

  if (plan) {
    writeJsonAtomic(planPath, plan);
  }

  // Refresh report.md & report.html
  const preflightPath = path.join(session.dir, 'preflight.json');
  const findingsPath = path.join(session.dir, 'findings.json');
  if (fs.existsSync(preflightPath) && fs.existsSync(findingsPath)) {
    const preflight = readJsonFile<PreflightResult>(preflightPath);
    const findingsDoc = readJsonFile<{ findings: Finding[] }>(findingsPath);
    const defenderPath = path.join(session.dir, 'defender.json');
    const defenderScan = fs.existsSync(defenderPath) ? readJsonFile<DefenderScanResult>(defenderPath) : null;
    const snapshotPath = path.join(session.dir, 'snapshot.json');
    const snapshot = fs.existsSync(snapshotPath) ? readJsonFile<any>(snapshotPath) : null;
    const manifest = new ManifestStore(session.id, session.dir).getManifest();
    writeSessionReports(
      session.dir,
      {
        sessionId: session.id,
        preflight,
        findings: findingsDoc.findings,
        snapshot,
        defenderScan,
        advisories: plan?.advisories ?? [],
        stopConditions: plan?.stop_conditions ?? [],
        manifest,
      },
      globalOpts.reportFormat
    );
  }

  const exitCode: ExitCode = summary.failed > 0 ? EXIT_CODES.PARTIAL_FAILURE : EXIT_CODES.OK;
  bus.info('');
  bus.info(
    summary.failed === 0
      ? `✅ Undo complete: ⏪ ${summary.undone} restored cleanly, ⏭️ ${summary.not_reversible} not reversible.`
      : `⚠️  Undo finished with errors: ⏪ ${summary.undone} restored, ❌ ${summary.failed} failed, ⏭️ ${summary.not_reversible} not reversible.`
  );
  bus.emit('done', {
    command: 'undo',
    session_id: session.id,
    ...summary,
    exit_code: exitCode,
  });

  return exitCode;
}
