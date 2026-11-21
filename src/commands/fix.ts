import fs from 'node:fs';
import path from 'node:path';
import { EXIT_CODES, VERSION, type ExitCode } from '../constants.js';
import type { EventBus } from '../output/events.js';
import { writeSessionReports } from '../output/report-writer.js';
import { isElevated } from '../platform/privilege.js';
import { executeFixPlan } from '../remediation/executor.js';
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

export interface FixCommandOptions {
  interactive: boolean;
  approveIds?: string[];
  dryRun: boolean;
}

export async function runFixCommand(
  globalOpts: GlobalOptions,
  cmdOpts: FixCommandOptions,
  bus: EventBus
): Promise<ExitCode> {
  const platform = detectPlatform();
  if (platform === 'macos') {
    bus.error('`fcsweep fix` is not supported on macOS in v0.1. The macOS module is read-only `scan` only.');
    return EXIT_CODES.ERROR;
  }

  // Section 3: "There is no blanket --yes. `fix` without --interactive or --approve refuses to run."
  if (!cmdOpts.interactive && (!cmdOpts.approveIds || cmdOpts.approveIds.length === 0) && !cmdOpts.dryRun) {
    bus.error('Refusing to run `fix` without `--interactive` or `--approve <id,id>` (or `--dry-run`). There is no `--yes` flag.');
    return EXIT_CODES.ERROR;
  }

  const elevated = isElevated();
  if (!cmdOpts.dryRun && !elevated) {
    bus.error('`fcsweep fix` requires an elevated Administrator terminal (exit code 3).');
    bus.emit('done', { command: 'fix', exit_code: EXIT_CODES.ELEVATION_REQUIRED, error: 'Elevation required' });
    return EXIT_CODES.ELEVATION_REQUIRED;
  }

  const { root: sessionRoot } = resolveSessionRoot(globalOpts.sessionRoot, elevated);
  const session = resolveExistingSession(sessionRoot, globalOpts.session);
  bus.attachSession(session.id, session.dir);

  const preflight = readJsonFile<PreflightResult>(path.join(session.dir, 'preflight.json'));
  const findingsDoc = readJsonFile<{ findings: Finding[] }>(path.join(session.dir, 'findings.json'));
  const planPath = path.join(session.dir, 'plan.json');
  const plan = readJsonFile<Plan>(planPath);

  if (plan.stop_conditions.length > 0 && !cmdOpts.dryRun) {
    bus.error(
      `Stop condition active in session ${session.id}: ${plan.stop_conditions.map((s) => s.kind).join(', ')}. Automated fix is blocked.`
    );
    bus.emit('done', {
      command: 'fix',
      session_id: session.id,
      exit_code: EXIT_CODES.STOP_CONDITION,
      stop_conditions: plan.stop_conditions,
    });
    return EXIT_CODES.STOP_CONDITION;
  }

  bus.raw(
    bus.ui.banner(
      VERSION,
      `${cmdOpts.dryRun ? '🧪 Dry-Run Remediation Preview' : '🛠️  Applying Approved Fixes'} · Session ${session.id}`
    )
  );
  bus.emit('phase_start', { phase: 'fix', dry_run: cmdOpts.dryRun });
  bus.phase(cmdOpts.dryRun ? '🧪' : '🛠️ ', cmdOpts.dryRun ? 'Dry-Run Plan Preview' : 'Applying Approved Remediation');
  const summary = await executeFixPlan({
    sessionId: session.id,
    sessionDir: session.dir,
    findings: findingsDoc.findings,
    plan,
    elevated,
    dryRun: cmdOpts.dryRun,
    interactive: cmdOpts.interactive,
    approveIds: cmdOpts.approveIds,
    bus,
  });

  if (!cmdOpts.dryRun) {
    writeJsonAtomic(planPath, plan);
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
        advisories: plan.advisories,
        stopConditions: plan.stop_conditions,
        manifest,
      },
      globalOpts.reportFormat
    );
  }

  const exitCode: ExitCode = summary.failed > 0 ? EXIT_CODES.PARTIAL_FAILURE : EXIT_CODES.OK;
  bus.info('');
  bus.info(
    cmdOpts.dryRun
      ? `🧪 Dry-run complete (${summary.approved_ids.length} finding(s) previewed — nothing was changed).`
      : summary.failed === 0
        ? `🧹 Fix complete: ✅ ${summary.applied} swept safely, ⏭️ ${summary.skipped} skipped. Undo anytime with \`fcsweep undo --session ${session.id}\`.`
        : `⚠️  Fix finished with partial failures: ✅ ${summary.applied} succeeded, ❌ ${summary.failed} failed, ⏭️ ${summary.skipped} skipped.`
  );
  bus.emit('done', {
    command: 'fix',
    session_id: session.id,
    ...summary,
    exit_code: exitCode,
  });

  return exitCode;
}
