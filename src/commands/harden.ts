import fs from 'node:fs';
import path from 'node:path';
import { EXIT_CODES, VERSION, type ExitCode } from '../constants.js';
import { runWindowsPreflight } from '../collectors/windows/preflight.js';
import { runHardenApply, runHardenRevert } from '../hardening/windows-harden.js';
import type { EventBus } from '../output/events.js';
import { writeSessionReports } from '../output/report-writer.js';
import { isElevated } from '../platform/privilege.js';
import {
  createSession,
  detectPlatform,
  listSessions,
  readJsonFile,
  resolveExistingSession,
  resolveSessionRoot,
} from '../session/manager.js';
import type { DefenderScanResult, Finding, GlobalOptions, Manifest, Plan, PreflightResult } from '../types.js';

export async function runHardenCommand(
  globalOpts: GlobalOptions,
  revert: boolean,
  bus: EventBus
): Promise<ExitCode> {
  const platform = detectPlatform();
  if (platform === 'macos') {
    bus.error('`fcsweep harden` is Windows-only in v0.1.');
    return EXIT_CODES.ERROR;
  }

  const elevated = isElevated();
  if (!elevated) {
    bus.error('`fcsweep harden` requires an elevated Administrator terminal (exit code 3).');
    bus.emit('done', { command: 'harden', exit_code: EXIT_CODES.ELEVATION_REQUIRED, error: 'Elevation required' });
    return EXIT_CODES.ELEVATION_REQUIRED;
  }

  const { root: sessionRoot } = resolveSessionRoot(globalOpts.sessionRoot, elevated);

  if (revert) {
    const session = resolveExistingSession(sessionRoot, globalOpts.session);
    bus.attachSession(session.id, session.dir);
    bus.raw(bus.ui.banner(VERSION, `⏪ Reverting Windows Hardening · Session ${session.id}`));
    bus.emit('phase_start', { phase: 'harden_revert' });
    bus.phase('⏪', 'Restoring Prior Hardening Values');
    const res = await runHardenRevert({ sessionDir: session.dir, bus });
    const exitCode: ExitCode = res.failed > 0 ? EXIT_CODES.PARTIAL_FAILURE : EXIT_CODES.OK;
    bus.info('');
    bus.info(`✅ Hardening revert complete: ⏪ ${res.reverted} restored, ❌ ${res.failed} failed.`);
    bus.emit('done', {
      command: 'harden --revert',
      session_id: session.id,
      reverted: res.reverted,
      failed: res.failed,
      exit_code: exitCode,
    });
    return exitCode;
  }

  // Use specified/latest session if one exists, otherwise create a fresh session
  let session: { id: string; dir: string };
  if (globalOpts.session || listSessions(sessionRoot).length > 0) {
    session = resolveExistingSession(sessionRoot, globalOpts.session);
  } else {
    const created = createSession(sessionRoot, elevated);
    session = { id: created.id, dir: created.dir };
  }
  bus.attachSession(session.id, session.dir);

  const preflightPath = path.join(session.dir, 'preflight.json');
  const preflight: PreflightResult = fs.existsSync(preflightPath)
    ? readJsonFile<PreflightResult>(preflightPath)
    : await runWindowsPreflight(elevated, []);

  bus.raw(bus.ui.banner(VERSION, `🔒 Windows Hardening · Session ${session.id}`));
  bus.emit('phase_start', { phase: 'harden' });
  bus.phase('🔒', 'Applying Built-in Windows Protections', 'Every prior value is recorded for --revert');
  const { manifest: hardenManifest, failedCount } = await runHardenApply({
    sessionId: session.id,
    sessionDir: session.dir,
    preflight,
    bus,
  });

  // Update report.md & report.html if scan artifacts exist
  const findingsPath = path.join(session.dir, 'findings.json');
  if (fs.existsSync(findingsPath)) {
    const findingsDoc = readJsonFile<{ findings: Finding[] }>(findingsPath);
    const planPath = path.join(session.dir, 'plan.json');
    const plan = fs.existsSync(planPath) ? readJsonFile<Plan>(planPath) : null;
    const defenderPath = path.join(session.dir, 'defender.json');
    const defenderScan = fs.existsSync(defenderPath) ? readJsonFile<DefenderScanResult>(defenderPath) : null;
    const snapshotPath = path.join(session.dir, 'snapshot.json');
    const snapshot = fs.existsSync(snapshotPath) ? readJsonFile<any>(snapshotPath) : null;
    const manifestPath = path.join(session.dir, 'manifest.json');
    const fixManifest = fs.existsSync(manifestPath) ? readJsonFile<Manifest>(manifestPath) : null;
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
        manifest: fixManifest,
        hardenManifest,
      },
      globalOpts.reportFormat
    );
  }

  const exitCode: ExitCode = failedCount > 0 ? EXIT_CODES.PARTIAL_FAILURE : EXIT_CODES.OK;
  bus.emit('done', {
    command: 'harden',
    session_id: session.id,
    applied: hardenManifest.settings.filter((s) => s.status === 'applied').length,
    skipped: hardenManifest.settings.filter((s) => s.status === 'skipped').length,
    failed: failedCount,
    exit_code: exitCode,
  });

  return exitCode;
}
