import fs from 'node:fs';
import path from 'node:path';
import { EXIT_CODES, VERSION, type ExitCode } from '../constants.js';
import type { EventBus } from '../output/events.js';
import {
  openReportInBrowser,
  writeSessionReports,
  type ReportFormat,
} from '../output/report-writer.js';
import { isElevated } from '../platform/privilege.js';
import {
  readJsonFile,
  resolveExistingSession,
  resolveSessionRoot,
} from '../session/manager.js';
import type {
  DefenderScanResult,
  Finding,
  GlobalOptions,
  HardenManifest,
  Manifest,
  Plan,
  PreflightResult,
  Snapshot,
  VerifyResult,
} from '../types.js';

export interface ReportCommandOptions {
  format: ReportFormat;
  open: boolean;
  outPath?: string;
}

export async function runReportCommand(
  globalOpts: GlobalOptions,
  cmdOpts: ReportCommandOptions,
  bus: EventBus
): Promise<ExitCode> {
  const elevated = isElevated();
  const { root: sessionRoot } = resolveSessionRoot(globalOpts.sessionRoot, elevated);
  const session = resolveExistingSession(sessionRoot, globalOpts.session);
  bus.attachSession(session.id, session.dir);

  const preflight = readJsonFile<PreflightResult>(path.join(session.dir, 'preflight.json'));
  const findingsDoc = readJsonFile<{ findings: Finding[] }>(path.join(session.dir, 'findings.json'));

  const optRead = <T>(file: string): T | null => {
    const p = path.join(session.dir, file);
    return fs.existsSync(p) ? readJsonFile<T>(p) : null;
  };

  const snapshot = optRead<Snapshot>('snapshot.json');
  const defenderScan = optRead<DefenderScanResult>('defender.json');
  const plan = optRead<Plan>('plan.json');
  const manifest = optRead<Manifest>('manifest.json');
  const verifyResult = optRead<VerifyResult>('verify.json');
  const hardenManifest = optRead<HardenManifest>('harden-manifest.json');

  bus.raw(bus.ui.banner(VERSION, `Rendering report for session ${session.id}`));

  const written = writeSessionReports(
    session.dir,
    {
      sessionId: session.id,
      preflight,
      findings: findingsDoc.findings,
      snapshot,
      defenderScan,
      advisories: plan?.advisories ?? [],
      stopConditions: verifyResult?.stop_conditions ?? plan?.stop_conditions ?? [],
      manifest,
      verifyResult,
      hardenManifest,
    },
    cmdOpts.format
  );

  if (cmdOpts.outPath) {
    const resolvedOut = path.resolve(cmdOpts.outPath);
    const src =
      resolvedOut.toLowerCase().endsWith('.md') && written.mdPath
        ? written.mdPath
        : written.htmlPath ?? written.mdPath;
    if (src) {
      fs.mkdirSync(path.dirname(resolvedOut), { recursive: true });
      fs.copyFileSync(src, resolvedOut);
      bus.info(`📄 Copied report to ${resolvedOut}`);
    }
  }

  if (written.htmlPath) bus.info(`🌐 HTML report:     ${bus.ui.cyan(written.htmlPath)}`);
  if (written.mdPath) bus.info(`📝 Markdown report: ${bus.ui.dim(written.mdPath)}`);

  const openTarget = written.htmlPath ?? written.mdPath;
  if (cmdOpts.open && openTarget) {
    const opened = openReportInBrowser(openTarget);
    if (opened) {
      bus.info(`🚀 Opened ${openTarget} in your default browser.`);
    } else {
      bus.warn(`Could not auto-open browser. Open manually: ${openTarget}`);
    }
  }

  bus.emit('done', {
    command: 'report',
    session_id: session.id,
    html_path: written.htmlPath ?? null,
    md_path: written.mdPath ?? null,
    exit_code: EXIT_CODES.OK,
  });

  return EXIT_CODES.OK;
}
