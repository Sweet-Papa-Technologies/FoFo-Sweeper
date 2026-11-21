import fs from 'node:fs';
import path from 'node:path';
import { EXIT_CODES, type ExitCode } from '../constants.js';
import { loadRules } from '../data-loader.js';
import type { EventBus } from '../output/events.js';
import { renderMarkdownReport } from '../output/report.js';
import { isElevated } from '../platform/privilege.js';
import { buildPlan } from '../remediation/plan.js';
import { evaluateAdvisoriesAndStops } from '../scoring/advisories.js';
import { applyTriageVerdicts, buildTriageRequest } from '../scoring/triage.js';
import {
  readJsonFile,
  resolveExistingSession,
  resolveSessionRoot,
  writeJsonAtomic,
} from '../session/manager.js';
import type {
  DefenderScanResult,
  Finding,
  GlobalOptions,
  Plan,
  PreflightResult,
} from '../types.js';

export async function runTriageExportCommand(
  globalOpts: GlobalOptions,
  outPath: string | undefined,
  bus: EventBus
): Promise<ExitCode> {
  const elevated = isElevated();
  const { root: sessionRoot } = resolveSessionRoot(globalOpts.sessionRoot, elevated);
  const session = resolveExistingSession(sessionRoot, globalOpts.session);
  bus.attachSession(session.id, session.dir);

  const findingsFile = path.join(session.dir, 'findings.json');
  if (!fs.existsSync(findingsFile)) {
    throw new Error(`No findings.json found in session ${session.id}`);
  }
  const findingsData = readJsonFile<{ findings: Finding[] }>(findingsFile);
  const bundle = buildTriageRequest(session.id, findingsData.findings);

  const requestPath = path.join(session.dir, 'triage-request.json');
  writeJsonAtomic(requestPath, bundle);
  if (outPath) {
    writeJsonAtomic(path.resolve(outPath), bundle);
  }

  bus.info(`Exported ${bundle.items.length} review/suspicious item(s) to ${requestPath}`);
  bus.emit('done', {
    command: 'triage export',
    session_id: session.id,
    triage_request_path: requestPath,
    item_count: bundle.items.length,
    exit_code: EXIT_CODES.OK,
  });
  return EXIT_CODES.OK;
}

export async function runTriageImportCommand(
  globalOpts: GlobalOptions,
  verdictFilePath: string,
  bus: EventBus
): Promise<ExitCode> {
  if (!verdictFilePath) {
    throw new Error('triage import requires a verdict JSON file path');
  }
  const resolvedInput = path.resolve(verdictFilePath);
  if (!fs.existsSync(resolvedInput)) {
    throw new Error(`Verdict file not found: ${resolvedInput}`);
  }

  const elevated = isElevated();
  const { root: sessionRoot } = resolveSessionRoot(globalOpts.sessionRoot, elevated);
  const session = resolveExistingSession(sessionRoot, globalOpts.session);
  bus.attachSession(session.id, session.dir);

  const preflight = readJsonFile<PreflightResult>(path.join(session.dir, 'preflight.json'));
  const findingsFile = path.join(session.dir, 'findings.json');
  const findingsDoc = readJsonFile<{ session_id: string; generated_at: string; since_days: number; findings: Finding[] }>(findingsFile);
  const existingPlanPath = path.join(session.dir, 'plan.json');
  const existingPlan = fs.existsSync(existingPlanPath) ? readJsonFile<Plan>(existingPlanPath) : null;
  const defenderPath = path.join(session.dir, 'defender.json');
  const defenderScan = fs.existsSync(defenderPath) ? readJsonFile<DefenderScanResult>(defenderPath) : null;

  let rawJson: unknown;
  try {
    rawJson = JSON.parse(fs.readFileSync(resolvedInput, 'utf8').replace(/^\uFEFF/, ''));
  } catch (err) {
    throw new Error(`Invalid JSON in ${resolvedInput}: ${err instanceof Error ? err.message : String(err)}`);
  }

  const { updatedFindings, result } = applyTriageVerdicts(
    session.id,
    findingsDoc.findings,
    rawJson,
    preflight.platform
  );

  // Persist verdicts, updated findings, re-computed plan, and updated report.md
  const verdictsOutPath = path.join(session.dir, 'triage-verdicts.json');
  writeJsonAtomic(verdictsOutPath, result);
  writeJsonAtomic(findingsFile, { ...findingsDoc, findings: updatedFindings });

  const rules = loadRules(globalOpts.rulesPath);
  const { advisories, stopConditions } = evaluateAdvisoriesAndStops({
    preflight,
    findings: updatedFindings,
    defenderScan,
    rules,
  });

  const newPlan = buildPlan({
    sessionId: session.id,
    findings: updatedFindings,
    advisories,
    stopConditions,
    existingPlan,
  });
  writeJsonAtomic(existingPlanPath, newPlan);

  const reportMd = renderMarkdownReport({
    sessionId: session.id,
    preflight,
    findings: updatedFindings,
    defenderScan,
    advisories,
    stopConditions,
  });
  fs.writeFileSync(path.join(session.dir, 'report.md'), reportMd, 'utf8');

  const changedCount = result.accepted.filter((a) => a.tier_changed).length;
  bus.info(
    `Imported triage verdicts: ${result.accepted.length} accepted (${changedCount} tier change(s)), ${result.rejected.length} rejected.`
  );
  bus.emit('done', {
    command: 'triage import',
    session_id: session.id,
    accepted: result.accepted.length,
    rejected: result.rejected.length,
    tier_changes: changedCount,
    verdicts_path: verdictsOutPath,
    exit_code: EXIT_CODES.OK,
  });

  return EXIT_CODES.OK;
}
