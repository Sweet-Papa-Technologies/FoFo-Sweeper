import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { EXIT_CODES, type ExitCode } from '../constants.js';
import { resolveCollectorList, runCollectors } from '../collectors/index.js';
import { loadRules } from '../data-loader.js';
import type { EventBus } from '../output/events.js';
import { renderMarkdownReport } from '../output/report.js';
import { isElevated } from '../platform/privilege.js';
import { evaluateAdvisoriesAndStops } from '../scoring/advisories.js';
import {
  detectPlatform,
  readJsonFile,
  resolveExistingSession,
  resolveSessionRoot,
  writeJsonAtomic,
} from '../session/manager.js';
import type {
  CollectedItem,
  DefenderScanResult,
  Finding,
  GlobalOptions,
  Manifest,
  Plan,
  PreflightResult,
  VerifyItemStatus,
  VerifyResult,
} from '../types.js';

function normStr(s: string | null | undefined): string {
  return (s ?? '').replace(/\//g, '\\').toLowerCase().trim();
}

export function evaluateVerification(params: {
  sessionId: string;
  preflight: PreflightResult;
  findings: Finding[];
  manifest: Manifest;
  currentItems: CollectedItem[];
  previousVerify?: VerifyResult | null;
  bootTimeMs: number;
}): VerifyResult {
  const { sessionId, preflight, findings, manifest, currentItems, previousVerify, bootTimeMs } = params;
  const rules = loadRules();

  const prevCounts = new Map<string, number>();
  if (previousVerify) {
    for (const item of previousVerify.items) {
      prevCounts.set(`${item.finding_id}:${item.action}`, item.resurrection_count);
    }
  }

  const findingById = new Map(findings.map((f) => [f.id, f]));
  const succeededEntries = manifest.entries.filter(
    (e) => e.status === 'succeeded' && e.undo_status !== 'undone'
  );

  // Build lookup sets from current fresh snapshot
  const currentLocations = new Set(currentItems.map((i) => normStr(i.location)));
  const currentPaths = new Set(
    currentItems.map((i) => normStr(i.facts.target_path)).filter(Boolean)
  );
  const currentHashes = new Set(
    currentItems.map((i) => normStr(i.facts.sha256)).filter(Boolean)
  );
  const disabledServices = new Set(
    currentItems
      .filter((i) => i.kind === 'service' && normStr(i.facts.start_mode) === 'disabled')
      .map((i) => normStr(i.location))
  );

  const items: VerifyItemStatus[] = [];

  for (const entry of succeededEntries) {
    const f = findingById.get(entry.finding_id);
    const key = `${entry.finding_id}:${entry.action}`;
    const prevCount = prevCounts.get(key) ?? 0;

    if (entry.action === 'uninstall_program' || entry.action === 'guide_extension') {
      items.push({
        finding_id: entry.finding_id,
        location: entry.location,
        action: entry.action,
        status: 'not_applicable',
        resurrection_count: prevCount,
      });
      continue;
    }

    let returned = false;
    let evidence: string | undefined;
    const normLoc = normStr(entry.location);
    const normTarget = normStr(f?.facts.target_path);
    const normHash = normStr(f?.facts.sha256);

    switch (entry.action) {
      case 'disable_service': {
        // Service entry remains in Services registry when disabled; resurrected only if StartMode is no longer Disabled
        if (currentLocations.has(normLoc) && !disabledServices.has(normLoc)) {
          returned = true;
          evidence = 'Service StartMode is no longer Disabled';
        }
        break;
      }
      case 'quarantine_file': {
        if (normTarget && (currentPaths.has(normTarget) || fs.existsSync(f?.facts.target_path ?? ''))) {
          returned = true;
          evidence = `Quarantined file reappeared at ${f?.facts.target_path}`;
        } else if (normHash && currentHashes.has(normHash)) {
          returned = true;
          evidence = `File with matching SHA-256 ${normHash.slice(0, 16)}… reappeared`;
        }
        break;
      }
      case 'kill_process': {
        if (
          (normTarget && currentItems.some((i) => i.kind === 'process' && normStr(i.facts.target_path) === normTarget)) ||
          (normHash && currentItems.some((i) => i.kind === 'process' && normStr(i.facts.sha256) === normHash))
        ) {
          returned = true;
          evidence = 'Terminated process binary is running again';
        }
        break;
      }
      default: {
        // autorun, task (collector excludes Disabled tasks), wmi, hijack, policy, notification, proxy, hosts, exclusion, root cert
        if (currentLocations.has(normLoc)) {
          returned = true;
          evidence = `Entry reappeared at ${entry.location}`;
        }
        break;
      }
    }

    const newCount = returned ? prevCount + 1 : prevCount;
    items.push({
      finding_id: entry.finding_id,
      location: entry.location,
      action: entry.action,
      status: returned ? 'resurrected' : 'clean',
      resurrection_count: newCount,
      ...(evidence ? { evidence } : {}),
    });
  }

  // Check if machine rebooted after latest fix action
  const latestFixMs = succeededEntries.reduce((max, e) => {
    const t = Date.parse(e.completed_at || e.timestamp);
    return Number.isNaN(t) ? max : Math.max(max, t);
  }, 0);
  const postReboot = latestFixMs > 0 ? bootTimeMs > latestFixMs : false;
  const rebootRequired =
    preflight.pending_reboot || (succeededEntries.length > 0 && !postReboot);

  const { stopConditions } = evaluateAdvisoriesAndStops({
    preflight,
    findings,
    verifyItems: items,
    rules,
  });

  return {
    session_id: sessionId,
    verified_at: new Date().toISOString(),
    boot_time: new Date(bootTimeMs).toISOString(),
    post_reboot: postReboot,
    reboot_required: rebootRequired,
    items,
    resurrected_count: items.filter((i) => i.status === 'resurrected').length,
    stop_conditions: stopConditions,
  };
}

export async function runVerifyCommand(
  globalOpts: GlobalOptions,
  bus: EventBus
): Promise<ExitCode> {
  const platform = detectPlatform();
  const elevated = isElevated();
  const { root: sessionRoot } = resolveSessionRoot(globalOpts.sessionRoot, elevated);
  const session = resolveExistingSession(sessionRoot, globalOpts.session);
  bus.attachSession(session.id, session.dir);

  const preflight = readJsonFile<PreflightResult>(path.join(session.dir, 'preflight.json'));
  const findingsDoc = readJsonFile<{ findings: Finding[] }>(path.join(session.dir, 'findings.json'));
  const manifestPath = path.join(session.dir, 'manifest.json');
  const manifest: Manifest = fs.existsSync(manifestPath)
    ? readJsonFile<Manifest>(manifestPath)
    : { session_id: session.id, created_at: new Date().toISOString(), entries: [] };

  const verifyPath = path.join(session.dir, 'verify.json');
  const previousVerify = fs.existsSync(verifyPath) ? readJsonFile<VerifyResult>(verifyPath) : null;

  const collectors = globalOpts.only
    ? resolveCollectorList(platform, globalOpts.only)
    : preflight.collectors_requested.length > 0
      ? preflight.collectors_requested
      : resolveCollectorList(platform);

  bus.emit('phase_start', { phase: 'verify', collectors });
  const fresh = await runCollectors({
    platform,
    collectors,
    preflight,
    bus,
  });

  const bootTimeMs = Date.now() - os.uptime() * 1000;
  const result = evaluateVerification({
    sessionId: session.id,
    preflight,
    findings: findingsDoc.findings,
    manifest,
    currentItems: fresh.allItems,
    previousVerify,
    bootTimeMs,
  });

  writeJsonAtomic(verifyPath, result);

  // Update report.md with verification section
  const planPath = path.join(session.dir, 'plan.json');
  const plan = fs.existsSync(planPath) ? readJsonFile<Plan>(planPath) : null;
  const defenderPath = path.join(session.dir, 'defender.json');
  const defenderScan = fs.existsSync(defenderPath) ? readJsonFile<DefenderScanResult>(defenderPath) : null;
  const reportMd = renderMarkdownReport({
    sessionId: session.id,
    preflight,
    findings: findingsDoc.findings,
    defenderScan,
    advisories: plan?.advisories ?? [],
    stopConditions: result.stop_conditions,
    manifest,
    verifyResult: result,
  });
  fs.writeFileSync(path.join(session.dir, 'report.md'), reportMd, 'utf8');

  let exitCode: ExitCode = EXIT_CODES.OK;
  if (result.stop_conditions.length > 0) {
    exitCode = EXIT_CODES.STOP_CONDITION;
  } else if (result.resurrected_count > 0) {
    exitCode = EXIT_CODES.FINDINGS_NEED_REVIEW;
  } else if (result.reboot_required) {
    exitCode = EXIT_CODES.REBOOT_REQUIRED;
  }

  bus.info(
    `Verification complete: ${result.resurrected_count} resurrected item(s), post_reboot=${result.post_reboot}, reboot_required=${result.reboot_required}.`
  );
  bus.emit('done', {
    command: 'verify',
    session_id: session.id,
    resurrected_count: result.resurrected_count,
    reboot_required: result.reboot_required,
    stop_conditions: result.stop_conditions.length,
    exit_code: exitCode,
  });

  return exitCode;
}
