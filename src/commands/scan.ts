import fs from 'node:fs';
import path from 'node:path';
import { EXIT_CODES, type ExitCode } from '../constants.js';
import { resolveCollectorList, runCollectors } from '../collectors/index.js';
import { runMacosPreflight } from '../collectors/macos/preflight.js';
import { runWindowsPreflight } from '../collectors/windows/preflight.js';
import { loadRules } from '../data-loader.js';
import { runSafetyScannerFallback } from '../defender/safety-scanner.js';
import { readDefenderDetections, runWindowsDefenderScan } from '../defender/windows-defender.js';
import type { EventBus } from '../output/events.js';
import { renderMarkdownReport } from '../output/report.js';
import { classifyPath } from '../platform/file-facts.js';
import { isElevated } from '../platform/privilege.js';
import { buildPlan } from '../remediation/plan.js';
import { evaluateAdvisoriesAndStops } from '../scoring/advisories.js';
import { scoreAllItems } from '../scoring/engine.js';
import {
  createSession,
  detectPlatform,
  resolveSessionRoot,
  writeJsonAtomic,
} from '../session/manager.js';
import type {
  CollectedItem,
  DefenderScanResult,
  GlobalOptions,
  PreflightResult,
  Snapshot,
} from '../types.js';

export interface ScanCommandOptions {
  defenderMode: 'quick' | 'full' | 'none';
}

export async function runScanCommand(
  globalOpts: GlobalOptions,
  cmdOpts: ScanCommandOptions,
  bus: EventBus
): Promise<ExitCode> {
  const platform = detectPlatform();
  const elevated = isElevated();
  const { root: sessionRoot, fallbackUsed } = resolveSessionRoot(globalOpts.sessionRoot, elevated);
  const collectors = resolveCollectorList(platform, globalOpts.only);

  const session = createSession(sessionRoot, elevated, globalOpts.session);
  bus.attachSession(session.id, session.dir);

  if (fallbackUsed) {
    bus.warn(`Default system session root was not writable; using ${sessionRoot}`);
  }

  bus.emit('phase_start', { phase: 'preflight', platform, elevated });
  bus.info(`Session ${session.id} (${session.dir})`);

  let preflight: PreflightResult;
  if (platform === 'windows') {
    preflight = await runWindowsPreflight(elevated, collectors);
  } else if (platform === 'macos') {
    preflight = await runMacosPreflight(elevated, collectors);
  } else {
    preflight = {
      timestamp: new Date().toISOString(),
      tool_version: '0.1.0',
      platform,
      hostname: (await import('node:os')).hostname(),
      os_version: process.platform,
      os_build: (await import('node:os')).release(),
      arch: process.arch,
      elevated,
      pending_reboot: false,
      pending_reboot_reasons: [],
      free_disk_bytes: null,
      domain_joined: false,
      mdm_enrolled: false,
      av_products: [],
      defender: { available: false, active: false, mode: 'unavailable' },
      collectors_requested: collectors,
      collectors_skipped: [],
      collectors_partial: [],
      ransomware_indicators: [],
    };
  }

  // Phase 2: Snapshot (run every collector)
  bus.emit('phase_start', { phase: 'snapshot', collectors });
  const collected = await runCollectors({
    platform,
    collectors,
    preflight,
    bus,
  });

  // Persist preflight after collectors finish so skipped/partial lists are included
  writeJsonAtomic(path.join(session.dir, 'preflight.json'), preflight);

  const collectorSummary: Snapshot['collectors'] = {};
  for (const r of collected.results) {
    collectorSummary[r.collector] = {
      status: r.status,
      duration_ms: r.duration_ms,
      item_count: r.item_count,
      warnings: r.warnings,
      ...(r.error ? { error: r.error } : {}),
    };
  }

  const snapshot: Snapshot = {
    session_id: session.id,
    timestamp: new Date().toISOString(),
    platform,
    collectors: collectorSummary,
    items: collected.allItems,
  };
  writeJsonAtomic(path.join(session.dir, 'snapshot.json'), snapshot);

  // Phase 3: Known-threat scan (Windows only)
  let defenderScan: DefenderScanResult = {
    timestamp: new Date().toISOString(),
    engine: 'skipped',
    scan_type: cmdOpts.defenderMode,
    signature_updated: false,
    status: 'skipped',
    detections: [],
  };

  if (platform === 'windows' && cmdOpts.defenderMode !== 'none') {
    bus.emit('phase_start', { phase: 'defender', scan_type: cmdOpts.defenderMode });
    if (!elevated) {
      // Section 3: scan runs without elevation and marks skipped/partial
      const recentDetections = await readDefenderDetections(24);
      defenderScan = {
        timestamp: new Date().toISOString(),
        engine: 'defender',
        scan_type: cmdOpts.defenderMode,
        signature_updated: false,
        signature_version: preflight.defender.signature_version ?? null,
        status: 'skipped',
        detections: recentDetections,
        error: 'Active Defender scan skipped because process is not elevated; read recent detections only',
      };
      preflight.collectors_partial.push({
        collector: 'defender_scan',
        reason: 'Not elevated: skipped Update-MpSignature / Start-MpScan',
      });
      writeJsonAtomic(path.join(session.dir, 'preflight.json'), preflight);
      bus.warn('Not elevated: skipping active Defender scan (re-run elevated for Update-MpSignature + Start-MpScan).');
    } else if (preflight.defender.active) {
      bus.info(`Running Microsoft Defender ${cmdOpts.defenderMode} scan...`);
      defenderScan = await runWindowsDefenderScan(cmdOpts.defenderMode, { updateFirst: true });
    } else {
      bus.info(
        `Microsoft Defender is not active (mode=${preflight.defender.mode}); falling back to Microsoft Safety Scanner (detect-only)...`
      );
      defenderScan = await runSafetyScannerFallback(session.dir, cmdOpts.defenderMode);
    }
  }
  writeJsonAtomic(path.join(session.dir, 'defender.json'), defenderScan);

  // Fold any standalone Defender/Safety Scanner detections (e.g. EICAR file on disk) into items
  const itemsToScore: CollectedItem[] = [...collected.allItems];
  const existingPaths = new Set(
    collected.allItems
      .map((i) => i.facts.target_path?.replace(/\//g, '\\').toLowerCase())
      .filter(Boolean) as string[]
  );

  for (const det of defenderScan.detections) {
    for (const rawRes of det.resources) {
      const cleanedPath = rawRes.replace(/^[a-z]+:_/i, '').trim();
      const norm = cleanedPath.replace(/\//g, '\\').toLowerCase();
      if (norm && !existingPaths.has(norm)) {
        existingPaths.add(norm);
        const exists = fs.existsSync(cleanedPath);
        itemsToScore.push({
          collector: 'defender',
          kind: 'defender_detection',
          location: cleanedPath || `Threat:${det.threat_name}`,
          facts: {
            target_path: cleanedPath || null,
            file_exists: exists,
            path_class: cleanedPath ? classifyPath(cleanedPath, platform) : undefined,
            defender_hit: true,
            defender_threat_name: det.threat_name,
          },
          untrusted: {
            name: det.threat_name,
            raw_value: rawRes,
          },
          remediation_meta: cleanedPath ? { target_file_path: cleanedPath } : undefined,
        });
      }
    }
  }

  // Phase 4: Score
  bus.emit('phase_start', { phase: 'score', item_count: itemsToScore.length });
  const rules = loadRules(globalOpts.rulesPath);
  const findings = scoreAllItems(itemsToScore, {
    rules,
    platform,
    sinceDays: globalOpts.since,
    defenderExclusions: collected.defenderExclusions,
    defenderDetections: defenderScan.detections,
    protectedCtx: {
      platform,
      avProducts: preflight.av_products,
      toolPaths: [process.execPath, path.dirname(process.execPath)],
      sessionRoot,
    },
  });

  writeJsonAtomic(path.join(session.dir, 'findings.json'), {
    session_id: session.id,
    generated_at: new Date().toISOString(),
    since_days: globalOpts.since,
    findings,
  });

  const { advisories, stopConditions } = evaluateAdvisoriesAndStops({
    preflight,
    findings,
    defenderScan,
    rules,
  });

  const plan = buildPlan({
    sessionId: session.id,
    findings,
    advisories,
    stopConditions,
  });
  writeJsonAtomic(path.join(session.dir, 'plan.json'), plan);

  // Emit non-clean findings & advisories as NDJSON events
  for (const f of findings) {
    if (f.tier === 'clean') continue;
    bus.emit('finding', {
      id: f.id,
      collector: f.collector,
      kind: f.kind,
      location: f.location,
      tier: f.tier,
      score: f.score,
      signals: f.signals,
      proposed_action: f.proposed_action,
      protected: f.protected,
      facts: f.facts,
    });
  }
  for (const adv of advisories) {
    bus.emit('advisory', { ...adv });
  }

  // Render human report
  const reportMd = renderMarkdownReport({
    sessionId: session.id,
    preflight,
    findings,
    defenderScan,
    advisories,
    stopConditions,
  });
  const reportPath = path.join(session.dir, 'report.md');
  fs.writeFileSync(reportPath, reportMd, 'utf8');

  const counts = {
    malicious: findings.filter((f) => f.tier === 'malicious').length,
    suspicious: findings.filter((f) => f.tier === 'suspicious').length,
    review: findings.filter((f) => f.tier === 'review').length,
    clean: findings.filter((f) => f.tier === 'clean').length,
  };

  let exitCode: ExitCode = EXIT_CODES.OK;
  if (stopConditions.length > 0) {
    exitCode = EXIT_CODES.STOP_CONDITION;
  } else if (counts.malicious > 0 || counts.suspicious > 0 || counts.review > 0) {
    exitCode = EXIT_CODES.FINDINGS_NEED_REVIEW;
  }

  bus.info(
    `Scan complete: ${counts.malicious} malicious, ${counts.suspicious} suspicious, ${counts.review} review (${counts.clean} clean).`
  );
  bus.info(`Report written to: ${reportPath}`);

  bus.emit('done', {
    command: 'scan',
    session_id: session.id,
    session_dir: session.dir,
    report_path: reportPath,
    counts,
    stop_conditions: stopConditions.length,
    exit_code: exitCode,
  });

  return exitCode;
}
