import { EXIT_CODES, type ExitCode } from '../constants.js';
import {
  getDefenderStatus,
  readDefenderDetections,
  runWindowsDefenderOfflineScan,
  runWindowsDefenderScan,
  updateDefenderSignatures,
} from '../defender/windows-defender.js';
import type { EventBus } from '../output/events.js';
import { isElevated } from '../platform/privilege.js';
import { detectPlatform } from '../session/manager.js';
import type { GlobalOptions } from '../types.js';

export interface DefenderCommandOptions {
  status: boolean;
  update: boolean;
  quick: boolean;
  full: boolean;
  offline: boolean;
}

export async function runDefenderCommand(
  globalOpts: GlobalOptions,
  cmdOpts: DefenderCommandOptions,
  bus: EventBus
): Promise<ExitCode> {
  void globalOpts;
  if (detectPlatform() !== 'windows') {
    bus.error('`fcsweep defender` is only available on Windows.');
    return EXIT_CODES.ERROR;
  }

  const wantsScanOrMutate = cmdOpts.update || cmdOpts.quick || cmdOpts.full || cmdOpts.offline;
  const wantsStatus = cmdOpts.status || !wantsScanOrMutate;

  if (wantsScanOrMutate && !isElevated()) {
    bus.error('`fcsweep defender` scan/update/offline actions require an elevated Administrator terminal (exit code 3).');
    bus.emit('done', { command: 'defender', exit_code: EXIT_CODES.ELEVATION_REQUIRED, error: 'Elevation required' });
    return EXIT_CODES.ELEVATION_REQUIRED;
  }

  if (wantsStatus && !wantsScanOrMutate) {
    const status = await getDefenderStatus();
    const detections = await readDefenderDetections(168);
    if (!status.available) {
      bus.warn(`Microsoft Defender status unavailable: ${status.error ?? 'unknown'}`);
    } else {
      bus.info(
        `Microsoft Defender: mode=${status.am_running_mode ?? 'normal'}, realtime=${status.realtime_enabled}, ` +
          `tamper=${status.tamper_protected}, pua=${status.pua_protection}, signatures=${status.signature_version} (age=${status.signature_age_days}d)`
      );
      bus.info(`Recent detections (7d): ${detections.length}`);
    }
    bus.emit('done', {
      command: 'defender --status',
      status,
      recent_detections: detections,
      exit_code: detections.length > 0 ? EXIT_CODES.FINDINGS_NEED_REVIEW : EXIT_CODES.OK,
    });
    return detections.length > 0 ? EXIT_CODES.FINDINGS_NEED_REVIEW : EXIT_CODES.OK;
  }

  if (cmdOpts.offline) {
    bus.emit('phase_start', { phase: 'defender_offline' });
    bus.info('Scheduling Microsoft Defender Offline scan (system will reboot)...');
    const res = await runWindowsDefenderOfflineScan();
    if (!res.ok) {
      bus.error(`Start-MpWDOScan failed: ${res.error}`);
      bus.emit('done', { command: 'defender --offline', ok: false, error: res.error, exit_code: EXIT_CODES.ERROR });
      return EXIT_CODES.ERROR;
    }
    bus.emit('done', { command: 'defender --offline', ok: true, exit_code: EXIT_CODES.REBOOT_REQUIRED });
    return EXIT_CODES.REBOOT_REQUIRED;
  }

  if (cmdOpts.update && !cmdOpts.quick && !cmdOpts.full) {
    bus.emit('phase_start', { phase: 'defender_update' });
    const upd = await updateDefenderSignatures();
    if (!upd.ok) {
      bus.error(`Update-MpSignature failed: ${upd.error}`);
      bus.emit('done', { command: 'defender --update', ok: false, error: upd.error, exit_code: EXIT_CODES.ERROR });
      return EXIT_CODES.ERROR;
    }
    bus.info(`Defender signatures updated: ${upd.signatureVersion ?? 'latest'}`);
    bus.emit('done', {
      command: 'defender --update',
      ok: true,
      signature_version: upd.signatureVersion,
      exit_code: EXIT_CODES.OK,
    });
    return EXIT_CODES.OK;
  }

  const scanType = cmdOpts.full ? 'full' : 'quick';
  bus.emit('phase_start', { phase: 'defender_scan', scan_type: scanType });
  bus.info(`Starting Microsoft Defender ${scanType} scan...`);
  const result = await runWindowsDefenderScan(scanType, { updateFirst: cmdOpts.update || true });
  if (result.status === 'error') {
    bus.error(`Defender ${scanType} scan failed: ${result.error}`);
    bus.emit('done', { command: `defender --${scanType}`, ...result, exit_code: EXIT_CODES.ERROR });
    return EXIT_CODES.ERROR;
  }

  bus.info(
    `Defender ${scanType} scan complete (signatures ${result.signature_version ?? 'unknown'}): ${result.detections.length} detection(s).`
  );
  const exitCode: ExitCode = result.detections.length > 0 ? EXIT_CODES.FINDINGS_NEED_REVIEW : EXIT_CODES.OK;
  bus.emit('done', {
    command: `defender --${scanType}`,
    ...result,
    exit_code: exitCode,
  });
  return exitCode;
}
