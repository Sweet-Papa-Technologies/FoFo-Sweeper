import { EXIT_CODES, SESSION_RETENTION_DAYS, type ExitCode } from '../constants.js';
import type { EventBus } from '../output/events.js';
import { isElevated } from '../platform/privilege.js';
import { listSessions, purgeOldSessions, resolveSessionRoot } from '../session/manager.js';
import type { GlobalOptions } from '../types.js';

export interface SessionsCommandOptions {
  purge: boolean;
  days: number;
}

export async function runSessionsCommand(
  globalOpts: GlobalOptions,
  cmdOpts: SessionsCommandOptions,
  bus: EventBus
): Promise<ExitCode> {
  const elevated = isElevated();
  const { root: sessionRoot } = resolveSessionRoot(globalOpts.sessionRoot, elevated);

  if (cmdOpts.purge) {
    const days = Number.isFinite(cmdOpts.days) && cmdOpts.days >= 0 ? cmdOpts.days : SESSION_RETENTION_DAYS;
    const res = purgeOldSessions(sessionRoot, days);
    bus.info(
      `Purged ${res.purged.length} session(s) older than ${days} day(s); kept ${res.kept.length}.`
    );
    if (res.errors.length > 0) {
      for (const e of res.errors) bus.warn(`Failed to purge ${e.id}: ${e.error}`);
    }
    const exitCode: ExitCode = res.errors.length > 0 ? EXIT_CODES.PARTIAL_FAILURE : EXIT_CODES.OK;
    bus.emit('done', {
      command: 'sessions --purge',
      session_root: sessionRoot,
      older_than_days: days,
      ...res,
      exit_code: exitCode,
    });
    return exitCode;
  }

  const sessions = listSessions(sessionRoot);
  if (sessions.length === 0) {
    bus.info(`No sessions found in ${sessionRoot}.`);
  } else {
    bus.info(`Sessions in ${sessionRoot} (${sessions.length}):`);
    for (const s of sessions) {
      const counts = s.findings_summary
        ? `mal=${s.findings_summary.malicious} susp=${s.findings_summary.suspicious} rev=${s.findings_summary.review}`
        : 'no-findings';
      const kb = Math.round(s.size_bytes / 1024);
      bus.info(
        `  ${s.id}  age=${s.age_days}d  ${counts}  actions=${s.actions_taken ?? 0}  size=${kb}KB`
      );
    }
  }

  bus.emit('done', {
    command: 'sessions',
    session_root: sessionRoot,
    sessions,
    exit_code: EXIT_CODES.OK,
  });
  return EXIT_CODES.OK;
}
