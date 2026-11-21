import { DEFAULT_SINCE_DAYS, EXIT_CODES, SESSION_RETENTION_DAYS, VERSION, type ExitCode } from './constants.js';
import { runDefenderCommand } from './commands/defender.js';
import { runFixCommand } from './commands/fix.js';
import { runHardenCommand } from './commands/harden.js';
import { runScanCommand } from './commands/scan.js';
import { runSessionsCommand } from './commands/sessions.js';
import { runTriageExportCommand, runTriageImportCommand } from './commands/triage.js';
import { runUndoCommand } from './commands/undo.js';
import { runVerifyCommand } from './commands/verify.js';
import { EventBus } from './output/events.js';
import type { GlobalOptions } from './types.js';

export interface ParsedCli {
  command: string;
  subcommand?: string;
  positionals: string[];
  globalOpts: GlobalOptions;
  flags: Record<string, string | boolean>;
  showHelp: boolean;
  showVersion: boolean;
}

const VALUE_FLAGS = new Set([
  '--session',
  '--session-root',
  '--only',
  '--since',
  '--rules',
  '--defender',
  '--approve',
  '--item',
  '--out',
  '--days',
]);

export function parseArgv(argv: string[]): ParsedCli {
  const positionals: string[] = [];
  const flags: Record<string, string | boolean> = {};
  let showHelp = false;
  let showVersion = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '-h' || arg === '--help') {
      showHelp = true;
      continue;
    }
    if (arg === '-v' || arg === '--version') {
      showVersion = true;
      continue;
    }
    // Explicitly reject blanket --yes / -y (Section 3 design principle)
    if (arg === '--yes' || arg === '-y') {
      throw new Error('There is no blanket `--yes` flag. Use `--interactive` or `--approve <id,id>`.');
    }

    if (arg.startsWith('--')) {
      const eqIdx = arg.indexOf('=');
      if (eqIdx > 0) {
        const key = arg.slice(0, eqIdx);
        const val = arg.slice(eqIdx + 1);
        flags[key] = val;
      } else if (VALUE_FLAGS.has(arg)) {
        const next = argv[i + 1];
        if (next === undefined || next.startsWith('--')) {
          throw new Error(`Flag ${arg} requires a value`);
        }
        flags[arg] = next;
        i++;
      } else {
        flags[arg] = true;
      }
    } else {
      positionals.push(arg);
    }
  }

  const command = positionals[0] ?? '';
  const subcommand = positionals[1];

  const sinceRaw = typeof flags['--since'] === 'string' ? Number(flags['--since']) : DEFAULT_SINCE_DAYS;
  if (Number.isNaN(sinceRaw) || sinceRaw < 0) {
    throw new Error(`Invalid --since value: ${String(flags['--since'])}`);
  }

  const onlyRaw = typeof flags['--only'] === 'string' ? flags['--only'] : undefined;
  const only = onlyRaw
    ? onlyRaw
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
    : undefined;

  const globalOpts: GlobalOptions = {
    session: typeof flags['--session'] === 'string' ? flags['--session'] : undefined,
    json: flags['--json'] === true,
    sessionRoot: typeof flags['--session-root'] === 'string' ? flags['--session-root'] : undefined,
    only,
    since: sinceRaw,
    quiet: flags['--quiet'] === true,
    rulesPath: typeof flags['--rules'] === 'string' ? flags['--rules'] : undefined,
  };

  return {
    command,
    subcommand,
    positionals,
    globalOpts,
    flags,
    showHelp,
    showVersion,
  };
}

export function formatHelpText(): string {
  return `FoFo Care Sweep (fcsweep) v${VERSION}
Standalone deterministic malware, adware, and browser hijack cleanup CLI.

USAGE:
  fcsweep <command> [options]

COMMANDS:
  scan                    Read-only inspection, scoring, and report (default --defender quick)
  triage export           Export review/suspicious findings bundle for out-of-band AI triage
  triage import <file>    Validate and apply AI triage verdicts using fixed rules
  fix                     Apply approved actions (--interactive, --approve <id,id>, or --dry-run)
  verify                  Re-run collectors and flag any removed items that resurrected
  undo                    Revert a session (or one item with --item <id>) newest-first
  harden                  Apply built-in Windows hardening settings (--revert restores prior values)
  defender                Direct Microsoft Defender control (--status, --update, --quick, --full, --offline)
  sessions                List sessions (--purge removes sessions older than 30 days)

GLOBAL FLAGS:
  --session <id>          Session ID (default: newest for non-scan commands)
  --session-root <path>   Override default session directory
  --json                  Emit NDJSON events on stdout (human text on stderr)
  --only <c1,c2>          Run only named collectors
  --since <days>          Lookback window for "recent" signal (default: ${DEFAULT_SINCE_DAYS})
  --rules <path>          Override bundled rules.json scoring weights
  --quiet                 Suppress non-error human output
  -v, --version           Print version
  -h, --help              Show this help

EXIT CODES:
  0  Completed, nothing needs attention
  1  Tool error
  2  Completed, findings need review
  3  Elevation required
  4  Completed, reboot required to finish
  5  Partial: some actions failed
  6  Stop condition hit (run fcsweep defender --offline / Reset this PC)
`;
}

export async function runCli(argv: string[]): Promise<ExitCode> {
  let parsed: ParsedCli;
  try {
    parsed = parseArgv(argv);
  } catch (err) {
    process.stderr.write(`ERROR: ${err instanceof Error ? err.message : String(err)}\n`);
    return EXIT_CODES.ERROR;
  }

  if (parsed.showVersion) {
    process.stdout.write(`fcsweep ${VERSION}\n`);
    return EXIT_CODES.OK;
  }

  if (parsed.showHelp || !parsed.command) {
    process.stdout.write(formatHelpText());
    return EXIT_CODES.OK;
  }

  const bus = new EventBus({
    json: parsed.globalOpts.json,
    quiet: parsed.globalOpts.quiet,
  });

  try {
    switch (parsed.command) {
      case 'scan': {
        const defFlag = parsed.flags['--defender'];
        const defaultDef = process.platform === 'win32' ? 'quick' : 'none';
        const defenderMode = (typeof defFlag === 'string' ? defFlag : defaultDef).toLowerCase();
        if (defenderMode !== 'quick' && defenderMode !== 'full' && defenderMode !== 'none') {
          throw new Error(`Invalid --defender mode "${defenderMode}". Use quick, full, or none.`);
        }
        return await runScanCommand(parsed.globalOpts, { defenderMode }, bus);
      }

      case 'triage': {
        if (parsed.subcommand === 'export') {
          const outPath = typeof parsed.flags['--out'] === 'string' ? parsed.flags['--out'] : undefined;
          return await runTriageExportCommand(parsed.globalOpts, outPath, bus);
        }
        if (parsed.subcommand === 'import') {
          const fileArg = parsed.positionals[2];
          if (!fileArg) throw new Error('Usage: fcsweep triage import <verdicts.json>');
          return await runTriageImportCommand(parsed.globalOpts, fileArg, bus);
        }
        throw new Error('Usage: fcsweep triage <export|import <file>>');
      }

      case 'fix': {
        const approveRaw = typeof parsed.flags['--approve'] === 'string' ? parsed.flags['--approve'] : undefined;
        const approveIds = approveRaw
          ? approveRaw
              .split(',')
              .map((s) => s.trim())
              .filter(Boolean)
          : undefined;
        return await runFixCommand(
          parsed.globalOpts,
          {
            interactive: parsed.flags['--interactive'] === true,
            approveIds,
            dryRun: parsed.flags['--dry-run'] === true,
          },
          bus
        );
      }

      case 'verify':
        return await runVerifyCommand(parsed.globalOpts, bus);

      case 'undo': {
        const itemId = typeof parsed.flags['--item'] === 'string' ? parsed.flags['--item'] : undefined;
        return await runUndoCommand(parsed.globalOpts, itemId, bus);
      }

      case 'harden':
        return await runHardenCommand(parsed.globalOpts, parsed.flags['--revert'] === true, bus);

      case 'defender':
        return await runDefenderCommand(
          parsed.globalOpts,
          {
            status: parsed.flags['--status'] === true,
            update: parsed.flags['--update'] === true,
            quick: parsed.flags['--quick'] === true,
            full: parsed.flags['--full'] === true,
            offline: parsed.flags['--offline'] === true,
          },
          bus
        );

      case 'sessions': {
        const days =
          typeof parsed.flags['--days'] === 'string'
            ? Number(parsed.flags['--days'])
            : SESSION_RETENTION_DAYS;
        return await runSessionsCommand(
          parsed.globalOpts,
          {
            purge: parsed.flags['--purge'] === true,
            days,
          },
          bus
        );
      }

      default:
        bus.error(`Unknown command: ${parsed.command}. Run 'fcsweep --help' for usage.`);
        return EXIT_CODES.ERROR;
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    bus.error(msg);
    bus.emit('done', {
      command: parsed.command,
      error: msg,
      exit_code: EXIT_CODES.ERROR,
    });
    return EXIT_CODES.ERROR;
  }
}
