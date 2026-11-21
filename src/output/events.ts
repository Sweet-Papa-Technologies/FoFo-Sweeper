import fs from 'node:fs';
import path from 'node:path';
import type { NdjsonEvent, NdjsonEventType } from '../types.js';
import { shouldUseColor, TerminalUI } from './ui.js';

export class EventBus {
  readonly jsonMode: boolean;
  readonly quiet: boolean;
  readonly ui: TerminalUI;
  private sessionId?: string;
  private logFilePath?: string;

  constructor(options: {
    json: boolean;
    quiet: boolean;
    color?: boolean;
    sessionId?: string;
    sessionDir?: string;
  }) {
    this.jsonMode = options.json;
    this.quiet = options.quiet;
    this.ui = new TerminalUI(options.json ? false : shouldUseColor(options.color));
    this.sessionId = options.sessionId;
    if (options.sessionDir) {
      this.attachSession(options.sessionId ?? path.basename(options.sessionDir), options.sessionDir);
    }
  }

  attachSession(sessionId: string, sessionDir: string): void {
    this.sessionId = sessionId;
    this.logFilePath = path.join(sessionDir, 'actions.log');
  }

  emit(event: NdjsonEventType, payload: Record<string, unknown> = {}): void {
    const record: NdjsonEvent = {
      event,
      timestamp: new Date().toISOString(),
      ...(this.sessionId ? { session_id: this.sessionId } : {}),
      ...payload,
    };

    const line = JSON.stringify(record) + '\n';

    if (this.logFilePath) {
      try {
        fs.appendFileSync(this.logFilePath, line, { encoding: 'utf8' });
      } catch {
        // Never crash telemetry/logging if session folder was not initialized yet
      }
    }

    if (this.jsonMode) {
      process.stdout.write(line);
    }
  }

  /**
   * Prints formatted human-readable output.
   * In --json mode, human text goes strictly to stderr so stdout remains pure NDJSON.
   */
  raw(block: string): void {
    if (this.quiet || !block) return;
    if (this.jsonMode) {
      process.stderr.write(block + '\n');
    } else {
      process.stdout.write(block + '\n');
    }
  }

  info(message: string): void {
    if (this.quiet) return;
    if (this.jsonMode) {
      process.stderr.write(message + '\n');
    } else {
      process.stdout.write(message + '\n');
    }
  }

  phase(emoji: string, title: string, detail?: string): void {
    if (this.quiet) return;
    this.raw(this.ui.phase(emoji, title, detail));
  }

  warn(message: string): void {
    if (this.quiet && !this.jsonMode) return;
    const prefix = this.ui.yellow('⚠️  WARN:');
    process.stderr.write(`${prefix} ${message}\n`);
  }

  error(message: string): void {
    const prefix = this.ui.red('❌ ERROR:');
    process.stderr.write(`${prefix} ${message}\n`);
  }
}
