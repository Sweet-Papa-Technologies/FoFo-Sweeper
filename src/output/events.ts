import fs from 'node:fs';
import path from 'node:path';
import type { NdjsonEvent, NdjsonEventType } from '../types.js';

export class EventBus {
  private readonly jsonMode: boolean;
  private readonly quiet: boolean;
  private sessionId?: string;
  private logFilePath?: string;

  constructor(options: { json: boolean; quiet: boolean; sessionId?: string; sessionDir?: string }) {
    this.jsonMode = options.json;
    this.quiet = options.quiet;
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
   * Prints human-readable progress text.
   * In --json mode, human text goes strictly to stderr so stdout remains pure NDJSON.
   */
  info(message: string): void {
    if (this.quiet) return;
    if (this.jsonMode) {
      process.stderr.write(message + '\n');
    } else {
      process.stdout.write(message + '\n');
    }
  }

  warn(message: string): void {
    if (this.quiet && !this.jsonMode) return;
    process.stderr.write(`WARN: ${message}\n`);
  }

  error(message: string): void {
    process.stderr.write(`ERROR: ${message}\n`);
  }
}
