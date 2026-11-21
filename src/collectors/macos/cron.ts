import fs from 'node:fs';
import path from 'node:path';
import { execFileSafe } from '../../platform/exec.js';
import type { CollectedItem, CollectorRunResult } from '../../types.js';

const DEFAULT_PERIODIC_FILES = new Set([
  '100.clean-logs',
  '110.clean-tmps',
  '130.clean-msgs',
  '140.clean-rwho',
  '199.clean-fax',
  '310.accounting',
  '400.status-disks',
  '420.status-network',
  '430.status-rwho',
  '500.queuerun',
  '999.local',
  '320.whatis',
  '200.accounting',
]);

export async function collectMacosCron(timeoutMs: number): Promise<CollectorRunResult> {
  const start = Date.now();
  const items: CollectedItem[] = [];
  const warnings: string[] = [];

  // 1. Current user crontab
  const ct = await execFileSafe('crontab', ['-l'], { timeoutMs: Math.min(timeoutMs, 10_000) });
  if (ct.exitCode === 0 && ct.stdout.trim()) {
    const lines = ct.stdout.split(/\r?\n/);
    lines.forEach((rawLine, idx) => {
      const line = rawLine.trim();
      if (!line || line.startsWith('#') || /^[A-Za-z_][A-Za-z0-9_]*=/.test(line)) return;
      items.push({
        collector: 'cron',
        kind: 'cron_job',
        location: `crontab:user:L${idx + 1}`,
        facts: {},
        untrusted: {
          name: `User crontab line ${idx + 1}`,
          command_line: line,
        },
        command_inspect: line,
      });
    });
  }

  // 2. /etc/crontab
  if (fs.existsSync('/etc/crontab')) {
    try {
      const content = fs.readFileSync('/etc/crontab', 'utf8');
      content.split(/\r?\n/).forEach((rawLine, idx) => {
        const line = rawLine.trim();
        if (!line || line.startsWith('#') || /^[A-Za-z_][A-Za-z0-9_]*=/.test(line)) return;
        items.push({
          collector: 'cron',
          kind: 'cron_job',
          location: `/etc/crontab:L${idx + 1}`,
          facts: { runs_as: 'root' },
          untrusted: {
            name: `/etc/crontab line ${idx + 1}`,
            command_line: line,
          },
          command_inspect: line,
        });
      });
    } catch {
      // ignore
    }
  }

  // 3. Non-default additions in /etc/periodic/{daily,weekly,monthly}
  for (const sub of ['daily', 'weekly', 'monthly']) {
    const dir = path.join('/etc/periodic', sub);
    if (!fs.existsSync(dir)) continue;
    try {
      for (const f of fs.readdirSync(dir)) {
        if (DEFAULT_PERIODIC_FILES.has(f)) continue;
        const fullPath = path.join(dir, f);
        let contentSnippet = '';
        try {
          contentSnippet = fs.readFileSync(fullPath, 'utf8').slice(0, 300);
        } catch {
          // ignore
        }
        items.push({
          collector: 'cron',
          kind: 'cron_job',
          location: fullPath,
          facts: {
            target_path: fullPath,
            file_exists: true,
            runs_as: 'root',
          },
          untrusted: {
            name: f,
            command_line: contentSnippet || fullPath,
          },
          command_inspect: contentSnippet || fullPath,
        });
      }
    } catch {
      // ignore
    }
  }

  return {
    collector: 'cron',
    status: warnings.length > 0 ? 'partial' : 'ok',
    duration_ms: Date.now() - start,
    item_count: items.length,
    items,
    warnings,
  };
}
