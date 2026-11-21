import type { Advisory, Finding, StopCondition, Tier } from '../types.js';
import { sanitizeUntrusted } from './sanitize.js';

export interface ColorOptions {
  enabled: boolean;
}

export function shouldUseColor(explicit?: boolean): boolean {
  if (explicit === true) return true;
  if (explicit === false) return false;
  if (process.env.NO_COLOR !== undefined && process.env.NO_COLOR !== '') return false;
  if (process.env.FORCE_COLOR !== undefined && process.env.FORCE_COLOR !== '0') return true;
  if (process.env.TERM === 'dumb') return false;
  return Boolean(process.stdout.isTTY || process.stderr.isTTY);
}

const ANSI = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  italic: '\x1b[3m',
  underline: '\x1b[4m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  gray: '\x1b[90m',
  brightRed: '\x1b[91m',
  brightGreen: '\x1b[92m',
  brightYellow: '\x1b[93m',
  brightCyan: '\x1b[96m',
  brightWhite: '\x1b[97m',
  bgRed: '\x1b[41m',
  bgYellow: '\x1b[43m',
  bgCyan: '\x1b[46m',
  bgGreen: '\x1b[42m',
} as const;

export class TerminalUI {
  readonly color: boolean;

  constructor(color: boolean) {
    this.color = color;
  }

  private wrap(codes: string[], text: string): string {
    if (!this.color) return text;
    return `${codes.join('')}${text}${ANSI.reset}`;
  }

  bold(s: string): string {
    return this.wrap([ANSI.bold], s);
  }

  dim(s: string): string {
    return this.wrap([ANSI.dim], s);
  }

  gray(s: string): string {
    return this.wrap([ANSI.gray], s);
  }

  cyan(s: string): string {
    return this.wrap([ANSI.brightCyan], s);
  }

  teal(s: string): string {
    return this.wrap([ANSI.cyan], s);
  }

  green(s: string): string {
    return this.wrap([ANSI.brightGreen], s);
  }

  yellow(s: string): string {
    return this.wrap([ANSI.brightYellow], s);
  }

  red(s: string): string {
    return this.wrap([ANSI.brightRed], s);
  }

  magenta(s: string): string {
    return this.wrap([ANSI.magenta], s);
  }

  whiteBold(s: string): string {
    return this.wrap([ANSI.bold, ANSI.brightWhite], s);
  }

  formatDuration(ms: number): string {
    if (ms < 1000) return `${Math.round(ms)}ms`;
    return `${(ms / 1000).toFixed(1)}s`;
  }

  tierBadge(tier: Tier): string {
    switch (tier) {
      case 'malicious':
        return this.wrap([ANSI.bold, ANSI.brightRed], '🚨 MALICIOUS');
      case 'suspicious':
        return this.wrap([ANSI.bold, ANSI.brightYellow], '🟠 SUSPICIOUS');
      case 'review':
        return this.wrap([ANSI.bold, ANSI.brightCyan], '🔎 REVIEW');
      case 'clean':
        return this.wrap([ANSI.brightGreen], '✨ CLEAN');
    }
  }

  private wrapWords(text: string, width: number): string[] {
    const words = text.split(/\s+/).filter(Boolean);
    const lines: string[] = [];
    let current = '';
    for (const w of words) {
      if (!current) {
        current = w;
      } else if (current.length + 1 + w.length <= width) {
        current += ' ' + w;
      } else {
        lines.push(current);
        current = w;
      }
    }
    if (current) lines.push(current);
    return lines.length > 0 ? lines : [''];
  }

  banner(version: string, subtitle: string): string {
    const line = '─'.repeat(66);
    const title = `🧹 FoFo Care Sweep  ${this.dim(`fcsweep v${version}`)}`;
    return [
      this.teal(`╭${line}`),
      `${this.teal('│')}  ${this.whiteBold(title)}`,
      `${this.teal('│')}  ${this.dim(subtitle)}`,
      this.teal(`╰${line}`),
    ].join('\n');
  }

  phase(emoji: string, title: string, detail?: string): string {
    const suffix = detail ? ` ${this.dim(`— ${detail}`)}` : '';
    return `\n${emoji} ${this.whiteBold(title)}${suffix}`;
  }

  collectorRow(
    collector: string,
    status: 'ok' | 'partial' | 'error' | 'skipped',
    itemCount: number,
    durationMs: number,
    note?: string
  ): string {
    const icon =
      status === 'ok'
        ? this.green('✅')
        : status === 'partial'
          ? this.yellow('⚠️ ')
          : status === 'skipped'
            ? this.gray('⏭️ ')
            : this.red('❌');
    const namePad = collector.padEnd(14, ' ');
    const countStr = `${String(itemCount).padStart(4, ' ')} item${itemCount === 1 ? ' ' : 's'}`;
    const durStr = this.formatDuration(durationMs).padStart(7, ' ');
    const noteStr = note ? `  ${status === 'error' ? this.red(note.slice(0, 90)) : this.yellow(note.slice(0, 90))}` : '';
    return `  ${icon} ${this.bold(namePad)} ${this.dim(countStr)}  ${this.gray(durStr)}${noteStr}`;
  }

  advisoryBlock(adv: Advisory): string {
    const isCrit = adv.severity === 'critical';
    const isWarn = adv.severity === 'warning';
    const icon = isCrit ? '🛑' : adv.kind === 'remote_access_tool' ? '📞' : isWarn ? '⚠️ ' : 'ℹ️ ';
    const border = isCrit ? (s: string) => this.red(s) : isWarn ? (s: string) => this.yellow(s) : (s: string) => this.cyan(s);
    const head = border(`${icon} ${adv.title}`);
    const rule = '─'.repeat(66);
    const wrapped = this.wrapWords(adv.message, 68).map((ln) => `${border('│')}  ${ln}`);
    return [
      border(`┌${rule}`),
      `${border('│')}  ${this.bold(head)}`,
      ...wrapped,
      border(`└${rule}`),
    ].join('\n');
  }

  findingsPreview(findings: Finding[], maxShow: number = 8): string {
    const actionable = findings
      .filter((f) => f.tier === 'malicious' || f.tier === 'suspicious')
      .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));

    if (actionable.length === 0) return '';

    const lines: string[] = [
      '',
      `📋 ${this.whiteBold('Top Findings Requiring Attention')} ${this.dim(`(showing ${Math.min(actionable.length, maxShow)} of ${actionable.length})`)}`,
    ];

    for (const f of actionable.slice(0, maxShow)) {
      const scoreColor = f.tier === 'malicious' ? this.red(`${f.score}/100`) : this.yellow(`${f.score}/100`);
      const prot = f.protected ? ` ${this.magenta('🔒 PROTECTED')}` : '';
      const loc = sanitizeUntrusted(f.location, 76);
      const sigs = f.signals.join(', ');
      lines.push(
        `  ${this.tierBadge(f.tier)}  ${this.whiteBold(f.id)}  ${scoreColor}  ${this.dim(f.collector)}  ${this.cyan(loc)}${prot}`
      );
      lines.push(
        `     ${this.dim('signals:')} ${this.yellow(sigs || 'none')}  ${this.dim('· action:')} ${this.teal(f.proposed_action)}`
      );
    }

    if (actionable.length > maxShow) {
      lines.push(this.dim(`  … and ${actionable.length - maxShow} more in report.html / report.md`));
    }
    return lines.join('\n');
  }

  scanSummary(params: {
    counts: Record<Tier, number>;
    stopConditions: StopCondition[];
    sessionId: string;
    reportMdPath?: string;
    reportHtmlPath?: string;
    platform: string;
  }): string {
    const { counts, stopConditions, sessionId, reportMdPath, reportHtmlPath, platform } = params;
    const bar = '─'.repeat(66);

    const pills = [
      counts.malicious > 0 ? this.red(`🚨 ${counts.malicious} malicious`) : this.dim('🚨 0 malicious'),
      counts.suspicious > 0 ? this.yellow(`🟠 ${counts.suspicious} suspicious`) : this.dim('🟠 0 suspicious'),
      counts.review > 0 ? this.cyan(`🔎 ${counts.review} review`) : this.dim('🔎 0 review'),
      this.green(`✨ ${counts.clean} clean`),
    ].join('   ');

    let quip = '';
    if (stopConditions.length > 0) {
      quip = this.red('🛑 Stop condition triggered — see advisories above before taking action.');
    } else if (counts.malicious === 0 && counts.suspicious === 0 && counts.review === 0) {
      quip = this.green('🎉 All clear! Nothing sketchy hiding in the corners.');
    } else if (counts.malicious === 0 && counts.suspicious === 0) {
      quip = this.cyan('👍 Looking healthy — just a few low-priority review items to glance over.');
    } else {
      quip = this.yellow('🧹 Found items worth sweeping! Every reversible fix can be undone anytime.');
    }

    const lines: string[] = [
      '',
      this.teal(`╭${bar}`),
      `${this.teal('│')}  ${pills}`,
      `${this.teal('│')}  ${quip}`,
      this.teal(`╰${bar}`),
    ];

    lines.push(`  📁 ${this.dim('Session:')}  ${this.bold(sessionId)}`);
    if (reportHtmlPath) {
      lines.push(`  🌐 ${this.dim('HTML:')}     ${this.cyan(reportHtmlPath)}`);
    }
    if (reportMdPath) {
      lines.push(`  📝 ${this.dim('Markdown:')} ${this.dim(reportMdPath)}`);
    }

    // Friendly next-step commands
    const nextSteps: string[] = [];
    if (reportHtmlPath) {
      nextSteps.push(`fcsweep report --open --session ${sessionId}`);
    }
    if (platform === 'windows' && stopConditions.length === 0 && (counts.malicious > 0 || counts.suspicious > 0)) {
      nextSteps.push(`fcsweep fix --interactive --session ${sessionId}`);
    } else if (stopConditions.length > 0 && platform === 'windows') {
      nextSteps.push('fcsweep defender --offline');
    }

    if (nextSteps.length > 0) {
      lines.push('');
      lines.push(`👉 ${this.whiteBold('Next steps:')}`);
      for (const cmd of nextSteps) {
        lines.push(`   ${this.teal('$')} ${this.bold(cmd)}`);
      }
    }

    return lines.join('\n');
  }

  actionOk(actionId: string, findingId: string, action: string, detail: string): string {
    return `  ${this.green('✅')} ${this.whiteBold(actionId)} ${this.dim(`(${findingId} · ${action})`)} ${detail}`;
  }

  actionFail(actionId: string, findingId: string, action: string, error: string): string {
    return `  ${this.red('❌')} ${this.whiteBold(actionId)} ${this.dim(`(${findingId} · ${action})`)} ${this.red(error)}`;
  }

  actionUndo(actionId: string, findingId: string, action: string, detail: string): string {
    return `  ${this.cyan('⏪')} ${this.whiteBold(actionId)} ${this.dim(`(${findingId} · ${action})`)} ${detail}`;
  }

  actionSkip(actionId: string, action: string, detail: string): string {
    return `  ${this.gray('⏭️ ')} ${this.dim(`${actionId} (${action}): ${detail}`)}`;
  }
}
