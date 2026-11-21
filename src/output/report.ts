import type {
  Advisory,
  DefenderScanResult,
  Finding,
  HardenManifest,
  Manifest,
  PreflightResult,
  StopCondition,
  Tier,
  VerifyResult,
} from '../types.js';
import { formatUntrustedCode, sanitizeUntrusted } from './sanitize.js';

export interface ReportInput {
  sessionId: string;
  preflight: PreflightResult;
  findings: Finding[];
  defenderScan?: DefenderScanResult | null;
  advisories: Advisory[];
  stopConditions: StopCondition[];
  manifest?: Manifest | null;
  verifyResult?: VerifyResult | null;
  hardenManifest?: HardenManifest | null;
}

function countByTier(findings: Finding[]): Record<Tier, number> {
  const counts: Record<Tier, number> = { malicious: 0, suspicious: 0, review: 0, clean: 0 };
  for (const f of findings) counts[f.tier]++;
  return counts;
}

function buildVerdictParagraph(input: ReportInput): string {
  const counts = countByTier(input.findings);
  const { preflight, stopConditions, defenderScan } = input;

  if (stopConditions.length > 0) {
    return (
      `**STOP CONDITION TRIGGERED.** ${stopConditions.map((s) => s.message).join(' ')} ` +
      'Automated cleanup is not recommended for this state; follow the recovery steps below (`fcsweep defender --offline`, back up personal files, then Reset this PC).'
    );
  }

  const detCount = defenderScan?.detections.length ?? 0;
  const elevatedNote = preflight.elevated
    ? 'elevated'
    : 'non-elevated (some collectors may be partial or skipped)';

  if (counts.malicious === 0 && counts.suspicious === 0 && counts.review === 0) {
    return (
      `Clean sweep on **${sanitizeUntrusted(preflight.hostname, 64)}** (${preflight.os_version}, ${elevatedNote}). ` +
      `Inspected ${input.findings.length} item(s) across ${preflight.collectors_requested.length} collector(s)` +
      `${detCount > 0 ? ` with ${detCount} Microsoft signature detection(s)` : ''}; no findings require review or action.`
    );
  }

  return (
    `Sweep of **${sanitizeUntrusted(preflight.hostname, 64)}** (${preflight.os_version}, ${elevatedNote}) found ` +
    `**${counts.malicious} malicious**, **${counts.suspicious} suspicious**, and **${counts.review} review** item(s) ` +
    `(${counts.clean} clean item(s) omitted from this report and preserved in \`snapshot.json\`). ` +
    (preflight.platform === 'macos'
      ? 'macOS v0.1 is read-only; review the findings below and remove unwanted items manually.'
      : counts.malicious > 0 || counts.suspicious > 0
        ? 'Review the findings below, then run `fcsweep fix --interactive` or `fcsweep fix --approve <ids>` from an elevated terminal.'
        : 'Only low-confidence review items were found; verify whether you recognize them before taking action.')
  );
}

function renderFinding(f: Finding): string {
  const lines: string[] = [];
  const protBadge = f.protected ? ' **[PROTECTED — REPORT ONLY]**' : '';
  lines.push(`### ${f.id} · ${f.kind} (score ${f.score}/100 · ${f.collector})${protBadge}`);
  lines.push('');
  lines.push(`- **Location:** ${formatUntrustedCode(f.location, 220)}`);
  lines.push(`- **Signals:** ${f.signals.length > 0 ? f.signals.map((s) => `\`${s}\``).join(', ') : 'none'}`);
  lines.push(`- **Proposed action:** \`${f.proposed_action}\``);
  if (f.protected && f.protected_reason) {
    lines.push(`- **Protected reason:** ${f.protected_reason}`);
  }

  // Measured facts
  const factParts: string[] = [];
  if (f.facts.target_path) factParts.push(`path=${formatUntrustedCode(f.facts.target_path, 200)}`);
  if (f.facts.file_exists === false) factParts.push('file_exists=false');
  if (f.facts.sig_status) factParts.push(`sig=${f.facts.sig_status}`);
  if (f.facts.signer) factParts.push(`signer=${formatUntrustedCode(f.facts.signer, 120)}`);
  if (f.facts.notarized === false) factParts.push('notarized=false');
  if (f.facts.path_class) factParts.push(`path_class=${f.facts.path_class}`);
  if (f.facts.sha256) factParts.push(`sha256=\`${f.facts.sha256.slice(0, 16)}…\``);
  if (f.facts.file_created) factParts.push(`created=${f.facts.file_created}`);
  if (f.facts.runs_as) factParts.push(`runs_as=${formatUntrustedCode(f.facts.runs_as, 80)}`);
  if (f.facts.defender_hit) {
    factParts.push(`defender_hit=true (${formatUntrustedCode(f.facts.defender_threat_name ?? 'detected', 100)})`);
  }
  if (f.facts.covered_by_exclusion) factParts.push('covered_by_exclusion=true');
  if (f.facts.program_tag) factParts.push(`tag=${f.facts.program_tag}`);
  if (f.facts.listening_ports && f.facts.listening_ports.length > 0) {
    factParts.push(`ports=[${f.facts.listening_ports.join(', ')}]`);
  }
  if (factParts.length > 0) {
    lines.push(`- **Measured facts:** ${factParts.join(' · ')}`);
  }

  // Attacker-controlled / machine strings strictly code-formatted & truncated
  const untrustedEntries = Object.entries(f.untrusted).filter(
    ([, v]) => typeof v === 'string' && v.trim().length > 0
  );
  if (untrustedEntries.length > 0) {
    const rendered = untrustedEntries
      .map(([k, v]) => `${k}=${formatUntrustedCode(v, 160)}`)
      .join(' · ');
    lines.push(`- **Machine strings (untrusted):** ${rendered}`);
  }

  // Model triage opinion, shown beside measured facts, never replacing them
  if (f.triage) {
    lines.push(
      `- **Model triage opinion:** \`${f.triage.verdict}\` (${f.triage.confidence} confidence, cited: ${f.triage.cited_facts.map((c) => `\`${c}\``).join(', ')}) — ${sanitizeUntrusted(f.triage.reason, 200)}` +
        (f.triage.tier_changed ? ` *(tier: ${f.triage.previous_tier} -> ${f.tier})*` : '')
    );
  }

  lines.push('');
  return lines.join('\n');
}

export function renderMarkdownReport(input: ReportInput): string {
  const { sessionId, preflight, findings, defenderScan, advisories, stopConditions, manifest, verifyResult, hardenManifest } = input;
  const lines: string[] = [];

  lines.push(`# FoFo Care Sweep Report — \`${sessionId}\``);
  lines.push('');
  lines.push(`> Generated ${new Date().toISOString()} · fcsweep v${preflight.tool_version}`);
  lines.push('');

  // 1. One-paragraph verdict
  lines.push('## Verdict');
  lines.push('');
  lines.push(buildVerdictParagraph(input));
  lines.push('');

  // 2. Advisories & Stop Conditions
  if (advisories.length > 0 || stopConditions.length > 0) {
    lines.push('## Advisories');
    lines.push('');
    for (const adv of advisories) {
      const prefix = adv.severity === 'critical' ? '[CRITICAL]' : adv.severity === 'warning' ? '[WARNING]' : '[INFO]';
      lines.push(`- **${prefix} ${adv.title}:** ${adv.message}`);
    }
    lines.push('');
  }

  // 3. System & Security Summary
  lines.push('## System & Security State');
  lines.push('');
  lines.push(`- **Host:** ${formatUntrustedCode(preflight.hostname, 64)} · **OS:** ${preflight.os_version} (${preflight.os_build}, ${preflight.arch})`);
  lines.push(`- **Elevated:** ${preflight.elevated ? 'Yes' : 'No'} · **Domain/MDM joined:** ${preflight.domain_joined || preflight.mdm_enrolled ? 'Yes' : 'No'}`);
  if (preflight.platform === 'windows') {
    lines.push(
      `- **Microsoft Defender:** mode=\`${preflight.defender.mode}\`, real-time=\`${String(preflight.defender.realtime_enabled ?? 'unknown')}\`, tamper=\`${String(preflight.defender.tamper_protected ?? 'unknown')}\`, signatures=\`${preflight.defender.signature_version ?? 'unknown'}\``
    );
    if (preflight.av_products.length > 0) {
      lines.push(
        `- **Registered Antivirus:** ${preflight.av_products.map((a) => `${formatUntrustedCode(a.display_name, 80)} (${a.enabled ? 'enabled' : 'disabled'})`).join(', ')}`
      );
    }
    if (defenderScan) {
      lines.push(
        `- **Known-Threat Scan:** engine=\`${defenderScan.engine}\`, type=\`${defenderScan.scan_type}\`, status=\`${defenderScan.status}\`, detections=${defenderScan.detections.length}`
      );
    }
  }
  if (preflight.collectors_skipped.length > 0) {
    lines.push(
      `- **Skipped collectors:** ${preflight.collectors_skipped.map((c) => `\`${c.collector}\` (${c.reason})`).join(', ')}`
    );
  }
  if (preflight.collectors_partial.length > 0) {
    lines.push(
      `- **Partial collectors:** ${preflight.collectors_partial.map((c) => `\`${c.collector}\` (${c.reason})`).join(', ')}`
    );
  }
  lines.push('');

  // 4. Findings grouped by tier (review and above; clean stays in snapshot.json only)
  const tiers: Array<{ key: Tier; heading: string }> = [
    { key: 'malicious', heading: 'Malicious Findings (Score 80–100)' },
    { key: 'suspicious', heading: 'Suspicious Findings (Score 50–79)' },
    { key: 'review', heading: 'Review Findings (Score 20–49)' },
  ];

  let anyShown = false;
  for (const t of tiers) {
    const group = findings
      .filter((f) => f.tier === t.key)
      .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
    if (group.length === 0) continue;
    anyShown = true;
    lines.push(`## ${t.heading}`);
    lines.push('');
    for (const f of group) {
      lines.push(renderFinding(f));
    }
  }

  if (!anyShown) {
    lines.push('## Findings');
    lines.push('');
    lines.push('No items scored in the review, suspicious, or malicious tiers.');
    lines.push('');
  }

  // 5. Verification results (if verify was run)
  if (verifyResult) {
    lines.push('## Verification');
    lines.push('');
    lines.push(
      `Verified at ${verifyResult.verified_at} · Resurrected items: **${verifyResult.resurrected_count}** · Post-reboot: ${verifyResult.post_reboot ? 'Yes' : 'No'}`
    );
    lines.push('');
    for (const v of verifyResult.items) {
      lines.push(
        `- \`${v.finding_id}\` (${v.action}) at ${formatUntrustedCode(v.location, 140)}: **${v.status}**` +
          (v.resurrection_count > 0 ? ` (resurrected ${v.resurrection_count}x)` : '')
      );
    }
    if (verifyResult.reboot_required) {
      lines.push('');
      lines.push('> Reboot this machine and run `fcsweep verify` again to confirm persistence did not return at startup.');
    }
    lines.push('');
  }

  // 6. Changes taken & how to undo
  lines.push('## Changes & Undo');
  lines.push('');
  if (!manifest || manifest.entries.length === 0) {
    lines.push('No remediation changes have been applied in this session.');
  } else {
    if (manifest.restore_point) {
      lines.push(
        `- **System Restore point:** ${manifest.restore_point.created ? 'Created' : `Not created (${manifest.restore_point.message ?? 'unavailable'})`}`
      );
    }
    for (const e of manifest.entries) {
      const undoInfo = e.undo_status ? ` · undo=\`${e.undo_status}\`` : '';
      lines.push(
        `- \`${e.action_id}\` (\`${e.finding_id}\` · \`${e.action}\`): **${e.status}**${undoInfo} — ${formatUntrustedCode(e.location, 120)}`
      );
    }
    lines.push('');
    lines.push('### How to undo');
    lines.push('');
    lines.push(`- Revert every change in this session: \`fcsweep undo --session ${sessionId}\``);
    lines.push(`- Revert a single finding: \`fcsweep undo --session ${sessionId} --item <finding-id>\``);
  }

  if (hardenManifest && hardenManifest.settings.length > 0) {
    lines.push('');
    lines.push('### Hardening applied');
    lines.push('');
    for (const s of hardenManifest.settings) {
      lines.push(`- **${s.name}**: \`${s.status}\`${s.message ? ` — ${s.message}` : ''}`);
    }
    lines.push('');
    lines.push(`- Revert hardening: \`fcsweep harden --revert --session ${sessionId}\``);
  }

  lines.push('');
  return lines.join('\n');
}
