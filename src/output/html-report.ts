import type {
  Advisory,
  DefenderScanResult,
  Finding,
  HardenManifest,
  Manifest,
  PreflightResult,
  Snapshot,
  StopCondition,
  Tier,
  VerifyResult,
} from '../types.js';
import { sanitizeUntrusted } from './sanitize.js';

export interface HtmlReportInput {
  sessionId: string;
  preflight: PreflightResult;
  findings: Finding[];
  snapshot?: Snapshot | null;
  defenderScan?: DefenderScanResult | null;
  advisories: Advisory[];
  stopConditions: StopCondition[];
  manifest?: Manifest | null;
  verifyResult?: VerifyResult | null;
  hardenManifest?: HardenManifest | null;
}

/**
 * Strict HTML entity escaper. Every machine-sourced or untrusted string passes
 * through this before touching HTML — neutralizing any XSS / tag injection.
 */
export function escapeHtml(raw: string | null | undefined): string {
  if (raw == null) return '';
  return String(raw)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function fmtBytes(bytes: number | null | undefined): string {
  if (typeof bytes !== 'number' || !Number.isFinite(bytes)) return '—';
  const gb = bytes / (1024 ** 3);
  if (gb >= 1) return `${gb.toFixed(1)} GB`;
  const mb = bytes / (1024 ** 2);
  if (mb >= 1) return `${mb.toFixed(1)} MB`;
  return `${Math.round(bytes / 1024)} KB`;
}

function fmtDuration(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

const BRAND_SHIELD_SVG = `<svg width="40" height="40" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <defs>
    <linearGradient id="sg1" x1="8" y1="6" x2="56" y2="58" gradientUnits="userSpaceOnUse">
      <stop stop-color="#5de2cf"/>
      <stop offset="0.5" stop-color="#2ab3a6"/>
      <stop offset="1" stop-color="#115e67"/>
    </linearGradient>
    <linearGradient id="sg2" x1="12" y1="42" x2="54" y2="20" gradientUnits="userSpaceOnUse">
      <stop stop-color="#ff8c5a"/>
      <stop offset="1" stop-color="#f95b3d"/>
    </linearGradient>
  </defs>
  <path d="M32 5L11 13.5V30.5C11 45.2 20 55.6 32 60C44 55.6 53 45.2 53 30.5V13.5L32 5Z" fill="url(#sg1)" stroke="#8ef4e6" stroke-opacity="0.45" stroke-width="1.5"/>
  <path d="M32 5V60C44 55.6 53 45.2 53 30.5V13.5L32 5Z" fill="#0b3b42" fill-opacity="0.32"/>
  <path d="M13 35H21L25.5 23L31.5 42L37.5 26L41.5 35H51" stroke="url(#sg2)" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="48" cy="20" r="2.2" fill="#8ef4e6"/>
  <circle cx="44" cy="15" r="1.4" fill="#ff9e74"/>
</svg>`;

function renderFindingCard(f: Finding, sessionId: string): string {
  const tierClass = `tier-${f.tier}`;
  const tierLabel =
    f.tier === 'malicious'
      ? '🚨 Malicious'
      : f.tier === 'suspicious'
        ? '🟠 Suspicious'
        : '🔎 Review';

  const signalsHtml =
    f.signals.length > 0
      ? f.signals
          .map((s) => {
            const high =
              s === 'defender_hit' ||
              s === 'system_name_wrong_dir' ||
              s === 'lolbin_remote' ||
              s === 'trace_paste_exec' ||
              s.startsWith('hijack_') ||
              s === 'mac_suspicious_profile';
            return `<span class="chip ${high ? 'chip-danger' : 'chip-warn'}">${escapeHtml(s)}</span>`;
          })
          .join('')
      : '<span class="chip">none</span>';

  const factRows: Array<[string, string]> = [];
  if (f.facts.target_path) factRows.push(['Target Path', String(f.facts.target_path)]);
  if (f.facts.file_exists === false) factRows.push(['File Exists', 'false (orphan entry)']);
  if (f.facts.sig_status) factRows.push(['Signature', String(f.facts.sig_status)]);
  if (f.facts.signer) factRows.push(['Signer', String(f.facts.signer)]);
  if (f.facts.notarized !== undefined && f.facts.notarized !== null) {
    factRows.push(['Notarized', String(f.facts.notarized)]);
  }
  if (f.facts.path_class) factRows.push(['Path Class', String(f.facts.path_class)]);
  if (f.facts.sha256) factRows.push(['SHA-256', String(f.facts.sha256)]);
  if (f.facts.file_created) factRows.push(['Created (UTC)', String(f.facts.file_created)]);
  if (f.facts.runs_as) factRows.push(['Runs As', String(f.facts.runs_as)]);
  if (f.facts.defender_hit) {
    factRows.push(['Defender Detection', String(f.facts.defender_threat_name || 'Confirmed threat')]);
  }
  if (f.facts.covered_by_exclusion) factRows.push(['Defender Exclusion', 'Covered by exclusion']);
  if (f.facts.program_tag) factRows.push(['Program Tag', `${f.facts.program_tag} (${f.facts.program_tag_name ?? ''})`]);
  if (f.facts.cert_thumbprint) factRows.push(['Cert Thumbprint', String(f.facts.cert_thumbprint)]);
  if (f.facts.listening_ports && f.facts.listening_ports.length > 0) {
    factRows.push(['Listening Ports', f.facts.listening_ports.join(', ')]);
  }

  const factsHtml =
    factRows.length > 0
      ? factRows
          .map(
            ([k, v]) =>
              `<div class="kv-row"><span class="kv-key">${escapeHtml(k)}</span><code class="kv-val">${escapeHtml(v)}</code></div>`
          )
          .join('')
      : '<div class="muted">No additional file facts recorded.</div>';

  const untrustedEntries = Object.entries(f.untrusted).filter(
    ([, v]) => typeof v === 'string' && v.trim().length > 0
  );
  const untrustedHtml =
    untrustedEntries.length > 0
      ? untrustedEntries
          .map(
            ([k, v]) =>
              `<div class="kv-row"><span class="kv-key">${escapeHtml(k)}</span><code class="kv-val untrusted-val">${escapeHtml(sanitizeUntrusted(v, 260))}</code></div>`
          )
          .join('')
      : '<div class="muted">None</div>';

  const triageHtml = f.triage
    ? `<div class="triage-box">
        <div class="triage-title">🤖 Model Triage Opinion · <strong>${escapeHtml(f.triage.verdict)}</strong> (${escapeHtml(f.triage.confidence)} confidence)</div>
        <p>${escapeHtml(sanitizeUntrusted(f.triage.reason, 200))}</p>
        <div class="muted">Cited facts: ${f.triage.cited_facts.map((c) => `<code>${escapeHtml(c)}</code>`).join(', ')}${f.triage.tier_changed ? ` · Tier: ${escapeHtml(f.triage.previous_tier)} → ${escapeHtml(f.tier)}` : ''}</div>
      </div>`
    : '';

  const canFix = !f.protected && f.proposed_action !== 'report_only' && f.proposed_action !== 'none';
  const cmdText = canFix
    ? `fcsweep fix --approve ${f.id} --session ${sessionId}`
    : '';

  const searchBlob = escapeHtml(
    `${f.id} ${f.collector} ${f.kind} ${f.location} ${f.signals.join(' ')} ${f.facts.target_path ?? ''} ${f.facts.signer ?? ''} ${sanitizeUntrusted(f.untrusted.name, 120)}`.toLowerCase()
  );

  return `<article class="finding-card ${tierClass}" data-tier="${escapeHtml(f.tier)}" data-collector="${escapeHtml(f.collector)}" data-protected="${f.protected ? 'true' : 'false'}" data-search="${searchBlob}">
    <div class="finding-head">
      <div class="finding-head-left">
        <span class="score-pill ${tierClass}">${f.score}</span>
        <div>
          <div class="finding-title-row">
            <span class="finding-id">${escapeHtml(f.id)}</span>
            <span class="tier-badge ${tierClass}">${tierLabel}</span>
            <span class="collector-badge">${escapeHtml(f.collector)} · ${escapeHtml(f.kind)}</span>
            ${f.protected ? '<span class="prot-badge">🔒 PROTECTED · REPORT ONLY</span>' : ''}
          </div>
          <div class="finding-loc"><code>${escapeHtml(sanitizeUntrusted(f.location, 220))}</code></div>
        </div>
      </div>
      <div class="finding-head-right">
        <span class="action-pill">${escapeHtml(f.proposed_action)}</span>
        ${cmdText ? `<button class="copy-btn" type="button" data-copy="${escapeHtml(cmdText)}" title="Copy approve command">📋 Copy fix cmd</button>` : ''}
      </div>
    </div>
    <div class="signals-row">${signalsHtml}</div>
    ${f.protected && f.protected_reason ? `<div class="prot-note">🔒 <strong>Protected:</strong> ${escapeHtml(f.protected_reason)}</div>` : ''}
    <div class="split-grid">
      <section class="panel-facts">
        <h4>📏 Measured Facts <span class="badge-trusted">Tool-verified</span></h4>
        ${factsHtml}
      </section>
      <section class="panel-untrusted">
        <h4>⚠️ Machine Strings <span class="badge-untrusted">Untrusted · Data Only</span></h4>
        ${untrustedHtml}
      </section>
    </div>
    ${triageHtml}
  </article>`;
}

export function renderHtmlReport(input: HtmlReportInput): string {
  const {
    sessionId,
    preflight,
    findings,
    snapshot,
    defenderScan,
    advisories,
    stopConditions,
    manifest,
    verifyResult,
    hardenManifest,
  } = input;

  const counts: Record<Tier, number> = { malicious: 0, suspicious: 0, review: 0, clean: 0 };
  for (const f of findings) counts[f.tier]++;

  const shownFindings = findings
    .filter((f) => f.tier !== 'clean')
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));

  const collectorsList = Array.from(new Set(shownFindings.map((f) => f.collector))).sort();

  const statusKind =
    stopConditions.length > 0
      ? 'status-stop'
      : counts.malicious > 0
        ? 'status-malicious'
        : counts.suspicious > 0
          ? 'status-suspicious'
          : counts.review > 0
            ? 'status-review'
            : 'status-clean';

  const statusHeadline =
    stopConditions.length > 0
      ? '🛑 Stop Condition Triggered'
      : counts.malicious > 0
        ? `🚨 ${counts.malicious} Malicious & ${counts.suspicious} Suspicious Finding(s)`
        : counts.suspicious > 0
          ? `🟠 ${counts.suspicious} Suspicious Finding(s) Detected`
          : counts.review > 0
            ? `🔎 ${counts.review} Item(s) to Review — No High-Risk Threats`
            : '✨ All Clear — Clean Sweep!';

  const verdictSubtext =
    stopConditions.length > 0
      ? 'Automated cleanup is paused. Follow the recovery steps below (Defender Offline, back up personal files, Reset this PC).'
      : counts.malicious === 0 && counts.suspicious === 0 && counts.review === 0
        ? `Inspected ${findings.length} item(s) across ${preflight.collectors_requested.length} collector(s) on ${preflight.hostname}. Nothing sketchy hiding in the corners.`
        : `Inspected ${findings.length} item(s) on ${preflight.hostname} (${counts.clean} clean item(s) archived in snapshot.json). Every reversible fix is backed up before execution and can be undone anytime.`;

  const advisoriesHtml =
    advisories.length > 0
      ? `<section class="advisories-stack">${advisories
          .map((a) => {
            const cls =
              a.severity === 'critical'
                ? 'adv-critical'
                : a.severity === 'warning'
                  ? 'adv-warning'
                  : 'adv-info';
            const icon =
              a.severity === 'critical'
                ? '🛑'
                : a.kind === 'remote_access_tool'
                  ? '📞'
                  : a.severity === 'warning'
                    ? '⚠️'
                    : 'ℹ️';
            return `<div class="advisory-card ${cls}">
              <div class="advisory-icon">${icon}</div>
              <div>
                <div class="advisory-title">${escapeHtml(a.title)}</div>
                <div class="advisory-msg">${escapeHtml(a.message)}</div>
              </div>
            </div>`;
          })
          .join('')}</section>`
      : '';

  // Collector breakdown table
  const collectorRows = snapshot
    ? Object.entries(snapshot.collectors)
        .map(([name, info]) => {
          const icon =
            info.status === 'ok'
              ? '✅'
              : info.status === 'partial'
                ? '⚠️'
                : info.status === 'skipped'
                  ? '⏭️'
                  : '❌';
          const note = info.error || info.warnings.join('; ') || '';
          return `<tr>
            <td><strong>${escapeHtml(name)}</strong></td>
            <td><span class="st-pill st-${escapeHtml(info.status)}">${icon} ${escapeHtml(info.status)}</span></td>
            <td class="num">${info.item_count}</td>
            <td class="num">${escapeHtml(fmtDuration(info.duration_ms))}</td>
            <td class="muted">${escapeHtml(note.slice(0, 140))}</td>
          </tr>`;
        })
        .join('')
    : '';

  // Changes & Undo section
  const manifestHtml =
    manifest && manifest.entries.length > 0
      ? `<table class="data-table">
          <thead><tr><th>Action ID</th><th>Finding</th><th>Action</th><th>Status</th><th>Undo</th><th>Location</th></tr></thead>
          <tbody>${manifest.entries
            .map(
              (e) => `<tr>
                <td><code>${escapeHtml(e.action_id)}</code></td>
                <td><code>${escapeHtml(e.finding_id)}</code></td>
                <td><code>${escapeHtml(e.action)}</code></td>
                <td><span class="st-pill st-${e.status === 'succeeded' ? 'ok' : 'error'}">${escapeHtml(e.status)}</span></td>
                <td>${escapeHtml(e.undo_status ?? '—')}</td>
                <td><code>${escapeHtml(sanitizeUntrusted(e.location, 100))}</code></td>
              </tr>`
            )
            .join('')}</tbody>
        </table>
        <div class="cmd-bar">
          <code>fcsweep undo --session ${escapeHtml(sessionId)}</code>
          <button class="copy-btn" type="button" data-copy="fcsweep undo --session ${escapeHtml(sessionId)}">📋 Copy undo command</button>
        </div>`
      : '<p class="muted">No remediation changes have been applied in this session yet (read-only scan).</p>';

  const verifyHtml = verifyResult
    ? `<section class="card">
        <h3>✅ Verification Summary</h3>
        <p class="muted">Verified at ${escapeHtml(verifyResult.verified_at)} · Resurrected: <strong>${verifyResult.resurrected_count}</strong> · Post-reboot: <strong>${verifyResult.post_reboot ? 'Yes' : 'No'}</strong></p>
        <table class="data-table">
          <thead><tr><th>Finding</th><th>Action</th><th>Status</th><th>Resurrections</th><th>Location</th></tr></thead>
          <tbody>${verifyResult.items
            .map(
              (v) => `<tr>
                <td><code>${escapeHtml(v.finding_id)}</code></td>
                <td><code>${escapeHtml(v.action)}</code></td>
                <td><span class="st-pill ${v.status === 'clean' ? 'st-ok' : 'st-error'}">${escapeHtml(v.status)}</span></td>
                <td class="num">${v.resurrection_count}</td>
                <td><code>${escapeHtml(sanitizeUntrusted(v.location, 100))}</code></td>
              </tr>`
            )
            .join('')}</tbody>
        </table>
      </section>`
    : '';

  const hardenHtml =
    hardenManifest && hardenManifest.settings.length > 0
      ? `<section class="card">
          <h3>🔒 Hardening Applied</h3>
          <table class="data-table">
            <thead><tr><th>Setting</th><th>Status</th><th>Details</th></tr></thead>
            <tbody>${hardenManifest.settings
              .map(
                (s) => `<tr>
                  <td><strong>${escapeHtml(s.name)}</strong></td>
                  <td><span class="st-pill ${s.status === 'applied' || s.status === 'reverted' ? 'st-ok' : s.status === 'failed' ? 'st-error' : 'st-partial'}">${escapeHtml(s.status)}</span></td>
                  <td class="muted">${escapeHtml(s.message ?? '')}</td>
                </tr>`
              )
              .join('')}</tbody>
          </table>
          <div class="cmd-bar">
            <code>fcsweep harden --revert --session ${escapeHtml(sessionId)}</code>
            <button class="copy-btn" type="button" data-copy="fcsweep harden --revert --session ${escapeHtml(sessionId)}">📋 Copy revert command</button>
          </div>
        </section>`
      : '';

  const avNames =
    preflight.av_products.length > 0
      ? preflight.av_products.map((a) => `${a.display_name} (${a.enabled ? 'enabled' : 'disabled'})`).join(', ')
      : preflight.platform === 'macos'
        ? 'XProtect / XProtect Remediator'
        : 'None detected';

  return `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FoFo Care Sweep Report — ${escapeHtml(sessionId)}</title>
<style>
  :root {
    --bg: #070b14;
    --bg-elev: #0e1525;
    --bg-card: #111a2d;
    --bg-code: #0a101d;
    --border: rgba(148, 163, 184, 0.16);
    --text: #e6edf7;
    --muted: #8ea0ba;
    --teal: #2dd4bf;
    --teal-deep: #146c72;
    --coral: #f97043;
    --red: #fb7185;
    --amber: #fbbf24;
    --cyan: #38bdf8;
    --green: #34d399;
    --purple: #c084fc;
    --shadow: 0 12px 32px rgba(0, 0, 0, 0.42);
  }
  [data-theme="light"] {
    --bg: #f3f6fb;
    --bg-elev: #ffffff;
    --bg-card: #ffffff;
    --bg-code: #eef2f8;
    --border: rgba(15, 23, 42, 0.12);
    --text: #0f172a;
    --muted: #475569;
    --teal: #0d9488;
    --teal-deep: #115e59;
    --coral: #ea580c;
    --red: #dc2626;
    --amber: #d97706;
    --cyan: #0284c7;
    --green: #059669;
    --purple: #7c3aed;
    --shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, Helvetica, Arial, sans-serif;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }
  .wrap { max-width: 1180px; margin: 0 auto; padding: 28px 22px 64px; }
  code {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
    font-size: 0.88em;
    background: var(--bg-code);
    padding: 2px 6px;
    border-radius: 5px;
    word-break: break-all;
  }
  .topbar {
    display: flex; align-items: center; justify-content: space-between; gap: 16px;
    margin-bottom: 22px; flex-wrap: wrap;
  }
  .brand { display: flex; align-items: center; gap: 14px; }
  .brand h1 { margin: 0; font-size: 1.45rem; letter-spacing: -0.02em; }
  .brand-sub { color: var(--muted); font-size: 0.88rem; }
  .top-actions { display: flex; align-items: center; gap: 10px; }
  .theme-btn, .copy-btn, .filter-pill {
    cursor: pointer; border: 1px solid var(--border); background: var(--bg-card);
    color: var(--text); border-radius: 9px; padding: 7px 12px; font-size: 0.84rem; font-weight: 600;
    transition: transform 0.12s ease, border-color 0.15s ease, background 0.15s ease;
  }
  .theme-btn:hover, .copy-btn:hover, .filter-pill:hover { border-color: var(--teal); transform: translateY(-1px); }
  .hero {
    border-radius: 16px; padding: 22px 26px; margin-bottom: 22px;
    background: linear-gradient(135deg, rgba(20, 108, 114, 0.25), rgba(17, 26, 45, 0.92));
    border: 1px solid var(--border); box-shadow: var(--shadow);
  }
  [data-theme="light"] .hero {
    background: linear-gradient(135deg, rgba(45, 212, 191, 0.16), rgba(255, 255, 255, 0.98));
  }
  .hero.status-malicious, .hero.status-stop { border-left: 5px solid var(--red); }
  .hero.status-suspicious { border-left: 5px solid var(--amber); }
  .hero.status-review { border-left: 5px solid var(--cyan); }
  .hero.status-clean { border-left: 5px solid var(--green); }
  .hero-title { font-size: 1.35rem; font-weight: 800; margin: 0 0 6px; }
  .hero-sub { margin: 0; color: var(--muted); font-size: 0.95rem; }
  .meta-pills { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }
  .meta-pill {
    font-size: 0.8rem; padding: 4px 10px; border-radius: 999px;
    background: var(--bg-code); border: 1px solid var(--border); color: var(--text);
  }
  .kpi-grid {
    display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; margin-bottom: 22px;
  }
  @media (max-width: 720px) { .kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
  .kpi {
    background: var(--bg-card); border: 1px solid var(--border); border-radius: 14px;
    padding: 16px 18px; cursor: pointer; transition: border-color 0.15s ease, transform 0.12s ease;
    box-shadow: var(--shadow);
  }
  .kpi:hover { transform: translateY(-2px); border-color: var(--teal); }
  .kpi-label { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); font-weight: 700; }
  .kpi-num { font-size: 2rem; font-weight: 800; margin-top: 4px; line-height: 1.1; }
  .kpi-mal .kpi-num { color: var(--red); }
  .kpi-susp .kpi-num { color: var(--amber); }
  .kpi-rev .kpi-num { color: var(--cyan); }
  .kpi-clean .kpi-num { color: var(--green); }
  .advisories-stack { display: grid; gap: 12px; margin-bottom: 22px; }
  .advisory-card {
    display: flex; gap: 14px; align-items: flex-start; padding: 14px 18px;
    border-radius: 12px; border: 1px solid var(--border);
  }
  .adv-critical { background: rgba(251, 113, 133, 0.12); border-color: rgba(251, 113, 133, 0.45); }
  .adv-warning { background: rgba(251, 191, 36, 0.11); border-color: rgba(251, 191, 36, 0.42); }
  .adv-info { background: rgba(56, 189, 248, 0.10); border-color: rgba(56, 189, 248, 0.35); }
  .advisory-icon { font-size: 1.35rem; line-height: 1.2; }
  .advisory-title { font-weight: 800; margin-bottom: 3px; }
  .advisory-msg { font-size: 0.92rem; color: var(--text); opacity: 0.92; }
  .card {
    background: var(--bg-card); border: 1px solid var(--border); border-radius: 14px;
    padding: 18px 20px; margin-bottom: 20px; box-shadow: var(--shadow);
  }
  .card h2, .card h3 { margin: 0 0 12px; font-size: 1.08rem; }
  .posture-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin-bottom: 14px;
  }
  .posture-item { background: var(--bg-code); padding: 10px 12px; border-radius: 10px; border: 1px solid var(--border); }
  .posture-k { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); font-weight: 700; }
  .posture-v { font-size: 0.92rem; font-weight: 600; margin-top: 2px; word-break: break-word; }
  .toolbar {
    display: flex; flex-wrap: wrap; gap: 10px; align-items: center; justify-content: space-between;
    margin-bottom: 16px;
  }
  .filter-group { display: flex; flex-wrap: wrap; gap: 6px; }
  .filter-pill.active { background: var(--teal-deep); color: #fff; border-color: var(--teal); }
  .search-group { display: flex; gap: 8px; flex-wrap: wrap; }
  .search-input, .select-input {
    background: var(--bg-card); color: var(--text); border: 1px solid var(--border);
    border-radius: 9px; padding: 7px 12px; font-size: 0.88rem; outline: none;
  }
  .search-input:focus, .select-input:focus { border-color: var(--teal); }
  .search-input { min-width: 240px; }
  .finding-card {
    background: var(--bg-card); border: 1px solid var(--border); border-radius: 14px;
    padding: 16px 18px; margin-bottom: 14px; box-shadow: var(--shadow);
  }
  .finding-card.tier-malicious { border-left: 4px solid var(--red); }
  .finding-card.tier-suspicious { border-left: 4px solid var(--amber); }
  .finding-card.tier-review { border-left: 4px solid var(--cyan); }
  .finding-head {
    display: flex; justify-content: space-between; align-items: flex-start; gap: 14px; flex-wrap: wrap;
  }
  .finding-head-left { display: flex; gap: 12px; align-items: flex-start; min-width: 0; flex: 1; }
  .finding-head-right { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .score-pill {
    min-width: 46px; height: 46px; border-radius: 12px; display: flex; align-items: center; justify-content: center;
    font-weight: 800; font-size: 1.05rem; flex-shrink: 0;
  }
  .score-pill.tier-malicious { background: rgba(251, 113, 133, 0.18); color: var(--red); border: 1px solid rgba(251, 113, 133, 0.45); }
  .score-pill.tier-suspicious { background: rgba(251, 191, 36, 0.16); color: var(--amber); border: 1px solid rgba(251, 191, 36, 0.45); }
  .score-pill.tier-review { background: rgba(56, 189, 248, 0.15); color: var(--cyan); border: 1px solid rgba(56, 189, 248, 0.4); }
  .finding-title-row { display: flex; flex-wrap: wrap; gap: 7px; align-items: center; margin-bottom: 4px; }
  .finding-id { font-weight: 800; font-family: ui-monospace, monospace; font-size: 0.98rem; }
  .tier-badge, .collector-badge, .prot-badge, .action-pill {
    font-size: 0.76rem; font-weight: 700; padding: 2px 8px; border-radius: 999px;
  }
  .tier-badge.tier-malicious { background: rgba(251, 113, 133, 0.18); color: var(--red); }
  .tier-badge.tier-suspicious { background: rgba(251, 191, 36, 0.18); color: var(--amber); }
  .tier-badge.tier-review { background: rgba(56, 189, 248, 0.16); color: var(--cyan); }
  .collector-badge { background: var(--bg-code); color: var(--muted); border: 1px solid var(--border); }
  .prot-badge { background: rgba(192, 132, 252, 0.16); color: var(--purple); border: 1px solid rgba(192, 132, 252, 0.4); }
  .action-pill { background: rgba(45, 212, 191, 0.14); color: var(--teal); border: 1px solid rgba(45, 212, 191, 0.35); font-family: ui-monospace, monospace; }
  .finding-loc { font-size: 0.88rem; }
  .signals-row { display: flex; flex-wrap: wrap; gap: 6px; margin: 12px 0; }
  .chip {
    font-size: 0.75rem; font-family: ui-monospace, monospace; font-weight: 600;
    padding: 3px 8px; border-radius: 6px; background: var(--bg-code); border: 1px solid var(--border);
  }
  .chip-danger { background: rgba(251, 113, 133, 0.14); color: var(--red); border-color: rgba(251, 113, 133, 0.38); }
  .chip-warn { background: rgba(251, 191, 36, 0.12); color: var(--amber); border-color: rgba(251, 191, 36, 0.34); }
  .prot-note {
    font-size: 0.85rem; padding: 8px 12px; border-radius: 8px; margin-bottom: 12px;
    background: rgba(192, 132, 252, 0.10); border: 1px solid rgba(192, 132, 252, 0.3);
  }
  .split-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
  @media (max-width: 820px) { .split-grid { grid-template-columns: 1fr; } }
  .panel-facts, .panel-untrusted {
    background: var(--bg-code); border-radius: 10px; padding: 12px 14px; border: 1px solid var(--border);
  }
  .panel-untrusted { border-color: rgba(249, 112, 67, 0.32); }
  .panel-facts h4, .panel-untrusted h4 {
    margin: 0 0 8px; font-size: 0.82rem; display: flex; justify-content: space-between; align-items: center;
  }
  .badge-trusted { font-size: 0.7rem; color: var(--green); background: rgba(52, 211, 153, 0.14); padding: 2px 7px; border-radius: 999px; }
  .badge-untrusted { font-size: 0.7rem; color: var(--coral); background: rgba(249, 112, 67, 0.14); padding: 2px 7px; border-radius: 999px; }
  .kv-row { display: grid; grid-template-columns: 132px minmax(0, 1fr); gap: 8px; margin-bottom: 5px; font-size: 0.82rem; align-items: baseline; }
  .kv-key { color: var(--muted); font-weight: 600; }
  .kv-val { background: transparent; padding: 0; color: var(--text); }
  .untrusted-val { color: var(--amber); }
  .triage-box {
    margin-top: 12px; padding: 10px 14px; border-radius: 10px;
    background: rgba(56, 189, 248, 0.10); border: 1px solid rgba(56, 189, 248, 0.35); font-size: 0.88rem;
  }
  .triage-title { font-weight: 700; margin-bottom: 4px; }
  .triage-box p { margin: 0 0 4px; }
  .data-table { width: 100%; border-collapse: collapse; font-size: 0.86rem; }
  .data-table th, .data-table td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }
  .data-table th { color: var(--muted); font-size: 0.76rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .data-table .num { text-align: right; font-variant-numeric: tabular-nums; }
  .st-pill { font-size: 0.76rem; font-weight: 700; padding: 2px 8px; border-radius: 999px; white-space: nowrap; }
  .st-ok { background: rgba(52, 211, 153, 0.15); color: var(--green); }
  .st-partial { background: rgba(251, 191, 36, 0.15); color: var(--amber); }
  .st-error { background: rgba(251, 113, 133, 0.16); color: var(--red); }
  .st-skipped { background: rgba(148, 163, 184, 0.16); color: var(--muted); }
  .cmd-bar {
    display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap;
    margin-top: 14px; padding: 10px 14px; border-radius: 10px; background: var(--bg-code); border: 1px solid var(--border);
  }
  .muted { color: var(--muted); font-size: 0.88rem; }
  .empty-box { text-align: center; padding: 36px 20px; color: var(--green); font-size: 1.05rem; font-weight: 700; }
  details summary { cursor: pointer; font-weight: 700; padding: 4px 0; }
  footer { margin-top: 32px; text-align: center; color: var(--muted); font-size: 0.82rem; }
</style>
</head>
<body>
<div class="wrap">
  <header class="topbar">
    <div class="brand">
      ${BRAND_SHIELD_SVG}
      <div>
        <h1>FoFo Care Sweep Report</h1>
        <div class="brand-sub">Session <code>${escapeHtml(sessionId)}</code> · fcsweep v${escapeHtml(preflight.tool_version)} · Generated ${escapeHtml(new Date().toISOString())}</div>
      </div>
    </div>
    <div class="top-actions">
      <button class="theme-btn" id="themeToggle" type="button">☀️ Light Mode</button>
    </div>
  </header>

  <section class="hero ${statusKind}">
    <div class="hero-title">${escapeHtml(statusHeadline)}</div>
    <p class="hero-sub">${escapeHtml(verdictSubtext)}</p>
    <div class="meta-pills">
      <span class="meta-pill">🖥️ ${escapeHtml(preflight.hostname)}</span>
      <span class="meta-pill">💻 ${escapeHtml(preflight.os_version)} (${escapeHtml(preflight.os_build)}, ${escapeHtml(preflight.arch)})</span>
      <span class="meta-pill">${preflight.elevated ? '🛡️ Elevated' : '👤 Standard User'}</span>
      ${preflight.platform === 'windows' ? `<span class="meta-pill">🦠 Defender: ${escapeHtml(preflight.defender.mode)}</span>` : ''}
      <span class="meta-pill">💾 Free Disk: ${escapeHtml(fmtBytes(preflight.free_disk_bytes))}</span>
    </div>
  </section>

  ${advisoriesHtml}

  <section class="kpi-grid">
    <div class="kpi kpi-mal" data-kpi-filter="malicious"><div class="kpi-label">🚨 Malicious</div><div class="kpi-num">${counts.malicious}</div></div>
    <div class="kpi kpi-susp" data-kpi-filter="suspicious"><div class="kpi-label">🟠 Suspicious</div><div class="kpi-num">${counts.suspicious}</div></div>
    <div class="kpi kpi-rev" data-kpi-filter="review"><div class="kpi-label">🔎 Review</div><div class="kpi-num">${counts.review}</div></div>
    <div class="kpi kpi-clean" data-kpi-filter="all"><div class="kpi-label">✨ Clean (archived)</div><div class="kpi-num">${counts.clean}</div></div>
  </section>

  <section class="card">
    <h2>🛡️ System &amp; Security Posture</h2>
    <div class="posture-grid">
      <div class="posture-item"><div class="posture-k">Registered Antivirus</div><div class="posture-v">${escapeHtml(avNames)}</div></div>
      <div class="posture-item"><div class="posture-k">Domain / MDM Joined</div><div class="posture-v">${preflight.domain_joined || preflight.mdm_enrolled ? 'Yes' : 'No (Personal / Unmanaged)'}</div></div>
      ${
        preflight.platform === 'windows'
          ? `<div class="posture-item"><div class="posture-k">Defender Signatures</div><div class="posture-v">${escapeHtml(preflight.defender.signature_version ?? 'unknown')} · Tamper: ${escapeHtml(String(preflight.defender.tamper_protected ?? 'unknown'))}</div></div>
             <div class="posture-item"><div class="posture-k">Known-Threat Scan</div><div class="posture-v">${escapeHtml(defenderScan?.engine ?? 'skipped')} (${escapeHtml(defenderScan?.scan_type ?? 'none')}) · ${defenderScan?.detections.length ?? 0} detection(s)</div></div>`
          : `<div class="posture-item"><div class="posture-k">Full Disk Access</div><div class="posture-v">${preflight.full_disk_access === true ? 'Granted' : preflight.full_disk_access === false ? 'Not Granted' : 'Unknown'}</div></div>`
      }
    </div>
    ${
      collectorRows
        ? `<details><summary>📦 Collector Breakdown (${Object.keys(snapshot!.collectors).length} collectors)</summary>
            <table class="data-table" style="margin-top:10px">
              <thead><tr><th>Collector</th><th>Status</th><th class="num">Items</th><th class="num">Duration</th><th>Notes</th></tr></thead>
              <tbody>${collectorRows}</tbody>
            </table>
          </details>`
        : ''
    }
  </section>

  <section>
    <div class="toolbar">
      <div class="filter-group" id="tierFilters">
        <button class="filter-pill active" type="button" data-tier-btn="all">All (${shownFindings.length})</button>
        <button class="filter-pill" type="button" data-tier-btn="malicious">🚨 Malicious (${counts.malicious})</button>
        <button class="filter-pill" type="button" data-tier-btn="suspicious">🟠 Suspicious (${counts.suspicious})</button>
        <button class="filter-pill" type="button" data-tier-btn="review">🔎 Review (${counts.review})</button>
        <button class="filter-pill" type="button" data-tier-btn="protected">🔒 Protected</button>
      </div>
      <div class="search-group">
        <select class="select-input" id="collectorFilter" aria-label="Filter by collector">
          <option value="all">All collectors</option>
          ${collectorsList.map((c) => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join('')}
        </select>
        <input class="search-input" id="searchInput" type="search" placeholder="Filter by ID, path, signal, signer…" aria-label="Search findings">
      </div>
    </div>

    <div id="findingsList">
      ${
        shownFindings.length > 0
          ? shownFindings.map((f) => renderFindingCard(f, sessionId)).join('\n')
          : '<div class="card empty-box">✨ Clean sweep! No findings scored in review, suspicious, or malicious tiers.</div>'
      }
    </div>
  </section>

  ${verifyHtml}

  <section class="card">
    <h3>⏪ Changes Taken &amp; Undo</h3>
    ${manifestHtml}
  </section>

  ${hardenHtml}

  <footer>
    Generated locally by <strong>FoFo Care Sweep (fcsweep)</strong> · 100% offline · Zero telemetry · Sweet Papa Technologies
  </footer>
</div>

<script>
(function () {
  var root = document.documentElement;
  var toggle = document.getElementById('themeToggle');
  function applyTheme(t) {
    root.setAttribute('data-theme', t);
    toggle.textContent = t === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode';
    try { localStorage.setItem('fcsweep-theme', t); } catch (e) {}
  }
  try {
    var saved = localStorage.getItem('fcsweep-theme');
    if (saved === 'light' || saved === 'dark') applyTheme(saved);
  } catch (e) {}
  toggle.addEventListener('click', function () {
    applyTheme(root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
  });

  var activeTier = 'all';
  var collectorSel = document.getElementById('collectorFilter');
  var searchInput = document.getElementById('searchInput');
  var cards = Array.prototype.slice.call(document.querySelectorAll('.finding-card'));
  var pills = Array.prototype.slice.call(document.querySelectorAll('[data-tier-btn]'));

  function applyFilters() {
    var col = collectorSel ? collectorSel.value : 'all';
    var q = (searchInput ? searchInput.value : '').trim().toLowerCase();
    cards.forEach(function (el) {
      var tier = el.getAttribute('data-tier');
      var c = el.getAttribute('data-collector');
      var prot = el.getAttribute('data-protected') === 'true';
      var blob = el.getAttribute('data-search') || '';
      var okTier = activeTier === 'all' || (activeTier === 'protected' ? prot : tier === activeTier);
      var okCol = col === 'all' || c === col;
      var okQ = !q || blob.indexOf(q) !== -1;
      el.style.display = okTier && okCol && okQ ? '' : 'none';
    });
  }

  function setTier(t) {
    activeTier = t;
    pills.forEach(function (b) {
      b.classList.toggle('active', b.getAttribute('data-tier-btn') === t);
    });
    applyFilters();
  }

  pills.forEach(function (b) {
    b.addEventListener('click', function () { setTier(b.getAttribute('data-tier-btn')); });
  });
  Array.prototype.slice.call(document.querySelectorAll('[data-kpi-filter]')).forEach(function (k) {
    k.addEventListener('click', function () { setTier(k.getAttribute('data-kpi-filter')); });
  });
  if (collectorSel) collectorSel.addEventListener('change', applyFilters);
  if (searchInput) searchInput.addEventListener('input', applyFilters);

  Array.prototype.slice.call(document.querySelectorAll('[data-copy]')).forEach(function (btn) {
    btn.addEventListener('click', function () {
      var text = btn.getAttribute('data-copy');
      if (!text) return;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () {
          var prev = btn.textContent;
          btn.textContent = '✅ Copied!';
          setTimeout(function () { btn.textContent = prev; }, 1400);
        });
      }
    });
  });
})();
</script>
</body>
</html>
`;
}
