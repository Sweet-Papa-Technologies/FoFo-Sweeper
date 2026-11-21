import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { escapeHtml, renderHtmlReport } from '../src/output/html-report.js';
import { TerminalUI } from '../src/output/ui.js';
import { parseArgv } from '../src/cli.js';
import type { Finding, PreflightResult } from '../src/types.js';

const samplePreflight: PreflightResult = {
  timestamp: '2026-11-21T12:00:00Z',
  tool_version: '0.1.0',
  platform: 'windows',
  hostname: 'WARLOCK',
  os_version: 'Microsoft Windows 11 Pro',
  os_build: '26100',
  arch: 'x64',
  elevated: true,
  pending_reboot: false,
  pending_reboot_reasons: [],
  free_disk_bytes: 250_000_000_000,
  domain_joined: false,
  mdm_enrolled: false,
  av_products: [{ display_name: 'Windows Defender', product_state: 397568, enabled: true, up_to_date: true }],
  defender: { available: true, active: true, mode: 'active', realtime_enabled: true, tamper_protected: true, signature_version: '1.463.398.0' },
  collectors_requested: ['autoruns', 'tasks'],
  collectors_skipped: [],
  collectors_partial: [],
  ransomware_indicators: [],
};

describe('HTML Report, XSS Protection, & Terminal UI', () => {
  it('escapes hostile HTML/XSS payloads in untrusted strings, locations, and triage reasons', () => {
    const xssPayload = '<script>alert("pwned")</script><img src=x onerror="alert(1)">';
    assert.ok(!escapeHtml(xssPayload).includes('<script>'));
    assert.ok(!escapeHtml(xssPayload).includes('<img'));

    const finding: Finding = {
      id: 'f-0001',
      collector: 'autoruns',
      kind: 'autorun_registry',
      location: `HKCU\\Run\\${xssPayload}`,
      facts: {
        target_path: 'C:\\Users\\alice\\AppData\\Roaming\\bad\\svchost.exe',
        sig_status: 'NotSigned',
        path_class: 'user_writable',
      },
      untrusted: {
        name: xssPayload,
        description: '" onmouseover="alert(2)" ',
      },
      signals: ['system_name_wrong_dir', 'user_writable_path', 'unsigned'],
      score: 85,
      tier: 'malicious',
      proposed_action: 'disable_autorun+quarantine_file',
      protected: false,
      triage: {
        verdict: 'malicious',
        confidence: 'high',
        cited_facts: ['sig_status'],
        reason: 'Unsigned svchost.exe outside Windows.',
        previous_tier: 'suspicious',
        tier_changed: true,
        imported_at: '2026-11-21T12:01:00Z',
      },
    };

    const html = renderHtmlReport({
      sessionId: '2026-11-21T12-00-00Z-abc123',
      preflight: samplePreflight,
      findings: [finding],
      advisories: [],
      stopConditions: [],
    });

    assert.ok(html.includes('<!DOCTYPE html>'));
    assert.ok(html.includes('FoFo Care Sweep Report'));
    assert.ok(!html.includes('<script>alert('), 'Raw <script> tag must never appear in HTML report');
    assert.ok(!html.includes('<img src=x onerror='), 'Raw <img onerror> must never appear in HTML report');
    assert.ok(html.includes('&lt;script&gt;alert(&quot;pwned&quot;)&lt;/script&gt;'));
    // Zero external network assets (Design Principle #7)
    assert.ok(!/<link[^>]+href="https?:/i.test(html), 'HTML report must not load external stylesheets');
    assert.ok(!/<script[^>]+src="https?:/i.test(html), 'HTML report must not load external scripts');
  });

  it('renders clean TerminalUI output with and without ANSI colors', () => {
    const plain = new TerminalUI(false);
    const colored = new TerminalUI(true);

    const bPlain = plain.banner('0.1.0', 'Windows · Elevated');
    assert.ok(bPlain.includes('FoFo Care Sweep'));
    assert.ok(!bPlain.includes('\x1b['), 'Plain UI must contain no ANSI escape sequences');

    const bColor = colored.banner('0.1.0', 'Windows · Elevated');
    assert.ok(bColor.includes('\x1b['), 'Colored UI should include ANSI codes');

    const row = plain.collectorRow('autoruns', 'ok', 15, 2245);
    assert.ok(row.includes('✅'));
    assert.ok(row.includes('autoruns'));
    assert.ok(row.includes('2.2s'));
  });

  it('parses report format, --html, --open, and --color/--no-color flags', () => {
    const p1 = parseArgv(['scan', '--format', 'html', '--open', '--no-color']);
    assert.equal(p1.globalOpts.reportFormat, 'html');
    assert.equal(p1.globalOpts.openReport, true);
    assert.equal(p1.globalOpts.color, false);

    const p2 = parseArgv(['report', '--html', '--color']);
    assert.equal(p2.command, 'report');
    assert.equal(p2.globalOpts.reportFormat, 'html');
    assert.equal(p2.globalOpts.color, true);
  });
});
