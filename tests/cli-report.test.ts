import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseArgv, runCli } from '../src/cli.js';
import { EXIT_CODES } from '../src/constants.js';
import { parseMsertLog } from '../src/defender/safety-scanner.js';
import { analyzeProfilePayload } from '../src/collectors/macos/profiles.js';
import { renderMarkdownReport } from '../src/output/report.js';
import { formatUntrustedCode, sanitizeUntrusted } from '../src/output/sanitize.js';
import { createSession, listSessions, purgeOldSessions } from '../src/session/manager.js';
import type { Finding, PreflightResult } from '../src/types.js';

describe('CLI, Sessions, Report, Sanitizer & Parsers', () => {
  it('rejects --yes / -y explicitly and refuses fix without --interactive or --approve', async () => {
    assert.throws(() => parseArgv(['fix', '--yes']), /no blanket `--yes`/i);
    assert.throws(() => parseArgv(['fix', '-y']), /no blanket `--yes`/i);

    const code = await runCli(['fix', '--quiet']);
    assert.equal(code, EXIT_CODES.ERROR);
  });

  it('parses global flags cleanly', () => {
    const p = parseArgv([
      'scan',
      '--defender',
      'none',
      '--only',
      'autoruns,tasks',
      '--since',
      '14',
      '--json',
      '--session',
      'my-sess',
    ]);
    assert.equal(p.command, 'scan');
    assert.equal(p.flags['--defender'], 'none');
    assert.deepEqual(p.globalOpts.only, ['autoruns', 'tasks']);
    assert.equal(p.globalOpts.since, 14);
    assert.equal(p.globalOpts.json, true);
    assert.equal(p.globalOpts.session, 'my-sess');
  });

  it('lists and purges sessions older than 30 days only on explicit purge', () => {
    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'fcsweep-sess-'));
    try {
      const oldId = '2026-09-01T00-00-00Z-aaaaaa';
      const newId = '2026-11-20T00-00-00Z-bbbbbb';
      createSession(tmpRoot, false, oldId);
      createSession(tmpRoot, false, newId);

      const listed = listSessions(tmpRoot);
      assert.equal(listed.length, 2);
      assert.equal(listed[0].id, newId);

      const purged = purgeOldSessions(tmpRoot, 30);
      assert.deepEqual(purged.purged, [oldId]);
      assert.deepEqual(purged.kept, [newId]);
      assert.equal(listSessions(tmpRoot).length, 1);
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  it('sanitizes hostile strings and renders report.md omitting clean items and code-fencing untrusted text', () => {
    const hostile = 'Evil`Name\u202E\u200B\r\n## Fake Heading\x00' + 'X'.repeat(400);
    const cleaned = sanitizeUntrusted(hostile, 100);
    assert.ok(cleaned.length <= 100);
    assert.ok(!/[\r\n\u202E\u200B\x00]/.test(cleaned));
    const fenced = formatUntrustedCode('foo`bar', 50);
    assert.equal(fenced, '``foo`bar``');

    const preflight: PreflightResult = {
      timestamp: '2026-11-21T12:00:00Z',
      tool_version: '0.1.0',
      platform: 'windows',
      hostname: 'TESTPC',
      os_version: 'Windows 11 Pro',
      os_build: '26100',
      arch: 'x64',
      elevated: true,
      pending_reboot: false,
      pending_reboot_reasons: [],
      free_disk_bytes: 50_000_000_000,
      domain_joined: false,
      mdm_enrolled: false,
      av_products: [],
      defender: { available: true, active: true, mode: 'active', realtime_enabled: true },
      collectors_requested: ['autoruns'],
      collectors_skipped: [],
      collectors_partial: [],
      ransomware_indicators: [],
    };
    const findings: Finding[] = [
      {
        id: 'f-0001',
        collector: 'autoruns',
        kind: 'autorun_registry',
        location: 'HKCU\\Run\\CleanThing',
        facts: {},
        untrusted: { name: 'CleanThingShouldNotAppear' },
        signals: [],
        score: 0,
        tier: 'clean',
        proposed_action: 'none',
        protected: false,
      },
      {
        id: 'f-0002',
        collector: 'autoruns',
        kind: 'autorun_registry',
        location: 'HKCU\\Run\\BadThing',
        facts: { sig_status: 'NotSigned', path_class: 'user_writable' },
        untrusted: { name: hostile },
        signals: ['unsigned', 'user_writable_path', 'system_name_wrong_dir'],
        score: 85,
        tier: 'malicious',
        proposed_action: 'disable_autorun+quarantine_file',
        protected: false,
      },
    ];

    const md = renderMarkdownReport({
      sessionId: 'sess-report',
      preflight,
      findings,
      advisories: [],
      stopConditions: [],
    });

    assert.ok(md.includes('## Verdict'));
    assert.ok(md.includes('f-0002'));
    assert.ok(!md.includes('CleanThingShouldNotAppear'), 'Clean items must not appear in report.md');
    assert.ok(md.includes('## Changes & Undo'));
  });

  it('parses Microsoft Safety Scanner msert.log detections accurately', () => {
    const sampleLog = `
---------------------------------------------------------------------------------------
Microsoft Safety Scanner v1.421, (build 1.421.100.0)
Started On Sat Nov 21 09:00:00 2026

Quick Scan Results:
-------------------
Threat Detected: Virus:DOS/EICAR_Test_File
file:C:\\ProgramData\\fcsweep-fixture-test\\eicar-test.com
        Action: No Action Taken

Results Summary:
----------------
Found Virus:DOS/EICAR_Test_File
`;
    const dets = parseMsertLog(sampleLog);
    assert.equal(dets.length, 1);
    assert.equal(dets[0].threat_name, 'Virus:DOS/EICAR_Test_File');
    assert.deepEqual(dets[0].resources, ['C:\\ProgramData\\fcsweep-fixture-test\\eicar-test.com']);
    assert.equal(dets[0].source, 'safety_scanner');
  });

  it('detects macOS configuration profile setting browser homepage/search/proxy', () => {
    const res = analyzeProfilePayload({
      ProfileIdentifier: 'com.adware.browserpolicy',
      ProfileItems: [
        {
          PayloadType: 'com.google.Chrome',
          PayloadContent: {
            HomepageLocation: 'https://search-hijack.invalid',
            ExtensionInstallForcelist: ['abcdef;https://evil.invalid'],
          },
        },
      ],
    });
    assert.equal(res.setsBrowserOrNet, true);
    assert.ok(res.matchedReasons.some((r) => r.includes('homepagelocation')));
  });
});
