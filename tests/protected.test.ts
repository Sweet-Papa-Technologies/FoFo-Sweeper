import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { checkProtected, type ProtectedContext } from '../src/scoring/protected.js';
import { executeFixPlan } from '../src/remediation/executor.js';
import { buildPlan } from '../src/remediation/plan.js';
import { EventBus } from '../src/output/events.js';
import type { CollectedItem, Finding } from '../src/types.js';

const baseCtx: ProtectedContext = {
  platform: 'windows',
  avProducts: [
    {
      display_name: 'Bitdefender Antivirus',
      product_state: 266240,
      enabled: true,
      up_to_date: true,
      path_to_signed_product_exe: 'C:\\Program Files\\Bitdefender\\Bitdefender Security\\bdagent.exe',
    },
  ],
  toolPaths: ['C:\\Tools\\fcsweep\\fcsweep.exe', 'C:\\Tools\\fcsweep'],
  sessionRoot: 'C:\\ProgramData\\FoFoCare\\Sweep\\sessions',
};

describe('Protected List (Section 6 — one test per protected entry)', () => {
  it('1. protects valid Microsoft-signed files inside Windows directories', () => {
    const item: CollectedItem = {
      collector: 'processes',
      kind: 'process',
      location: 'pid:400',
      facts: {
        target_path: 'C:\\Windows\\System32\\svchost.exe',
        sig_status: 'Valid',
        signer: 'CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US',
      },
      untrusted: {},
    };
    const res = checkProtected(item, baseCtx);
    assert.equal(res.protected, true);

    // Must NOT protect an unsigned svchost.exe or one in C:\Windows\Temp
    const unsignedWin = checkProtected(
      { ...item, facts: { ...item.facts, sig_status: 'NotSigned' } },
      baseCtx
    );
    assert.equal(unsignedWin.protected, false);

    const tempWin = checkProtected(
      { ...item, facts: { ...item.facts, target_path: 'C:\\Windows\\Temp\\svchost.exe' } },
      baseCtx
    );
    assert.equal(tempWin.protected, false);
  });

  it('2. protects registered antivirus products (both Defender and third-party AV)', () => {
    const defenderRes = checkProtected(
      {
        collector: 'services',
        kind: 'service',
        location: 'HKLM\\Services\\WinDefend',
        facts: {
          target_path: 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe',
          sig_status: 'Valid',
          signer: 'CN=Microsoft Windows, O=Microsoft Corporation',
        },
        untrusted: {},
      },
      baseCtx
    );
    assert.equal(defenderRes.protected, true);

    const thirdPartyRes = checkProtected(
      {
        collector: 'processes',
        kind: 'process',
        location: 'pid:900',
        facts: {
          target_path: 'C:\\Program Files\\Bitdefender\\Bitdefender Security\\vsserv.exe',
          sig_status: 'Valid',
          signer: 'CN=Bitdefender SRL',
        },
        untrusted: {},
      },
      baseCtx
    );
    assert.equal(thirdPartyRes.protected, true);
  });

  it('3. protects kernel drivers unconditionally (report-only)', () => {
    const res = checkProtected(
      {
        collector: 'services',
        kind: 'kernel_driver',
        location: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\UnknownDrv',
        facts: {
          target_path: 'C:\\ProgramData\\evil.sys',
          sig_status: 'NotSigned',
          is_kernel_driver: true,
        },
        untrusted: {},
      },
      baseCtx
    );
    assert.equal(res.protected, true);
  });

  it('4. protects the tool binary and session root directory', () => {
    const toolRes = checkProtected(
      {
        collector: 'processes',
        kind: 'process',
        location: 'pid:1234',
        facts: { target_path: 'C:\\Tools\\fcsweep\\fcsweep.exe', sig_status: 'NotSigned' },
        untrusted: {},
      },
      baseCtx
    );
    assert.equal(toolRes.protected, true);

    const sessionRes = checkProtected(
      {
        collector: 'autoruns',
        kind: 'autorun_startup',
        location: 'C:\\ProgramData\\FoFoCare\\Sweep\\sessions\\2026-11-21\\quarantine\\x.quarantined',
        facts: {
          target_path: 'C:\\ProgramData\\FoFoCare\\Sweep\\sessions\\2026-11-21\\quarantine\\x.quarantined',
        },
        untrusted: {},
      },
      baseCtx
    );
    assert.equal(sessionRes.protected, true);
  });

  it('5. protects Documents, Pictures, Desktop, and cloud-sync folders', () => {
    const personalPaths = [
      'C:\\Users\\alice\\Documents\\taxes.pdf.exe',
      'C:\\Users\\alice\\Pictures\\vacation.scr',
      'C:\\Users\\alice\\Desktop\\tool.exe',
      'C:\\Users\\alice\\OneDrive\\script.bat',
      'C:\\Users\\alice\\OneDrive - Sweet Papa\\work.exe',
      'C:\\Users\\alice\\Dropbox\\sync.exe',
      'C:\\Users\\alice\\Google Drive\\run.exe',
      'C:\\Users\\alice\\iCloudDrive\\app.exe',
      'C:\\Users\\alice\\Box\\helper.exe',
    ];
    for (const p of personalPaths) {
      const res = checkProtected(
        {
          collector: 'autoruns',
          kind: 'autorun_registry',
          location: 'HKCU\\Run\\Test',
          facts: { target_path: p, sig_status: 'NotSigned' },
          untrusted: {},
        },
        baseCtx
      );
      assert.equal(res.protected, true, `Expected protected=true for ${p}`);
    }
  });

  it('refuses to action a protected finding in fix even if explicitly passed to --approve', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fcsweep-prot-'));
    try {
      const protectedFinding: Finding = {
        id: 'f-0001',
        collector: 'services',
        kind: 'kernel_driver',
        location: 'HKLM\\Services\\ProtDrv',
        facts: { target_path: 'C:\\Windows\\System32\\drivers\\prot.sys', is_kernel_driver: true },
        untrusted: { name: 'ProtDrv' },
        signals: ['unsigned'],
        score: 90,
        tier: 'malicious',
        proposed_action: 'disable_service+quarantine_file', // even if forced
        protected: true,
        protected_reason: 'Kernel drivers are protected',
      };
      const plan = buildPlan({
        sessionId: 'test-sess',
        findings: [protectedFinding],
        advisories: [],
        stopConditions: [],
      });
      const bus = new EventBus({ json: false, quiet: true });
      const res = await executeFixPlan({
        sessionId: 'test-sess',
        sessionDir: tmpDir,
        findings: [protectedFinding],
        plan,
        elevated: true,
        dryRun: false,
        interactive: false,
        approveIds: ['f-0001'],
        bus,
        skipRestorePoint: true,
      });
      assert.equal(res.applied, 0);
      assert.equal(res.skipped, 1);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
