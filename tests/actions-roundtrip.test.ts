import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { EventBus } from '../src/output/events.js';
import { executeFixPlan } from '../src/remediation/executor.js';
import { executeUndo } from '../src/remediation/undo.js';
import { buildPlan } from '../src/remediation/plan.js';
import { sha256File } from '../src/session/manifest.js';
import type { ActionHooks } from '../src/remediation/actions.js';
import type { ActionType, Finding } from '../src/types.js';

const ALL_14_ACTIONS: ActionType[] = [
  'kill_process',
  'disable_autorun',
  'disable_task',
  'disable_service',
  'remove_wmi_subscription',
  'remove_hijack',
  'quarantine_file',
  'remove_policy',
  'remove_notification_permission',
  'reset_proxy',
  'reset_dns',
  'clean_hosts',
  'remove_defender_exclusion',
  'remove_root_cert',
  'uninstall_program',
];

describe('Remediation & Undo Round-Trip + Fail-Closed Backup Tests (Section 8 & 13)', () => {
  it('round-trips EVERY Section 8 action (apply -> undo -> exact state match) and verifies execution order', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fcsweep-rt-'));
    try {
      // Simulated OS state store for every action type so all 14+ actions round-trip on every OS in CI
      const initialState: Record<string, string> = {
        kill_process: 'running:pid=4321',
        disable_autorun: 'HKCU\\Run\\BadVal="C:\\bad.exe"',
        disable_task: '<Task><Enabled>true</Enabled></Task>',
        disable_service: 'StartMode=Auto;State=Running',
        remove_wmi_subscription: 'Filter=BadF;Consumer=BadC;Bound=true',
        remove_hijack: 'Shell=explorer.exe,bad.exe',
        quarantine_file: 'payload-bytes-original-hash',
        remove_policy: 'ExtensionInstallForcelist\\1=evil',
        remove_notification_permission: '{"https://spam.invalid:443,*":{"setting":1}}',
        reset_proxy: 'ProxyEnable=1;ProxyServer=127.0.0.1:8888',
        reset_dns: 'Servers=198.51.100.53',
        clean_hosts: '127.0.0.1 localhost\n1.2.3.4 evil.invalid\n',
        remove_defender_exclusion: 'ExclusionPath=C:\\Users\\alice\\AppData\\Roaming\\bad',
        remove_root_cert: 'CertThumbprint=DEADBEEF1234',
        uninstall_program: 'installed',
      };
      const liveState: Record<string, string> = { ...initialState };
      const executionOrder: ActionType[] = [];

      const hooks: ActionHooks = {
        customExecutor: {
          async backup(action, finding, ctx, seqKey) {
            const reversible = action !== 'kill_process' && action !== 'uninstall_program';
            let backupPath: string | null = null;
            let backupSha: string | null = null;
            if (reversible) {
              backupPath = path.join(ctx.backupsDir, `${seqKey}_${action}.bak`);
              fs.mkdirSync(ctx.backupsDir, { recursive: true });
              fs.writeFileSync(backupPath, liveState[action], 'utf8');
              backupSha = sha256File(backupPath);
            }
            return {
              backup_path: backupPath,
              backup_sha256: backupSha,
              inverse: {
                type: action,
                reversible,
                description: `Inverse of ${action} for ${finding.id}`,
                backup_path: backupPath,
                backup_sha256: backupSha,
                params: { key: action, backup_path: backupPath },
              },
            };
          },
          async apply(action) {
            executionOrder.push(action);
            if (action !== 'uninstall_program') {
              liveState[action] = `REMOVED:${action}`;
            }
            return `Applied ${action}`;
          },
          async undo(entry) {
            const key = String(entry.inverse.params.key);
            const bp = String(entry.inverse.params.backup_path);
            liveState[key] = fs.readFileSync(bp, 'utf8');
            return `Restored ${key}`;
          },
        },
      };

      const findings: Finding[] = ALL_14_ACTIONS.map((act, idx) => ({
        id: `f-${String(idx + 1).padStart(4, '0')}`,
        collector: 'test',
        kind: act,
        location: `test://${act}`,
        facts: {},
        untrusted: { name: act },
        signals: ['unsigned'],
        score: 85,
        tier: 'malicious',
        proposed_action: act,
        protected: false,
      }));

      const plan = buildPlan({
        sessionId: 'rt-sess',
        findings,
        advisories: [],
        stopConditions: [],
      });
      const bus = new EventBus({ json: false, quiet: true });

      const fixRes = await executeFixPlan({
        sessionId: 'rt-sess',
        sessionDir: tmpDir,
        findings,
        plan,
        elevated: true,
        dryRun: false,
        interactive: false,
        approveIds: findings.map((f) => f.id),
        bus,
        hooks,
        skipRestorePoint: true,
      });

      assert.equal(fixRes.applied, ALL_14_ACTIONS.length);
      assert.equal(fixRes.failed, 0);

      // Verify strict Section 4 Step 6 order: kill_process first, quarantine_file after persistence, network/browser after quarantine
      assert.equal(executionOrder[0], 'kill_process');
      const idxAutorun = executionOrder.indexOf('disable_autorun');
      const idxQuarantine = executionOrder.indexOf('quarantine_file');
      const idxHosts = executionOrder.indexOf('clean_hosts');
      const idxUninstall = executionOrder.indexOf('uninstall_program');
      assert.ok(idxAutorun < idxQuarantine, 'Persistence must disable before file quarantine');
      assert.ok(idxQuarantine < idxHosts, 'File quarantine must run before network/browser reset');
      assert.ok(idxHosts < idxUninstall, 'User-guided actions run last');

      // Now undo the entire session newest-first and verify EVERY reversible item matches pre-fix state exactly
      const undoRes = await executeUndo({
        sessionId: 'rt-sess',
        sessionDir: tmpDir,
        elevated: true,
        bus,
        plan,
        hooks,
      });

      assert.equal(undoRes.failed, 0);
      assert.equal(undoRes.not_reversible, 2); // kill_process + uninstall_program
      assert.equal(undoRes.undone, ALL_14_ACTIONS.length - 2);

      for (const act of ALL_14_ACTIONS) {
        if (act === 'kill_process' || act === 'uninstall_program') continue;
        assert.equal(liveState[act], initialState[act], `Round-trip mismatch for ${act}`);
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('proves fail-closed behavior: simulated backup failure for EACH action prevents paired change from running', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fcsweep-failclosed-'));
    try {
      const reversibleActions = ALL_14_ACTIONS.filter(
        (a) => a !== 'kill_process' && a !== 'uninstall_program'
      );

      for (const act of reversibleActions) {
        const sessDir = path.join(tmpDir, act);
        fs.mkdirSync(sessDir, { recursive: true });
        let applyCalled = false;

        const hooks: ActionHooks = {
          onBeforeBackup() {
            throw new Error(`Simulated backup disk failure for ${act}`);
          },
          customExecutor: {
            async backup() {
              throw new Error('Should not reach backup');
            },
            async apply() {
              applyCalled = true;
              return 'MUTATED!';
            },
            async undo() {
              return '';
            },
          },
        };

        const finding: Finding = {
          id: 'f-0001',
          collector: 'test',
          kind: act,
          location: `test://${act}`,
          facts: {},
          untrusted: {},
          signals: ['unsigned'],
          score: 85,
          tier: 'malicious',
          proposed_action: act,
          protected: false,
        };
        const plan = buildPlan({ sessionId: act, findings: [finding], advisories: [], stopConditions: [] });
        const bus = new EventBus({ json: false, quiet: true });

        const res = await executeFixPlan({
          sessionId: act,
          sessionDir: sessDir,
          findings: [finding],
          plan,
          elevated: true,
          dryRun: false,
          interactive: false,
          approveIds: ['f-0001'],
          bus,
          hooks,
          skipRestorePoint: true,
        });

        assert.equal(applyCalled, false, `FAIL-CLOSED VIOLATION: apply() ran despite backup failure for ${act}`);
        assert.equal(res.applied, 0);
        assert.equal(res.failed, 1);

        const manifest = JSON.parse(fs.readFileSync(path.join(sessDir, 'manifest.json'), 'utf8'));
        assert.equal(manifest.entries[0].status, 'skipped_backup_failed');
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('performs real filesystem round-trip for quarantine_file and remove_notification_permission', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fcsweep-fs-rt-'));
    try {
      const targetFile = path.join(tmpDir, 'malware-fixture.exe');
      fs.writeFileSync(targetFile, 'BENIGN-FIXTURE-CONTENT-1234567890', 'utf8');
      const originalHash = sha256File(targetFile);

      const prefsFile = path.join(tmpDir, 'Preferences');
      const originalPrefs = JSON.stringify({
        profile: {
          content_settings: {
            exceptions: {
              notifications: {
                'https://spam-popups.invalid:443,*': { setting: 1 },
                'https://mail.google.com:443,*': { setting: 1 },
              },
            },
          },
        },
      });
      fs.writeFileSync(prefsFile, originalPrefs, 'utf8');

      const sessionDir = path.join(tmpDir, 'session');
      fs.mkdirSync(sessionDir, { recursive: true });

      const findings: Finding[] = [
        {
          id: 'f-0001',
          collector: 'defender',
          kind: 'defender_detection',
          location: targetFile,
          facts: { target_path: targetFile, file_exists: true },
          untrusted: { name: 'fixture' },
          signals: ['defender_hit'],
          score: 100,
          tier: 'malicious',
          proposed_action: 'quarantine_file',
          protected: false,
          remediation_meta: { target_file_path: targetFile },
        },
        {
          id: 'f-0002',
          collector: 'browsers',
          kind: 'browser_notification',
          location: 'Chrome:Default:notification:https://spam-popups.invalid:443',
          facts: { browser: 'Chrome' },
          untrusted: { origin: 'https://spam-popups.invalid:443' },
          signals: ['browser_notification_spam'],
          score: 20,
          tier: 'review',
          proposed_action: 'remove_notification_permission',
          protected: false,
          remediation_meta: {
            browser: 'Chrome',
            preferences_path: prefsFile,
            notification_origin: 'https://spam-popups.invalid:443,*',
          },
        },
      ];

      const plan = buildPlan({ sessionId: 'fs-rt', findings, advisories: [], stopConditions: [] });
      const bus = new EventBus({ json: false, quiet: true });

      const fixRes = await executeFixPlan({
        sessionId: 'fs-rt',
        sessionDir,
        findings,
        plan,
        elevated: false,
        dryRun: false,
        interactive: false,
        approveIds: ['f-0001', 'f-0002'],
        bus,
        skipRestorePoint: true,
      });
      assert.equal(fixRes.applied, 2);
      assert.equal(fs.existsSync(targetFile), false, 'Target file should be moved to quarantine');

      const editedPrefs = JSON.parse(fs.readFileSync(prefsFile, 'utf8'));
      assert.equal(editedPrefs.profile.content_settings.exceptions.notifications['https://spam-popups.invalid:443,*'], undefined);
      assert.ok(editedPrefs.profile.content_settings.exceptions.notifications['https://mail.google.com:443,*']);

      // Now undo only f-0001 first, verify restored with exact hash
      const undo1 = await executeUndo({
        sessionId: 'fs-rt',
        sessionDir,
        itemId: 'f-0001',
        elevated: false,
        bus,
        plan,
      });
      assert.equal(undo1.undone, 1);
      assert.equal(fs.existsSync(targetFile), true);
      assert.equal(sha256File(targetFile), originalHash);

      // Undo remaining session (f-0002)
      const undo2 = await executeUndo({
        sessionId: 'fs-rt',
        sessionDir,
        elevated: false,
        bus,
        plan,
      });
      assert.equal(undo2.undone, 1);
      assert.equal(fs.readFileSync(prefsFile, 'utf8'), originalPrefs);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
