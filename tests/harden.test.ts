import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { EventBus } from '../src/output/events.js';
import { runHardenApply, runHardenRevert, type HardenBackend } from '../src/hardening/windows-harden.js';
import type { HardenSettingRecord, PreflightResult } from '../src/types.js';

function makeMockHardenBackend(state: Record<string, unknown>): HardenBackend {
  const now = () => new Date().toISOString();
  const makeRec = (id: string, name: string, newVal: unknown): HardenSettingRecord => {
    const prior = state[id];
    state[id] = newVal;
    return {
      id,
      name,
      status: 'applied',
      prior_value: prior,
      new_value: newVal,
      timestamp: now(),
    };
  };

  return {
    async applyDefenderRealtime() {
      return makeRec('defender_realtime', 'Defender Realtime', false);
    },
    async applyDefenderPua() {
      return makeRec('defender_pua', 'Defender PUA', 1);
    },
    async applyDefenderCloud() {
      return makeRec('defender_cloud', 'Defender Cloud', { MAPSReporting: 'Advanced' });
    },
    async applyDefenderAsr() {
      return makeRec('defender_asr', 'Defender ASR', ['5BEB7EFE-FD9A-4556-801D-275E5FFC04CC']);
    },
    async applySmartScreen() {
      return makeRec('smartscreen', 'SmartScreen', 'RequireAdmin');
    },
    async applyWindowsUpdate() {
      return makeRec('windows_update', 'Windows Update', 'Manual');
    },
    async applyShowFileExtensions() {
      return makeRec('show_file_extensions', 'HideFileExt', 0);
    },
    async checkTamperProtection() {
      return {
        id: 'tamper_protection',
        name: 'Tamper Protection',
        status: 'report_only',
        prior_value: true,
        new_value: null,
        message: 'Tamper Protection is ON.',
        timestamp: now(),
      };
    },
    async checkPendingUpdates() {
      return {
        id: 'pending_updates',
        name: 'Pending Updates',
        status: 'report_only',
        prior_value: 2,
        new_value: null,
        message: '2 pending updates',
        timestamp: now(),
      };
    },
    async revertSetting(record) {
      state[record.id] = record.prior_value;
      return { ok: true, message: `Restored ${record.id}` };
    },
  };
}

describe('Hardening & Revert (Section 9 & M4)', () => {
  it('applies all hardening settings and --revert restores every recorded prior value exactly', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fcsweep-harden-'));
    try {
      const initialState: Record<string, unknown> = {
        defender_realtime: true, // was disabled
        defender_pua: 0,
        defender_cloud: { MAPSReporting: 'Disabled' },
        defender_asr: [],
        smartscreen: 'Off',
        windows_update: 'Disabled',
        show_file_extensions: 1,
      };
      const liveState = { ...initialState };
      const backend = makeMockHardenBackend(liveState);
      const bus = new EventBus({ json: false, quiet: true });

      const applied = await runHardenApply({
        sessionId: 'h1',
        sessionDir: tmpDir,
        bus,
        backend,
      });
      assert.equal(applied.failedCount, 0);
      assert.equal(liveState.defender_realtime, false);
      assert.equal(liveState.defender_pua, 1);
      assert.equal(liveState.show_file_extensions, 0);

      const reverted = await runHardenRevert({
        sessionDir: tmpDir,
        bus,
        backend,
      });
      assert.equal(reverted.failed, 0);
      assert.equal(reverted.reverted, 7);
      assert.deepEqual(liveState, initialState);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('skips Defender rows when a third-party antivirus is registered and active', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fcsweep-harden-3p-'));
    try {
      const liveState: Record<string, unknown> = {
        defender_realtime: true,
        defender_pua: 0,
        defender_cloud: 'none',
        defender_asr: [],
        smartscreen: 'Off',
        windows_update: 'Disabled',
        show_file_extensions: 1,
      };
      const backend = makeMockHardenBackend(liveState);
      const bus = new EventBus({ json: false, quiet: true });

      const preflight = {
        av_products: [
          {
            display_name: 'Bitdefender Antivirus',
            product_state: 266240,
            enabled: true,
            up_to_date: true,
          },
        ],
      } as PreflightResult;

      const applied = await runHardenApply({
        sessionId: 'h2',
        sessionDir: tmpDir,
        preflight,
        bus,
        backend,
      });

      assert.equal(applied.manifest.third_party_av_detected, true);
      // Defender rows skipped and untouched
      assert.equal(liveState.defender_realtime, true);
      assert.equal(liveState.defender_pua, 0);
      const skippedIds = applied.manifest.settings
        .filter((s) => s.status === 'skipped')
        .map((s) => s.id);
      assert.deepEqual(skippedIds.sort(), [
        'defender_asr',
        'defender_cloud',
        'defender_pua',
        'defender_realtime',
      ]);
      // Non-Defender rows still applied!
      assert.equal(liveState.smartscreen, 'RequireAdmin');
      assert.equal(liveState.windows_update, 'Manual');
      assert.equal(liveState.show_file_extensions, 0);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
