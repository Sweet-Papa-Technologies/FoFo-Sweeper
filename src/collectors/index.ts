import { COLLECTOR_TIMEOUTS_MS, MACOS_COLLECTORS, WINDOWS_COLLECTORS } from '../constants.js';
import type {
  CollectedItem,
  CollectorRunResult,
  PlatformKind,
  PreflightResult,
} from '../types.js';
import type { EventBus } from '../output/events.js';

import { collectWindowsAutoruns } from './windows/autoruns.js';
import { collectWindowsTasks } from './windows/tasks.js';
import { collectWindowsServices } from './windows/services.js';
import { collectWindowsWmi } from './windows/wmi.js';
import { collectWindowsHijacks } from './windows/hijacks.js';
import { collectWindowsProcesses } from './windows/processes.js';
import { collectWindowsNetwork } from './windows/network.js';
import { collectWindowsCerts } from './windows/certs.js';
import { collectWindowsDefender } from './windows/defender.js';
import { collectWindowsBrowsers } from './windows/browsers.js';
import { collectWindowsPrograms } from './windows/programs.js';
import { collectWindowsTraces } from './windows/traces.js';

import { collectMacosLaunchItems } from './macos/launch_items.js';
import { collectMacosLoginItems } from './macos/login_items.js';
import { collectMacosProfiles } from './macos/profiles.js';
import { collectMacosBrowsers } from './macos/browsers.js';
import { collectMacosNetwork } from './macos/network.js';
import { collectMacosCron } from './macos/cron.js';
import { collectMacosPosture } from './macos/posture.js';

export function getSupportedCollectors(platform: PlatformKind): string[] {
  if (platform === 'windows') return [...WINDOWS_COLLECTORS];
  if (platform === 'macos') return [...MACOS_COLLECTORS];
  return [];
}

export function resolveCollectorList(platform: PlatformKind, only?: string[]): string[] {
  const supported = getSupportedCollectors(platform);
  if (!only || only.length === 0) return supported;
  const supportedSet = new Set(supported);
  const selected: string[] = [];
  for (const name of only) {
    const clean = name.trim().toLowerCase();
    if (!clean) continue;
    if (!supportedSet.has(clean)) {
      throw new Error(
        `Unknown collector "${clean}" for ${platform}. Valid collectors: ${supported.join(', ')}`
      );
    }
    if (!selected.includes(clean)) selected.push(clean);
  }
  return selected;
}

export interface RunCollectorsOutput {
  results: CollectorRunResult[];
  allItems: CollectedItem[];
  defenderExclusions: string[];
}

export async function runCollectors(params: {
  platform: PlatformKind;
  collectors: string[];
  preflight: PreflightResult;
  bus: EventBus;
}): Promise<RunCollectorsOutput> {
  const { platform, collectors, preflight, bus } = params;
  const results: CollectorRunResult[] = [];
  const allItems: CollectedItem[] = [];
  let defenderExclusions: string[] = [];

  for (const name of collectors) {
    const timeoutMs = COLLECTOR_TIMEOUTS_MS[name] ?? COLLECTOR_TIMEOUTS_MS.default;
    let res: CollectorRunResult;
    try {
      if (platform === 'windows') {
        switch (name) {
          case 'autoruns':
            res = await collectWindowsAutoruns(timeoutMs);
            break;
          case 'tasks':
            res = await collectWindowsTasks(timeoutMs);
            break;
          case 'services':
            res = await collectWindowsServices(timeoutMs);
            break;
          case 'wmi':
            res = await collectWindowsWmi(timeoutMs);
            break;
          case 'hijacks':
            res = await collectWindowsHijacks(timeoutMs);
            break;
          case 'processes':
            res = await collectWindowsProcesses(timeoutMs);
            break;
          case 'network':
            res = await collectWindowsNetwork(timeoutMs);
            break;
          case 'certs':
            res = await collectWindowsCerts(timeoutMs);
            break;
          case 'defender': {
            const defRes = await collectWindowsDefender(timeoutMs, preflight);
            defenderExclusions = defRes.exclusions;
            res = defRes;
            break;
          }
          case 'browsers':
            res = await collectWindowsBrowsers(timeoutMs, preflight);
            break;
          case 'programs':
            res = await collectWindowsPrograms(timeoutMs);
            break;
          case 'traces':
            res = await collectWindowsTraces(timeoutMs);
            break;
          default:
            res = {
              collector: name,
              status: 'skipped',
              duration_ms: 0,
              item_count: 0,
              items: [],
              warnings: [`Unknown Windows collector: ${name}`],
            };
        }
      } else if (platform === 'macos') {
        switch (name) {
          case 'launch_items':
            res = await collectMacosLaunchItems(timeoutMs);
            break;
          case 'login_items':
            res = await collectMacosLoginItems(timeoutMs);
            break;
          case 'profiles':
            res = await collectMacosProfiles(timeoutMs, preflight);
            break;
          case 'browsers':
            res = await collectMacosBrowsers(timeoutMs, preflight);
            break;
          case 'network':
            res = await collectMacosNetwork(timeoutMs);
            break;
          case 'cron':
            res = await collectMacosCron(timeoutMs);
            break;
          case 'posture':
            res = await collectMacosPosture(timeoutMs);
            break;
          default:
            res = {
              collector: name,
              status: 'skipped',
              duration_ms: 0,
              item_count: 0,
              items: [],
              warnings: [`Unknown macOS collector: ${name}`],
            };
        }
      } else {
        res = {
          collector: name,
          status: 'skipped',
          duration_ms: 0,
          item_count: 0,
          items: [],
          warnings: [`No collectors defined for platform: ${platform}`],
        };
      }
    } catch (err) {
      // Section 5: "A collector that fails records the error and returns nothing; it never aborts the scan."
      res = {
        collector: name,
        status: 'error',
        duration_ms: 0,
        item_count: 0,
        items: [],
        warnings: [],
        error: err instanceof Error ? err.message : String(err),
      };
    }

    results.push(res);
    allItems.push(...res.items);

    if (res.status === 'skipped' || res.status === 'error') {
      preflight.collectors_skipped.push({
        collector: res.collector,
        reason: res.error || res.warnings.join('; ') || res.status,
      });
    } else if (res.status === 'partial') {
      preflight.collectors_partial.push({
        collector: res.collector,
        reason: res.warnings.join('; ') || 'partial',
      });
    }

    bus.emit('collector_done', {
      collector: res.collector,
      status: res.status,
      item_count: res.item_count,
      duration_ms: res.duration_ms,
      ...(res.error ? { error: res.error } : {}),
      ...(res.warnings.length > 0 ? { warnings: res.warnings } : {}),
    });

    const rowNote = res.error || (res.warnings.length > 0 ? `${res.warnings.length} warning(s)` : undefined);
    bus.raw(bus.ui.collectorRow(res.collector, res.status, res.item_count, res.duration_ms, rowNote));
  }

  return { results, allItems, defenderExclusions };
}
