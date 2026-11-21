import { execFileSafe } from '../../platform/exec.js';
import { classifyPath } from '../../platform/file-facts.js';
import type { CollectedItem, CollectorRunResult } from '../../types.js';

export async function collectMacosLoginItems(timeoutMs: number): Promise<CollectorRunResult> {
  const start = Date.now();
  const res = await execFileSafe('sfltool', ['dumpbtm'], { timeoutMs: Math.min(timeoutMs, 30_000) });
  const durationMs = Date.now() - start;

  const combined = `${res.stdout}\n${res.stderr}`;
  if (res.exitCode !== 0 || /must be root|permission denied|not authorized|operation not permitted/i.test(combined)) {
    return {
      collector: 'login_items',
      status: 'partial',
      duration_ms: durationMs,
      item_count: 0,
      items: [],
      warnings: ['`sfltool dumpbtm` requires root privileges (re-run with sudo to inspect Background Task Management login items).'],
    };
  }

  const items: CollectedItem[] = [];
  const blocks = res.stdout.split(/\n\s*#\d+:/);
  for (const block of blocks.slice(1)) {
    const nameMatch = block.match(/Name:\s*(.+)/);
    const devMatch = block.match(/Developer Name:\s*(.+)/);
    const urlMatch = block.match(/URL:\s*file:\/\/(.+)/);
    const typeMatch = block.match(/Type:\s*(.+)/);
    const dispMatch = block.match(/Disposition:\s*(.+)/);

    const name = nameMatch?.[1]?.trim() || 'Unknown Login Item';
    const rawPath = urlMatch?.[1] ? decodeURIComponent(urlMatch[1].trim()) : null;
    const developer = devMatch?.[1]?.trim() || null;

    items.push({
      collector: 'login_items',
      kind: 'login_item',
      location: rawPath || `BTM:${name}`,
      facts: {
        target_path: rawPath,
        path_class: rawPath ? classifyPath(rawPath, 'macos') : undefined,
        signer: developer,
      },
      untrusted: {
        name,
        publisher: developer,
        raw_value: [typeMatch?.[1]?.trim(), dispMatch?.[1]?.trim()].filter(Boolean).join(' | '),
      },
    });
  }

  return {
    collector: 'login_items',
    status: 'ok',
    duration_ms: durationMs,
    item_count: items.length,
    items,
    warnings: [],
  };
}
