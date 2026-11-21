import { getMicrosoftRootThumbprints } from '../../data-loader.js';
import { ensureArray, runPowerShellJson } from '../../platform/powershell.js';
import type { CollectedItem, CollectorRunResult } from '../../types.js';

interface RawCert {
  store: 'LocalMachine\\Root' | 'CurrentUser\\Root';
  thumbprint: string;
  subject: string;
  issuer: string;
  not_before?: string | null;
  not_after?: string | null;
  friendly_name?: string | null;
}

export async function collectWindowsCerts(timeoutMs: number): Promise<CollectorRunResult> {
  const start = Date.now();
  const script = `
$items = @()
foreach ($storePath in @('Cert:\\LocalMachine\\Root', 'Cert:\\CurrentUser\\Root')) {
  $storeLabel = if ($storePath -like '*LocalMachine*') { 'LocalMachine\\Root' } else { 'CurrentUser\\Root' }
  try {
    foreach ($c in @(Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue)) {
      if (-not $c -or -not $c.Thumbprint) { continue }
      $nb = $null
      $na = $null
      try { $nb = $c.NotBefore.ToUniversalTime().ToString('o') } catch {}
      try { $na = $c.NotAfter.ToUniversalTime().ToString('o') } catch {}
      $items += [ordered]@{
        store = $storeLabel
        thumbprint = [string]$c.Thumbprint.ToUpperInvariant()
        subject = [string]$c.Subject
        issuer = [string]$c.Issuer
        not_before = $nb
        not_after = $na
        friendly_name = [string]$c.FriendlyName
      }
    }
  } catch {}
}
ConvertTo-Json -InputObject @($items) -Depth 5 -Compress
`;

  const res = await runPowerShellJson<RawCert[]>(script, { timeoutMs });
  const durationMs = Date.now() - start;
  if (!res.ok) {
    return {
      collector: 'certs',
      status: 'error',
      duration_ms: durationMs,
      item_count: 0,
      items: [],
      warnings: [],
      error: res.error || res.stderr || 'certs collector failed',
    };
  }

  const msRoots = getMicrosoftRootThumbprints();
  const seen = new Set<string>();
  const items: CollectedItem[] = [];

  for (const r of ensureArray(res.data)) {
    const tp = (r.thumbprint || '').toUpperCase().replace(/\s+/g, '');
    const dedupeKey = `${r.store}:${tp}`;
    if (!tp || seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);

    const inMsList = msRoots.has(tp);
    items.push({
      collector: 'certs',
      kind: 'root_certificate',
      location: `Cert:\\${r.store}\\${tp}`,
      facts: {
        cert_thumbprint: tp,
        cert_store: r.store,
        in_ms_root_list: inMsList,
        entry_created: r.not_before ?? null,
      },
      untrusted: {
        name: r.friendly_name || r.subject,
        subject: r.subject,
        issuer: r.issuer,
      },
      remediation_meta: {
        cert_store: r.store,
        cert_thumbprint: tp,
      },
    });
  }

  return {
    collector: 'certs',
    status: 'ok',
    duration_ms: durationMs,
    item_count: items.length,
    items,
    warnings: [],
  };
}
