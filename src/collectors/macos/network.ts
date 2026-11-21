import { execFileSafe } from '../../platform/exec.js';
import { parseHostsFile } from '../windows/network.js';
import type { CollectedItem, CollectorRunResult } from '../../types.js';

export async function collectMacosNetwork(timeoutMs: number): Promise<CollectorRunResult> {
  const start = Date.now();
  const items: CollectedItem[] = [];
  const warnings: string[] = [];

  const [proxyRes, dnsRes] = await Promise.all([
    execFileSafe('scutil', ['--proxy'], { timeoutMs: Math.min(timeoutMs, 10_000) }),
    execFileSafe('scutil', ['--dns'], { timeoutMs: Math.min(timeoutMs, 10_000) }),
  ]);

  if (proxyRes.exitCode === 0) {
    const out = proxyRes.stdout;
    const httpEnabled = /HTTPEnable\s*:\s*1/.test(out);
    const httpsEnabled = /HTTPSEnable\s*:\s*1/.test(out);
    const pacEnabled = /ProxyAutoConfigEnable\s*:\s*1/.test(out);
    const socksEnabled = /SOCKSEnable\s*:\s*1/.test(out);

    if (httpEnabled || httpsEnabled || pacEnabled || socksEnabled) {
      const httpHost = out.match(/HTTPProxy\s*:\s*(.+)/)?.[1]?.trim() ?? '';
      const httpPort = out.match(/HTTPPort\s*:\s*(\d+)/)?.[1]?.trim() ?? '';
      const pacUrl = out.match(/ProxyAutoConfigURLString\s*:\s*(.+)/)?.[1]?.trim() ?? '';
      const server = httpHost ? `${httpHost}${httpPort ? ':' + httpPort : ''}` : null;
      items.push({
        collector: 'network',
        kind: 'proxy_setting',
        location: 'macOS:scutil --proxy',
        facts: {
          proxy_server: server,
          proxy_pac_url: pacUrl || null,
        },
        untrusted: {
          raw_value: [server, pacUrl].filter(Boolean).join(' | '),
        },
      });
    }
  } else {
    warnings.push('scutil --proxy failed');
  }

  if (dnsRes.exitCode === 0) {
    const servers = Array.from(dnsRes.stdout.matchAll(/nameserver\[\d+\]\s*:\s*([^\s]+)/g)).map(
      (m) => m[1]
    );
    const uniqueServers = Array.from(new Set(servers));
    if (uniqueServers.length > 0) {
      items.push({
        collector: 'network',
        kind: 'dns_setting',
        location: 'macOS:scutil --dns',
        facts: {
          dns_servers: uniqueServers,
        },
        untrusted: {
          raw_value: uniqueServers.join(', '),
        },
      });
    }
  }

  for (const entry of parseHostsFile('/etc/hosts')) {
    items.push({
      collector: 'network',
      kind: 'hosts_entry',
      location: `/etc/hosts -> ${entry.domain}`,
      facts: {
        hosts_ip: entry.ip,
        hosts_domain: entry.domain,
      },
      untrusted: {
        name: entry.domain,
        raw_value: entry.line,
      },
    });
  }

  return {
    collector: 'network',
    status: warnings.length > 0 ? 'partial' : 'ok',
    duration_ms: Date.now() - start,
    item_count: items.length,
    items,
    warnings,
  };
}
