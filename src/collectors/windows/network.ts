import fs from 'node:fs';
import path from 'node:path';
import { ensureArray, runPowerShellJson } from '../../platform/powershell.js';
import type { CollectedItem, CollectorRunResult } from '../../types.js';
import { PS_FILE_FACTS_HELPER } from './ps-common.js';

interface RawNetwork {
  proxies?: Array<{
    scope: 'user' | 'winhttp';
    user_sid?: string | null;
    location: string;
    proxy_enable?: boolean;
    proxy_server?: string | null;
    auto_config_url?: string | null;
  }>;
  dns?: Array<{
    interface_alias: string;
    servers: string[];
  }>;
  firewall_profiles?: Array<{
    name: string;
    enabled: boolean;
  }>;
  custom_firewall_rules?: Array<{
    name: string;
    display_name: string;
    direction: string;
    action: string;
    program?: string | null;
  }>;
}

const LOCALHOST_HOSTS = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'broadcasthost',
  'host.docker.internal',
  'gateway.docker.internal',
  'kubernetes.docker.internal',
]);

export function parseHostsFile(hostsPath: string): Array<{ line: string; ip: string; domain: string }> {
  const results: Array<{ line: string; ip: string; domain: string }> = [];
  if (!fs.existsSync(hostsPath)) return results;
  let content = '';
  try {
    content = fs.readFileSync(hostsPath, 'utf8');
  } catch {
    return results;
  }
  for (const rawLine of content.split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const withoutComment = trimmed.split('#')[0].trim();
    const parts = withoutComment.split(/\s+/).filter(Boolean);
    if (parts.length < 2) continue;
    const ip = parts[0];
    for (const domain of parts.slice(1)) {
      const domLower = domain.toLowerCase();
      if (LOCALHOST_HOSTS.has(domLower)) continue;
      results.push({ line: trimmed, ip, domain });
    }
  }
  return results;
}

export async function collectWindowsNetwork(timeoutMs: number): Promise<CollectorRunResult> {
  const start = Date.now();
  const script = `
${PS_FILE_FACTS_HELPER}

$proxies = @()

# Per-user WinINET proxy settings
$userSids = Get-LoadedUserHives
if ($userSids.Count -eq 0) {
  $p = 'Registry::HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'
  try {
    $props = Get-ItemProperty -LiteralPath $p -ErrorAction SilentlyContinue
    if ($props -and (($props.ProxyEnable -eq 1 -and -not [string]::IsNullOrWhiteSpace($props.ProxyServer)) -or -not [string]::IsNullOrWhiteSpace($props.AutoConfigURL))) {
      $proxies += [ordered]@{
        scope = 'user'
        user_sid = 'HKCU'
        location = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'
        proxy_enable = ($props.ProxyEnable -eq 1)
        proxy_server = [string]$props.ProxyServer
        auto_config_url = [string]$props.AutoConfigURL
      }
    }
  } catch {}
} else {
  foreach ($sid in $userSids) {
    $p = 'Registry::HKEY_USERS\\' + $sid + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'
    try {
      $props = Get-ItemProperty -LiteralPath $p -ErrorAction SilentlyContinue
      if ($props -and (($props.ProxyEnable -eq 1 -and -not [string]::IsNullOrWhiteSpace($props.ProxyServer)) -or -not [string]::IsNullOrWhiteSpace($props.AutoConfigURL))) {
        $proxies += [ordered]@{
          scope = 'user'
          user_sid = $sid
          location = ('HKU\\' + $sid + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings')
          proxy_enable = ($props.ProxyEnable -eq 1)
          proxy_server = [string]$props.ProxyServer
          auto_config_url = [string]$props.AutoConfigURL
        }
      }
    } catch {}
  }
}

# System WinHTTP proxy
try {
  $whOut = (& netsh.exe winhttp show proxy 2>&1) -join "\`n"
  if ($whOut -match 'Proxy Server\\(s\\)\\s*:\\s*(.+)' -and $matches[1].Trim() -notmatch 'Direct access') {
    $proxies += [ordered]@{
      scope = 'winhttp'
      user_sid = $null
      location = 'WinHTTP System Proxy'
      proxy_enable = $true
      proxy_server = $matches[1].Trim()
      auto_config_url = $null
    }
  }
} catch {}

# DNS servers per active adapter
$dnsList = @()
try {
  foreach ($d in @(Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 -ErrorAction SilentlyContinue)) {
    if ($d -and $d.ServerAddresses -and $d.ServerAddresses.Count -gt 0) {
      $dnsList += [ordered]@{
        interface_alias = [string]$d.InterfaceAlias
        servers = @($d.ServerAddresses | ForEach-Object { [string]$_ })
      }
    }
  }
} catch {}

# Firewall profiles
$fwProfiles = @()
try {
  foreach ($fp in @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
    $fwProfiles += [ordered]@{
      name = [string]$fp.Name
      enabled = [bool]$fp.Enabled
    }
  }
} catch {}

# Non-built-in enabled inbound allow rules pointing to user-writable programs
$fwRules = @()
try {
  $rules = Get-NetFirewallRule -Enabled True -Action Allow -Direction Inbound -ErrorAction SilentlyContinue |
    Where-Object { [string]::IsNullOrEmpty($_.Group) } | Select-Object -First 40
  foreach ($r in @($rules)) {
    $app = $null
    try {
      $af = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue
      if ($af -and $af.Program -and $af.Program -ne 'Any') { $app = [string]$af.Program }
    } catch {}
    if ($app) {
      $fwRules += [ordered]@{
        name = [string]$r.Name
        display_name = [string]$r.DisplayName
        direction = [string]$r.Direction
        action = [string]$r.Action
        program = $app
      }
    }
  }
} catch {}

[ordered]@{
  proxies = @($proxies)
  dns = @($dnsList)
  firewall_profiles = @($fwProfiles)
  custom_firewall_rules = @($fwRules)
} | ConvertTo-Json -Depth 6 -Compress
`;

  const res = await runPowerShellJson<RawNetwork>(script, { timeoutMs });
  const durationMs = Date.now() - start;
  const warnings: string[] = [];
  if (!res.ok) {
    warnings.push(res.error || 'Partial network collection failure');
  }

  const raw = res.data ?? {};
  const items: CollectedItem[] = [];

  for (const p of ensureArray(raw.proxies)) {
    items.push({
      collector: 'network',
      kind: 'proxy_setting',
      location: p.location,
      facts: {
        proxy_server: p.proxy_server || null,
        proxy_pac_url: p.auto_config_url || null,
      },
      untrusted: {
        raw_value: [p.proxy_server, p.auto_config_url].filter(Boolean).join(' | '),
      },
      remediation_meta: {
        proxy_scope: p.scope,
        proxy_user_sid: p.user_sid ?? undefined,
      },
    });
  }

  for (const d of ensureArray(raw.dns)) {
    items.push({
      collector: 'network',
      kind: 'dns_setting',
      location: `DNS:${d.interface_alias}`,
      facts: {
        dns_servers: ensureArray(d.servers),
      },
      untrusted: {
        name: d.interface_alias,
        raw_value: ensureArray(d.servers).join(', '),
      },
      remediation_meta: {
        adapter_interface_alias: d.interface_alias,
      },
    });
  }

  // Hosts file entries (read directly in Node)
  const sysRoot = process.env.SystemRoot || 'C:\\Windows';
  const hostsPath = path.join(sysRoot, 'System32', 'drivers', 'etc', 'hosts');
  for (const entry of parseHostsFile(hostsPath)) {
    items.push({
      collector: 'network',
      kind: 'hosts_entry',
      location: `${hostsPath} -> ${entry.domain}`,
      facts: {
        hosts_ip: entry.ip,
        hosts_domain: entry.domain,
      },
      untrusted: {
        name: entry.domain,
        raw_value: entry.line,
      },
      remediation_meta: {
        hosts_line: entry.line,
        hosts_ip: entry.ip,
        hosts_domain: entry.domain,
      },
    });
  }

  // Disabled firewall profiles (informational / posture)
  for (const fp of ensureArray(raw.firewall_profiles)) {
    items.push({
      collector: 'network',
      kind: 'firewall_profile',
      location: `WindowsFirewall:${fp.name}`,
      facts: {
        firewall_enabled: fp.enabled,
      },
      untrusted: {
        name: fp.name,
      },
    });
  }

  for (const r of ensureArray(raw.custom_firewall_rules)) {
    items.push({
      collector: 'network',
      kind: 'firewall_rule',
      location: `FirewallRule:${r.name}`,
      facts: {
        target_path: r.program || null,
      },
      untrusted: {
        name: r.display_name || r.name,
        raw_value: `${r.direction} ${r.action} ${r.program ?? ''}`.trim(),
      },
    });
  }

  return {
    collector: 'network',
    status: res.ok ? 'ok' : 'partial',
    duration_ms: durationMs,
    item_count: items.length,
    items,
    warnings,
  };
}
