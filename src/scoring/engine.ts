import type {
  CollectedItem,
  DefenderDetection,
  Finding,
  PlatformKind,
  RulesConfig,
  Tier,
} from '../types.js';
import { classifyPath, getBasenameLower } from '../platform/file-facts.js';
import { checkProtected, type ProtectedContext } from './protected.js';

export interface ScoringContext {
  rules: RulesConfig;
  platform: PlatformKind;
  sinceDays: number;
  now?: Date;
  defenderExclusions: string[];
  defenderDetections: DefenderDetection[];
  protectedCtx: ProtectedContext;
}

const LOLBIN_REMOTE_INDICATORS: RegExp[] = [
  /(?:^|\s)-(?:enc|enco|encod|encode|encoded|encodedcommand|ec)\s+[A-Za-z0-9+/=]{12,}/i,
  /https?:\/\/[^\s'"]+/i,
  /ftp:\/\/[^\s'"]+/i,
  /\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|start-bitstransfer|frombase64string)\b/i,
  /\b(?:urlcache|split|-f)\b.*\bhttp/i,
  /\\(?:temp|tmp|appdata\\local\\temp|users\\public|programdata)\\[^\\]+\.(?:ps1|vbs|vbe|js|jse|hta|bat|cmd|sct|dll|exe)/i,
  /\b(?:javascript:|vbscript:|scrobj\.dll)\b/i,
];

const TRACE_PASTE_EXEC_PATTERNS: RegExp[] = [
  // PowerShell / curl / mshta / certutil / bitsadmin download-and-execute one-liners (ClickFix / fake-CAPTCHA)
  /\b(?:powershell|pwsh)\b.*(?:\biwr\b|\birm\b|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|webclient).*(?:\biex\b|invoke-expression|start-process|\|\s*iex)/i,
  /\b(?:powershell|pwsh)\b.*(?:-(?:enc|encodedcommand|e)\s+[A-Za-z0-9+/=]{16,})/i,
  /\bmshta(?:\.exe)?\s+["']?https?:\/\//i,
  /\bcurl(?:\.exe)?\b.*https?:\/\/.*(?:\|\s*(?:cmd|powershell|pwsh|sh|bash)|-o\s+.*&&)/i,
  /\bcertutil(?:\.exe)?\b.*-urlcache.*https?:\/\//i,
  /\bbitsadmin(?:\.exe)?\b.*\/transfer.*https?:\/\//i,
  /\bcmd(?:\.exe)?\b.*\/c.*(?:curl|powershell|mshta|certutil|bitsadmin).*https?:\/\//i,
];

const MAC_SHELL_CURL_PIPE_PATTERNS: RegExp[] = [
  /\b(?:curl|wget)\b.*https?:\/\/.*(?:\|\s*(?:sh|bash|zsh|python|python3|osascript|perl)|>\s*\/tmp\/)/i,
  /\b(?:sh|bash|zsh)\s+-c\b.*(?:curl|wget|base64\s+-d|base64\s+--decode|openssl\s+enc)/i,
  /\bosascript\s+-e\b.*(?:do shell script).*(?:curl|wget|base64|\/tmp\/)/i,
  /\bpython3?\s+-c\b.*(?:urllib|requests|base64|exec\()/i,
];

export function matchesLolbinRemote(commandLine: string | null | undefined, rules: RulesConfig): boolean {
  if (!commandLine) return false;
  const lower = commandLine.toLowerCase();
  const hasLolbin = rules.lolbins.some((bin) => {
    const escaped = bin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`(?:^|[\\\\/\\s"'])${escaped}(?:[\\s"']|$)`, 'i').test(lower);
  });
  if (!hasLolbin) return false;
  return LOLBIN_REMOTE_INDICATORS.some((re) => re.test(commandLine));
}

export function matchesTracePasteExec(text: string | null | undefined): boolean {
  if (!text) return false;
  return TRACE_PASTE_EXEC_PATTERNS.some((re) => re.test(text));
}

export function matchesMacShellCurlPipe(commandLine: string | null | undefined): boolean {
  if (!commandLine) return false;
  return MAC_SHELL_CURL_PIPE_PATTERNS.some((re) => re.test(commandLine));
}

export function hasDoubleExtension(filePath: string | null | undefined, rules: RulesConfig): boolean {
  const base = getBasenameLower(filePath);
  if (!base) return false;
  for (const execExt of rules.executable_extensions) {
    if (!base.endsWith(execExt)) continue;
    const stem = base.slice(0, -execExt.length);
    for (const decoy of rules.double_extension_decoys) {
      if (stem.endsWith(decoy)) {
        return true;
      }
    }
  }
  return false;
}

export function isCoveredByDefenderExclusion(
  targetPath: string | null | undefined,
  exclusions: string[]
): boolean {
  if (!targetPath || exclusions.length === 0) return false;
  const normTarget = targetPath.replace(/\//g, '\\').toLowerCase();
  const base = getBasenameLower(normTarget);
  const ext = base.includes('.') ? '.' + base.split('.').pop() : '';

  for (const rawEx of exclusions) {
    if (!rawEx) continue;
    const ex = rawEx.replace(/\//g, '\\').toLowerCase().replace(/\\+$/, '');
    if (!ex) continue;
    // Path prefix exclusion
    if (normTarget === ex || normTarget.startsWith(ex + '\\')) {
      return true;
    }
    // Process name exclusion
    if (base && ex === base) {
      return true;
    }
    // Extension exclusion (e.g. .exe or exe)
    if (ext && (ex === ext || `.${ex}` === ext)) {
      return true;
    }
  }
  return false;
}

export function isRiskyDefenderExclusion(
  exclusionType: string | null | undefined,
  exclusionValue: string | null | undefined
): boolean {
  if (!exclusionValue) return false;
  const val = exclusionValue.replace(/\//g, '\\').toLowerCase().trim();
  if (exclusionType === 'ExclusionExtension') {
    const riskyExts = new Set(['exe', '.exe', 'dll', '.dll', 'ps1', '.ps1', 'bat', '.bat', 'cmd', '.cmd', 'vbs', '.vbs', 'js', '.js', 'scr', '.scr', 'msi', '.msi', '*']);
    return riskyExts.has(val);
  }
  if (exclusionType === 'ExclusionPath') {
    if (/^[a-z]:\\?$/.test(val) || val === '*' || val === 'c:\\users' || val === 'c:\\users\\') {
      return true;
    }
    if (
      /\\appdata(\\|$)/.test(val) ||
      /\\temp(\\|$)/.test(val) ||
      /\\tmp(\\|$)/.test(val) ||
      /\\downloads(\\|$)/.test(val) ||
      /^[a-z]:\\programdata(\\|$)/.test(val) ||
      /^[a-z]:\\users\\public(\\|$)/.test(val)
    ) {
      return true;
    }
  }
  if (exclusionType === 'ExclusionProcess') {
    const riskyProcs = new Set(['powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'svchost.exe']);
    return riskyProcs.has(getBasenameLower(val));
  }
  return false;
}

export function isRandomLookingMacLabel(label: string | null | undefined): boolean {
  if (!label) return false;
  const s = label.trim();
  if (!s) return false;
  // Standard Apple or known vendor reverse-DNS labels look clean (e.g., com.vendor.product)
  // Flag single-segment random alphanumeric strings, hex/UUID-only labels, or very high consonant/digit entropy
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s)) return true;
  if (/^[a-z0-9]{12,}$/i.test(s) && !s.includes('.')) return true;
  const parts = s.split('.');
  const last = parts[parts.length - 1] ?? '';
  if (last.length >= 10 && /[0-9]/.test(last) && /[a-z]/i.test(last)) {
    // Check character transition randomness
    const digits = (last.match(/[0-9]/g) ?? []).length;
    if (digits >= 4 && digits < last.length) return true;
  }
  return false;
}

export function scoreToTier(score: number, rules: RulesConfig): Tier {
  if (score >= rules.tiers.malicious_min) return 'malicious';
  if (score > rules.tiers.review_max) return 'suspicious';
  if (score > rules.tiers.clean_max) return 'review';
  return 'clean';
}

export function deriveProposedAction(
  item: CollectedItem,
  tier: Tier,
  isProtected: boolean,
  platform: PlatformKind
): string {
  if (isProtected) return 'report_only';
  if (platform === 'macos') return 'report_only'; // macOS v0.1 is scan-only
  if (tier === 'clean') return 'none';

  const hasRemovableFile = Boolean(
    item.facts.target_path &&
      item.facts.file_exists !== false &&
      item.facts.path_class !== 'windows_system' &&
      item.facts.path_class !== 'user_personal'
  );

  switch (item.kind) {
    case 'autorun_registry':
    case 'autorun_startup':
      return hasRemovableFile && item.kind === 'autorun_registry'
        ? 'disable_autorun+quarantine_file'
        : 'disable_autorun';
    case 'scheduled_task':
      return hasRemovableFile ? 'disable_task+quarantine_file' : 'disable_task';
    case 'service':
      return hasRemovableFile ? 'disable_service+quarantine_file' : 'disable_service';
    case 'kernel_driver':
      return 'report_only';
    case 'wmi_subscription':
      return hasRemovableFile ? 'remove_wmi_subscription+quarantine_file' : 'remove_wmi_subscription';
    case 'hijack':
      return hasRemovableFile ? 'remove_hijack+quarantine_file' : 'remove_hijack';
    case 'process':
      return hasRemovableFile ? 'kill_process+quarantine_file' : 'kill_process';
    case 'browser_policy':
      return 'remove_policy';
    case 'browser_extension':
      return 'guide_extension';
    case 'browser_notification':
      return 'remove_notification_permission';
    case 'proxy_setting':
      return 'reset_proxy';
    case 'dns_setting':
      return 'reset_dns';
    case 'hosts_entry':
      return 'clean_hosts';
    case 'defender_exclusion':
      return 'remove_defender_exclusion';
    case 'root_certificate':
      return 'remove_root_cert';
    case 'installed_program':
      return 'uninstall_program';
    case 'defender_detection':
      return hasRemovableFile ? 'quarantine_file' : 'report_only';
    case 'run_mru':
    case 'ps_history':
    case 'defender_policy':
    case 'firewall_rule':
    default:
      return 'report_only';
  }
}

function isWithinSinceDays(isoDate: string | null | undefined, sinceDays: number, nowMs: number): boolean {
  if (!isoDate) return false;
  const ts = Date.parse(isoDate);
  if (Number.isNaN(ts)) return false;
  const ageMs = nowMs - ts;
  return ageMs >= 0 && ageMs <= sinceDays * 24 * 60 * 60 * 1000;
}

function matchesDefenderDetection(
  targetPath: string | null | undefined,
  detections: DefenderDetection[]
): DefenderDetection | null {
  if (!targetPath || detections.length === 0) return null;
  const normTarget = targetPath.replace(/\//g, '\\').toLowerCase();
  for (const det of detections) {
    for (const res of det.resources) {
      // Defender resources often look like "file:_C:\Users\...\eicar.com" or "process:_..."
      const cleaned = res
        .replace(/^[a-z]+:_/i, '')
        .replace(/\//g, '\\')
        .toLowerCase();
      if (cleaned === normTarget || cleaned.endsWith(normTarget) || normTarget.endsWith(cleaned)) {
        return det;
      }
    }
  }
  return null;
}

export function scoreItem(item: CollectedItem, seq: number, ctx: ScoringContext): Finding {
  const { rules, platform, sinceDays } = ctx;
  const nowMs = (ctx.now ?? new Date()).getTime();
  const facts = { ...item.facts };
  const signals = new Set<string>();

  const targetPath = facts.target_path ?? null;
  if (targetPath && !facts.path_class) {
    facts.path_class = classifyPath(targetPath, platform);
  }

  // Inspect command line early so protected check knows about LOLBin persistence abuse
  // Note: traces (run_mru / ps_history) use dedicated trace_paste_exec (60) rather than double-counting lolbin_remote (40)
  const cmdToInspect = item.command_inspect ?? item.untrusted.command_line ?? null;
  const isTraceItem = item.kind === 'run_mru' || item.kind === 'ps_history';
  const isLolbinRemote = !isTraceItem && platform === 'windows' && matchesLolbinRemote(cmdToInspect, rules);

  // Protected check
  const prot = checkProtected({ ...item, facts }, ctx.protectedCtx, {
    isLolbinAbuse: isLolbinRemote || item.kind === 'hijack' || item.kind === 'wmi_subscription',
  });

  // 1. defender_hit
  const detHit = matchesDefenderDetection(targetPath, ctx.defenderDetections);
  if (facts.defender_hit || detHit) {
    facts.defender_hit = true;
    if (detHit && !facts.defender_threat_name) {
      facts.defender_threat_name = detHit.threat_name;
    }
    signals.add('defender_hit');
  }

  // 2. system_name_wrong_dir (Windows)
  if (platform === 'windows' && targetPath && facts.file_exists !== false) {
    const base = getBasenameLower(targetPath);
    if (
      rules.system_binary_names.includes(base) &&
      facts.path_class !== 'windows_system'
    ) {
      // Note: valid Microsoft-signed binaries in Program Files (e.g. pwsh or WinSxS copies) are not impersonators
      const isSignedMs =
        facts.sig_status === 'Valid' &&
        typeof facts.signer === 'string' &&
        facts.signer.toLowerCase().includes('microsoft');
      if (!isSignedMs) {
        signals.add('system_name_wrong_dir');
      }
    }
  }

  // 3. lolbin_remote (inspects measured command line, NEVER untrusted descriptions/names)
  if (isLolbinRemote) {
    signals.add('lolbin_remote');
  }

  // 4. covered_by_exclusion
  if (
    platform === 'windows' &&
    item.kind !== 'defender_exclusion' &&
    (facts.covered_by_exclusion || isCoveredByDefenderExclusion(targetPath, ctx.defenderExclusions))
  ) {
    facts.covered_by_exclusion = true;
    signals.add('covered_by_exclusion');
  }

  // 5. forced_extension
  if (facts.force_installed && !facts.domain_or_mdm_joined) {
    signals.add('forced_extension');
  }

  // 6. sig_invalid & unsigned (only when a target file actually exists)
  if (targetPath && facts.file_exists !== false) {
    if (
      facts.sig_status === 'HashMismatch' ||
      facts.sig_status === 'NotTrusted' ||
      facts.sig_status === 'UnknownError'
    ) {
      signals.add('sig_invalid');
    } else if (platform === 'windows' && facts.sig_status === 'NotSigned') {
      signals.add('unsigned');
    } else if (
      platform === 'macos' &&
      (facts.sig_status === 'NotSigned' || facts.sig_status === 'AdHoc')
    ) {
      signals.add('mac_unsigned_or_adhoc');
    }

    if (platform === 'macos' && facts.notarized === false && facts.path_class !== 'macos_system') {
      signals.add('mac_not_notarized');
    }
  }

  // 7. user_writable_path
  if (targetPath && facts.path_class === 'user_writable') {
    if (platform === 'windows') {
      signals.add('user_writable_path');
    } else if (platform === 'macos') {
      signals.add('mac_user_writable_or_hidden');
    }
  }

  // 8. hidden_or_system_attr
  if (facts.hidden_attr || facts.system_attr || facts.hidden_task) {
    signals.add('hidden_or_system_attr');
  }

  // 9. recent
  const createdRef = facts.file_created ?? facts.entry_created ?? facts.install_date ?? null;
  if (isWithinSinceDays(createdRef, sinceDays, nowMs)) {
    // Only add 'recent' when the item is a file/persistence/program/trace item (not built-in OS posture)
    if (item.kind !== 'posture') {
      signals.add('recent');
    }
  }

  // 10. double_extension
  if (targetPath && hasDoubleExtension(targetPath, rules)) {
    signals.add('double_extension');
  }

  // 11. orphan
  if (targetPath && facts.file_exists === false) {
    signals.add('orphan');
  }

  // 12. trace_paste_exec
  if (
    (item.kind === 'run_mru' || item.kind === 'ps_history') &&
    (facts.trace_paste_match || matchesTracePasteExec(cmdToInspect))
  ) {
    facts.trace_paste_match = true;
    signals.add('trace_paste_exec');
  }

  // 13. Specialized deterministic security signals (non-file / structural items)
  if (item.kind === 'hijack') {
    switch (facts.hijack_type) {
      case 'ifeo_debugger':
        signals.add('hijack_debugger');
        break;
      case 'winlogon_shell':
      case 'winlogon_userinit':
        signals.add('hijack_winlogon');
        break;
      case 'appinit_dlls':
        signals.add('hijack_appinit');
        break;
      case 'boot_execute':
        signals.add('hijack_bootexecute');
        break;
    }
  }

  if (item.kind === 'wmi_subscription') {
    signals.add('wmi_persistence');
  }

  if (item.kind === 'root_certificate' && facts.in_ms_root_list === false) {
    signals.add('untrusted_root_cert');
  }

  if (item.kind === 'defender_policy') {
    signals.add('defender_disabled_policy');
  }

  if (item.kind === 'defender_exclusion') {
    if (isRiskyDefenderExclusion(facts.exclusion_type, facts.exclusion_value)) {
      signals.add('defender_exclusion_risky');
    } else {
      signals.add('defender_exclusion_custom');
    }
  }

  if (item.kind === 'browser_policy' && !facts.domain_or_mdm_joined && !facts.force_installed) {
    signals.add('browser_policy_unmanaged');
  }

  if (item.kind === 'browser_extension') {
    if (
      facts.install_source === 'sideloaded' ||
      facts.install_source === 'unpacked' ||
      facts.install_source === 'external_crx'
    ) {
      signals.add('browser_sideloaded_extension');
    }
  }

  if (item.kind === 'browser_notification') {
    signals.add('browser_notification_spam');
  }

  if (item.kind === 'proxy_setting') {
    signals.add('proxy_configured');
  }

  if (item.kind === 'hosts_entry') {
    const dom = (facts.hosts_domain ?? '').toLowerCase();
    const isSecDomain = rules.security_domains.some(
      (sd) => dom === sd || dom.endsWith('.' + sd)
    );
    if (isSecDomain) {
      signals.add('hosts_security_block');
    } else {
      signals.add('hosts_modified');
    }
  }

  if (item.kind === 'installed_program') {
    if (facts.program_tag === 'remote_access_tool') {
      signals.add('remote_access_tool');
    } else if (facts.program_tag === 'bundleware') {
      signals.add('known_bundleware');
    }
  }

  // macOS specialized signals
  if (platform === 'macos') {
    if (item.kind === 'launch_item' || item.kind === 'cron_job') {
      if (matchesMacShellCurlPipe(cmdToInspect)) {
        signals.add('mac_shell_curl_pipe');
      }
      if (item.kind === 'launch_item' && isRandomLookingMacLabel(item.location)) {
        signals.add('mac_random_label');
      }
    }
    if (item.kind === 'config_profile' && facts.profile_sets_browser_or_net) {
      signals.add('mac_suspicious_profile');
    }
    if (item.kind === 'posture' && (facts.sip_enabled === false || facts.gatekeeper_enabled === false)) {
      signals.add('mac_posture_weakened');
    }
  }

  // Reduce noise on legitimately signed apps living in AppData (e.g. VS Code, Discord, Slack, Spotify, Zoom, nvm)
  // Valid Authenticode signature with NO high-risk behavioral signals (lolbin, system_name_wrong_dir, exclusion, defender_hit)
  // should stay in review (<=35) rather than landing in suspicious on a clean Windows box!
  // Let's check: user_writable_path (25) + recent (10) = 35 -> review! Clean Windows box has ZERO findings > review!
  // What about a running process in Program Files with Valid sig + recent? Only recent (10) -> clean!
  // What about unsigned binary in Program Files with no other signals? unsigned (20) -> review!

  // Sum weights from rules.json, capped at 100
  let total = 0;
  const signalList = Array.from(signals);
  for (const sig of signalList) {
    const def = rules.signals[sig];
    if (def) {
      total += def.weight;
    }
  }
  const score = Math.min(100, Math.max(0, total));
  const tier = scoreToTier(score, rules);
  const proposedAction = deriveProposedAction({ ...item, facts }, tier, prot.protected, platform);

  return {
    id: `f-${String(seq).padStart(4, '0')}`,
    collector: item.collector,
    kind: item.kind,
    location: item.location,
    facts,
    untrusted: item.untrusted,
    signals: signalList,
    score,
    tier,
    proposed_action: proposedAction,
    protected: prot.protected,
    ...(prot.reason ? { protected_reason: prot.reason } : {}),
    ...(item.remediation_meta ? { remediation_meta: item.remediation_meta } : {}),
  };
}

export function scoreAllItems(items: CollectedItem[], ctx: ScoringContext): Finding[] {
  return items.map((item, idx) => scoreItem(item, idx + 1, ctx));
}
