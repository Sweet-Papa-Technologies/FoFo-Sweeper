import type {
  Advisory,
  DefenderScanResult,
  Finding,
  PreflightResult,
  RulesConfig,
  StopCondition,
  VerifyItemStatus,
} from '../types.js';

export function evaluateAdvisoriesAndStops(params: {
  preflight: PreflightResult;
  findings: Finding[];
  defenderScan?: DefenderScanResult | null;
  verifyItems?: VerifyItemStatus[];
  rules: RulesConfig;
}): { advisories: Advisory[]; stopConditions: StopCondition[] } {
  const { preflight, findings, defenderScan, verifyItems, rules } = params;
  const advisories: Advisory[] = [];
  const stopConditions: StopCondition[] = [];

  // 1. Stop Condition: Ransomware indicators (encrypted files or ransom notes)
  if (preflight.ransomware_indicators.length > 0) {
    stopConditions.push({
      kind: 'ransomware_detected',
      message: 'Possible ransomware activity detected (ransom notes or mass-encrypted files found).',
      recommendation:
        'Do NOT run automated cleanup. Disconnect from the network, run `fcsweep defender --offline`, preserve encrypted files for decryption options, back up unaffected personal files, and use Reset this PC.',
      evidence: preflight.ransomware_indicators,
    });
  }

  // 2. Stop Condition: Repeated resurrection (item resurrected twice)
  if (verifyItems && verifyItems.length > 0) {
    const repeated = verifyItems.filter((v) => v.resurrection_count >= 2);
    if (repeated.length > 0) {
      stopConditions.push({
        kind: 'repeated_resurrection',
        message: `${repeated.length} removed item(s) resurrected two or more times across verifications.`,
        recommendation:
          'Active persistence is surviving user-mode removal. Run `fcsweep defender --offline` first, then back up personal files and use Reset this PC.',
        evidence: repeated.map((r) => `${r.finding_id} (${r.location}, count=${r.resurrection_count})`),
      });
    }
  }

  // 3. Stop Condition: Defender disabled and unable to be re-enabled (with no other active AV)
  const hasOtherActiveAv = preflight.av_products.some(
    (av) => av.enabled && !/windows defender|microsoft defender/i.test(av.display_name)
  );
  if (
    preflight.platform === 'windows' &&
    !hasOtherActiveAv &&
    preflight.defender.mode === 'disabled' &&
    preflight.defender.disabled_by_policy &&
    preflight.defender.service_status?.toLowerCase() === 'stopped'
  ) {
    stopConditions.push({
      kind: 'defender_unrecoverable',
      message:
        'Microsoft Defender is disabled by policy and its service is stopped, with no alternative antivirus active.',
      recommendation:
        'Run `fcsweep defender --offline` (or boot into Windows Recovery), then back up personal files and use Reset this PC if Defender cannot be restored.',
      evidence: [
        `defender.mode=${preflight.defender.mode}`,
        `defender.service_status=${preflight.defender.service_status ?? 'unknown'}`,
        ...(preflight.defender.error ? [preflight.defender.error] : []),
      ],
    });
  }

  // 4. Stop Condition: Boot-start kernel driver scored malicious
  const maliciousBootDrivers = findings.filter(
    (f) => (f.kind === 'kernel_driver' || f.facts.is_kernel_driver) && f.facts.is_boot_start && f.tier === 'malicious'
  );
  if (maliciousBootDrivers.length > 0) {
    stopConditions.push({
      kind: 'malicious_boot_driver',
      message: `${maliciousBootDrivers.length} boot-start kernel driver(s) scored malicious.`,
      recommendation:
        'Kernel-mode boot persistence cannot be safely cleaned from inside the running OS. Run `fcsweep defender --offline`, then back up personal files and use Reset this PC.',
      evidence: maliciousBootDrivers.map((d) => `${d.id}: ${d.location} (score=${d.score})`),
    });
  }

  // Convert stop conditions into critical advisories too
  for (const sc of stopConditions) {
    advisories.push({
      kind: 'stop_condition',
      severity: 'critical',
      title: `STOP CONDITION: ${sc.kind.replace(/_/g, ' ')}`,
      message: `${sc.message} ${sc.recommendation}`,
      finding_ids: [],
    });
  }

  // Non-blocking Advisory 1: Unknown Remote-Access Tool (phone support scam indicator)
  const ratFindings = findings.filter((f) => f.signals.includes('remote_access_tool'));
  if (ratFindings.length > 0) {
    const names = Array.from(
      new Set(ratFindings.map((f) => f.facts.program_tag_name || f.location))
    );
    advisories.push({
      kind: 'remote_access_tool',
      severity: 'warning',
      title: 'Remote-access software detected',
      message:
        `Detected remote-access tool(s): ${names.join(', ')}. ` +
        'If you did not intentionally install these (or were guided by a phone caller claiming to be tech support), uninstall them immediately and disconnect remote sessions.',
      finding_ids: ratFindings.map((f) => f.id),
    });
  }

  // Non-blocking Advisory 2: Credential theft risk
  const credReasons: string[] = [];
  const credFindingIds: string[] = [];

  // Infostealer Defender detections
  const allDetections = defenderScan?.detections ?? [];
  for (const det of allDetections) {
    const lower = det.threat_name.toLowerCase();
    if (rules.infostealer_patterns.some((pat) => lower.includes(pat))) {
      credReasons.push(`Infostealer detection: ${det.threat_name}`);
    }
  }
  for (const f of findings) {
    if (f.facts.defender_threat_name) {
      const lower = f.facts.defender_threat_name.toLowerCase();
      if (rules.infostealer_patterns.some((pat) => lower.includes(pat))) {
        credFindingIds.push(f.id);
        if (!credReasons.some((r) => r.includes(f.facts.defender_threat_name!))) {
          credReasons.push(`Infostealer detection on ${f.id}: ${f.facts.defender_threat_name}`);
        }
      }
    }
    if (f.signals.includes('trace_paste_exec')) {
      credFindingIds.push(f.id);
      credReasons.push(`Pasted download-and-execute command found in ${f.kind} (${f.id})`);
    }
  }
  if (ratFindings.length > 0) {
    credReasons.push('Remote-access software installed (verify whether authorized)');
    for (const r of ratFindings) credFindingIds.push(r.id);
  }

  if (credReasons.length > 0) {
    advisories.push({
      kind: 'credential_theft',
      severity: 'warning',
      title: 'Credential-theft risk — change passwords from a different device',
      message:
        `Indicators suggesting potential credential exposure were found (${credReasons.join('; ')}). ` +
        'Change email, banking, and important account passwords and sign out of all other sessions FROM A DIFFERENT, CLEAN DEVICE.',
      finding_ids: Array.from(new Set(credFindingIds)),
    });
  }

  // Advisory 3: macOS Full Disk Access guidance
  if (preflight.platform === 'macos' && preflight.full_disk_access === false) {
    advisories.push({
      kind: 'full_disk_access',
      severity: 'info',
      title: 'macOS Full Disk Access not granted',
      message:
        preflight.fda_guidance ||
        'Some locations (Safari data, user TCC/Mail/Background items) could not be read. Grant Full Disk Access to your Terminal app in System Settings -> Privacy & Security -> Full Disk Access and re-run.',
      finding_ids: [],
    });
  }

  // Advisory 4: Pending reboot
  if (preflight.pending_reboot) {
    advisories.push({
      kind: 'reboot_required',
      severity: 'info',
      title: 'System reboot pending',
      message: `Windows reports a pending reboot (${preflight.pending_reboot_reasons.join(', ') || 'system update/file rename'}). After remediation, reboot and run \`fcsweep verify\`.`,
      finding_ids: [],
    });
  }

  return { advisories, stopConditions };
}
