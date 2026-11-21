import { TRIAGE_REASON_MAX_CHARS, UNTRUSTED_MAX_CHARS } from '../constants.js';
import { loadTriagePrompt } from '../data-loader.js';
import { sanitizeUntrusted, sanitizeUntrustedRecord } from '../output/sanitize.js';
import type {
  Finding,
  PlatformKind,
  Tier,
  TriageBundleItem,
  TriageImportResult,
  TriageRequest,
  TriageVerdictInput,
} from '../types.js';
import { deriveProposedAction } from './engine.js';

const VALID_VERDICTS = new Set(['benign', 'suspicious', 'malicious']);
const VALID_CONFIDENCES = new Set(['low', 'medium', 'high']);
const BENIGN_DOWNGRADE_BLOCKING_SIGNALS = new Set([
  'lolbin_remote',
  'covered_by_exclusion',
  'system_name_wrong_dir',
]);

export function buildTriageRequest(sessionId: string, findings: Finding[]): TriageRequest {
  const greyItems: TriageBundleItem[] = findings
    .filter((f) => f.tier === 'review' || f.tier === 'suspicious')
    .map((f) => ({
      id: f.id,
      collector: f.collector,
      kind: f.kind,
      location: sanitizeUntrusted(f.location, UNTRUSTED_MAX_CHARS),
      tier: f.tier,
      score: f.score,
      signals: [...f.signals],
      facts: { ...f.facts },
      untrusted_machine_data: sanitizeUntrustedRecord(f.untrusted, UNTRUSTED_MAX_CHARS),
    }));

  return {
    schema_version: 1,
    session_id: sessionId,
    exported_at: new Date().toISOString(),
    system_prompt: loadTriagePrompt(),
    expected_response_schema: {
      type: 'object',
      required: ['verdicts'],
      properties: {
        verdicts: {
          type: 'array',
          items: {
            type: 'object',
            required: ['id', 'verdict', 'confidence', 'cited_facts', 'reason'],
            additionalProperties: false,
            properties: {
              id: { type: 'string' },
              verdict: { enum: ['benign', 'suspicious', 'malicious'] },
              confidence: { enum: ['low', 'medium', 'high'] },
              cited_facts: { type: 'array', minItems: 1, items: { type: 'string' } },
              reason: { type: 'string', maxLength: TRIAGE_REASON_MAX_CHARS },
            },
          },
        },
      },
    },
    items: greyItems,
  };
}

function validateVerdictShape(raw: unknown): { ok: true; verdict: TriageVerdictInput } | { ok: false; id: string | null; reason: string } {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, id: null, reason: 'Verdict entry is not a JSON object' };
  }
  const obj = raw as Record<string, unknown>;
  const id = typeof obj.id === 'string' ? obj.id.trim() : null;
  if (!id) {
    return { ok: false, id: null, reason: 'Missing or invalid finding id' };
  }
  if (typeof obj.verdict !== 'string' || !VALID_VERDICTS.has(obj.verdict)) {
    return { ok: false, id, reason: `Invalid verdict value: ${String(obj.verdict)}` };
  }
  if (typeof obj.confidence !== 'string' || !VALID_CONFIDENCES.has(obj.confidence)) {
    return { ok: false, id, reason: `Invalid confidence value: ${String(obj.confidence)}` };
  }
  if (!Array.isArray(obj.cited_facts) || obj.cited_facts.length === 0) {
    return { ok: false, id, reason: 'cited_facts must be a non-empty array of fact keys' };
  }
  for (const cf of obj.cited_facts) {
    if (typeof cf !== 'string' || !cf.trim()) {
      return { ok: false, id, reason: 'cited_facts contains a non-string or empty entry' };
    }
  }
  if (typeof obj.reason !== 'string' || obj.reason.trim().length === 0) {
    return { ok: false, id, reason: 'Missing or empty reason' };
  }
  const cleanReason = sanitizeUntrusted(obj.reason, TRIAGE_REASON_MAX_CHARS);
  if (obj.reason.trim().length > TRIAGE_REASON_MAX_CHARS) {
    return { ok: false, id, reason: `reason exceeds ${TRIAGE_REASON_MAX_CHARS} characters` };
  }

  return {
    ok: true,
    verdict: {
      id,
      verdict: obj.verdict as TriageVerdictInput['verdict'],
      confidence: obj.confidence as TriageVerdictInput['confidence'],
      cited_facts: obj.cited_facts.map((c) => String(c).trim()),
      reason: cleanReason,
    },
  };
}

/**
 * Applies Section 7 deterministic verdict rules.
 * The model never chooses an action and can never modify protected, defender_hit, or malicious-tier items.
 */
export function applyTriageVerdicts(
  sessionId: string,
  findings: Finding[],
  rawInput: unknown,
  platform: PlatformKind
): { updatedFindings: Finding[]; result: TriageImportResult } {
  const importedAt = new Date().toISOString();
  const rawList: unknown[] = Array.isArray(rawInput)
    ? rawInput
    : rawInput && typeof rawInput === 'object' && Array.isArray((rawInput as { verdicts?: unknown[] }).verdicts)
      ? (rawInput as { verdicts: unknown[] }).verdicts
      : [];

  const byId = new Map<string, Finding>();
  const updatedFindings = findings.map((f) => ({ ...f }));
  for (const f of updatedFindings) {
    byId.set(f.id, f);
  }

  const accepted: TriageImportResult['accepted'] = [];
  const rejected: TriageImportResult['rejected'] = [];

  if (
    !Array.isArray(rawInput) &&
    !(rawInput && typeof rawInput === 'object' && Array.isArray((rawInput as { verdicts?: unknown[] }).verdicts))
  ) {
    rejected.push({
      id: null,
      reason: 'Input JSON must be an array of verdicts or an object with a "verdicts" array',
    });
    return {
      updatedFindings,
      result: { session_id: sessionId, imported_at: importedAt, accepted, rejected },
    };
  }

  const seenIds = new Set<string>();

  for (const entry of rawList) {
    const shape = validateVerdictShape(entry);
    if (!shape.ok) {
      rejected.push({ id: shape.id, reason: shape.reason, raw: entry });
      continue;
    }
    const v = shape.verdict;
    if (seenIds.has(v.id)) {
      rejected.push({ id: v.id, reason: 'Duplicate verdict for finding id' });
      continue;
    }
    seenIds.add(v.id);

    const finding = byId.get(v.id);
    if (!finding) {
      rejected.push({ id: v.id, reason: 'Finding id does not exist in this session' });
      continue;
    }

    // Section 7 rule: reject any verdict citing a field in `untrusted` or a nonexistent fact key
    const untrustedKeys = new Set(Object.keys(finding.untrusted ?? {}));
    const factKeys = new Set(Object.keys(finding.facts ?? {}));
    let invalidCitation: string | null = null;
    for (const cf of v.cited_facts) {
      if (cf.startsWith('untrusted.') || cf.startsWith('untrusted_machine_data.') || untrustedKeys.has(cf)) {
        invalidCitation = `cited_facts references untrusted field "${cf}"`;
        break;
      }
      if (!factKeys.has(cf)) {
        invalidCitation = `cited_facts references unknown fact key "${cf}"`;
        break;
      }
    }
    if (invalidCitation) {
      rejected.push({ id: v.id, reason: invalidCitation });
      continue;
    }

    const previousTier: Tier = finding.tier;
    let newTier: Tier = previousTier;
    let note: string | undefined;

    // Hard immutability rules (Section 7):
    // Any verdict never changes a protected item, a defender_hit, or a malicious-tier item.
    if (finding.protected) {
      note = 'Protected item: tier unchanged';
    } else if (finding.facts.defender_hit || finding.signals.includes('defender_hit')) {
      note = 'Defender hit: tier unchanged';
    } else if (previousTier === 'malicious') {
      note = 'Already malicious tier: tier unchanged';
    } else if (previousTier === 'clean') {
      note = 'Clean tier is outside triage scope: tier unchanged';
    } else {
      // Review or suspicious grey middle
      if (v.verdict === 'malicious' && v.confidence === 'high') {
        if (previousTier === 'suspicious') {
          newTier = 'malicious';
        } else if (previousTier === 'review') {
          newTier = 'suspicious'; // "Moves a review item to suspicious, no further"
        }
      } else if (v.verdict === 'suspicious') {
        if (previousTier === 'review') {
          newTier = 'suspicious';
        }
      } else if (v.verdict === 'benign') {
        if (previousTier === 'review') {
          newTier = 'clean';
        } else if (previousTier === 'suspicious') {
          const validSigner = finding.facts.sig_status === 'Valid';
          const hasBlockingSignal = finding.signals.some((s) =>
            BENIGN_DOWNGRADE_BLOCKING_SIGNALS.has(s)
          );
          if (validSigner && !hasBlockingSignal) {
            newTier = 'review';
          } else {
            note =
              'Suspicious item not downgraded to review (requires valid signature and no lolbin_remote, covered_by_exclusion, or system_name_wrong_dir signal)';
          }
        }
      }
    }

    const tierChanged = newTier !== previousTier;
    finding.tier = newTier;
    finding.proposed_action = deriveProposedAction(
      {
        collector: finding.collector,
        kind: finding.kind,
        location: finding.location,
        facts: finding.facts,
        untrusted: finding.untrusted,
        remediation_meta: finding.remediation_meta,
      },
      newTier,
      finding.protected,
      platform
    );
    finding.triage = {
      verdict: v.verdict,
      confidence: v.confidence,
      cited_facts: v.cited_facts,
      reason: v.reason,
      previous_tier: previousTier,
      tier_changed: tierChanged,
      imported_at: importedAt,
    };

    accepted.push({
      id: v.id,
      verdict: v.verdict,
      confidence: v.confidence,
      cited_facts: v.cited_facts,
      reason: v.reason,
      previous_tier: previousTier,
      new_tier: newTier,
      tier_changed: tierChanged,
      ...(note ? { note } : {}),
    });
  }

  return {
    updatedFindings,
    result: {
      session_id: sessionId,
      imported_at: importedAt,
      accepted,
      rejected,
    },
  };
}
