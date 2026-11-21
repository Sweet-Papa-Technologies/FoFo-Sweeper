import type { ActionType, Advisory, Finding, Plan, PlanItem, StopCondition } from '../types.js';

const VALID_ACTIONS = new Set<ActionType>([
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
  'guide_extension',
  'report_only',
]);

export function parseProposedActions(proposed: string): ActionType[] {
  if (!proposed || proposed === 'none' || proposed === 'report_only') return [];
  const parts = proposed
    .split('+')
    .map((s) => s.trim())
    .filter((s): s is ActionType => VALID_ACTIONS.has(s as ActionType) && s !== 'report_only');
  return parts;
}

export function buildPlan(params: {
  sessionId: string;
  findings: Finding[];
  advisories: Advisory[];
  stopConditions: StopCondition[];
  existingPlan?: Plan | null;
}): Plan {
  const now = new Date().toISOString();
  const prevStateById = new Map<string, PlanItem['approval_state']>();
  if (params.existingPlan) {
    for (const item of params.existingPlan.items) {
      prevStateById.set(item.finding_id, item.approval_state);
    }
  }

  const items: PlanItem[] = params.findings
    .filter((f) => f.tier !== 'clean')
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id))
    .map((f) => {
      const actions = f.protected ? [] : parseProposedActions(f.proposed_action);
      const prev = prevStateById.get(f.id);
      return {
        finding_id: f.id,
        collector: f.collector,
        kind: f.kind,
        location: f.location,
        tier: f.tier,
        score: f.score,
        protected: f.protected,
        actions,
        // Section 8: Malicious pre-selected in --interactive; Suspicious listed not pre-selected; Review report only
        default_selected: !f.protected && f.tier === 'malicious' && actions.length > 0,
        approval_state: prev ?? 'pending',
        proposed_action: f.proposed_action,
      };
    });

  return {
    session_id: params.sessionId,
    created_at: params.existingPlan?.created_at ?? now,
    updated_at: now,
    items,
    advisories: params.advisories,
    stop_conditions: params.stopConditions,
  };
}
