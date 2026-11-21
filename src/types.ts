export type PlatformKind = 'windows' | 'macos' | 'linux';

export type Tier = 'clean' | 'review' | 'suspicious' | 'malicious';

export type SigStatus =
  | 'Valid'
  | 'NotSigned'
  | 'HashMismatch'
  | 'NotTrusted'
  | 'UnknownError'
  | 'AdHoc'
  | 'NotApplicable';

export type PathClass =
  | 'windows_system'
  | 'program_files'
  | 'user_writable'
  | 'user_personal'
  | 'macos_system'
  | 'macos_applications'
  | 'other';

export type ActionType =
  | 'kill_process'
  | 'disable_autorun'
  | 'disable_task'
  | 'disable_service'
  | 'remove_wmi_subscription'
  | 'remove_hijack'
  | 'quarantine_file'
  | 'remove_policy'
  | 'remove_notification_permission'
  | 'reset_proxy'
  | 'reset_dns'
  | 'clean_hosts'
  | 'remove_defender_exclusion'
  | 'remove_root_cert'
  | 'uninstall_program'
  | 'guide_extension'
  | 'report_only';

export interface FileFacts {
  target_path?: string | null;
  file_exists?: boolean;
  sha256?: string | null;
  file_size?: number | null;
  file_created?: string | null;
  file_modified?: string | null;
  sig_status?: SigStatus;
  signer?: string | null;
  notarized?: boolean | null;
  path_class?: PathClass;
  hidden_attr?: boolean;
  system_attr?: boolean;
}

export interface FindingFacts extends FileFacts {
  runs_as?: string | null;
  defender_hit?: boolean;
  defender_threat_name?: string | null;
  covered_by_exclusion?: boolean;
  hidden_task?: boolean;
  start_mode?: string | null;
  service_state?: string | null;
  is_kernel_driver?: boolean;
  is_boot_start?: boolean;
  listening_ports?: number[];
  pid?: number | null;
  ppid?: number | null;
  session_id?: number | null;
  domain_or_mdm_joined?: boolean;
  browser?: string | null;
  extension_id?: string | null;
  force_installed?: boolean;
  install_source?: string | null;
  policy_key?: string | null;
  cert_thumbprint?: string | null;
  cert_store?: string | null;
  in_ms_root_list?: boolean;
  exclusion_type?: string | null;
  exclusion_value?: string | null;
  program_tag?: 'remote_access_tool' | 'bundleware' | null;
  program_tag_name?: string | null;
  install_date?: string | null;
  entry_created?: string | null;
  trace_source?: string | null;
  trace_paste_match?: boolean;
  hijack_type?: 'ifeo_debugger' | 'winlogon_shell' | 'winlogon_userinit' | 'appinit_dlls' | 'boot_execute' | 'active_setup' | 'shell_ext' | 'bho' | null;
  profile_sets_browser_or_net?: boolean;
  sip_enabled?: boolean | null;
  gatekeeper_enabled?: boolean | null;
  hosts_domain?: string | null;
  hosts_ip?: string | null;
  proxy_server?: string | null;
  proxy_pac_url?: string | null;
  dns_servers?: string[];
  [key: string]: unknown;
}

export interface UntrustedData {
  name?: string | null;
  description?: string | null;
  command_line?: string | null;
  publisher?: string | null;
  version?: string | null;
  subject?: string | null;
  issuer?: string | null;
  raw_value?: string | null;
  origin?: string | null;
  label?: string | null;
  [key: string]: string | null | undefined;
}

export interface RemediationMeta {
  registry_hive?: string;
  registry_key?: string;
  registry_value_name?: string;
  registry_default_value?: string;
  startup_file_path?: string;
  task_path?: string;
  task_name?: string;
  service_name?: string;
  service_start_mode?: string;
  service_state?: string;
  pid?: number;
  wmi_filter_name?: string;
  wmi_consumer_name?: string;
  wmi_consumer_class?: string;
  wmi_binding_path?: string;
  target_file_path?: string;
  browser?: string;
  profile_path?: string;
  preferences_path?: string;
  notification_origin?: string;
  extension_id?: string;
  extension_page_url?: string;
  policy_hive?: string;
  policy_key?: string;
  policy_value_name?: string;
  proxy_scope?: 'user' | 'winhttp';
  proxy_user_sid?: string;
  adapter_interface_alias?: string;
  hosts_line?: string;
  hosts_ip?: string;
  hosts_domain?: string;
  exclusion_type?: 'ExclusionPath' | 'ExclusionProcess' | 'ExclusionExtension' | 'ExclusionIpAddress';
  exclusion_value?: string;
  cert_store?: 'LocalMachine\\Root' | 'CurrentUser\\Root';
  cert_thumbprint?: string;
  uninstall_string?: string;
}

export interface CollectedItem {
  collector: string;
  kind: string;
  location: string;
  facts: FindingFacts;
  untrusted: UntrustedData;
  remediation_meta?: RemediationMeta;
  /** Internal non-untrusted command text inspected solely for deterministic LOLBin/paste pattern checks */
  command_inspect?: string | null;
}

export interface TriageApplied {
  verdict: 'benign' | 'suspicious' | 'malicious';
  confidence: 'low' | 'medium' | 'high';
  cited_facts: string[];
  reason: string;
  previous_tier: Tier;
  tier_changed: boolean;
  imported_at: string;
}

export interface Finding {
  id: string;
  collector: string;
  kind: string;
  location: string;
  facts: FindingFacts;
  untrusted: UntrustedData;
  signals: string[];
  score: number;
  tier: Tier;
  proposed_action: string;
  protected: boolean;
  protected_reason?: string;
  triage?: TriageApplied;
  remediation_meta?: RemediationMeta;
}

export interface AvProductInfo {
  display_name: string;
  product_state: number;
  enabled: boolean;
  up_to_date: boolean;
  path_to_signed_product_exe?: string | null;
  path_to_signed_reporting_exe?: string | null;
}

export interface DefenderStatusInfo {
  available: boolean;
  active: boolean;
  mode: 'active' | 'passive' | 'displaced' | 'disabled' | 'unavailable';
  realtime_enabled?: boolean | null;
  antispyware_enabled?: boolean | null;
  antivirus_enabled?: boolean | null;
  tamper_protected?: boolean | null;
  pua_protection?: number | string | null;
  signature_version?: string | null;
  signature_age_days?: number | null;
  engine_version?: string | null;
  service_status?: string | null;
  disabled_by_policy?: boolean;
  error?: string | null;
}

export interface PreflightResult {
  timestamp: string;
  tool_version: string;
  platform: PlatformKind;
  hostname: string;
  os_version: string;
  os_build: string;
  arch: string;
  elevated: boolean;
  pending_reboot: boolean;
  pending_reboot_reasons: string[];
  free_disk_bytes: number | null;
  domain_joined: boolean;
  mdm_enrolled: boolean;
  av_products: AvProductInfo[];
  defender: DefenderStatusInfo;
  collectors_requested: string[];
  collectors_skipped: Array<{ collector: string; reason: string }>;
  collectors_partial: Array<{ collector: string; reason: string }>;
  full_disk_access?: boolean | null;
  fda_guidance?: string | null;
  ransomware_indicators: string[];
}

export interface CollectorRunResult {
  collector: string;
  status: 'ok' | 'partial' | 'error' | 'skipped';
  duration_ms: number;
  item_count: number;
  items: CollectedItem[];
  warnings: string[];
  error?: string;
}

export interface Snapshot {
  session_id: string;
  timestamp: string;
  platform: PlatformKind;
  collectors: Record<
    string,
    {
      status: 'ok' | 'partial' | 'error' | 'skipped';
      duration_ms: number;
      item_count: number;
      warnings: string[];
      error?: string;
    }
  >;
  items: CollectedItem[];
}

export interface DefenderDetection {
  threat_id: string;
  threat_name: string;
  severity?: string | null;
  category?: string | null;
  resources: string[];
  action_taken?: string | null;
  detection_time?: string | null;
  source: 'defender' | 'safety_scanner';
}

export interface DefenderScanResult {
  timestamp: string;
  engine: 'defender' | 'safety_scanner' | 'skipped';
  scan_type: 'quick' | 'full' | 'offline' | 'none';
  signature_updated: boolean;
  signature_version?: string | null;
  status: 'ok' | 'skipped' | 'error';
  detections: DefenderDetection[];
  msert_path?: string | null;
  msert_signer?: string | null;
  msert_log?: string | null;
  error?: string | null;
}

export interface Advisory {
  kind: 'credential_theft' | 'remote_access_tool' | 'stop_condition' | 'full_disk_access' | 'reboot_required';
  severity: 'info' | 'warning' | 'critical';
  title: string;
  message: string;
  finding_ids: string[];
}

export interface StopCondition {
  kind: 'ransomware_detected' | 'repeated_resurrection' | 'defender_unrecoverable' | 'malicious_boot_driver';
  message: string;
  recommendation: string;
  evidence: string[];
}

export interface PlanItem {
  finding_id: string;
  collector: string;
  kind: string;
  location: string;
  tier: Tier;
  score: number;
  protected: boolean;
  actions: ActionType[];
  default_selected: boolean;
  approval_state: 'pending' | 'approved' | 'rejected' | 'skipped' | 'applied' | 'failed' | 'undone';
  proposed_action: string;
}

export interface Plan {
  session_id: string;
  created_at: string;
  updated_at: string;
  items: PlanItem[];
  advisories: Advisory[];
  stop_conditions: StopCondition[];
}

export interface InverseSpec {
  type: ActionType;
  reversible: boolean;
  description: string;
  backup_path?: string | null;
  backup_sha256?: string | null;
  params: Record<string, unknown>;
}

export interface ManifestEntry {
  action_id: string;
  finding_id: string;
  action: ActionType;
  location: string;
  timestamp: string;
  backup_path: string | null;
  backup_sha256: string | null;
  inverse: InverseSpec;
  status: 'pending' | 'succeeded' | 'failed' | 'skipped_backup_failed';
  error?: string | null;
  detail?: string | null;
  completed_at?: string | null;
  undo_status?: 'undone' | 'undo_failed' | 'not_reversible' | null;
  undo_at?: string | null;
  undo_error?: string | null;
}

export interface Manifest {
  session_id: string;
  created_at: string;
  restore_point?: {
    attempted: boolean;
    created: boolean;
    description?: string;
    message?: string;
    timestamp?: string;
  };
  entries: ManifestEntry[];
}

export interface VerifyItemStatus {
  finding_id: string;
  location: string;
  action: ActionType;
  status: 'clean' | 'resurrected' | 'still_present' | 'not_applicable';
  resurrection_count: number;
  evidence?: string;
}

export interface VerifyResult {
  session_id: string;
  verified_at: string;
  boot_time: string | null;
  post_reboot: boolean;
  reboot_required: boolean;
  items: VerifyItemStatus[];
  resurrected_count: number;
  stop_conditions: StopCondition[];
}

export interface HardenSettingRecord {
  id: string;
  name: string;
  status: 'applied' | 'skipped' | 'failed' | 'report_only' | 'reverted' | 'revert_failed';
  prior_value: unknown;
  new_value: unknown;
  backup_path?: string | null;
  message?: string;
  timestamp: string;
}

export interface HardenManifest {
  session_id: string;
  applied_at: string;
  reverted_at?: string | null;
  third_party_av_detected: boolean;
  av_names: string[];
  settings: HardenSettingRecord[];
}

export interface TriageBundleItem {
  id: string;
  collector: string;
  kind: string;
  location: string;
  tier: Tier;
  score: number;
  signals: string[];
  facts: FindingFacts;
  untrusted_machine_data: Record<string, string>;
}

export interface TriageRequest {
  schema_version: 1;
  session_id: string;
  exported_at: string;
  system_prompt: string;
  expected_response_schema: Record<string, unknown>;
  items: TriageBundleItem[];
}

export interface TriageVerdictInput {
  id: string;
  verdict: 'benign' | 'suspicious' | 'malicious';
  confidence: 'low' | 'medium' | 'high';
  cited_facts: string[];
  reason: string;
}

export interface TriageImportResult {
  session_id: string;
  imported_at: string;
  accepted: Array<{
    id: string;
    verdict: 'benign' | 'suspicious' | 'malicious';
    confidence: 'low' | 'medium' | 'high';
    cited_facts: string[];
    reason: string;
    previous_tier: Tier;
    new_tier: Tier;
    tier_changed: boolean;
    note?: string;
  }>;
  rejected: Array<{
    id: string | null;
    reason: string;
    raw?: unknown;
  }>;
}

export interface RulesConfig {
  schema_version: number;
  tiers: {
    clean_max: number;
    review_max: number;
    suspicious_max: number;
    malicious_min: number;
  };
  signals: Record<string, { weight: number; description: string }>;
  system_binary_names: string[];
  lolbins: string[];
  double_extension_decoys: string[];
  executable_extensions: string[];
  security_domains: string[];
  infostealer_patterns: string[];
}

export interface ProgramsCatalog {
  remote_access_tools: Array<{ id: string; name: string; patterns: string[] }>;
  bundleware: Array<{ id: string; name: string; patterns: string[] }>;
}

export interface MicrosoftRootsData {
  source: string;
  generated_at: string;
  count: number;
  thumbprints: string[];
  roots: Array<{ thumbprint: string; subject: string }>;
}

export type NdjsonEventType =
  | 'phase_start'
  | 'collector_done'
  | 'finding'
  | 'needs_approval'
  | 'action_start'
  | 'action_done'
  | 'advisory'
  | 'done';

export interface NdjsonEvent {
  event: NdjsonEventType;
  timestamp: string;
  session_id?: string;
  [key: string]: unknown;
}

export interface GlobalOptions {
  session?: string;
  json: boolean;
  sessionRoot?: string;
  only?: string[];
  since: number;
  quiet: boolean;
  rulesPath?: string;
  reportFormat: 'both' | 'html' | 'md';
  openReport: boolean;
  color?: boolean;
}
