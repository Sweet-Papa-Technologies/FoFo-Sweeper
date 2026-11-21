declare const __FCSWEEP_VERSION__: string | undefined;

export const VERSION: string =
  typeof __FCSWEEP_VERSION__ !== 'undefined' ? __FCSWEEP_VERSION__ : '0.1.0';

export const EXIT_CODES = {
  OK: 0,
  ERROR: 1,
  FINDINGS_NEED_REVIEW: 2,
  ELEVATION_REQUIRED: 3,
  REBOOT_REQUIRED: 4,
  PARTIAL_FAILURE: 5,
  STOP_CONDITION: 6,
} as const;

export type ExitCode = (typeof EXIT_CODES)[keyof typeof EXIT_CODES];

export const DEFAULT_SINCE_DAYS = 30;
export const SESSION_RETENTION_DAYS = 30;
export const UNTRUSTED_MAX_CHARS = 300;
export const TRIAGE_REASON_MAX_CHARS = 200;

export const COLLECTOR_TIMEOUTS_MS: Record<string, number> = {
  default: 60_000,
  processes: 180_000,
  browsers: 180_000,
};

export const WINDOWS_COLLECTORS = [
  'autoruns',
  'tasks',
  'services',
  'wmi',
  'hijacks',
  'processes',
  'network',
  'certs',
  'defender',
  'browsers',
  'programs',
  'traces',
] as const;

export const MACOS_COLLECTORS = [
  'launch_items',
  'login_items',
  'profiles',
  'browsers',
  'network',
  'cron',
  'posture',
] as const;

export const ASR_RULES = [
  {
    id: '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC',
    name: 'Block execution of potentially obfuscated scripts',
  },
  {
    id: 'D3E037E1-3EB8-44C8-A917-57927947596D',
    name: 'Block JavaScript or VBScript from launching downloaded executable content',
  },
  {
    id: 'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550',
    name: 'Block executable content from email client and webmail',
  },
  {
    id: 'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4',
    name: 'Block untrusted and unsigned processes that run from USB',
  },
] as const;

export const MSERT_DOWNLOAD_URL = 'https://go.microsoft.com/fwlink/?LinkId=212732';
