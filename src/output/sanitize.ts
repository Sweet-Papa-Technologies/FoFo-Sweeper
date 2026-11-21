import { UNTRUSTED_MAX_CHARS } from '../constants.js';

/**
 * Strips ASCII control characters (including CR/LF/TAB -> space), DEL, C1 controls,
 * zero-width characters, soft hyphens, and Unicode bidirectional override/isolate controls
 * that attackers use for filename/prompt spoofing.
 */
const CONTROL_AND_BIDI_RE =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u00AD\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g;

export function sanitizeUntrusted(
  value: string | null | undefined,
  maxLen: number = UNTRUSTED_MAX_CHARS
): string {
  if (value == null) return '';
  let cleaned = String(value)
    .replace(/\r\n|\r|\n|\t/g, ' ')
    .replace(CONTROL_AND_BIDI_RE, '')
    .replace(/\s{2,}/g, ' ')
    .trim();

  if (cleaned.length > maxLen) {
    cleaned = cleaned.slice(0, Math.max(0, maxLen - 1)) + '…';
  }
  return cleaned;
}

export function sanitizeUntrustedRecord(
  record: Record<string, string | null | undefined>,
  maxLen: number = UNTRUSTED_MAX_CHARS
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(record)) {
    if (v === null || v === undefined) continue;
    const s = sanitizeUntrusted(v, maxLen);
    if (s.length > 0) {
      out[k] = s;
    }
  }
  return out;
}

/**
 * Renders an untrusted string safely as inline Markdown code, escaping any backticks
 * and preventing markdown injection or multi-line layout breaks.
 */
export function formatUntrustedCode(
  value: string | null | undefined,
  maxLen: number = 180
): string {
  const s = sanitizeUntrusted(value, maxLen);
  if (!s) return '`—`';
  // Choose a backtick fence longer than any run of backticks inside s
  let maxTicks = 0;
  for (const m of s.matchAll(/`+/g)) {
    if (m[0].length > maxTicks) maxTicks = m[0].length;
  }
  const fence = '`'.repeat(maxTicks + 1);
  const needsPad = s.startsWith('`') || s.endsWith('`');
  return needsPad ? `${fence} ${s} ${fence}` : `${fence}${s}${fence}`;
}
