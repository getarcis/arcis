/**
 * @module @arcis/node/sanitizers/pii
 * PII (Personally Identifiable Information) detection and redaction
 *
 * Detects: email addresses, phone numbers, credit card numbers, SSNs, IP addresses
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export type PiiType = 'email' | 'phone' | 'credit_card' | 'ssn' | 'ip_address';

export interface PiiMatch {
  type: PiiType;
  value: string;
  start: number;
  end: number;
}

export interface PiiScanOptions {
  /** PII types to scan for. Default: all types */
  types?: PiiType[];
}

export interface PiiRedactOptions extends PiiScanOptions {
  /** Replacement for redacted values. Default: '[REDACTED]' */
  replacement?: string;
  /** Use type-specific replacements like '[EMAIL]', '[SSN]'. Default: false */
  typeLabels?: boolean;
}

// ─── Patterns ────────────────────────────────────────────────────────────────

// Email: simplified RFC 5322 — catches real-world emails without ReDoS risk
const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+/g;

// US phone numbers: (xxx) xxx-xxxx, xxx-xxx-xxxx, xxx.xxx.xxxx, xxx xxx xxxx, +1xxxxxxxxxx
const PHONE_RE = /(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g;

// Credit cards: 13-19 digits with optional separators (spaces or dashes)
const CREDIT_CARD_RE = /\b(?:\d[ -]*?){13,19}\b/g;

// SSN: XXX-XX-XXXX (with dashes or spaces)
const SSN_RE = /\b\d{3}[-\s]\d{2}[-\s]\d{4}\b/g;

// IPv4 addresses
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;

// IPv6 addresses (simplified — full addresses and common abbreviations)
const IPV6_RE = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b/g;

const PATTERN_MAP: Record<PiiType, RegExp[]> = {
  email: [EMAIL_RE],
  phone: [PHONE_RE],
  credit_card: [CREDIT_CARD_RE],
  ssn: [SSN_RE],
  ip_address: [IPV4_RE, IPV6_RE],
};

const ALL_TYPES: PiiType[] = ['email', 'phone', 'credit_card', 'ssn', 'ip_address'];

const TYPE_LABELS: Record<PiiType, string> = {
  email: '[EMAIL]',
  phone: '[PHONE]',
  credit_card: '[CREDIT_CARD]',
  ssn: '[SSN]',
  ip_address: '[IP_ADDRESS]',
};

// ─── Luhn Check ──────────────────────────────────────────────────────────────

/**
 * Validate a credit card number using the Luhn algorithm.
 * Strips spaces and dashes before checking.
 */
function luhnCheck(value: string): boolean {
  const digits = value.replace(/[\s-]/g, '');
  if (!/^\d{13,19}$/.test(digits)) return false;

  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

// ─── Core Functions ──────────────────────────────────────────────────────────

/**
 * Scan a string for PII and return all matches.
 *
 * @param input - String to scan
 * @param options - Optional scan configuration
 * @returns Array of PII matches with type, value, and position
 *
 * @example
 * scanPii('Call me at 555-123-4567 or email john@example.com')
 * // [
 * //   { type: 'phone', value: '555-123-4567', start: 11, end: 23 },
 * //   { type: 'email', value: 'john@example.com', start: 33, end: 49 }
 * // ]
 */
export function scanPii(input: string, options: PiiScanOptions = {}): PiiMatch[] {
  if (!input || typeof input !== 'string') return [];

  const types = options.types ?? ALL_TYPES;
  const matches: PiiMatch[] = [];

  for (const type of types) {
    const patterns = PATTERN_MAP[type];
    if (!patterns) continue;

    for (const pattern of patterns) {
      const re = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = re.exec(input)) !== null) {
        const value = match[0];

        // Credit card: validate with Luhn algorithm
        if (type === 'credit_card' && !luhnCheck(value)) continue;

        // SSN: reject invalid ranges (000, 666, 900-999 for area)
        if (type === 'ssn') {
          const area = parseInt(value.substring(0, 3), 10);
          if (area === 0 || area === 666 || area >= 900) continue;
        }

        matches.push({
          type,
          value,
          start: match.index,
          end: match.index + value.length,
        });
      }
    }
  }

  // Sort by position
  matches.sort((a, b) => a.start - b.start);
  return matches;
}

/**
 * Check if a string contains any PII.
 *
 * @param input - String to check
 * @param options - Optional scan configuration
 * @returns true if PII is detected
 */
export function detectPii(input: string, options: PiiScanOptions = {}): boolean {
  return scanPii(input, options).length > 0;
}

/**
 * Redact PII from a string, replacing matches with a placeholder.
 *
 * @param input - String to redact
 * @param options - Redaction options
 * @returns String with PII replaced
 *
 * @example
 * redactPii('Email: john@example.com, SSN: 123-45-6789')
 * // 'Email: [REDACTED], SSN: [REDACTED]'
 *
 * redactPii('Email: john@example.com', { typeLabels: true })
 * // 'Email: [EMAIL]'
 */
export function redactPii(input: string, options: PiiRedactOptions = {}): string {
  if (!input || typeof input !== 'string') return input;

  const matches = scanPii(input, options);
  if (matches.length === 0) return input;

  const replacement = options.replacement ?? '[REDACTED]';

  // Replace from end to preserve positions
  let result = input;
  for (let i = matches.length - 1; i >= 0; i--) {
    const m = matches[i];
    const label = options.typeLabels ? TYPE_LABELS[m.type] : replacement;
    result = result.substring(0, m.start) + label + result.substring(m.end);
  }

  return result;
}

/**
 * Scan an object's string values for PII recursively.
 *
 * @param obj - Object to scan
 * @param options - Optional scan configuration
 * @returns Array of PII matches with the field path prepended
 */
export function scanObjectPii(
  obj: Record<string, unknown>,
  options: PiiScanOptions = {},
  path = '',
): (PiiMatch & { field: string })[] {
  const results: (PiiMatch & { field: string })[] = [];
  if (!obj || typeof obj !== 'object') return results;

  for (const [key, value] of Object.entries(obj)) {
    const fieldPath = path ? `${path}.${key}` : key;

    if (typeof value === 'string') {
      const matches = scanPii(value, options);
      for (const m of matches) {
        results.push({ ...m, field: fieldPath });
      }
    } else if (value && typeof value === 'object' && !Array.isArray(value)) {
      results.push(...scanObjectPii(value as Record<string, unknown>, options, fieldPath));
    } else if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        const item = value[i];
        if (typeof item === 'string') {
          const matches = scanPii(item, options);
          for (const m of matches) {
            results.push({ ...m, field: `${fieldPath}[${i}]` });
          }
        } else if (item && typeof item === 'object') {
          results.push(...scanObjectPii(item as Record<string, unknown>, options, `${fieldPath}[${i}]`));
        }
      }
    }
  }

  return results;
}

/**
 * Redact PII from all string values in an object recursively.
 *
 * @param obj - Object to redact
 * @param options - Redaction options
 * @returns New object with PII redacted
 */
export function redactObjectPii<T extends Record<string, unknown>>(
  obj: T,
  options: PiiRedactOptions = {},
): T {
  if (!obj || typeof obj !== 'object') return obj;

  const result: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === 'string') {
      result[key] = redactPii(value, options);
    } else if (Array.isArray(value)) {
      result[key] = value.map(item => {
        if (typeof item === 'string') return redactPii(item, options);
        if (item && typeof item === 'object') return redactObjectPii(item as Record<string, unknown>, options);
        return item;
      });
    } else if (value && typeof value === 'object') {
      result[key] = redactObjectPii(value as Record<string, unknown>, options);
    } else {
      result[key] = value;
    }
  }

  return result as T;
}
