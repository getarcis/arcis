/**
 * @module @arcis/node/validation/email
 * Advanced email validation with disposable detection and typo suggestions.
 *
 * Three levels of validation:
 * 1. Syntax — RFC-compliant format checking
 * 2. Domain intelligence — disposable/free provider detection, typo correction
 * 3. MX verification — DNS MX record lookup (async, optional)
 *
 * @example
 * const result = validateEmail('user@tempmail.com');
 * // { valid: false, reason: 'disposable' }
 *
 * const result = validateEmail('user@gmial.com');
 * // { valid: true, reason: 'typo', suggestion: 'user@gmail.com' }
 */

import { promises as dns } from 'dns';

export interface EmailValidationOptions {
  /** Check for disposable email providers. Default: true */
  checkDisposable?: boolean;
  /** Suggest corrections for typos. Default: true */
  suggestTypoFix?: boolean;
  /** Verify MX records via DNS. Default: false */
  checkMx?: boolean;
  /** Additional blocked domains */
  blockedDomains?: string[];
  /** Additional allowed domains (bypasses disposable check) */
  allowedDomains?: string[];
}

export interface EmailValidationResult {
  /** Whether the email is valid */
  valid: boolean;
  /** Reason for the result */
  reason: 'valid' | 'invalid_syntax' | 'disposable' | 'no_mx' | 'blocked' | 'typo';
  /** Suggested correction if a typo was detected */
  suggestion: string | null;
  /** Whether the domain is a free email provider */
  isFree: boolean;
  /** Whether the domain is a disposable email provider */
  isDisposable: boolean;
  /** The normalized email address */
  normalized: string;
}

// RFC 5321: local part max 64, domain max 255, total max 254
const MAX_EMAIL_LENGTH = 254;
const MAX_LOCAL_LENGTH = 64;
const MAX_DOMAIN_LENGTH = 255;

/**
 * Strict email syntax regex.
 * - No consecutive dots in local part
 * - No leading/trailing dots in local part
 * - Domain must have at least one dot
 * - No spaces anywhere
 */
const EMAIL_SYNTAX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;

/** Common free email providers */
const FREE_PROVIDERS = new Set([
  'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
  'protonmail.com', 'proton.me', 'icloud.com', 'mail.com', 'zoho.com',
  'yandex.com', 'gmx.com', 'gmx.net', 'live.com', 'msn.com',
  'me.com', 'mac.com', 'fastmail.com', 'tutanota.com', 'hey.com',
]);

/** Common disposable email domains */
const DISPOSABLE_DOMAINS = new Set([
  // Popular disposable services
  'guerrillamail.com', 'guerrillamail.net', 'guerrillamail.org',
  'tempmail.com', 'temp-mail.org', 'temp-mail.io',
  'throwaway.email', 'throwaway.com',
  'mailinator.com', 'mailinator.net',
  'yopmail.com', 'yopmail.fr', 'yopmail.net',
  'sharklasers.com', 'grr.la', 'guerrillamail.info',
  'guerrillamail.biz', 'guerrillamail.de',
  'trashmail.com', 'trashmail.me', 'trashmail.net',
  'dispostable.com', 'maildrop.cc',
  'mailnesia.com', 'tempail.com',
  'mohmal.com', 'getnada.com',
  'emailondeck.com', 'discard.email',
  'fakeinbox.com', 'mailcatch.com',
  'mintemail.com', 'tempr.email',
  'tempinbox.com', 'burnermail.io',
  'mailsac.com', 'harakirimail.com',
  'tempmailo.com', 'emailfake.com',
  'crazymailing.com', 'armyspy.com',
  'dayrep.com', 'einrot.com',
  'fleckens.hu', 'gustr.com',
  'jourrapide.com', 'rhyta.com',
  'superrito.com', 'teleworm.us',
  '10minutemail.com', '10minutemail.net',
  'minutemail.com', 'tempsky.com',
  'spamgourmet.com', 'mytrashmail.com',
  'mailexpire.com', 'safetymail.info',
  'filzmail.com', 'trashymail.com',
  'sharkmail.com', 'jetable.org',
  'nospam.ze.tc', 'trash-me.com',
  'dodgit.com', 'mailmoat.com',
  'spamfree24.org', 'incognitomail.org',
  'tempomail.fr', 'ephemail.net',
  'hidemail.de', 'spaml.de',
  'uggsrock.com', 'binkmail.com',
  'suremail.info', 'bugmenot.com',
]);

/** Common typos and their corrections */
const DOMAIN_TYPOS: Record<string, string> = {
  'gmial.com': 'gmail.com',
  'gmaill.com': 'gmail.com',
  'gmai.com': 'gmail.com',
  'gamil.com': 'gmail.com',
  'gnail.com': 'gmail.com',
  'gmal.com': 'gmail.com',
  'gmil.com': 'gmail.com',
  'gmail.co': 'gmail.com',
  'gmail.cm': 'gmail.com',
  'gmail.om': 'gmail.com',
  'gmail.con': 'gmail.com',
  'gmail.cim': 'gmail.com',
  'gmail.comm': 'gmail.com',
  'yahooo.com': 'yahoo.com',
  'yaho.com': 'yahoo.com',
  'yahoo.co': 'yahoo.com',
  'yahoo.cm': 'yahoo.com',
  'yahoo.con': 'yahoo.com',
  'yahho.com': 'yahoo.com',
  'hotmial.com': 'hotmail.com',
  'hotmal.com': 'hotmail.com',
  'hotmai.com': 'hotmail.com',
  'hotmil.com': 'hotmail.com',
  'hotmail.co': 'hotmail.com',
  'hotmail.cm': 'hotmail.com',
  'hotmail.con': 'hotmail.com',
  'outlok.com': 'outlook.com',
  'outloo.com': 'outlook.com',
  'outlook.co': 'outlook.com',
  'outlook.cm': 'outlook.com',
  'protonmal.com': 'protonmail.com',
  'protonmail.co': 'protonmail.com',
  'icloud.co': 'icloud.com',
  'icloud.cm': 'icloud.com',
  'icoud.com': 'icloud.com',
};

function invalidResult(reason: EmailValidationResult['reason'], email: string): EmailValidationResult {
  return {
    valid: false,
    reason,
    suggestion: null,
    isFree: false,
    isDisposable: false,
    normalized: email,
  };
}

/**
 * Validate an email address with syntax checking, disposable detection,
 * and typo suggestions.
 *
 * @param email - Email address to validate
 * @param options - Validation options
 * @returns Validation result
 *
 * @example
 * validateEmail('user@gmail.com')
 * // { valid: true, reason: 'valid', isFree: true }
 *
 * validateEmail('user@tempmail.com')
 * // { valid: false, reason: 'disposable' }
 *
 * validateEmail('user@gmial.com')
 * // { valid: true, reason: 'typo', suggestion: 'user@gmail.com' }
 */
export function validateEmail(
  email: string,
  options: EmailValidationOptions = {}
): EmailValidationResult {
  const {
    checkDisposable = true,
    suggestTypoFix = true,
    blockedDomains = [],
    allowedDomains = [],
  } = options;

  // Normalize
  const normalized = email.trim().toLowerCase();

  // Basic checks
  if (!normalized || normalized.length > MAX_EMAIL_LENGTH) {
    return invalidResult('invalid_syntax', normalized);
  }

  const atIndex = normalized.lastIndexOf('@');
  if (atIndex === -1) {
    return invalidResult('invalid_syntax', normalized);
  }

  const localPart = normalized.slice(0, atIndex);
  const domain = normalized.slice(atIndex + 1);

  // Length checks
  if (localPart.length === 0 || localPart.length > MAX_LOCAL_LENGTH) {
    return invalidResult('invalid_syntax', normalized);
  }
  if (domain.length === 0 || domain.length > MAX_DOMAIN_LENGTH) {
    return invalidResult('invalid_syntax', normalized);
  }

  // Consecutive dots in local part
  if (localPart.includes('..')) {
    return invalidResult('invalid_syntax', normalized);
  }

  // Leading/trailing dots in local part
  if (localPart.startsWith('.') || localPart.endsWith('.')) {
    return invalidResult('invalid_syntax', normalized);
  }

  // Full regex validation
  if (!EMAIL_SYNTAX.test(normalized)) {
    return invalidResult('invalid_syntax', normalized);
  }

  // Check if domain is explicitly allowed (bypass other checks)
  const allowedSet = new Set(allowedDomains.map(d => d.toLowerCase()));
  if (allowedSet.has(domain)) {
    return {
      valid: true,
      reason: 'valid',
      suggestion: null,
      isFree: FREE_PROVIDERS.has(domain),
      isDisposable: false,
      normalized,
    };
  }

  // Check blocked domains
  const blockedSet = new Set(blockedDomains.map(d => d.toLowerCase()));
  if (blockedSet.has(domain)) {
    return invalidResult('blocked', normalized);
  }

  // Check disposable
  const isDisposable = DISPOSABLE_DOMAINS.has(domain);
  if (checkDisposable && isDisposable) {
    return {
      valid: false,
      reason: 'disposable',
      suggestion: null,
      isFree: false,
      isDisposable: true,
      normalized,
    };
  }

  // Check typos
  const isFree = FREE_PROVIDERS.has(domain);
  if (suggestTypoFix && DOMAIN_TYPOS[domain]) {
    const corrected = `${localPart}@${DOMAIN_TYPOS[domain]}`;
    return {
      valid: true,
      reason: 'typo',
      suggestion: corrected,
      isFree: FREE_PROVIDERS.has(DOMAIN_TYPOS[domain]),
      isDisposable: false,
      normalized,
    };
  }

  return {
    valid: true,
    reason: 'valid',
    suggestion: null,
    isFree,
    isDisposable,
    normalized,
  };
}

/**
 * Verify that the email domain has MX records (can receive email).
 *
 * This performs a DNS lookup and requires network access.
 * Use for registration flows where you need high confidence.
 *
 * @param email - Email address to verify
 * @returns True if the domain has MX records
 *
 * @example
 * if (await verifyEmailMx('user@example.com')) {
 *   // Domain can receive email
 * }
 */
export async function verifyEmailMx(email: string): Promise<boolean> {
  if (!isValidEmailSyntax(email)) return false;

  const atIndex = email.lastIndexOf('@');
  const domain = email.slice(atIndex + 1).trim().toLowerCase();
  if (!domain) return false;

  try {
    const records = await dns.resolveMx(domain);
    return records.length > 0;
  } catch {
    return false;
  }
}

/**
 * Quick check if an email address has valid syntax.
 * Faster than validateEmail() — just syntax, no domain intelligence.
 */
export function isValidEmailSyntax(email: string): boolean {
  const normalized = email.trim().toLowerCase();
  if (!normalized || normalized.length > MAX_EMAIL_LENGTH) return false;

  const atIndex = normalized.lastIndexOf('@');
  if (atIndex === -1) return false;

  const localPart = normalized.slice(0, atIndex);
  if (localPart.includes('..') || localPart.startsWith('.') || localPart.endsWith('.')) return false;

  return EMAIL_SYNTAX.test(normalized);
}
