/**
 * @module @arcis/node/validation/redirect
 * Open Redirect prevention
 *
 * Prevents attackers from using your app to redirect users to malicious sites
 * via manipulated query parameters like ?returnUrl=http://evil.com
 *
 * @example
 * import { validateRedirect, isRedirectSafe } from '@arcis/node';
 *
 * // Block open redirects
 * validateRedirect('http://evil.com')                    // { safe: false, reason: 'absolute URL not in allowed hosts' }
 * validateRedirect('//evil.com')                         // { safe: false, reason: 'protocol-relative URL not in allowed hosts' }
 * validateRedirect('javascript:alert(1)')                // { safe: false, reason: 'dangerous protocol: javascript:' }
 *
 * // Allow safe redirects
 * validateRedirect('/dashboard')                         // { safe: true }
 * validateRedirect('/users?page=2')                      // { safe: true }
 * validateRedirect('https://myapp.com/home', { allowedHosts: ['myapp.com'] })  // { safe: true }
 */

/** Options for redirect validation */
export interface ValidateRedirectOptions {
  /** Hostnames that are allowed for absolute URL redirects */
  allowedHosts?: string[];
  /** Allow protocol-relative URLs (//example.com). Default: false */
  allowProtocolRelative?: boolean;
  /** Allowed protocols for absolute URLs. Default: ['http:', 'https:'] */
  allowedProtocols?: string[];
}

/** Result of redirect validation */
export interface ValidateRedirectResult {
  /** Whether the redirect URL is safe */
  safe: boolean;
  /** Reason the redirect was blocked (only set when safe=false) */
  reason?: string;
}

/** Protocols that can execute code or exfiltrate data */
const DANGEROUS_PROTOCOLS = /^(javascript|data|vbscript|blob):/i;

/** Characters used to disguise URLs (tabs, newlines inside scheme) */
const CONTROL_CHARS = /[\t\n\r]/g;

/**
 * Validate a redirect URL to prevent open redirect attacks.
 *
 * Safe redirects:
 * - Relative paths: /dashboard, /users?page=2, ../settings
 * - Absolute URLs to allowed hosts (when configured)
 *
 * Blocked redirects:
 * - Absolute URLs to unknown hosts
 * - Protocol-relative URLs (//evil.com)
 * - javascript:, data:, vbscript:, blob: protocols
 * - Backslash-prefixed paths (\\evil.com — browser treats as //)
 * - URLs with control characters that could disguise the target
 *
 * @param url - The redirect target URL to validate
 * @param options - Validation options
 * @returns Validation result with safe flag and optional reason
 */
export function validateRedirect(
  url: string,
  options: ValidateRedirectOptions = {},
): ValidateRedirectResult {
  const {
    allowedHosts = [],
    allowProtocolRelative = false,
    allowedProtocols = ['http:', 'https:'],
  } = options;

  if (typeof url !== 'string' || url.trim() === '') {
    return { safe: false, reason: 'invalid redirect: empty or not a string' };
  }

  // Strip control characters that could disguise the URL
  const cleaned = url.replace(CONTROL_CHARS, '');

  // Block dangerous protocols (javascript:, data:, etc.)
  const proto = cleaned.match(DANGEROUS_PROTOCOLS);
  if (proto) {
    return { safe: false, reason: `dangerous protocol: ${proto[0]}` };
  }

  // Block backslash-prefixed paths — browsers treat \ as / in URLs
  // so \evil.com or \/evil.com could redirect to //evil.com
  if (cleaned.startsWith('\\')) {
    return { safe: false, reason: 'backslash-prefixed URL (browser treats as protocol-relative)' };
  }

  // Check protocol-relative URLs (//evil.com)
  if (cleaned.startsWith('//')) {
    if (!allowProtocolRelative) {
      // Still check allowedHosts
      const host = extractHost(cleaned);
      if (host && allowedHosts.some(h => host === h.toLowerCase())) {
        return { safe: true };
      }
      return { safe: false, reason: 'protocol-relative URL not in allowed hosts' };
    }
    const host = extractHost(cleaned);
    if (host && allowedHosts.length > 0 && !allowedHosts.some(h => host === h.toLowerCase())) {
      return { safe: false, reason: 'protocol-relative URL not in allowed hosts' };
    }
    return { safe: true };
  }

  // Check if it's an absolute URL (has scheme)
  let parsed: URL;
  try {
    parsed = new URL(cleaned);
  } catch {
    // Not a valid absolute URL — treat as relative path (safe)
    return { safe: true };
  }

  // If we got here, it parsed as an absolute URL
  // Check protocol
  if (!allowedProtocols.includes(parsed.protocol)) {
    return { safe: false, reason: `disallowed protocol: ${parsed.protocol}` };
  }

  // Check if host is in allowed list. Match against host:port form when
  // a non-default port is present, falling back to hostname only when
  // the URL uses a default port. parsed.port is "" for default ports
  // (80 for http, 443 for https), so hostWithPort equals hostname in
  // those cases. Non-default ports must be explicitly listed: a bare
  // 'myapp.com' entry does NOT permit redirects to 'myapp.com:9999'.
  const hostname = parsed.hostname.toLowerCase();
  const hostWithPort = parsed.port ? `${hostname}:${parsed.port}` : hostname;
  if (allowedHosts.length === 0) {
    return { safe: false, reason: 'absolute URL not in allowed hosts' };
  }

  if (!allowedHosts.some(h => h.toLowerCase() === hostWithPort)) {
    return { safe: false, reason: `host not allowed: ${hostWithPort}` };
  }

  return { safe: true };
}

/**
 * Convenience wrapper that returns true/false.
 *
 * @param url - The redirect URL to check
 * @param options - Validation options
 * @returns true if the redirect is safe
 */
export function isRedirectSafe(url: string, options: ValidateRedirectOptions = {}): boolean {
  return validateRedirect(url, options).safe;
}

/**
 * Extract host (with optional port) from a protocol-relative URL.
 * Returns hostname for default ports, "hostname:port" for non-default.
 * Optional userinfo (user:pass@) is stripped.
 */
function extractHost(url: string): string | null {
  // //user:pass@hostname/path  ->  authority = "user:pass@hostname"
  // //hostname:port/path       ->  authority = "hostname:port"
  const match = url.match(/^\/\/([^/?#]+)/);
  if (!match) return null;
  // Strip userinfo if present
  const authority = match[1].includes('@')
    ? match[1].slice(match[1].indexOf('@') + 1)
    : match[1];
  return authority.toLowerCase();
}
