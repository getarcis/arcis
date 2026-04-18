/**
 * @module @arcis/node/validation/url
 * SSRF (Server-Side Request Forgery) prevention
 *
 * Validates URLs to ensure they don't target private/internal networks,
 * localhost, cloud metadata endpoints, or use dangerous protocols.
 *
 * @example
 * import { validateUrl } from '@arcis/node';
 *
 * // Block SSRF attempts
 * validateUrl('http://169.254.169.254/latest/meta-data/')  // { safe: false, reason: 'link-local address' }
 * validateUrl('http://10.0.0.1/admin')                     // { safe: false, reason: 'private address (10.0.0.0/8)' }
 * validateUrl('http://localhost/secret')                    // { safe: false, reason: 'loopback address' }
 * validateUrl('file:///etc/passwd')                         // { safe: false, reason: 'disallowed protocol: file:' }
 *
 * // Allow safe URLs
 * validateUrl('https://api.example.com/data')               // { safe: true }
 */

/** Options for URL validation */
export interface ValidateUrlOptions {
  /** Allowed protocols. Default: ['http:', 'https:'] */
  allowedProtocols?: string[];
  /** Additional hostnames to block (e.g., internal service names) */
  blockedHosts?: string[];
  /** Additional hostnames to always allow (bypass IP checks) */
  allowedHosts?: string[];
  /** Allow localhost/loopback. Default: false */
  allowLocalhost?: boolean;
  /** Allow private/internal IPs. Default: false */
  allowPrivate?: boolean;
}

/** Result of URL validation */
export interface ValidateUrlResult {
  /** Whether the URL is safe to fetch */
  safe: boolean;
  /** Reason the URL was blocked (only set when safe=false) */
  reason?: string;
}

/**
 * Validate a URL for SSRF safety.
 *
 * Checks:
 * 1. Valid URL format
 * 2. Allowed protocol (default: http, https only)
 * 3. Not localhost/loopback (127.x.x.x, ::1, localhost)
 * 4. Not private IP (10.x, 172.16-31.x, 192.168.x)
 * 5. Not link-local (169.254.x.x — includes AWS/GCP/Azure metadata)
 * 6. Not blocked hostname
 * 7. No credentials in URL (user:pass@host)
 *
 * @param url - The URL string to validate
 * @param options - Validation options
 * @returns Validation result with safe flag and optional reason
 */
export function validateUrl(url: string, options: ValidateUrlOptions = {}): ValidateUrlResult {
  const {
    allowedProtocols = ['http:', 'https:'],
    blockedHosts = [],
    allowedHosts = [],
    allowLocalhost = false,
    allowPrivate = false,
  } = options;

  if (typeof url !== 'string' || url.trim() === '') {
    return { safe: false, reason: 'invalid URL: empty or not a string' };
  }

  // Parse URL
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { safe: false, reason: 'invalid URL: failed to parse' };
  }

  // Check protocol
  if (!allowedProtocols.includes(parsed.protocol)) {
    return { safe: false, reason: `disallowed protocol: ${parsed.protocol}` };
  }

  // Check for credentials in URL (user:pass@host)
  if (parsed.username || parsed.password) {
    return { safe: false, reason: 'URL contains credentials' };
  }

  const hostname = parsed.hostname.toLowerCase();

  // Check explicit allowlist first (bypass IP checks)
  if (allowedHosts.some(h => hostname === h.toLowerCase())) {
    return { safe: true };
  }

  // Check explicit blocklist
  if (blockedHosts.some(h => hostname === h.toLowerCase())) {
    return { safe: false, reason: `blocked host: ${hostname}` };
  }

  // Check localhost/loopback
  if (!allowLocalhost) {
    if (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === '[::1]' ||
      hostname === '::1' ||
      hostname === '0.0.0.0' ||
      hostname.endsWith('.localhost')
    ) {
      return { safe: false, reason: 'loopback address' };
    }

    // Check 127.x.x.x range
    if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      return { safe: false, reason: 'loopback address' };
    }
  }

  // Check decimal IP (e.g., 2130706433 = 127.0.0.1)
  if (!allowLocalhost || !allowPrivate) {
    const decimalCheck = checkDecimalIp(hostname, allowLocalhost, allowPrivate);
    if (decimalCheck) {
      return { safe: false, reason: decimalCheck };
    }
  }

  // Check octal IP (e.g., 0177.0.0.1 = 127.0.0.1)
  if (!allowLocalhost || !allowPrivate) {
    const octalCheck = checkOctalIp(hostname, allowLocalhost, allowPrivate);
    if (octalCheck) {
      return { safe: false, reason: octalCheck };
    }
  }

  // Check private/internal IPs
  if (!allowPrivate) {
    const privateCheck = checkPrivateIp(hostname);
    if (privateCheck) {
      return { safe: false, reason: privateCheck };
    }
  }

  return { safe: true };
}

/**
 * Convenience wrapper that returns true/false.
 *
 * @param url - The URL to check
 * @param options - Validation options
 * @returns true if the URL is safe to fetch
 */
export function isUrlSafe(url: string, options: ValidateUrlOptions = {}): boolean {
  return validateUrl(url, options).safe;
}

/**
 * Check if a hostname is a private/internal IP address.
 * Returns the reason string if private, or null if not.
 */
function checkPrivateIp(hostname: string): string | null {
  // 10.0.0.0/8
  if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
    return 'private address (10.0.0.0/8)';
  }

  // 172.16.0.0/12 (172.16.x.x - 172.31.x.x)
  const match172 = hostname.match(/^172\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/);
  if (match172) {
    const second = parseInt(match172[1], 10);
    if (second >= 16 && second <= 31) {
      return 'private address (172.16.0.0/12)';
    }
  }

  // 192.168.0.0/16
  if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
    return 'private address (192.168.0.0/16)';
  }

  // 169.254.0.0/16 — link-local, includes cloud metadata endpoints
  // AWS: 169.254.169.254, GCP: metadata.google.internal, Azure: 169.254.169.254
  if (/^169\.254\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
    return 'link-local address (169.254.0.0/16)';
  }

  // 0.0.0.0/8 (current network)
  if (/^0\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
    return 'current network address (0.0.0.0/8)';
  }

  // Cloud metadata hostnames
  if (
    hostname === 'metadata.google.internal' ||
    hostname === 'metadata.internal' ||
    hostname === 'metadata.azure.internal'
  ) {
    return 'cloud metadata endpoint';
  }

  // IPv6 private ranges (bracket-wrapped in URLs)
  let ipv6 = hostname.replace(/^\[|\]$/g, '');
  // Strip zone ID (e.g., ::1%eth0 → ::1)
  const zoneIdx = ipv6.indexOf('%');
  if (zoneIdx !== -1) {
    ipv6 = ipv6.slice(0, zoneIdx);
  }
  if (
    ipv6 === '::1' ||
    ipv6 === '::' ||
    /^fc[0-9a-f]{2}:/i.test(ipv6) ||
    /^fd[0-9a-f]{2}:/i.test(ipv6) ||
    /^fe80:/i.test(ipv6) ||
    /^ff[0-9a-f]{2}:/i.test(ipv6)  // IPv6 multicast (ff00::/8)
  ) {
    return 'private IPv6 address';
  }

  // IPv6-mapped IPv4 — dotted form (::ffff:127.0.0.1)
  const mappedDotted = ipv6.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i);
  if (mappedDotted) {
    const mappedIp = mappedDotted[1];
    if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(mappedIp)) {
      return 'IPv6-mapped loopback address';
    }
    const mappedCheck = checkPrivateIp(mappedIp);
    if (mappedCheck) {
      return `IPv6-mapped ${mappedCheck}`;
    }
  }

  // IPv6-mapped IPv4 — hex form (::ffff:7f00:1 = 127.0.0.1)
  // Node's URL parser normalizes ::ffff:a.b.c.d to ::ffff:XXYY:ZZWW
  const mappedHex = ipv6.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
  if (mappedHex) {
    const hi = parseInt(mappedHex[1], 16);
    const lo = parseInt(mappedHex[2], 16);
    const a = (hi >> 8) & 0xFF;
    const b = hi & 0xFF;
    const c = (lo >> 8) & 0xFF;
    const d = lo & 0xFF;
    const dotted = `${a}.${b}.${c}.${d}`;
    if (a === 127) {
      return 'IPv6-mapped loopback address';
    }
    const hexCheck = checkPrivateIp(dotted);
    if (hexCheck) {
      return `IPv6-mapped ${hexCheck}`;
    }
  }

  return null;
}

/**
 * Parse a decimal integer as an IPv4 address and check if it's private/loopback.
 * e.g., 2130706433 = 127.0.0.1, 167772160 = 10.0.0.0
 */
function checkDecimalIp(hostname: string, allowLocalhost: boolean, allowPrivate: boolean): string | null {
  // Must be a pure decimal integer
  if (!/^\d+$/.test(hostname)) return null;

  const num = parseInt(hostname, 10);
  if (isNaN(num) || num < 0 || num > 0xFFFFFFFF) return null;

  const a = (num >>> 24) & 0xFF;
  const b = (num >>> 16) & 0xFF;
  const c = (num >>> 8) & 0xFF;
  const d = num & 0xFF;
  const dotted = `${a}.${b}.${c}.${d}`;

  // Check loopback
  if (!allowLocalhost && a === 127) {
    return `loopback address (decimal IP: ${dotted})`;
  }

  // Check private ranges
  if (!allowPrivate) {
    const privateCheck = checkPrivateIp(dotted);
    if (privateCheck) {
      return `${privateCheck} (decimal IP: ${dotted})`;
    }
  }

  return null;
}

/**
 * Parse octal-notation IPv4 address and check if it's private/loopback.
 * e.g., 0177.0.0.1 = 127.0.0.1, 0x7f.0.0.1 = 127.0.0.1
 */
function checkOctalIp(hostname: string, allowLocalhost: boolean, allowPrivate: boolean): string | null {
  // Must look like a dotted quad where at least one octet has a leading zero or 0x prefix
  const parts = hostname.split('.');
  if (parts.length !== 4) return null;

  // Check if any part uses octal (leading 0) or hex (0x) notation
  const hasAlternateNotation = parts.some(p => /^0[0-7]+$/.test(p) || /^0x[0-9a-fA-F]+$/i.test(p));
  if (!hasAlternateNotation) return null;

  const octets: number[] = [];
  for (const part of parts) {
    let val: number;
    if (/^0x[0-9a-fA-F]+$/i.test(part)) {
      val = parseInt(part, 16);
    } else if (/^0[0-7]*$/.test(part)) {
      val = parseInt(part, 8);
    } else if (/^\d+$/.test(part)) {
      val = parseInt(part, 10);
    } else {
      return null;
    }
    if (val < 0 || val > 255) return null;
    octets.push(val);
  }

  const dotted = octets.join('.');

  // Check loopback
  if (!allowLocalhost && octets[0] === 127) {
    return `loopback address (octal IP: ${dotted})`;
  }

  // Check private ranges
  if (!allowPrivate) {
    const privateCheck = checkPrivateIp(dotted);
    if (privateCheck) {
      return `${privateCheck} (octal IP: ${dotted})`;
    }
  }

  return null;
}
