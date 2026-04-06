/**
 * @module @arcis/node/utils/fingerprint
 * Deterministic request fingerprinting via SHA-256.
 *
 * Generates a stable hash from request characteristics for
 * rate limiting keys, abuse detection, and analytics.
 *
 * @example
 * const fp = await fingerprint(req);
 * // "a3f2b8c1d4e5..."
 */

import { createHash } from 'crypto';
import { detectClientIp } from './ip';
import type { DetectIpOptions } from './ip';

export interface FingerprintOptions {
  /** Include IP address in fingerprint. Default: true */
  ip?: boolean;
  /** Include User-Agent header. Default: true */
  userAgent?: boolean;
  /** Include Accept header. Default: true */
  accept?: boolean;
  /** Include Accept-Language header. Default: true */
  acceptLanguage?: boolean;
  /** Include Accept-Encoding header. Default: true */
  acceptEncoding?: boolean;
  /** Additional custom components to include */
  custom?: string[];
  /** IP detection options */
  ipOptions?: DetectIpOptions;
}

interface RequestLike {
  headers: Record<string, string | string[] | undefined>;
  socket?: { remoteAddress?: string };
  connection?: { remoteAddress?: string };
  ip?: string;
}

function getHeader(req: RequestLike, name: string): string {
  const val = req.headers[name];
  if (Array.isArray(val)) return val[0] ?? '';
  return val ?? '';
}

/**
 * Generate a deterministic fingerprint for a request.
 *
 * Creates a SHA-256 hash from configurable request components.
 * The fingerprint is stable across requests from the same client
 * (same IP, browser, language settings).
 *
 * @param req - HTTP request object
 * @param options - Fingerprint configuration
 * @returns Hex-encoded SHA-256 hash (64 characters)
 *
 * @example
 * // Default fingerprint (IP + UA + Accept headers)
 * const fp = fingerprint(req);
 *
 * @example
 * // IP-only fingerprint (for simple rate limiting)
 * const fp = fingerprint(req, { userAgent: false, accept: false, acceptLanguage: false, acceptEncoding: false });
 *
 * @example
 * // With custom components
 * const fp = fingerprint(req, { custom: [req.body?.userId] });
 */
export function fingerprint(req: RequestLike, options: FingerprintOptions = {}): string {
  const {
    ip = true,
    userAgent = true,
    accept = true,
    acceptLanguage = true,
    acceptEncoding = true,
    custom = [],
    ipOptions,
  } = options;

  const components: string[] = [];

  if (ip) {
    components.push(`ip:${detectClientIp(req, ipOptions)}`);
  }
  if (userAgent) {
    components.push(`ua:${getHeader(req, 'user-agent')}`);
  }
  if (accept) {
    components.push(`accept:${getHeader(req, 'accept')}`);
  }
  if (acceptLanguage) {
    components.push(`lang:${getHeader(req, 'accept-language')}`);
  }
  if (acceptEncoding) {
    components.push(`enc:${getHeader(req, 'accept-encoding')}`);
  }

  for (const c of custom) {
    if (c !== null && c !== undefined) components.push(`custom:${c}`);
  }

  // Sort for deterministic ordering
  components.sort();

  const hash = createHash('sha256');
  hash.update(components.join('|'));
  return hash.digest('hex');
}
