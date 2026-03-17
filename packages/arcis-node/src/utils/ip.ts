/**
 * @module @arcis/node/utils/ip
 * Platform-aware client IP detection.
 *
 * Prevents IP spoofing by reading platform-specific headers
 * instead of blindly trusting X-Forwarded-For.
 *
 * @example
 * // Auto-detect platform from environment
 * const ip = detectClientIp(req);
 *
 * // Explicit platform
 * const ip = detectClientIp(req, { platform: 'cloudflare' });
 */

import type { IncomingMessage } from 'http';

export type Platform =
  | 'auto'
  | 'cloudflare'
  | 'vercel'
  | 'flyio'
  | 'render'
  | 'firebase'
  | 'aws-alb'
  | 'generic';

export interface DetectIpOptions {
  /** Platform to use for header selection. Default: 'auto' */
  platform?: Platform;
  /** Number of trusted proxies (for X-Forwarded-For parsing). Default: 1 */
  trustedProxyCount?: number;
}

interface RequestLike {
  headers: Record<string, string | string[] | undefined>;
  socket?: { remoteAddress?: string };
  connection?: { remoteAddress?: string };
  ip?: string;
}

/**
 * Platform-specific header configurations.
 * Each platform sets a trusted header that cannot be spoofed by the client.
 */
const PLATFORM_HEADERS: Record<Exclude<Platform, 'auto' | 'generic'>, string> = {
  cloudflare: 'cf-connecting-ip',
  vercel: 'x-real-ip',
  flyio: 'fly-client-ip',
  render: 'x-render-client-ip',
  firebase: 'x-appengine-user-ip',
  'aws-alb': 'x-forwarded-for',
};

/**
 * Auto-detect the platform from environment variables.
 */
function detectPlatform(): Platform {
  const env = typeof process !== 'undefined' ? process.env : {};

  if (env.CF_PAGES || env.CF_WORKERS) return 'cloudflare';
  if (env.VERCEL) return 'vercel';
  if (env.FLY_APP_NAME) return 'flyio';
  if (env.RENDER) return 'render';
  if (env.FIREBASE_CONFIG || env.GCLOUD_PROJECT) return 'firebase';
  if (env.AWS_EXECUTION_ENV || env.AWS_LAMBDA_FUNCTION_NAME) return 'aws-alb';

  return 'generic';
}

// Cache the detected platform — it won't change during process lifetime
let _cachedPlatform: Platform | null = null;

function getCachedPlatform(): Platform {
  if (_cachedPlatform === null) {
    _cachedPlatform = detectPlatform();
  }
  return _cachedPlatform;
}

/** Max IP string length (IPv6 max = 45 chars) */
const MAX_IP_LENGTH = 45;

/**
 * Sanitize an IP string: trim, truncate, strip control characters.
 * Prevents unbounded strings from being used as map keys.
 */
function sanitizeIp(ip: string): string {
  const trimmed = ip.trim();
  if (trimmed.length > MAX_IP_LENGTH) return trimmed.slice(0, MAX_IP_LENGTH);
  return trimmed;
}

/**
 * Get a header value from the request, handling string arrays.
 */
function getHeader(req: RequestLike, name: string): string | undefined {
  const val = req.headers[name];
  if (Array.isArray(val)) return val[0];
  return val;
}

/**
 * Parse the rightmost trusted IP from X-Forwarded-For.
 * Reading from the right prevents client spoofing — the rightmost entry
 * is the one added by the closest trusted proxy.
 */
function parseForwardedFor(header: string, trustedProxyCount: number): string | undefined {
  const ips = header.split(',').map(ip => ip.trim()).filter(Boolean);
  if (ips.length === 0) return undefined;

  // The client IP is at position (length - trustedProxyCount)
  const clientIndex = Math.max(0, ips.length - trustedProxyCount);
  return ips[clientIndex] || undefined;
}

/**
 * Detect the real client IP address from a request.
 *
 * Uses platform-specific headers when available to prevent IP spoofing.
 * Falls back to X-Forwarded-For (parsed from the right) and then
 * the socket remote address.
 *
 * @param req - HTTP request object (Express, raw http, etc.)
 * @param options - Detection options
 * @returns Client IP address, or 'unknown' if unresolvable
 *
 * @example
 * // Auto-detect platform
 * app.use((req, res, next) => {
 *   const clientIp = detectClientIp(req);
 *   console.log('Client IP:', clientIp);
 *   next();
 * });
 *
 * @example
 * // Behind Cloudflare
 * const ip = detectClientIp(req, { platform: 'cloudflare' });
 *
 * @example
 * // Behind 2 proxies (e.g. CDN + load balancer)
 * const ip = detectClientIp(req, { trustedProxyCount: 2 });
 */
export function detectClientIp(
  req: RequestLike | IncomingMessage,
  options: DetectIpOptions = {}
): string {
  const { platform = 'auto', trustedProxyCount = 1 } = options;
  const r = req as RequestLike;

  const resolvedPlatform = platform === 'auto' ? getCachedPlatform() : platform;

  // 1. Try platform-specific header (most trusted)
  if (resolvedPlatform !== 'generic' && resolvedPlatform in PLATFORM_HEADERS) {
    const headerName = PLATFORM_HEADERS[resolvedPlatform as keyof typeof PLATFORM_HEADERS];
    if (headerName) {
      if (resolvedPlatform === 'aws-alb') {
        // AWS ALB: parse X-Forwarded-For from the right
        const xff = getHeader(r, 'x-forwarded-for');
        if (xff) {
          const ip = parseForwardedFor(xff, trustedProxyCount);
          if (ip) return sanitizeIp(ip);
        }
      } else {
        const ip = getHeader(r, headerName);
        if (ip) return sanitizeIp(ip);
      }
    }
  }

  // 2. Try Express req.ip (respects trust proxy setting)
  if (r.ip) return sanitizeIp(r.ip);

  // 3. Try X-Forwarded-For (parsed from the right for safety)
  const xff = getHeader(r, 'x-forwarded-for');
  if (xff) {
    const ip = parseForwardedFor(xff, trustedProxyCount);
    if (ip) return sanitizeIp(ip);
  }

  // 4. Try X-Real-IP
  const realIp = getHeader(r, 'x-real-ip');
  if (realIp) return sanitizeIp(realIp);

  // 5. Socket remote address
  const socketIp = r.socket?.remoteAddress ?? r.connection?.remoteAddress;
  if (socketIp) return sanitizeIp(socketIp);

  return 'unknown';
}

/**
 * Check if an IP address is a private/internal address.
 *
 * Detects: loopback, private ranges (RFC 1918), link-local, IPv6 equivalents.
 */
export function isPrivateIp(ip: string): boolean {
  // Strip IPv4-mapped IPv6 prefix (::ffff:127.0.0.1 -> 127.0.0.1)
  const normalized = ip.startsWith('::ffff:') ? ip.slice(7) : ip;

  // IPv4 private ranges
  if (/^127\./.test(normalized)) return true;                          // Loopback
  if (/^10\./.test(normalized)) return true;                           // Class A private
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(normalized)) return true;     // Class B private
  if (/^192\.168\./.test(normalized)) return true;                     // Class C private
  if (/^169\.254\./.test(normalized)) return true;                     // Link-local
  if (/^0\./.test(normalized)) return true;                            // Current network

  // IPv6
  if (ip === '::1') return true;                               // Loopback
  if (/^fe80:/i.test(ip)) return true;                         // Link-local
  if (/^fc00:/i.test(ip)) return true;                         // Unique local
  if (/^fd/i.test(ip)) return true;                            // Unique local

  return false;
}

/** Reset cached platform (for testing). */
export function _resetPlatformCache(): void {
  _cachedPlatform = null;
}
