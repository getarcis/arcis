/**
 * @module @arcis/node/validation/url-async
 *
 * Async SSRF guard that closes the DNS-rebinding TOCTOU gap left open
 * by the synchronous `validateUrl` (sdk-vectors.md #31, issue #50).
 *
 * The synchronous `validateUrl` only checks the *string form* of the
 * hostname. It catches obvious cases — `127.0.0.1`, `10.0.0.1`,
 * `169.254.169.254` — but a hostname like `evil.com` passes through
 * even when its DNS A-record points to `10.0.0.1`, because resolution
 * happens later inside `fetch`. An attacker controlling the
 * `evil.com` zone can also rebind the answer between Arcis's check
 * and the actual TCP connect, which is the classic DNS TOCTOU.
 *
 * Two layers of fix shipped here:
 *
 * 1. **`validateUrlAsync(url, options)`** — runs the existing sync
 *    `validateUrl` first, then `dns.lookup(hostname, { all: true })`,
 *    then re-runs the same private-range check on every resolved
 *    address. Returns the pinned IP list so callers can reuse it for
 *    the actual connection (closing the TOCTOU window).
 *
 * 2. **`pinnedDnsLookup(ip)`** — returns a Node `lookup` callback
 *    that resolves any hostname to the pre-validated IP. Wire this
 *    into `https.request({ lookup })` / `http.request({ lookup })`
 *    so the connection uses the IP Arcis already validated, not
 *    whatever DNS returns at connect time. Pure stdlib — no undici,
 *    no extra dep.
 *
 * 3. **`safeFollowRedirect(prev, location, options)`** — when the
 *    server replies 30x, run the same async guard against the new
 *    Location URL. Resolves the absolute URL using the previous
 *    response URL as base. Caller decides whether to follow.
 *
 * The function signatures keep `lookup` injectable so tests can
 * substitute a fake resolver without monkey-patching `node:dns`.
 *
 * ```ts
 * import https from 'node:https';
 * import { validateUrlAsync, pinnedDnsLookup } from '@arcis/node';
 *
 * const result = await validateUrlAsync(url);
 * if (!result.safe) throw new Error(result.reason);
 *
 * https.get(url, { lookup: pinnedDnsLookup(result.resolvedIp!) }, (res) => {
 *   // The TCP connect now goes to result.resolvedIp regardless of
 *   // what DNS would say at this exact moment.
 * });
 * ```
 */

import * as dns from 'node:dns';
import { validateUrl, type ValidateUrlOptions, type ValidateUrlResult } from './url';

/**
 * Subset of `dns.lookup`'s `{ all: true }` callback signature. Kept
 * narrow so a test fake can satisfy it without depending on Node's
 * full `LookupAddress` type.
 */
export type LookupAddress = { address: string; family: number };

/**
 * Function shape compatible with `dns.lookup(hostname, { all: true })`.
 * Returns a list of resolved addresses. Tests inject a fake.
 */
export type DnsLookup = (hostname: string) => Promise<LookupAddress[]>;

const defaultLookup: DnsLookup = (hostname) =>
  new Promise((resolve, reject) => {
    dns.lookup(hostname, { all: true }, (err, addresses) => {
      if (err) reject(err);
      else resolve(addresses);
    });
  });

export interface ValidateUrlAsyncOptions extends ValidateUrlOptions {
  /**
   * DNS lookup function. Defaults to a Promise wrapper around
   * `dns.lookup(hostname, { all: true })`. Tests inject a stub.
   */
  lookup?: DnsLookup;
  /**
   * If true, accept the first non-private IP and ignore the rest.
   * Default false: every resolved IP must pass the private-range
   * check. Hosts with mixed-public/private answers (round-robin DNS
   * with one internal record) still fail-closed.
   */
  acceptFirstPublic?: boolean;
}

export interface ValidateUrlAsyncResult extends ValidateUrlResult {
  /**
   * Single pinned IP (the first public address if all checks passed,
   * or undefined when the string-only synchronous validator already
   * decided — e.g., the hostname *was* a literal IP). Use this with
   * `pinnedDnsLookup()` to wire the actual fetch.
   */
  resolvedIp?: string;
  /** Every IP returned by DNS, in resolver order. */
  resolvedIps?: string[];
}

/**
 * Reuses the existing private-range check from the sync validator.
 * We re-run `validateUrl` with the resolved IP swapped in as the
 * URL host. That way every existing rule (link-local, decimal-IP,
 * cloud-metadata hostname, IPv6-mapped, etc.) applies post-DNS too,
 * without forking the rule list.
 */
function checkResolvedIp(ip: string, options: ValidateUrlOptions): ValidateUrlResult {
  // Build a synthetic URL that hands the IP to validateUrl. The
  // protocol is irrelevant for the private-range check; pick http to
  // avoid IPv6 bracket questions.
  const isIpv6 = ip.includes(':');
  const host = isIpv6 ? `[${ip}]` : ip;
  // Strip credentials + allowedHosts/blockedHosts because they apply
  // to the original hostname, not the resolved IP. We're only
  // re-running the IP-range checks here.
  const { allowedProtocols, allowLocalhost, allowPrivate } = options;
  return validateUrl(`http://${host}/`, {
    allowedProtocols,
    allowLocalhost,
    allowPrivate,
  });
}

/**
 * Async SSRF guard with DNS resolution. Runs the sync validator
 * first, then resolves DNS and validates every returned IP against
 * the same private-range rules. Returns a pinned IP for the caller
 * to reuse.
 *
 * Failure modes (any returns `{ safe: false, reason }`):
 * - Sync validator already rejects (string-pattern fail).
 * - DNS lookup throws (NXDOMAIN, network error). Reason carries the
 *   underlying error message.
 * - DNS returns no addresses.
 * - Any resolved address fails the private-range check (default) or
 *   *all* fail it when `acceptFirstPublic` is true.
 */
export async function validateUrlAsync(
  url: string,
  options: ValidateUrlAsyncOptions = {},
): Promise<ValidateUrlAsyncResult> {
  const sync = validateUrl(url, options);
  if (!sync.safe) return sync;

  // If the hostname is a literal IP, the sync validator has already
  // checked it. Skip the DNS round-trip.
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { safe: false, reason: 'invalid URL: failed to parse' };
  }
  const host = parsed.hostname.replace(/^\[|\]$/g, '');
  if (isLiteralIp(host)) return { safe: true };

  // Allowed-hosts allowlist takes precedence in the sync validator
  // and also bypasses the IP check here. The contract: if you
  // explicitly allowed the hostname, you accept whatever DNS returns.
  if (options.allowedHosts?.some((h) => host.toLowerCase() === h.toLowerCase())) {
    return { safe: true };
  }

  const lookup = options.lookup ?? defaultLookup;
  let addresses: LookupAddress[];
  try {
    addresses = await lookup(host);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { safe: false, reason: `DNS lookup failed: ${msg}` };
  }

  if (addresses.length === 0) {
    return { safe: false, reason: 'DNS returned no addresses' };
  }

  const ips = addresses.map((a) => a.address);
  const acceptFirstPublic = options.acceptFirstPublic === true;
  let firstPublic: string | undefined;
  for (const ip of ips) {
    const ipResult = checkResolvedIp(ip, options);
    if (ipResult.safe) {
      if (firstPublic === undefined) firstPublic = ip;
    } else if (!acceptFirstPublic) {
      return {
        safe: false,
        reason: `resolved IP ${ip} is unsafe: ${ipResult.reason}`,
        resolvedIps: ips,
      };
    }
  }

  if (firstPublic === undefined) {
    return {
      safe: false,
      reason: 'all resolved IPs are private/loopback',
      resolvedIps: ips,
    };
  }

  return { safe: true, resolvedIp: firstPublic, resolvedIps: ips };
}

/**
 * Build a `lookup` callback that pins the resolution to a single
 * pre-validated IP, regardless of what DNS would say at connect time.
 * Drop into `https.request({ lookup })` / `http.request({ lookup })`.
 *
 * Closes the TOCTOU window between `validateUrlAsync` and the actual
 * TCP connect. The pinned IP must be one that already passed the
 * async validator — wiring it without that check defeats the purpose.
 *
 * The returned function matches Node's `dns.lookup` callback shape
 * for the `{ all: false, family: 0 }` case (single address). The
 * default Node http/https stack uses that shape.
 */
export function pinnedDnsLookup(
  ip: string,
): (
  hostname: string,
  options: { family?: number; hints?: number; verbatim?: boolean },
  callback: (err: NodeJS.ErrnoException | null, address: string, family: number) => void,
) => void {
  if (typeof ip !== 'string' || ip.trim() === '') {
    throw new TypeError('pinnedDnsLookup: ip must be a non-empty string');
  }
  const family = ip.includes(':') ? 6 : 4;
  return (_hostname, _options, callback) => {
    callback(null, ip, family);
  };
}

/**
 * Validate a redirect target with the same TOCTOU-aware pipeline.
 *
 * `prev` is the URL of the response that returned the 30x; `location`
 * is the raw `Location:` header value (which may be relative). The
 * function resolves `location` against `prev` per RFC 3986 then runs
 * `validateUrlAsync` on the absolute result.
 *
 * Use this on every hop of a redirect chain. Without it, a server
 * that you trust today can redirect tomorrow's request to
 * `http://169.254.169.254/`.
 */
export async function safeFollowRedirect(
  prev: string,
  location: string,
  options: ValidateUrlAsyncOptions = {},
): Promise<ValidateUrlAsyncResult> {
  if (typeof location !== 'string' || location.trim() === '') {
    return { safe: false, reason: 'redirect Location is empty' };
  }
  let absolute: URL;
  try {
    absolute = new URL(location, prev);
  } catch {
    return { safe: false, reason: 'invalid redirect URL' };
  }
  return validateUrlAsync(absolute.toString(), options);
}

/**
 * Detect whether a hostname is a literal IPv4/IPv6 (with or without
 * IPv6 brackets stripped). Mirrors what the sync validator already
 * checks via dotted-quad / decimal / octal regexes; we only need it
 * to know whether to skip the DNS round-trip.
 */
function isLiteralIp(host: string): boolean {
  // IPv4 dotted quad
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) return true;
  // Decimal IP (single integer)
  if (/^\d+$/.test(host)) return true;
  // Octal/hex IP forms
  if (/^0[0-7x]/.test(host) && /^[0-9a-fx.]+$/i.test(host) && host.includes('.')) return true;
  // IPv6: contains a colon and no slashes/spaces
  if (host.includes(':') && !/[/\s]/.test(host)) return true;
  return false;
}
