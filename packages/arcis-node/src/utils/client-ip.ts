/**
 * @module @arcis/node/utils/client-ip
 * Trust-aware client IP resolution and the rate-limit key function.
 *
 * Every Arcis feature that keys on the client address (rate limiters,
 * brute-force protection, correlation tracking, telemetry `ip`, IP
 * reputation and every framework adapter) resolves the address here, so a
 * client can never choose its own key. See spec/API_SPEC.md, "Client IP
 * resolution".
 *
 * This module has no Node built-in imports so it also runs on edge runtimes
 * (Next.js middleware, Cloudflare Workers, Deno, Bun).
 */

import { warnOnce, _resetWarnings } from '../core/warn-once';

/**
 * Proxies trusted when `trustedProxies` is not configured. Equal to Express's
 * `trust proxy` value `loopback, linklocal, uniquelocal`.
 */
export const DEFAULT_TRUSTED_PROXIES: readonly string[] = Object.freeze([
  '127.0.0.0/8',
  '::1/128',
  '169.254.0.0/16',
  'fe80::/10',
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  'fc00::/7',
]);

/** Rate-limit key shared by every request whose client address is unknown. */
export const UNKNOWN_CLIENT_KEY = 'unknown';

/** Client IP resolution options accepted by `arcis()`, every adapter and every limiter. */
export interface ClientIpOptions {
  /**
   * IPs and CIDR ranges of proxies allowed to report the client address in
   * `X-Forwarded-For`. Default: {@link DEFAULT_TRUSTED_PROXIES} (loopback,
   * link-local and private ranges). An empty list trusts nothing.
   */
  trustedProxies?: readonly string[];
  /**
   * A header that carries the client IP (for example `cf-connecting-ip` or
   * `x-real-ip`). Read only from a trusted peer; on runtimes without a peer
   * address it is read as configured. Default: none.
   */
  clientIpHeader?: string;
}

/** Reads one request header by lowercase name. */
export type HeaderGetter = (name: string) => string | null | undefined;

/** A compiled resolver for one trust configuration. */
export interface ClientIpResolver {
  /** True when `trustedProxies` was passed explicitly. */
  readonly explicitTrust: boolean;
  /**
   * Resolve from the socket peer address and the request headers (the spec's
   * trust walk). Returns `null` when the peer is not a valid IP.
   */
  fromPeer(peer: string | null | undefined, getHeader: HeaderGetter): string | null;
  /**
   * Resolve where the runtime exposes no peer address: the configured
   * header, else the platform header on Vercel (`VERCEL=1`) or Cloudflare
   * Workers, else `null` (callers then use {@link UNKNOWN_CLIENT_KEY}).
   */
  fromEdge(getHeader: HeaderGetter): string | null;
  /** {@link ClientIpResolver.fromPeer} when a peer address exists, {@link ClientIpResolver.fromEdge} otherwise. */
  resolve(peer: string | null | undefined, getHeader: HeaderGetter): string | null;
}

/** Reset the once-per-process warnings. Test helper. */
export function _resetClientIpWarnings(): void {
  _resetWarnings();
}

// ─── Parsing ────────────────────────────────────────────────────────────────

const V4_OCTET = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)$/;
const V6_GROUP = /^[0-9a-f]{1,4}$/i;

function parseIPv4(value: string): number | null {
  const parts = value.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    if (!V4_OCTET.test(part)) return null;
    n = n * 256 + Number(part);
  }
  return n;
}

interface ParsedIPv6 {
  groups: number[];
  /** True when the text ends in dotted IPv4 notation, e.g. `::1.2.3.4`. */
  dotted: boolean;
}

/** Parse IPv6 text without a zone. Accepts what Node's `net.isIPv6` accepts. */
function parseIPv6(value: string): ParsedIPv6 | null {
  if (!value.includes(':')) return null;
  const gap = value.indexOf('::');
  if (gap !== -1 && value.indexOf('::', gap + 1) !== -1) return null;
  const head = gap === -1 ? value : value.slice(0, gap);
  const tail = gap === -1 ? '' : value.slice(gap + 2);
  let dotted = false;

  const toGroups = (text: string, allowDottedLast: boolean): number[] | null => {
    if (text === '') return [];
    const parts = text.split(':');
    const out: number[] = [];
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      if (allowDottedLast && i === parts.length - 1 && part.includes('.')) {
        const v4 = parseIPv4(part);
        if (v4 === null) return null;
        out.push(Math.floor(v4 / 65536), v4 % 65536);
        dotted = true;
      } else {
        if (!V6_GROUP.test(part)) return null;
        out.push(parseInt(part, 16));
      }
    }
    return out;
  };

  const left = toGroups(head, gap === -1);
  const right = toGroups(tail, true);
  if (left === null || right === null) return null;
  if (gap === -1) return left.length === 8 ? { groups: left, dotted } : null;
  const missing = 8 - left.length - right.length;
  if (missing < 1) return null;
  return { groups: [...left, ...new Array<number>(missing).fill(0), ...right], dotted };
}

/** Address as eight 16-bit groups; IPv4 maps to `::ffff:a.b.c.d`. */
function toGroups(address: string): number[] | null {
  const v4 = parseIPv4(address);
  if (v4 !== null) return [0, 0, 0, 0, 0, 0xffff, Math.floor(v4 / 65536), v4 % 65536];
  return parseIPv6(address)?.groups ?? null;
}

function stripZone(value: string): string {
  const zone = value.indexOf('%');
  return zone !== -1 && value.includes(':') ? value.slice(0, zone) : value;
}

const MAPPED_DOTTED = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i;

/**
 * Normalize an address: trim, drop an IPv6 zone, unwrap IPv4-mapped IPv6
 * (`::ffff:1.2.3.4` becomes `1.2.3.4`) and lowercase.
 *
 * @param value - Candidate address text
 * @returns The normalized address, or `null` when it is not a valid IP
 */
export function normalizeIp(value: string | null | undefined): string | null {
  if (typeof value !== 'string') return null;
  let address = stripZone(value.trim());
  const mapped = MAPPED_DOTTED.exec(address);
  if (mapped) address = mapped[1];
  return toGroups(address) === null ? null : address.toLowerCase();
}

/** Strip a port from a forwarded entry: `1.2.3.4:80`, `[2001:db8::1]:443`. */
function stripPort(value: string): string {
  const v = value.trim();
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(v);
  if (bracketed) return bracketed[1];
  const v4WithPort = /^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/.exec(v);
  if (v4WithPort) return v4WithPort[1];
  return v;
}

/** Comma-separated header entries, right-most first, empty entries dropped. */
function forwardedEntries(header: string): string[] {
  const entries: string[] = [];
  const parts = header.split(',');
  for (let i = parts.length - 1; i >= 0; i--) {
    const entry = parts[i].trim();
    if (entry) entries.push(stripPort(entry));
  }
  return entries;
}

/** The right-most valid address in a header value, if any. */
function rightmostIp(header: string | null | undefined): string | null {
  if (!header) return null;
  const entries = forwardedEntries(header);
  return entries.length > 0 ? normalizeIp(entries[0]) : null;
}

// ─── Trust ranges ───────────────────────────────────────────────────────────

interface TrustRange {
  groups: number[];
  /** Prefix length over the 128-bit form (IPv4 ranges are offset by 96). */
  prefix: number;
}

function parseRange(entry: string): TrustRange {
  const text = entry.trim();
  const slash = text.indexOf('/');
  const base = slash === -1 ? text : text.slice(0, slash);
  const isV4 = parseIPv4(base) !== null;
  const groups = toGroups(base);
  const maxBits = isV4 ? 32 : 128;
  const prefixText = slash === -1 ? String(maxBits) : text.slice(slash + 1);
  const bits = /^\d{1,3}$/.test(prefixText) ? Number(prefixText) : NaN;
  if (groups === null || !(bits >= 0 && bits <= maxBits)) {
    throw new TypeError(`Invalid trustedProxies entry: ${JSON.stringify(entry)} (expected an IP or CIDR range)`);
  }
  if (bits === 0) {
    warnOnce(
      'trust-all',
      `trustedProxies contains ${JSON.stringify(entry)}, which trusts every address. ` +
        'Any client can then set X-Forwarded-For and choose its own rate-limit key. ' +
        'List only your proxy addresses.',
    );
  }
  return { groups, prefix: isV4 ? bits + 96 : bits };
}

function inRange(address: number[], range: TrustRange): boolean {
  let bits = range.prefix;
  for (let i = 0; i < 8 && bits > 0; i++) {
    if (bits >= 16) {
      if (address[i] !== range.groups[i]) return false;
      bits -= 16;
    } else {
      const mask = (0xffff << (16 - bits)) & 0xffff;
      return (address[i] & mask) === (range.groups[i] & mask);
    }
  }
  return true;
}

// ─── Resolver ───────────────────────────────────────────────────────────────

/** True on Vercel, where the platform overwrites client-supplied IP headers. */
function onVercel(): boolean {
  return typeof process !== 'undefined' && process.env?.VERCEL === '1';
}

/** True on Cloudflare Workers, where `cf-connecting-ip` is set by the platform. */
function onCloudflareWorkers(): boolean {
  return typeof navigator !== 'undefined' && navigator.userAgent === 'Cloudflare-Workers';
}

/**
 * Compile a resolver for one trust configuration. Invalid `trustedProxies`
 * entries throw a `TypeError` here, at construction.
 *
 * @param options - Trust configuration
 * @returns A resolver reusable across requests
 */
export function createClientIpResolver(options: ClientIpOptions = {}): ClientIpResolver {
  const explicitTrust = options.trustedProxies !== undefined;
  const ranges = (options.trustedProxies ?? DEFAULT_TRUSTED_PROXIES).map(parseRange);
  const headerName = options.clientIpHeader?.trim().toLowerCase() || undefined;

  const isTrusted = (address: string): boolean => {
    const groups = toGroups(address);
    return groups !== null && ranges.some((range) => inRange(groups, range));
  };

  const fromPeer = (peer: string | null | undefined, getHeader: HeaderGetter): string | null => {
    const peerIp = normalizeIp(peer);
    if (peerIp === null) return null;
    const forwarded = getHeader('x-forwarded-for');

    // A public peer's forwarded headers are ignored entirely.
    if (!isTrusted(peerIp)) {
      if (forwarded || (headerName && getHeader(headerName))) {
        warnOnce(
          'untrusted-forwarded',
          `Forwarded client IP headers arrived from ${peerIp}, which is not a trusted proxy, ` +
            'and were ignored. If this server runs behind a proxy or load balancer, add its ' +
            'address to trustedProxies.',
        );
      }
      return peerIp;
    }

    if (headerName) {
      const configured = rightmostIp(getHeader(headerName));
      if (configured) return configured;
    }
    if (!forwarded) return peerIp;

    // Walk from the peer through X-Forwarded-For right to left. The client is
    // the first entry that is not a valid, trusted address, or the left-most
    // entry when every hop is trusted.
    const entries = forwardedEntries(forwarded);
    let selected = entries.length - 1;
    for (let i = 0; i < entries.length - 1; i++) {
      const address = normalizeIp(entries[i]);
      if (address === null || !isTrusted(address)) {
        selected = i;
        break;
      }
    }
    // An invalid selected entry falls back to the trusted hop that reported it.
    for (let i = selected; i >= 0; i--) {
      const address = normalizeIp(entries[i]);
      if (address !== null) return address;
    }
    return peerIp;
  };

  const fromEdge = (getHeader: HeaderGetter): string | null => {
    if (headerName) {
      const configured = rightmostIp(getHeader(headerName));
      if (configured) return configured;
    }
    if (onVercel()) {
      return normalizeIp(getHeader('x-real-ip')) ?? rightmostIp(getHeader('x-forwarded-for'));
    }
    if (onCloudflareWorkers()) return normalizeIp(getHeader('cf-connecting-ip'));
    return null;
  };

  const resolve = (peer: string | null | undefined, getHeader: HeaderGetter): string | null =>
    peer ? fromPeer(peer, getHeader) : fromEdge(getHeader);

  return { explicitTrust, fromPeer, fromEdge, resolve };
}

/**
 * Resolve the client IP for one request with the spec's trust walk.
 *
 * @param peer - Socket peer address, before any header parsing
 * @param headers - Request headers (Node object, Fetch `Headers`, or a getter)
 * @param options - Trust configuration
 * @returns The client IP, or `null` when the peer is not a valid IP
 *
 * @example
 * resolveClientIp(req.socket.remoteAddress, req.headers, { trustedProxies: ['10.0.0.0/8'] });
 */
export function resolveClientIp(
  peer: string | null | undefined,
  headers: Record<string, string | string[] | undefined> | Headers | HeaderGetter,
  options: ClientIpOptions = {},
): string | null {
  return createClientIpResolver(options).fromPeer(peer, toHeaderGetter(headers));
}

/** Build a {@link HeaderGetter} from a Node headers object, Fetch `Headers` or getter. */
export function toHeaderGetter(
  headers: Record<string, string | string[] | undefined> | Headers | HeaderGetter | undefined,
): HeaderGetter {
  if (typeof headers === 'function') return headers;
  if (!headers) return () => undefined;
  if (typeof (headers as Headers).get === 'function' && typeof (headers as Headers).has === 'function') {
    const web = headers as Headers;
    return (name) => web.get(name);
  }
  const node = headers as Record<string, string | string[] | undefined>;
  return (name) => {
    const value = node[name];
    return Array.isArray(value) ? value.join(', ') : value;
  };
}

// ─── Rate-limit key ─────────────────────────────────────────────────────────

/** RFC 5952 text form: lowercase, no leading zeros, longest zero run compressed. */
function formatIPv6(groups: number[]): string {
  let bestStart = -1;
  let bestLength = 1;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLength) {
      bestStart = i;
      bestLength = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestStart === -1) return hex.join(':');
  const left = hex.slice(0, bestStart).join(':');
  const right = hex.slice(bestStart + bestLength).join(':');
  return `${left}::${right}`;
}

/**
 * Rate-limit key for a client IP, equal to express-rate-limit's
 * `ipKeyGenerator`. IPv4 (and IPv4-mapped IPv6) keys on the IPv4 address;
 * IPv6 keys on its network, written `<network>/<subnet>`, so one IPv6
 * allocation cannot mint unlimited keys.
 *
 * @param ip - A client IP, normally from the resolver
 * @param ipv6Subnet - IPv6 prefix length 1-128, or `false` for the full address. Default: 56
 * @returns The rate-limit key
 *
 * @example
 * ipKeyGenerator('2001:db8:1234:56ff::9'); // '2001:db8:1234:5600::/56'
 */
export function ipKeyGenerator(ip: string, ipv6Subnet: number | false = 56): string {
  const parsed = parseIPv6(stripZone(ip));
  if (parsed === null) return ip;
  const g = parsed.groups;
  const zeroHead = g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0;
  const embedsV4 = zeroHead && (g[5] === 0xffff || (g[5] === 0 && parsed.dotted));
  if (embedsV4) return `${g[6] >> 8}.${g[6] & 0xff}.${g[7] >> 8}.${g[7] & 0xff}`;
  if (!ipv6Subnet) return ip;
  const masked = g.map((group, i) => {
    const bits = Math.min(16, Math.max(0, ipv6Subnet - i * 16));
    return bits === 0 ? 0 : group & ((0xffff << (16 - bits)) & 0xffff);
  });
  return `${formatIPv6(masked)}/${ipv6Subnet}`;
}

/**
 * Validate an `ipv6Subnet` option at construction.
 *
 * @throws RangeError when it is not an integer 1-128 or `false`
 */
export function validateIpv6Subnet(value: number | false | undefined, owner: string): number | false {
  if (value === undefined) return 56;
  if (value === false || (Number.isInteger(value) && value >= 1 && value <= 128)) return value;
  throw new RangeError(`${owner}: ipv6Subnet must be an integer from 1 to 128 or false (got ${String(value)})`);
}

/**
 * Key for a resolved client IP: {@link ipKeyGenerator} for a real address,
 * {@link UNKNOWN_CLIENT_KEY} when none could be determined.
 */
export function clientKey(ip: string | null, ipv6Subnet: number | false = 56): string {
  return ip === null ? UNKNOWN_CLIENT_KEY : ipKeyGenerator(ip, ipv6Subnet);
}

// ─── Node-style requests (Express, Nuxt/h3, raw http) ───────────────────────

/** Minimal Node / Express request shape the resolver reads. */
export interface NodeRequestLike {
  headers: Record<string, string | string[] | undefined>;
  socket?: { remoteAddress?: string };
  /** Framework-resolved address (Express `req.ip`). */
  ip?: string;
  /** Express application, used to read the `trust proxy` setting. */
  app?: { get?(setting: string): unknown };
}

/**
 * Build a per-request client IP function for Node-style requests. When
 * `trustedProxies` is not configured and the Express app has a non-default
 * `trust proxy` setting, Express's resolved `req.ip` is used; otherwise the
 * socket peer address goes through the Arcis trust walk.
 *
 * @param options - Trust configuration
 * @returns `(req) => clientIp | null`
 */
export function createNodeClientIp(options: ClientIpOptions = {}): (req: NodeRequestLike) => string | null {
  const resolver = createClientIpResolver(options);
  return (req) => {
    if (!resolver.explicitTrust && typeof req.app?.get === 'function') {
      const trust = req.app.get('trust proxy');
      if (trust !== undefined && trust !== false) {
        if (trust === true) {
          warnOnce(
            'permissive-trust-proxy',
            "Express 'trust proxy' is true, so any client can choose its rate-limit key with " +
              'X-Forwarded-For. Set it to your proxy addresses or a hop count instead.',
          );
        }
        const frameworkIp = normalizeIp(req.ip);
        if (frameworkIp !== null) return frameworkIp;
      }
    }
    // Without a socket (mocks, some serverless shims) the framework address is
    // the closest thing to a peer.
    const peer = req.socket?.remoteAddress ?? req.ip;
    return resolver.fromPeer(peer, toHeaderGetter(req.headers));
  };
}

/** Warn once that requests share the `unknown` key because no address is available. */
export function warnUnknownClient(runtime: string): void {
  warnOnce(
    'unknown-client',
    `${runtime}: no client address is available, so rate limiting keys these requests on one ` +
      'shared "unknown" bucket. Configure clientIpHeader or getClientIp for your platform.',
  );
}
