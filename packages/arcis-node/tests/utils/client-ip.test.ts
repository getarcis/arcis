/**
 * Client IP resolver + rate-limit key function.
 * Runs every case in spec/client-ip-vectors.json, then cross-checks the key
 * function and the address parser against express-rate-limit and node:net.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { isIP } from 'node:net';
import { ipKeyGenerator as erlIpKeyGenerator } from 'express-rate-limit';
import {
  resolveClientIp,
  createClientIpResolver,
  createNodeClientIp,
  ipKeyGenerator,
  normalizeIp,
  clientKey,
  validateIpv6Subnet,
  DEFAULT_TRUSTED_PROXIES,
  UNKNOWN_CLIENT_KEY,
  _resetClientIpWarnings,
} from '../../src/utils/client-ip';

interface ResolutionCase {
  id: string;
  trusted_proxies: string[] | null;
  peer: string;
  x_forwarded_for: string | null;
  expected_client_ip: string | null;
  expected_key: string | null;
}

interface KeyCase {
  ip: string;
  ipv6_subnet: number | false;
  expected_key: string;
}

const vectors = JSON.parse(
  readFileSync(resolve(__dirname, '../../../../spec/client-ip-vectors.json'), 'utf-8'),
) as {
  default_trusted_proxies: string[];
  resolution: ResolutionCase[];
  keys: KeyCase[];
};

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  _resetClientIpWarnings();
});

describe('client-ip-vectors.json', () => {
  it('has the expected number of cases', () => {
    expect(vectors.resolution).toHaveLength(624);
    expect(vectors.keys).toHaveLength(40);
  });

  it('default trust set matches the fixture', () => {
    expect([...DEFAULT_TRUSTED_PROXIES]).toEqual(vectors.default_trusted_proxies);
  });

  it.each(vectors.resolution.map((c) => [c.id, c] as const))('resolution %s', (_id, c) => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const headers = c.x_forwarded_for === null ? {} : { 'x-forwarded-for': c.x_forwarded_for };
    const options = c.trusted_proxies === null ? {} : { trustedProxies: c.trusted_proxies };
    const ip = resolveClientIp(c.peer, headers, options);
    expect(ip).toBe(c.expected_client_ip);
    expect(ip === null ? null : ipKeyGenerator(ip)).toBe(c.expected_key);
  });

  it.each(vectors.keys.map((c) => [`${c.ip} /${String(c.ipv6_subnet)}`, c] as const))(
    'key %s',
    (_id, c) => {
      expect(ipKeyGenerator(c.ip, c.ipv6_subnet)).toBe(c.expected_key);
    },
  );
});

describe('ipKeyGenerator parity with express-rate-limit', () => {
  // Deterministic pseudo-random IPv6 addresses with zero runs of every length.
  let seed = 12345;
  const rand = (n: number): number => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return seed % n;
  };
  const addresses: string[] = [];
  for (let i = 0; i < 400; i++) {
    const groups = Array.from({ length: 8 }, () => (rand(3) === 0 ? 0 : rand(0x10000)));
    addresses.push(groups.map((g) => g.toString(16)).join(':'));
  }
  addresses.push('::', '1::', '::1:0:0:0', '0:0:1::', '1:0:0:2:0:0:0:3', '::ffff:102:304', '::1.2.3.4');

  it('matches for every subnet on generated addresses', () => {
    for (const address of addresses) {
      for (const subnet of [1, 7, 16, 33, 48, 56, 64, 100, 127, 128, false] as const) {
        expect(ipKeyGenerator(address, subnet), `${address}/${subnet}`).toBe(
          erlIpKeyGenerator(address, subnet),
        );
      }
    }
  });

  it('leaves IPv4 and non-IP keys unchanged', () => {
    expect(ipKeyGenerator('203.0.113.9')).toBe('203.0.113.9');
    expect(ipKeyGenerator('not-an-ip')).toBe('not-an-ip');
  });
});

describe('normalizeIp', () => {
  const samples = [
    '1.2.3.4', '01.2.3.4', '256.1.1.1', '1.2.3', '::', '::1', '1::', ':::', '1:2:3:4:5:6:7:8',
    '1:2:3:4:5:6:7:8:9', '1:2:3:4:5:6:7::', '::1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8::',
    '::ffff:1.2.3.4', '1:2:3:4:5:6:1.2.3.4', '1.2.3.4::', 'fe80::1', 'FE80::ABCD',
    '12345::1', 'g::1', '1:2::3::4', ':1::', '::1.2.3', '2001:db8::1.2.3.4',
  ];

  it('accepts exactly what node:net isIP accepts', () => {
    for (const sample of samples) {
      expect(normalizeIp(sample) !== null, sample).toBe(isIP(sample) !== 0);
    }
  });

  it('drops zones, unwraps IPv4-mapped IPv6 and lowercases', () => {
    expect(normalizeIp(' FE80::1%eth0 ')).toBe('fe80::1');
    expect(normalizeIp('::FFFF:198.51.100.7')).toBe('198.51.100.7');
    expect(normalizeIp('2001:DB8::1')).toBe('2001:db8::1');
    expect(normalizeIp(undefined)).toBeNull();
  });
});

describe('resolver behavior', () => {
  it('a public peer rotating X-Forwarded-For always resolves to the peer', () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const seen = new Set<string | null>();
    for (let i = 0; i < 20; i++) {
      seen.add(resolveClientIp('203.0.113.5', { 'x-forwarded-for': `198.51.100.${i}` }));
    }
    expect([...seen]).toEqual(['203.0.113.5']);
  });

  it('warns once when forwarded headers come from an untrusted peer', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const resolver = createClientIpResolver();
    resolver.fromPeer('203.0.113.5', () => '1.1.1.1');
    resolver.fromPeer('203.0.113.6', () => '1.1.1.2');
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).toContain('trustedProxies');
  });

  it('warns once when trustedProxies trusts every address', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    createClientIpResolver({ trustedProxies: ['0.0.0.0/0'] });
    createClientIpResolver({ trustedProxies: ['::/0'] });
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it('rejects invalid trustedProxies entries at construction', () => {
    expect(() => createClientIpResolver({ trustedProxies: ['10.0.0.0/33'] })).toThrow(TypeError);
    expect(() => createClientIpResolver({ trustedProxies: ['proxy.local'] })).toThrow(TypeError);
    expect(() => createClientIpResolver({ trustedProxies: ['::/129'] })).toThrow(TypeError);
  });

  it('matches IPv4 peers against IPv4-mapped IPv6 ranges and the reverse', () => {
    expect(resolveClientIp('10.0.0.1', { 'x-forwarded-for': '198.51.100.7' }, { trustedProxies: ['::ffff:10.0.0.0/104'] })).toBe('198.51.100.7');
    expect(resolveClientIp('::ffff:10.0.0.1', { 'x-forwarded-for': '198.51.100.7' }, { trustedProxies: ['10.0.0.0/8'] })).toBe('198.51.100.7');
  });

  it('reads a configured client IP header only from a trusted peer', () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const headers = { 'cf-connecting-ip': '198.51.100.9', 'x-forwarded-for': '198.51.100.7' };
    expect(resolveClientIp('10.0.0.2', headers, { clientIpHeader: 'CF-Connecting-IP' })).toBe('198.51.100.9');
    expect(resolveClientIp('203.0.113.5', headers, { clientIpHeader: 'cf-connecting-ip' })).toBe('203.0.113.5');
    // An unusable configured header falls back to the X-Forwarded-For walk.
    expect(resolveClientIp('10.0.0.2', { 'cf-connecting-ip': 'junk', 'x-forwarded-for': '198.51.100.7' }, { clientIpHeader: 'cf-connecting-ip' })).toBe('198.51.100.7');
  });

  it('returns null for a missing or invalid peer', () => {
    expect(resolveClientIp(undefined, {})).toBeNull();
    expect(resolveClientIp('not-an-ip', { 'x-forwarded-for': '1.1.1.1' })).toBeNull();
  });

  it('accepts Fetch Headers', () => {
    const headers = new Headers({ 'x-forwarded-for': '198.51.100.7' });
    expect(resolveClientIp('127.0.0.1', headers)).toBe('198.51.100.7');
  });
});

describe('edge resolution (no peer address)', () => {
  const get = (h: Record<string, string>) => (name: string) => h[name];

  it('returns null with no platform and no configuration', () => {
    vi.stubEnv('VERCEL', '');
    expect(createClientIpResolver().fromEdge(get({ 'x-forwarded-for': '1.1.1.1', 'cf-connecting-ip': '2.2.2.2', 'x-real-ip': '3.3.3.3' }))).toBeNull();
  });

  it('on Vercel uses x-real-ip, then the right-most X-Forwarded-For entry', () => {
    vi.stubEnv('VERCEL', '1');
    const resolver = createClientIpResolver();
    expect(resolver.fromEdge(get({ 'x-real-ip': '198.51.100.1', 'x-forwarded-for': '6.6.6.6, 198.51.100.2' }))).toBe('198.51.100.1');
    expect(resolver.fromEdge(get({ 'x-forwarded-for': '6.6.6.6, 198.51.100.2' }))).toBe('198.51.100.2');
    expect(resolver.fromEdge(get({ 'cf-connecting-ip': '198.51.100.3' }))).toBeNull();
  });

  it('on Cloudflare Workers uses cf-connecting-ip only', () => {
    vi.stubEnv('VERCEL', '');
    vi.stubGlobal('navigator', { userAgent: 'Cloudflare-Workers' });
    const resolver = createClientIpResolver();
    expect(resolver.fromEdge(get({ 'cf-connecting-ip': '198.51.100.4', 'x-forwarded-for': '6.6.6.6' }))).toBe('198.51.100.4');
    expect(resolver.fromEdge(get({ 'x-forwarded-for': '6.6.6.6' }))).toBeNull();
  });

  it('uses an explicitly configured header anywhere', () => {
    vi.stubEnv('VERCEL', '');
    const resolver = createClientIpResolver({ clientIpHeader: 'fly-client-ip' });
    expect(resolver.fromEdge(get({ 'fly-client-ip': '198.51.100.5' }))).toBe('198.51.100.5');
  });
});

describe('createNodeClientIp (Express trust proxy)', () => {
  const app = (trust: unknown) => ({ get: (name: string) => (name === 'trust proxy' ? trust : undefined) });

  it('ignores req.ip when trust proxy is the default (false)', () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const ipOf = createNodeClientIp();
    const req = { headers: { 'x-forwarded-for': '6.6.6.6' }, socket: { remoteAddress: '203.0.113.5' }, ip: '6.6.6.6', app: app(false) };
    expect(ipOf(req)).toBe('203.0.113.5');
  });

  it("uses Express's resolved req.ip when trust proxy is configured", () => {
    const ipOf = createNodeClientIp();
    const req = { headers: {}, socket: { remoteAddress: '203.0.113.5' }, ip: '198.51.100.7', app: app('203.0.113.5') };
    expect(ipOf(req)).toBe('198.51.100.7');
  });

  it('explicit trustedProxies wins over the Express setting', () => {
    const ipOf = createNodeClientIp({ trustedProxies: [] });
    const req = { headers: {}, socket: { remoteAddress: '203.0.113.5' }, ip: '198.51.100.7', app: app('loopback') };
    expect(ipOf(req)).toBe('203.0.113.5');
  });

  it('warns once when trust proxy is true', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const ipOf = createNodeClientIp();
    const req = { headers: {}, socket: { remoteAddress: '203.0.113.5' }, ip: '198.51.100.7', app: app(true) };
    ipOf(req);
    ipOf(req);
    expect(warn).toHaveBeenCalledTimes(1);
  });
});

describe('clientKey and validateIpv6Subnet', () => {
  it('maps a missing address to the shared unknown key', () => {
    expect(clientKey(null)).toBe(UNKNOWN_CLIENT_KEY);
    expect(clientKey('2001:db8:1:2::1', 64)).toBe('2001:db8:1:2::/64');
  });

  it('validates ipv6Subnet', () => {
    expect(validateIpv6Subnet(undefined, 'x')).toBe(56);
    expect(validateIpv6Subnet(false, 'x')).toBe(false);
    expect(() => validateIpv6Subnet(0, 'x')).toThrow(RangeError);
    expect(() => validateIpv6Subnet(129, 'x')).toThrow(RangeError);
    expect(() => validateIpv6Subnet(56.5, 'x')).toThrow(RangeError);
  });
});
