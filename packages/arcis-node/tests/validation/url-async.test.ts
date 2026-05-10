/**
 * Async SSRF guard tests (sdk-vectors.md #31, issue #50).
 *
 * Tests inject a fake `lookup` function rather than monkey-patching
 * `node:dns`, so they run deterministically without touching the
 * resolver.
 */

import { describe, it, expect } from 'vitest';
import {
  validateUrlAsync,
  pinnedDnsLookup,
  safeFollowRedirect,
  type DnsLookup,
  type LookupAddress,
} from '../../src/validation/url-async';

function fakeLookup(map: Record<string, string[]>): DnsLookup {
  return async (hostname) => {
    const ips = map[hostname];
    if (!ips) {
      const err = new Error(`getaddrinfo ENOTFOUND ${hostname}`);
      throw err;
    }
    return ips.map<LookupAddress>((a) => ({ address: a, family: a.includes(':') ? 6 : 4 }));
  };
}

describe('validateUrlAsync', () => {
  describe('Sync delegation', () => {
    it('returns the sync verdict when string-pattern validation already fails', async () => {
      const r = await validateUrlAsync('http://127.0.0.1/');
      expect(r.safe).toBe(false);
      expect(r.reason).toMatch(/loopback/);
      // Did not need DNS — no resolvedIps populated.
      expect(r.resolvedIps).toBeUndefined();
    });

    it('rejects disallowed protocols before DNS', async () => {
      const r = await validateUrlAsync('file:///etc/passwd');
      expect(r.safe).toBe(false);
      expect(r.reason).toMatch(/protocol/);
    });

    it('rejects credentials in URL before DNS', async () => {
      const r = await validateUrlAsync('http://user:pass@example.com/');
      expect(r.safe).toBe(false);
      expect(r.reason).toMatch(/credentials/);
    });

    it('skips DNS for literal IPv4 hostnames', async () => {
      // 8.8.8.8 is public and the sync check passes. No DNS lookup
      // should happen — pass a lookup that throws to assert.
      const lookup: DnsLookup = async () => {
        throw new Error('lookup should not be called for literal IPs');
      };
      const r = await validateUrlAsync('http://8.8.8.8/', { lookup });
      expect(r.safe).toBe(true);
      expect(r.resolvedIp).toBeUndefined();
    });

    it('skips DNS for literal IPv6 hostnames', async () => {
      const lookup: DnsLookup = async () => {
        throw new Error('lookup should not be called');
      };
      const r = await validateUrlAsync('http://[2001:4860:4860::8888]/', { lookup });
      expect(r.safe).toBe(true);
    });
  });

  describe('DNS-resolved private IP rejection (the TOCTOU fix)', () => {
    it('rejects when DNS resolves to a private IP', async () => {
      const lookup = fakeLookup({ 'evil.com': ['10.0.0.1'] });
      const r = await validateUrlAsync('http://evil.com/', { lookup });
      expect(r.safe).toBe(false);
      expect(r.reason).toMatch(/10\.0\.0\.1/);
      expect(r.reason).toMatch(/private/);
      expect(r.resolvedIps).toEqual(['10.0.0.1']);
    });

    it('rejects when DNS resolves to a loopback IP', async () => {
      const lookup = fakeLookup({ 'rebind.example': ['127.0.0.1'] });
      const r = await validateUrlAsync('http://rebind.example/', { lookup });
      expect(r.safe).toBe(false);
      expect(r.reason).toMatch(/127\.0\.0\.1/);
      expect(r.reason).toMatch(/loopback/);
    });

    it('rejects when DNS resolves to AWS metadata link-local', async () => {
      const lookup = fakeLookup({ 'aws.poison.tld': ['169.254.169.254'] });
      const r = await validateUrlAsync('http://aws.poison.tld/', { lookup });
      expect(r.safe).toBe(false);
      expect(r.reason).toMatch(/169\.254/);
    });

    it('rejects when DNS resolves to an IPv6 loopback', async () => {
      const lookup = fakeLookup({ 'rebind6.example': ['::1'] });
      const r = await validateUrlAsync('http://rebind6.example/', { lookup });
      expect(r.safe).toBe(false);
      expect(r.reason).toMatch(/::1|loopback|IPv6/);
    });

    it('rejects when ANY of multiple resolved IPs is private (default fail-closed)', async () => {
      // Mixed-answer DNS: one public, one internal. Default contract
      // fails closed because the connection picker (kernel, libc,
      // browser) might pick the internal one.
      const lookup = fakeLookup({ 'mixed.example': ['1.2.3.4', '10.0.0.1'] });
      const r = await validateUrlAsync('http://mixed.example/', { lookup });
      expect(r.safe).toBe(false);
      expect(r.reason).toMatch(/10\.0\.0\.1/);
      expect(r.resolvedIps).toEqual(['1.2.3.4', '10.0.0.1']);
    });

    it('with acceptFirstPublic: true, accepts when AT LEAST ONE IP is public', async () => {
      const lookup = fakeLookup({ 'mixed.example': ['1.2.3.4', '10.0.0.1'] });
      const r = await validateUrlAsync('http://mixed.example/', {
        lookup,
        acceptFirstPublic: true,
      });
      expect(r.safe).toBe(true);
      expect(r.resolvedIp).toBe('1.2.3.4');
      expect(r.resolvedIps).toEqual(['1.2.3.4', '10.0.0.1']);
    });

    it('with acceptFirstPublic: true, still rejects when ALL IPs are private', async () => {
      const lookup = fakeLookup({ 'all-bad.example': ['10.0.0.1', '127.0.0.1'] });
      const r = await validateUrlAsync('http://all-bad.example/', {
        lookup,
        acceptFirstPublic: true,
      });
      expect(r.safe).toBe(false);
      expect(r.reason).toMatch(/all resolved IPs/);
    });
  });

  describe('Public DNS happy path', () => {
    it('accepts a hostname that resolves to a public IP and returns the pinned IP', async () => {
      const lookup = fakeLookup({ 'api.example.com': ['93.184.216.34'] });
      const r = await validateUrlAsync('https://api.example.com/data', { lookup });
      expect(r.safe).toBe(true);
      expect(r.resolvedIp).toBe('93.184.216.34');
      expect(r.resolvedIps).toEqual(['93.184.216.34']);
    });

    it('accepts a hostname with multiple public answers and pins to the first', async () => {
      const lookup = fakeLookup({
        'cdn.example.com': ['93.184.216.34', '198.51.100.1'],
      });
      const r = await validateUrlAsync('https://cdn.example.com/', { lookup });
      expect(r.safe).toBe(true);
      expect(r.resolvedIp).toBe('93.184.216.34');
      expect(r.resolvedIps?.length).toBe(2);
    });

    it('accepts an IPv6 public address from DNS', async () => {
      const lookup = fakeLookup({ 'v6.example.com': ['2606:2800:220:1::cafe'] });
      const r = await validateUrlAsync('https://v6.example.com/', { lookup });
      expect(r.safe).toBe(true);
      expect(r.resolvedIp).toBe('2606:2800:220:1::cafe');
    });
  });

  describe('Allowlist / blocklist interaction', () => {
    it('respects allowedHosts and skips DNS', async () => {
      // The allowedHosts contract is "trust this hostname unconditionally."
      // Skipping DNS makes that contract honest — we promised to trust it.
      const lookup: DnsLookup = async () => {
        throw new Error('lookup should not be called');
      };
      const r = await validateUrlAsync('http://internal-allowed.svc/', {
        lookup,
        allowedHosts: ['internal-allowed.svc'],
      });
      expect(r.safe).toBe(true);
    });

    it('rejects blockedHosts at the sync stage (no DNS)', async () => {
      const lookup: DnsLookup = async () => {
        throw new Error('lookup should not be called');
      };
      const r = await validateUrlAsync('http://forbidden.svc/', {
        lookup,
        blockedHosts: ['forbidden.svc'],
      });
      expect(r.safe).toBe(false);
      expect(r.reason).toMatch(/blocked host/);
    });
  });

  describe('Failure modes', () => {
    it('returns a failure result when DNS lookup throws', async () => {
      const lookup: DnsLookup = async () => {
        throw new Error('getaddrinfo ENOTFOUND nowhere.invalid');
      };
      const r = await validateUrlAsync('http://nowhere.invalid/', { lookup });
      expect(r.safe).toBe(false);
      expect(r.reason).toMatch(/DNS lookup failed/);
      expect(r.reason).toMatch(/ENOTFOUND/);
    });

    it('returns a failure result when DNS returns no addresses', async () => {
      const lookup: DnsLookup = async () => [];
      const r = await validateUrlAsync('http://empty.example/', { lookup });
      expect(r.safe).toBe(false);
      expect(r.reason).toMatch(/no addresses/);
    });

    it('rejects malformed URLs even before sync check', async () => {
      const r = await validateUrlAsync('not a url');
      expect(r.safe).toBe(false);
    });
  });
});

describe('pinnedDnsLookup', () => {
  it('returns a callback that resolves any hostname to the pinned IPv4', () => {
    const lookup = pinnedDnsLookup('203.0.113.5');
    let captured: { err: unknown; address: string; family: number } | null = null;
    lookup('any.host', {}, (err, address, family) => {
      captured = { err, address, family };
    });
    expect(captured!.err).toBeNull();
    expect(captured!.address).toBe('203.0.113.5');
    expect(captured!.family).toBe(4);
  });

  it('returns family=6 for IPv6 pins', () => {
    const lookup = pinnedDnsLookup('2606:2800:220:1::cafe');
    let captured: { address: string; family: number } | null = null;
    lookup('any', {}, (_err, address, family) => {
      captured = { address, family };
    });
    expect(captured!.family).toBe(6);
  });

  it('throws TypeError on empty IP (developer mistake)', () => {
    expect(() => pinnedDnsLookup('')).toThrow(TypeError);
    expect(() => pinnedDnsLookup('   ')).toThrow(TypeError);
  });
});

describe('safeFollowRedirect', () => {
  it('runs the async guard against the new absolute URL', async () => {
    const lookup = fakeLookup({ 'next.example.com': ['1.2.3.4'] });
    const r = await safeFollowRedirect(
      'https://api.example.com/v1/things/1',
      'https://next.example.com/',
      { lookup },
    );
    expect(r.safe).toBe(true);
    expect(r.resolvedIp).toBe('1.2.3.4');
  });

  it('resolves a relative Location against the previous URL', async () => {
    // The new path is relative — without resolving against `prev`,
    // we would get an "invalid URL" error and miss the real check.
    const lookup = fakeLookup({ 'api.example.com': ['1.2.3.4'] });
    const r = await safeFollowRedirect(
      'https://api.example.com/v1/things/1',
      '/v2/things/1',
      { lookup },
    );
    expect(r.safe).toBe(true);
  });

  it('rejects a redirect that points at a private IP after DNS', async () => {
    // The classic redirect-to-internal: server you trust 30xs you to
    // a hostname that resolves to an internal address.
    const lookup = fakeLookup({ 'internal.poison.tld': ['10.0.0.1'] });
    const r = await safeFollowRedirect(
      'https://api.example.com/v1/redirect',
      'http://internal.poison.tld/admin',
      { lookup },
    );
    expect(r.safe).toBe(false);
    expect(r.reason).toMatch(/10\.0\.0\.1|private/);
  });

  it('rejects a redirect to a literal cloud-metadata IP', async () => {
    const r = await safeFollowRedirect(
      'https://api.example.com/v1/redirect',
      'http://169.254.169.254/latest/meta-data/',
    );
    expect(r.safe).toBe(false);
    expect(r.reason).toMatch(/169\.254/);
  });

  it('rejects an empty Location header', async () => {
    const r = await safeFollowRedirect('https://api.example.com/', '');
    expect(r.safe).toBe(false);
    expect(r.reason).toMatch(/empty/);
  });

  it('rejects a malformed Location', async () => {
    const r = await safeFollowRedirect('https://api.example.com/', 'http://[bad-uri');
    expect(r.safe).toBe(false);
    expect(r.reason).toMatch(/invalid redirect/);
  });
});
