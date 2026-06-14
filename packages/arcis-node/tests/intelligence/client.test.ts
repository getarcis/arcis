import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { IntelligenceClient, reputationSeverityTier } from '../../src/intelligence/client';

const ENDPOINT = 'https://intel.test';

function repResponse(body: Record<string, unknown>): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

function makeClient(overrides = {}): IntelligenceClient {
  return new IntelligenceClient({
    endpoint: ENDPOINT,
    apiKey: 'ak_test',
    workspaceId: 'ws1',
    cloudDecisions: ['ip-rep'],
    ...overrides,
  });
}

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('IntelligenceClient', () => {
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchSpy = vi.fn().mockResolvedValue(repResponse({ ip: '8.8.8.8', found: false }));
    vi.stubGlobal('fetch', fetchSpy);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  describe('construction', () => {
    it('throws if endpoint is missing', () => {
      expect(() => new IntelligenceClient({ endpoint: '' })).toThrow(/endpoint/);
    });
  });

  describe('check (cache-first, non-blocking)', () => {
    it('returns found:false on first call and schedules a background refresh', async () => {
      fetchSpy.mockResolvedValue(
        repResponse({ ip: '203.0.113.7', found: true, severity: 6, categories: ['tor'], sources: ['tor-exit'] }),
      );
      const client = makeClient();
      const first = client.check('203.0.113.7');
      expect(first).toEqual({ ip: '203.0.113.7', found: false });

      // Background refresh populates the cache; the next read is a hit.
      await vi.waitFor(() => expect(client.cacheSize).toBe(1));
      const second = client.check('203.0.113.7');
      expect(second.found).toBe(true);
      expect(second.severity).toBe(6);
      client.close();
    });

    it('never looks up private / loopback / unknown IPs', () => {
      const client = makeClient();
      for (const ip of ['127.0.0.1', '10.0.0.5', '192.168.1.1', '::1', 'unknown', '']) {
        expect(client.check(ip)).toEqual({ ip, found: false });
      }
      expect(fetchSpy).not.toHaveBeenCalled();
      client.close();
    });

    it('is inert when cloudDecisions omits ip-rep', () => {
      const client = new IntelligenceClient({ endpoint: ENDPOINT });
      expect(client.check('203.0.113.7')).toEqual({ ip: '203.0.113.7', found: false });
      expect(fetchSpy).not.toHaveBeenCalled();
      client.close();
    });

    it('de-dupes concurrent refreshes for the same IP', async () => {
      const client = makeClient();
      client.check('203.0.113.9');
      client.check('203.0.113.9');
      client.check('203.0.113.9');
      await vi.waitFor(() => expect(fetchSpy).toHaveBeenCalled());
      expect(fetchSpy).toHaveBeenCalledTimes(1);
      client.close();
    });

    it('caches a clean (found:false) verdict so it is not re-queried', async () => {
      const client = makeClient();
      client.check('203.0.113.50');
      await vi.waitFor(() => expect(client.cacheSize).toBe(1));
      // Second check reads cache; no new fetch.
      client.check('203.0.113.50');
      await delay(10);
      expect(fetchSpy).toHaveBeenCalledTimes(1);
      client.close();
    });
  });

  describe('lookup (await, fail-open)', () => {
    it('normalizes a found verdict (snake_case -> camelCase)', async () => {
      fetchSpy.mockResolvedValue(
        repResponse({
          ip: '203.0.113.7',
          found: true,
          severity: 8,
          categories: ['tor', 'abuse'],
          sources: ['tor-exit', 'abuseipdb'],
          first_seen: '2026-06-01',
          last_seen: '2026-06-11',
          matched: '203.0.113.0/24',
        }),
      );
      const client = makeClient();
      const rep = await client.lookup('203.0.113.7');
      expect(rep).toEqual({
        ip: '203.0.113.7',
        found: true,
        severity: 8,
        categories: ['tor', 'abuse'],
        sources: ['tor-exit', 'abuseipdb'],
        firstSeen: '2026-06-01',
        lastSeen: '2026-06-11',
        matched: '203.0.113.0/24',
      });
      client.close();
    });

    it('sends auth + workspace headers and a URL-encoded IP', async () => {
      const client = makeClient();
      await client.lookup('203.0.113.7');
      const [url, init] = fetchSpy.mock.calls[0]!;
      expect(url).toBe('https://intel.test/v1/intel/ip-reputation/203.0.113.7');
      expect(init.headers.authorization).toBe('Bearer ak_test');
      expect(init.headers['x-workspace-id']).toBe('ws1');
      client.close();
    });

    it('fails open on HTTP 500 and calls onError', async () => {
      fetchSpy.mockResolvedValue(new Response('boom', { status: 500 }));
      const onError = vi.fn();
      const client = makeClient({ onError });
      const rep = await client.lookup('203.0.113.7');
      expect(rep).toEqual({ ip: '203.0.113.7', found: false });
      expect(onError).toHaveBeenCalledOnce();
      client.close();
    });

    it('fails open on a network error', async () => {
      fetchSpy.mockRejectedValue(new Error('ECONNREFUSED'));
      const onError = vi.fn();
      const client = makeClient({ onError });
      const rep = await client.lookup('203.0.113.7');
      expect(rep).toEqual({ ip: '203.0.113.7', found: false });
      expect(onError).toHaveBeenCalledOnce();
      client.close();
    });

    it('does not fetch for private IPs', async () => {
      const client = makeClient();
      const rep = await client.lookup('10.1.2.3');
      expect(rep).toEqual({ ip: '10.1.2.3', found: false });
      expect(fetchSpy).not.toHaveBeenCalled();
      client.close();
    });
  });

  describe('cache lifecycle', () => {
    it('evicts least-recently-used beyond cacheMax', async () => {
      const client = makeClient({ cacheMax: 2 });
      for (const ip of ['203.0.113.1', '203.0.113.2', '203.0.113.3']) {
        client.check(ip);
        // serialize so each refresh resolves before the next, keeping
        // insertion order deterministic for the eviction assertion.
        await vi.waitFor(() => expect(fetchSpy).toHaveBeenCalled());
        await delay(5);
      }
      await vi.waitFor(() => expect(client.cacheSize).toBeLessThanOrEqual(2));
      client.close();
    });

    it('re-queries after the TTL expires', async () => {
      const client = makeClient({ cacheTtlMs: 1000 }); // floor is 1000ms
      client.check('203.0.113.7');
      await vi.waitFor(() => expect(client.cacheSize).toBe(1));
      expect(fetchSpy).toHaveBeenCalledTimes(1);
      await delay(1050);
      // Entry is now stale; check schedules a fresh fetch.
      client.check('203.0.113.7');
      await vi.waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2));
      client.close();
    });

    it('check returns found:false and stops fetching after close()', async () => {
      const client = makeClient();
      client.close();
      expect(client.check('203.0.113.7')).toEqual({ ip: '203.0.113.7', found: false });
      await delay(10);
      expect(fetchSpy).not.toHaveBeenCalled();
    });
  });

  describe('reputationSeverityTier', () => {
    it('buckets numeric severity', () => {
      expect(reputationSeverityTier(10)).toBe('critical');
      expect(reputationSeverityTier(9)).toBe('critical');
      expect(reputationSeverityTier(8)).toBe('high');
      expect(reputationSeverityTier(5)).toBe('medium');
      expect(reputationSeverityTier(2)).toBe('low');
      expect(reputationSeverityTier(undefined)).toBe('low');
    });
  });
});
