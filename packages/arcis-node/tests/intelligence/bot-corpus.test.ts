import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { IntelligenceClient } from '../../src/intelligence/client';
import {
  detectBot,
  mergeBotPatterns,
  _resetBotPatternsForTest,
} from '../../src/middleware/bot-detection';
import type { Request } from 'express';

const ENDPOINT = 'https://intel.test';

function reqWithUa(ua: string): Request {
  return { headers: { 'user-agent': ua, accept: 'text/html' } } as unknown as Request;
}

function corpusResponse(entries: unknown[]): Response {
  return new Response(JSON.stringify({ schema_version: '1', count: entries.length, entries }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

describe('mergeBotPatterns', () => {
  afterEach(() => _resetBotPatternsForTest());

  it('classifies a novel UA after merging a corpus entry', () => {
    const ua = 'ArcisTestCrawler-XYZ-9000/1.0';
    expect(detectBot(reqWithUa(ua)).name).toBe(null); // unknown before merge

    const n = mergeBotPatterns([
      { id: 'arcis-test-crawler', category: 'SECURITY_SCANNER', name: 'ArcisTestCrawler', patterns: ['ArcisTestCrawler-XYZ-9000'], forbidden: [] },
    ]);
    expect(n).toBe(1);

    const after = detectBot(reqWithUa(ua));
    expect(after.isBot).toBe(true);
    expect(after.category).toBe('SECURITY_SCANNER');
    expect(after.name).toBe('ArcisTestCrawler');
  });

  it('skips an entry with an uncompilable pattern (fail-open)', () => {
    const n = mergeBotPatterns([
      { id: 'bad', category: 'SCRAPER', name: 'bad', patterns: ['('], forbidden: [] },
      { id: 'good', category: 'SCRAPER', name: 'good', patterns: ['GoodBotXYZ'], forbidden: [] },
    ]);
    expect(n).toBe(1); // only the good one
    expect(detectBot(reqWithUa('GoodBotXYZ/2.0')).name).toBe('good');
  });

  it('reset restores the bundled corpus', () => {
    mergeBotPatterns([{ id: 'temp', category: 'SCRAPER', name: 'temp', patterns: ['TempBotZZZ'], forbidden: [] }]);
    expect(detectBot(reqWithUa('TempBotZZZ')).name).toBe('temp');
    _resetBotPatternsForTest();
    expect(detectBot(reqWithUa('TempBotZZZ')).name).toBe(null);
  });
});

describe('IntelligenceClient.fetchBotCorpus', () => {
  let fetchSpy: ReturnType<typeof vi.fn>;
  beforeEach(() => {
    fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('returns well-formed entries from the snapshot', async () => {
    fetchSpy.mockResolvedValue(
      corpusResponse([
        { id: 'a', category: 'AI_CRAWLER', name: 'A', patterns: ['Abot'], forbidden: [] },
        { id: 'bad', name: 'no-patterns' }, // dropped (missing fields)
      ]),
    );
    const client = new IntelligenceClient({ endpoint: ENDPOINT, cloudDecisions: ['bot-corpus'] });
    const entries = await client.fetchBotCorpus();
    expect(entries).toHaveLength(1);
    expect(entries[0]!.id).toBe('a');
    client.close();
  });

  it('fails open to [] on HTTP error', async () => {
    fetchSpy.mockResolvedValue(new Response('nope', { status: 500 }));
    const onError = vi.fn();
    const client = new IntelligenceClient({ endpoint: ENDPOINT, cloudDecisions: ['bot-corpus'], onError });
    expect(await client.fetchBotCorpus()).toEqual([]);
    expect(onError).toHaveBeenCalledOnce();
    client.close();
  });

  it('fails open to [] on a network error', async () => {
    fetchSpy.mockRejectedValue(new Error('ECONNREFUSED'));
    const client = new IntelligenceClient({ endpoint: ENDPOINT, cloudDecisions: ['bot-corpus'] });
    expect(await client.fetchBotCorpus()).toEqual([]);
    client.close();
  });
});
