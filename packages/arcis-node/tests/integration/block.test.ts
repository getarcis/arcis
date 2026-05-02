/**
 * Block-mode integration tests.
 *
 * When arcis() is constructed with `block: true`, attack payloads in
 * req.body, req.query, or req.params must produce a 403 SECURITY_THREAT
 * before reaching the route handler.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Request, Response } from 'express';
import arcis from '../../src/index';
import { createTestServer, TestServer } from '../setup';

describe('Integration: arcis({ block: true })', () => {
  let server: TestServer;
  let stack: ReturnType<typeof arcis>;

  beforeAll(async () => {
    stack = arcis({ block: true, rateLimit: false });
    server = await createTestServer((app) => {
      app.use(...stack);
      app.post('/echo', (req: Request, res: Response) => {
        res.json({ received: req.body });
      });
      app.get('/items', (_req: Request, res: Response) => {
        res.json({ ok: true });
      });
    });
  });

  afterAll(async () => {
    stack.close();
    await server.close();
  });

  it('passes clean GET requests', async () => {
    const r = await fetch(server.url +'/items');
    expect(r.status).toBe(200);
  });

  it('passes clean POST bodies', async () => {
    const r = await fetch(server.url +'/echo', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'alice' }),
    });
    expect(r.status).toBe(200);
  });

  const cases: Array<[string, string, string]> = [
    ['xss', JSON.stringify({ q: '<script>alert(1)</script>' }), 'xss'],
    ['sql', JSON.stringify({ q: "1' OR '1'='1'" }), 'sql'],
    ['path', JSON.stringify({ q: '../../etc/passwd' }), 'path'],
    ['command', JSON.stringify({ q: '$(whoami)' }), 'command'],
    ['nosql', JSON.stringify({ $where: 'function(){return true}' }), 'nosql'],
    // Raw JSON — JSON.stringify drops __proto__ since it's an inherited slot.
    ['prototype', '{"__proto__":{"polluted":true}}', 'prototype'],
    ['ssti', JSON.stringify({ q: '{{ 7 * 7 }}' }), 'ssti'],
    ['xxe', JSON.stringify({ q: '<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>' }), 'xxe'],
  ];

  for (const [label, rawBody, expectedVector] of cases) {
    it(`blocks ${label} payload with 403`, async () => {
      const r = await fetch(server.url +'/echo', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: rawBody,
      });
      expect(r.status).toBe(403);
      const body = (await r.json()) as { code: string; vector: string };
      expect(body.code).toBe('SECURITY_THREAT');
      expect(body.vector).toBe(expectedVector);
    });
  }

  it('blocks XSS in query string', async () => {
    const r = await fetch(server.url +'/items?q=' + encodeURIComponent('<script>alert(1)</script>'));
    expect(r.status).toBe(403);
    const body = (await r.json()) as { vector: string };
    expect(body.vector).toBe('xss');
  });
});

describe('Integration: CSRF + bot marker tagging', () => {
  it('CSRF deny sets req.__arcis with vector=csrf', async () => {
    // Direct unit-style test: invoke the middleware against a fake req/res.
    const { csrfProtection } = await import('../../src/index');
    const mw = csrfProtection();
    const req = {
      method: 'POST',
      path: '/x',
      url: '/x',
      headers: { cookie: '' },
      cookies: {},
    } as unknown as Request;
    let captured: number | undefined;
    let body: unknown;
    const res = {
      status(code: number) { captured = code; return this; },
      json(b: unknown) { body = b; return this; },
    } as unknown as Response;
    mw(req, res, () => undefined);
    expect(captured).toBe(403);
    expect((req as { __arcis?: { vector?: string } }).__arcis?.vector).toBe('csrf');
    expect(body).toMatchObject({ error: expect.any(String) });
  });

  it('bot deny sets req.__arcis with vector=bot', async () => {
    const { botProtection } = await import('../../src/index');
    const mw = botProtection({ deny: ['SCRAPER'], defaultAction: 'allow' });
    const req = {
      method: 'GET',
      headers: { 'user-agent': 'curl/8.0.0' },
    } as unknown as Request;
    let captured: number | undefined;
    const res = {
      status(code: number) { captured = code; return this; },
      json() { return this; },
    } as unknown as Response;
    mw(req, res, () => undefined);
    expect(captured).toBe(403);
    expect((req as { __arcis?: { vector?: string } }).__arcis?.vector).toBe('bot');
  });
});

describe('Integration: arcis() default (no block)', () => {
  let server: TestServer;
  let stack: ReturnType<typeof arcis>;

  beforeAll(async () => {
    stack = arcis({ rateLimit: false });
    server = await createTestServer((app) => {
      app.use(...stack);
      app.post('/echo', (req: Request, res: Response) => {
        res.json({ received: req.body });
      });
    });
  });

  afterAll(async () => {
    stack.close();
    await server.close();
  });

  it('does not 403 on attack payloads (silent sanitize preserved)', async () => {
    const r = await fetch(server.url +'/echo', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ q: "<script>alert(1)</script>" }),
    });
    expect(r.status).toBe(200);
  });
});
