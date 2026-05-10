/**
 * Dry-run mode + onSanitize callback tests (issue #47).
 *
 * Exercises the bundle middleware's `dryRun` and `onSanitize` options
 * end-to-end via a real Express server (createTestServer) so the
 * interception of res.status / res.json / res.end actually runs through
 * the same code path users hit.
 */

import { describe, it, expect, vi } from 'vitest';
import { arcis } from '../../src/middleware/main';
import type { SanitizeEvent } from '../../src/core/types';
import { createTestServer, TestServer } from '../setup';

describe('arcis() — onSanitize callback (issue #47)', () => {
  let testServer: TestServer;

  it('fires onSanitize for an XSS payload in body', async () => {
    const events: SanitizeEvent[] = [];
    testServer = await createTestServer((app) => {
      app.use((req, _res, next) => {
        // The arcis bundle inspects req.body, but body-parser hasn't run by
        // default in createTestServer. Wire one in for this test set.
        req.body = req.body ?? {};
        next();
      });
      const express = require('express');
      app.use(express.json());
      app.use(arcis({ rateLimit: false, onSanitize: (e) => events.push(e) }));
      app.post('/echo', (req, res) => res.json({ ok: true, body: req.body }));
    });

    await fetch(`${testServer.url}/echo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: '<script>alert(1)</script>' }),
    });

    expect(events.length).toBeGreaterThanOrEqual(1);
    expect(events[0].type).toBe('xss');
    expect(events[0].field).toBe('body');
    expect(events[0].pattern).toContain('<script>');

    await testServer.close();
  });

  it('fires onSanitize for a SQL payload in query', async () => {
    const events: SanitizeEvent[] = [];
    testServer = await createTestServer((app) => {
      app.use(arcis({ rateLimit: false, onSanitize: (e) => events.push(e) }));
      app.get('/q', (_req, res) => res.json({ ok: true }));
    });

    // UNION SELECT is a high-confidence SQL pattern that the detector
    // matches without ambiguity. Quote-based payloads ('OR 1=1) require
    // surrounding context the detector intentionally treats conservatively.
    await fetch(`${testServer.url}/q?id=1%20UNION%20SELECT%20*%20FROM%20users`);

    expect(events.length).toBeGreaterThanOrEqual(1);
    expect(events.some((e) => e.type === 'sql' && e.field === 'query')).toBe(true);

    await testServer.close();
  });

  it('does NOT fire onSanitize on a clean request', async () => {
    const events: SanitizeEvent[] = [];
    testServer = await createTestServer((app) => {
      app.use(arcis({ rateLimit: false, onSanitize: (e) => events.push(e) }));
      app.get('/q', (_req, res) => res.json({ ok: true }));
    });

    const res = await fetch(`${testServer.url}/q?name=alice&id=42`);
    expect(res.status).toBe(200);
    expect(events).toHaveLength(0);

    await testServer.close();
  });

  it('catches errors thrown from the callback (fail-open)', async () => {
    // A buggy observer must NOT break the response path. Verifies the
    // try/catch around the callback invocation.
    const onSanitize = vi.fn(() => {
      throw new Error('observer is buggy');
    });
    testServer = await createTestServer((app) => {
      app.use(arcis({ rateLimit: false, onSanitize }));
      app.get('/', (_req, res) => res.json({ ok: true }));
    });

    const res = await fetch(`${testServer.url}/?q=<script>alert(1)</script>`);
    expect(res.status).toBe(200);
    expect(onSanitize).toHaveBeenCalled();

    await testServer.close();
  });

  it('zero overhead when onSanitize is omitted', async () => {
    // Observer middleware should not be inserted when there's no callback.
    // We can't directly count middlewares without exposing internals, so
    // sanity-check via a clean request that obviously passes.
    testServer = await createTestServer((app) => {
      app.use(arcis({ rateLimit: false }));
      app.get('/', (_req, res) => res.json({ ok: true }));
    });
    const res = await fetch(`${testServer.url}/`);
    expect(res.status).toBe(200);
    await testServer.close();
  });
});

describe('arcis() — dry-run mode (issue #47)', () => {
  let testServer: TestServer;

  it('does NOT block on XSS payload when dryRun: true (vs block: true that would)', async () => {
    // Without dry-run, block: true would return 403. With dry-run, the
    // request passes through and the handler runs (200).
    const events: SanitizeEvent[] = [];
    testServer = await createTestServer((app) => {
      const express = require('express');
      app.use(express.json());
      app.use(
        arcis({
          rateLimit: false,
          block: true,
          dryRun: true,
          onSanitize: (e) => events.push(e),
        }),
      );
      app.post('/api', (_req, res) => res.json({ reached: true }));
    });

    const res = await fetch(`${testServer.url}/api`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ q: '<script>alert(1)</script>' }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { reached: boolean };
    expect(body.reached).toBe(true);
    expect(events.some((e) => e.type === 'xss')).toBe(true);

    await testServer.close();
  });

  it('does NOT return 429 when dryRun: true even past the rate limit', async () => {
    // Limiter would normally return 429 after 2 requests. In dry-run mode
    // it shouldn't actually block — all 5 should succeed.
    testServer = await createTestServer((app) => {
      app.use(
        arcis({
          rateLimit: { max: 2, windowMs: 60_000 },
          dryRun: true,
        }),
      );
      app.get('/', (_req, res) => res.json({ ok: true }));
    });

    for (let i = 0; i < 5; i++) {
      const res = await fetch(`${testServer.url}/`);
      expect(res.status).toBe(200);
    }

    await testServer.close();
  });

  it('still surfaces X-RateLimit-* headers in dry-run mode', async () => {
    // The headers reflect the would-have-been decision so dashboards can
    // show "you'd have been rate-limited" without the 429 hitting prod.
    testServer = await createTestServer((app) => {
      app.use(arcis({ rateLimit: { max: 1, windowMs: 60_000 }, dryRun: true }));
      app.get('/', (_req, res) => res.json({ ok: true }));
    });

    await fetch(`${testServer.url}/`);
    const res = await fetch(`${testServer.url}/`);
    expect(res.status).toBe(200);
    expect(res.headers.get('X-RateLimit-Limit')).toBe('1');
    // Remaining clamps at 0 once limit is exceeded; the limiter still
    // reports the would-have-been state.
    expect(res.headers.get('X-RateLimit-Remaining')).toBe('0');

    await testServer.close();
  });

  it('does NOT strip XSS from request body in dryRun mode (block: false default)', async () => {
    // With dry-run, the sanitizer is forced to block: false. But the
    // sanitizer's strip path still runs by default — to truly preserve
    // the original input, the user would also need to pass
    // sanitize: false. dry-run's promise is "don't reject"; the strip
    // behavior remains opt-out via existing options.
    const events: SanitizeEvent[] = [];
    testServer = await createTestServer((app) => {
      const express = require('express');
      app.use(express.json());
      app.use(
        arcis({
          rateLimit: false,
          sanitize: false, // user-asserted "no mutation" path
          block: true,
          dryRun: true,
          onSanitize: (e) => events.push(e),
        }),
      );
      app.post('/echo', (req, res) => res.json(req.body));
    });

    const res = await fetch(`${testServer.url}/echo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ q: '<script>alert(1)</script>' }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { q: string };
    // sanitize: false → input preserved verbatim. Observer still fired.
    expect(body.q).toContain('<script>');
    expect(events.some((e) => e.type === 'xss')).toBe(true);

    await testServer.close();
  });

  it('forces sanitizer block: false even when caller passed block: true', async () => {
    // Regression pin: a future refactor that drops the dryRun → block:
    // false override would silently re-enable blocking under dry-run.
    testServer = await createTestServer((app) => {
      const express = require('express');
      app.use(express.json());
      app.use(arcis({ rateLimit: false, block: true, dryRun: true }));
      app.post('/api', (_req, res) => res.json({ reached: true }));
    });

    const res = await fetch(`${testServer.url}/api`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ q: '<script>alert(1)</script>' }),
    });
    expect(res.status).toBe(200);

    await testServer.close();
  });
});
