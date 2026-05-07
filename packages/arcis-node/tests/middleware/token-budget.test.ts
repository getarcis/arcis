/**
 * Token-Budget Middleware Tests
 * Tests for src/middleware/token-budget.ts
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Request, Response } from 'express';
import { tokenBudget } from '../../src/middleware/token-budget';
import { mockRequest, mockResponse } from '../setup';

function run(
  middleware: ReturnType<typeof tokenBudget>,
  reqOverrides: Record<string, unknown> = {},
): { req: ReturnType<typeof mockRequest>; res: ReturnType<typeof mockResponse>; next: ReturnType<typeof vi.fn> } {
  const req = mockRequest({ ip: '1.2.3.4', body: { prompt: 'hello world' }, ...reqOverrides });
  const res = mockResponse();
  const next = vi.fn();
  middleware(req as Request, res as Response, next);
  return { req, res, next };
}

describe('tokenBudget middleware', () => {
  let mw: ReturnType<typeof tokenBudget>;
  beforeEach(() => {
    if (mw) mw.close();
  });

  describe('Default behavior (passthrough until budget hit)', () => {
    it('lets safe requests through and increments usage', () => {
      mw = tokenBudget({ maxTokens: 1000 });
      const { res, next } = run(mw, { ip: '10.0.0.1', body: { prompt: 'short' } });
      expect(next).toHaveBeenCalledTimes(1);
      expect(res.status).not.toHaveBeenCalled();
      const inspected = mw.inspect('10.0.0.1');
      expect(inspected?.used).toBeGreaterThan(0);
    });

    it('sets X-Token-Budget-* headers on every response', () => {
      mw = tokenBudget({ maxTokens: 1000 });
      const { res } = run(mw);
      expect(res.setHeader).toHaveBeenCalledWith('X-Token-Budget-Limit', '1000');
      expect(res.setHeader).toHaveBeenCalledWith('X-Token-Budget-Used', '0');
      expect(res.setHeader).toHaveBeenCalledWith('X-Token-Budget-Remaining', '1000');
      expect(res.setHeader).toHaveBeenCalledWith(
        'X-Token-Budget-Reset',
        expect.any(String),
      );
    });
  });

  describe('Budget exhaustion (429)', () => {
    it('returns 429 when projected usage exceeds maxTokens', () => {
      // Use a tiny maxTokens so a single request blows the budget.
      mw = tokenBudget({ maxTokens: 1 });
      // First request charges 3+ tokens (body { prompt: 'hello world' }) so
      // projected exceeds 1 and we get 429 immediately.
      const { res, next } = run(mw, { ip: '5.5.5.5' });
      expect(res.status).toHaveBeenCalledWith(429);
      expect(next).not.toHaveBeenCalled();
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: expect.any(String), maxTokens: 1, retryAfter: expect.any(Number) }),
      );
      expect(res.setHeader).toHaveBeenCalledWith('Retry-After', expect.any(String));
    });

    it('isolates buckets per key (different IPs share no budget)', () => {
      mw = tokenBudget({ maxTokens: 5 });
      // 5 tokens fits ~20 bytes — both small request bodies should pass.
      const a = run(mw, { ip: '1.1.1.1', body: 'hi' });
      const b = run(mw, { ip: '2.2.2.2', body: 'hi' });
      expect(a.next).toHaveBeenCalled();
      expect(b.next).toHaveBeenCalled();
      expect(mw.inspect('1.1.1.1')?.used).toBeLessThanOrEqual(5);
      expect(mw.inspect('2.2.2.2')?.used).toBeLessThanOrEqual(5);
    });
  });

  describe('Per-request cap (413)', () => {
    it('returns 413 when a single request exceeds maxRequestTokens', () => {
      mw = tokenBudget({ maxTokens: 100_000, maxRequestTokens: 2 });
      const { res, next } = run(mw, { body: { prompt: 'this is too long' } });
      expect(res.status).toHaveBeenCalledWith(413);
      expect(next).not.toHaveBeenCalled();
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.any(String),
          requestTokens: expect.any(Number),
          maxRequestTokens: 2,
        }),
      );
    });

    it('does NOT charge the per-window budget when oversize-rejected', () => {
      mw = tokenBudget({ maxTokens: 100_000, maxRequestTokens: 2 });
      const { res } = run(mw, { ip: '7.7.7.7', body: { prompt: 'too big to count' } });
      expect(res.status).toHaveBeenCalledWith(413);
      // Budget should remain untouched for this key
      expect(mw.inspect('7.7.7.7')).toBeNull();
    });
  });

  describe('Custom estimator + key generator', () => {
    it('uses the custom keyGenerator for budget isolation', () => {
      mw = tokenBudget({
        maxTokens: 1,
        keyGenerator: (req) =>
          (req.headers as Record<string, string>)['x-api-key'] ?? 'anon',
      });
      const r1 = run(mw, { headers: { 'x-api-key': 'tenant-A' }, body: 'this body is large enough' });
      const r2 = run(mw, { headers: { 'x-api-key': 'tenant-B' }, body: 'this body is large enough' });
      // Each tenant gets its own budget, so each independently blows the
      // window once, but they don't collide.
      expect(r1.res.status).toHaveBeenCalledWith(429);
      expect(r2.res.status).toHaveBeenCalledWith(429);
      expect(mw.inspect('tenant-A')).not.toBeNull();
      expect(mw.inspect('tenant-B')).not.toBeNull();
    });

    it('uses the custom estimator', () => {
      // Charge a flat 50 tokens per request regardless of body
      mw = tokenBudget({ maxTokens: 100, estimateTokens: () => 50 });
      run(mw, { ip: '9.9.9.9' });
      run(mw, { ip: '9.9.9.9' });
      // Two requests at 50 each = 100 used, exactly at limit
      const inspected = mw.inspect('9.9.9.9');
      expect(inspected?.used).toBe(100);
    });
  });

  describe('Skip', () => {
    it('skips budget enforcement when skip(req) returns true', () => {
      mw = tokenBudget({ maxTokens: 1, skip: (req) => req.path === '/health' });
      const { res, next } = run(mw, { path: '/health', body: 'huge huge huge huge' });
      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });
  });

  describe('Edge cases', () => {
    it('handles empty body and query without crashing', () => {
      mw = tokenBudget({ maxTokens: 100 });
      const req = mockRequest({ ip: '1.1.1.1' });
      // Strip body and query entirely
      delete (req as Record<string, unknown>).body;
      delete (req as Record<string, unknown>).query;
      const res = mockResponse();
      const next = vi.fn();
      mw(req as Request, res as Response, next);
      expect(next).toHaveBeenCalled();
    });

    it('handles circular body without throwing (estimator falls back to 0)', () => {
      mw = tokenBudget({ maxTokens: 100 });
      const cyclic: Record<string, unknown> = { name: 'a' };
      cyclic.self = cyclic;
      const req = mockRequest({ ip: '1.1.1.1', body: cyclic });
      const res = mockResponse();
      const next = vi.fn();
      mw(req as Request, res as Response, next);
      expect(next).toHaveBeenCalled();
    });

    it('inspect() returns null for unknown keys', () => {
      mw = tokenBudget();
      expect(mw.inspect('nobody')).toBeNull();
    });

    it('close() is idempotent and does not throw', () => {
      mw = tokenBudget();
      expect(() => mw.close()).not.toThrow();
      expect(() => mw.close()).not.toThrow();
    });
  });
});
