/**
 * NestJS Adapter Tests
 * Tests for src/middleware/nestjs.ts (ArcisMiddleware + ArcisModule)
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Request, Response } from 'express';
import {
  ArcisMiddleware,
  ArcisModule,
  ARCIS_OPTIONS,
} from '../../src/middleware/nestjs';
import { mockRequest, mockResponse } from '../setup';

describe('ArcisMiddleware (NestJS class adapter)', () => {
  let mw: ArcisMiddleware;

  beforeEach(() => {
    mw = new ArcisMiddleware();
  });

  it('exposes a NestMiddleware-shaped use(req, res, next)', () => {
    expect(typeof mw.use).toBe('function');
    expect(mw.use.length).toBe(3);
  });

  it('sequentially walks the underlying arcis() handler stack and calls next() once at the end', async () => {
    const req = mockRequest({ body: { ok: 1 } });
    const res = mockResponse();
    const next = vi.fn();

    mw.use(req as Request, res as Response, next);
    await new Promise((r) => setImmediate(r));

    // next() must be called exactly once when all internal handlers pass through
    expect(next).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledWith();
  });

  it('sanitizes XSS in req.body via the underlying middleware stack', async () => {
    const req = mockRequest({ body: { name: '<script>alert(1)</script>' } });
    const res = mockResponse();
    const next = vi.fn();

    mw.use(req as Request, res as Response, next);
    await new Promise((r) => setImmediate(r));

    expect((req.body as { name: string }).name).not.toContain('<script>');
    expect(next).toHaveBeenCalled();
  });

  it('sets security headers via the underlying middleware stack', async () => {
    const req = mockRequest();
    const res = mockResponse();
    const next = vi.fn();

    mw.use(req as Request, res as Response, next);
    await new Promise((r) => setImmediate(r));

    // headers middleware should have called setHeader on the response
    expect(res.setHeader).toHaveBeenCalled();
  });

  it('blocks attack payloads when constructed with block:true', async () => {
    const blocking = new ArcisMiddleware({ block: true });
    const req = mockRequest({ body: { q: '<script>alert(1)</script>' } });
    const res = mockResponse();
    const next = vi.fn();

    blocking.use(req as Request, res as Response, next);
    await new Promise((r) => setImmediate(r));

    // Blocking sanitizer responds 403 directly; next() must NOT be called with no error
    expect(res.status).toHaveBeenCalledWith(403);
    blocking.close();
  });

  it('forwards errors from internal handlers via next(err)', async () => {
    // Build a middleware that injects a sanitizer with mode:'reject' so SQL
    // injection produces a SecurityThreatError surfaced via next(err).
    const rejecting = new ArcisMiddleware({
      sanitize: { mode: 'reject', sql: true },
      // Disable rate limiter so close() side-effects don't interfere
      rateLimit: false,
    });
    const req = mockRequest({ body: { q: "'; DROP TABLE users; --" } });
    const res = mockResponse();
    const next = vi.fn();

    rejecting.use(req as Request, res as Response, next);
    await new Promise((r) => setImmediate(r));

    expect(next).toHaveBeenCalled();
    const arg = (next.mock.calls[0] ?? [])[0];
    expect(arg).toBeInstanceOf(Error);
    rejecting.close();
  });

  it('close() releases rate-limiter intervals without throwing', () => {
    const m = new ArcisMiddleware();
    expect(() => m.close()).not.toThrow();
  });
});

describe('ArcisModule.forRoot() (NestJS DynamicModule)', () => {
  it('returns a DynamicModule literal pointing at ArcisModule', () => {
    const mod = ArcisModule.forRoot();
    expect(mod.module).toBe(ArcisModule);
  });

  it('exports ArcisMiddleware so other modules can consume it', () => {
    const mod = ArcisModule.forRoot();
    expect(mod.exports).toContain(ArcisMiddleware);
  });

  it('provides ARCIS_OPTIONS with the user-supplied options', () => {
    const opts = { block: true, rateLimit: { max: 7 } as const };
    const mod = ArcisModule.forRoot(opts);
    const optionsProvider = (mod.providers ?? []).find(
      (p): p is { provide: symbol; useValue: unknown } =>
        typeof p === 'object' && p !== null && 'provide' in p && p.provide === ARCIS_OPTIONS,
    );
    expect(optionsProvider).toBeDefined();
    expect(optionsProvider?.useValue).toBe(opts);
  });

  it('provides ArcisMiddleware via useFactory + inject(ARCIS_OPTIONS)', () => {
    const mod = ArcisModule.forRoot();
    const factoryProvider = (mod.providers ?? []).find(
      (p): p is { provide: typeof ArcisMiddleware; useFactory: Function; inject: unknown[] } =>
        typeof p === 'object' && p !== null && 'provide' in p && p.provide === ArcisMiddleware,
    );
    expect(factoryProvider).toBeDefined();
    expect(typeof factoryProvider?.useFactory).toBe('function');
    expect(factoryProvider?.inject).toEqual([ARCIS_OPTIONS]);
  });

  it('useFactory builds a working ArcisMiddleware from injected options', () => {
    const opts = { block: false };
    const mod = ArcisModule.forRoot(opts);
    const factoryProvider = (mod.providers ?? []).find(
      (p): p is { provide: typeof ArcisMiddleware; useFactory: (o: unknown) => unknown } =>
        typeof p === 'object' && p !== null && 'provide' in p && p.provide === ArcisMiddleware,
    ) as { useFactory: (o: unknown) => ArcisMiddleware };

    const instance = factoryProvider.useFactory(opts);
    expect(instance).toBeInstanceOf(ArcisMiddleware);
    expect(typeof instance.use).toBe('function');
    instance.close();
  });

  it('defaults options to {} when forRoot() is called without arguments', () => {
    const mod = ArcisModule.forRoot();
    const optionsProvider = (mod.providers ?? []).find(
      (p): p is { provide: symbol; useValue: unknown } =>
        typeof p === 'object' && p !== null && 'provide' in p && p.provide === ARCIS_OPTIONS,
    );
    expect(optionsProvider?.useValue).toEqual({});
  });
});
