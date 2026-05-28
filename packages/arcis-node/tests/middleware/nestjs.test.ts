/**
 * NestJS Adapter Tests
 * Tests for src/middleware/nestjs.ts (ArcisMiddleware + ArcisModule)
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Request, Response } from 'express';
import {
  ArcisGuard,
  ArcisMiddleware,
  ArcisModule,
  ARCIS_OPTIONS,
} from '../../src/middleware/nestjs';
import { mockRequest, mockResponse } from '../setup';

function execContext(req: Partial<Request>, res: Partial<Response>): never {
  // Minimal NestJS ExecutionContext stub: only the http path is exercised.
  return {
    switchToHttp: () => ({
      getRequest: () => req,
      getResponse: () => res,
      getNext: () => () => undefined,
    }),
  } as never;
}

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

  it('also exports ArcisGuard for the recommended deny-on-detect path', () => {
    const mod = ArcisModule.forRoot();
    expect(mod.exports).toContain(ArcisGuard);
  });
});

describe('ArcisGuard (NestJS CanActivate adapter)', () => {
  it('returns true for safe input (no threats, no response written)', async () => {
    const guard = new ArcisGuard({ block: true });
    const req = mockRequest({ query: { q: 'hello world' } });
    const res = mockResponse();
    const result = await guard.canActivate(execContext(req, res));
    expect(result).toBe(true);
    expect(res.status).not.toHaveBeenCalledWith(403);
    guard.close();
  });

  it('returns false when the sanitizer writes a 403 for a SQL payload in query', async () => {
    const guard = new ArcisGuard({ block: true });
    // res.headersSent must reflect that a response was written
    const res = mockResponse() as unknown as Response & { headersSent: boolean };
    Object.defineProperty(res, 'headersSent', {
      get(): boolean {
        return (this as { _written?: boolean })._written === true;
      },
      configurable: true,
    });
    (res.status as unknown as ReturnType<typeof vi.fn>).mockImplementation(function (
      this: Response & { _written: boolean },
      code: number,
    ) {
      if (code === 403) (this as { _written: boolean })._written = true;
      return this;
    });
    const req = mockRequest({ query: { q: "'; DROP TABLE users; --" } });
    const result = await guard.canActivate(execContext(req, res));
    expect(result).toBe(false);
    expect(res.status).toHaveBeenCalledWith(403);
    guard.close();
  });

  it('returns false when an XSS payload in body triggers the sanitizer block', async () => {
    const guard = new ArcisGuard({ block: true });
    const res = mockResponse() as unknown as Response & { headersSent: boolean };
    Object.defineProperty(res, 'headersSent', {
      get(): boolean {
        return (this as { _written?: boolean })._written === true;
      },
      configurable: true,
    });
    (res.status as unknown as ReturnType<typeof vi.fn>).mockImplementation(function (
      this: Response & { _written: boolean },
      code: number,
    ) {
      if (code === 403) (this as { _written: boolean })._written = true;
      return this;
    });
    const req = mockRequest({
      body: { comment: '<script>alert(1)</script>' },
      method: 'POST',
    });
    const result = await guard.canActivate(execContext(req, res));
    expect(result).toBe(false);
    expect(res.status).toHaveBeenCalledWith(403);
    guard.close();
  });

  it('exposes close() for OnApplicationShutdown teardown', () => {
    const guard = new ArcisGuard();
    expect(() => guard.close()).not.toThrow();
  });

  it('uses {} when constructed without arguments', () => {
    const guard = new ArcisGuard();
    expect(guard).toBeInstanceOf(ArcisGuard);
    guard.close();
  });
});
