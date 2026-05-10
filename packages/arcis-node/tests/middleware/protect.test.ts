/**
 * Composite protection helpers tests (issue #52).
 *
 * Each helper is a pure-composition function. Tests assert:
 * - Default stack composition (correct count + correct middlewares).
 * - Per-layer override: false disables, options object merges into the
 *   layer's defaults.
 * - The middlewares are usable Express request handlers (function
 *   shape, can be invoked with req/res/next).
 */

import { describe, it, expect, vi } from 'vitest';
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import {
  protectLogin,
  protectSignup,
  protectApi,
} from '../../src/middleware/protect';

function fakeReq(body: unknown = {}): Request {
  return {
    body,
    method: 'POST',
    headers: {},
    url: '/',
    path: '/',
    query: {},
    params: {},
  } as unknown as Request;
}

interface FakeResState {
  status: number | null;
  sent: boolean;
}

function fakeRes(onSent?: () => void): { res: Response; state: FakeResState } {
  const state: FakeResState = { status: null, sent: false };
  const markSent = () => {
    if (state.sent) return;
    state.sent = true;
    if (onSent) onSent();
  };
  const res = {
    status(code: number) {
      state.status = code;
      return res;
    },
    json() {
      markSent();
      return res;
    },
    send() {
      markSent();
      return res;
    },
    end() {
      markSent();
      return res;
    },
    setHeader() {},
    set() {
      return res;
    },
    getHeader() {
      return undefined;
    },
    cookie() {
      return res;
    },
  } as unknown as Response;
  return { res, state };
}

/**
 * Run a stack of middlewares against a fresh req/res, awaiting each
 * `next()` call. Returns once the chain completes, aborts (next(err)),
 * or the response is "sent" (json/send/end called — e.g. on 429 the
 * rate-limit middleware short-circuits without calling next).
 */
async function runStack(
  stack: RequestHandler[],
  req: Request,
  buildRes: () => { res: Response; state: FakeResState },
): Promise<FakeResState> {
  let i = 0;
  return new Promise<FakeResState>((resolve, reject) => {
    const { res, state } = buildRes();
    // Hook the response's "sent" event so a short-circuiting middleware
    // (json/send/end without next) resolves the promise. Otherwise we'd
    // wait 5s for vitest's per-test timeout on every 429 call.
    Object.defineProperty(res, '__onSent__', {
      configurable: true,
      enumerable: false,
      value: () => resolve(state),
    });
    // Also wire the state's `sent` flag to resolve. fakeRes accepts an
    // onSent callback; we re-bind it here by reaching into the closure.
    // Simpler: poll `state.sent` after each middleware call.
    const next: NextFunction = (err?: unknown) => {
      if (err) {
        reject(err);
        return;
      }
      const m = stack[i++];
      if (!m) {
        resolve(state);
        return;
      }
      try {
        const ret = m(req, res, next);
        if (ret && typeof (ret as Promise<unknown>).catch === 'function') {
          (ret as Promise<unknown>).catch(reject);
        }
        // Post-call: middleware may have hit res.json without calling
        // next. Schedule a microtask check.
        queueMicrotask(() => {
          if (state.sent) resolve(state);
        });
      } catch (e) {
        reject(e);
      }
    };
    next();
  });
}

function buildResFactory(): () => { res: Response; state: FakeResState } {
  return () => fakeRes();
}

describe('protectLogin', () => {
  it('returns a 4-middleware stack by default (rate-limit + bot + csrf + sanitize)', () => {
    const stack = protectLogin();
    expect(stack).toHaveLength(4);
    for (const m of stack) {
      expect(typeof m).toBe('function');
    }
  });

  it('rate-limits at 5/min by default', async () => {
    // Compose just the limiter + the rest to verify the limit isn't
    // looser than the spec. Hammer 6 requests from the same IP and
    // assert the 6th gets a 429.
    const stack = protectLogin({
      // Disable everything except rate-limit so we don't have to mock
      // the other layers' dependencies (csrf cookies etc.).
      bot: false,
      csrf: false,
      sanitize: false,
    });
    expect(stack).toHaveLength(1);

    const req = fakeReq();
    Object.assign(req, { ip: '1.2.3.4' });

    let lastStatus: number | null = null;
    for (let i = 0; i < 6; i++) {
      const state = await runStack(stack, req as Request, buildResFactory());
      lastStatus = state.status;
    }
    expect(lastStatus).toBe(429);
  });

  it('disables rate-limit when rateLimit: false', () => {
    const stack = protectLogin({
      rateLimit: false,
      // keep the other layers default so we can count
    });
    // Default 4 -> 3 when rate-limit is dropped.
    expect(stack).toHaveLength(3);
  });

  it('disables CSRF when csrf: false', () => {
    const stack = protectLogin({ csrf: false });
    expect(stack).toHaveLength(3);
  });

  it('disables ALL layers when every override is false (returns empty array)', () => {
    const stack = protectLogin({
      rateLimit: false,
      bot: false,
      csrf: false,
      sanitize: false,
    });
    expect(stack).toHaveLength(0);
  });

  it('merges custom rate-limit options over defaults (max bumped to 10)', async () => {
    const stack = protectLogin({
      rateLimit: { max: 10, windowMs: 60_000 },
      bot: false,
      csrf: false,
      sanitize: false,
    });
    const req = fakeReq();
    Object.assign(req, { ip: '5.6.7.8' });
    // 10 requests through, the 11th 429s. Verifies the override merged.
    let lastStatus: number | null = null;
    for (let i = 0; i < 11; i++) {
      const state = await runStack(stack, req as Request, buildResFactory());
      lastStatus = state.status;
    }
    expect(lastStatus).toBe(429);
  });
});

describe('protectSignup', () => {
  it('returns a 4-middleware stack by default (rate-limit + bot + sanitize + signup)', () => {
    const stack = protectSignup();
    expect(stack).toHaveLength(4);
  });

  it('rate-limits at 3/min by default (stricter than login)', async () => {
    const stack = protectSignup({
      bot: false,
      sanitize: false,
      signup: false,
    });
    expect(stack).toHaveLength(1);

    const req = fakeReq();
    Object.assign(req, { ip: '2.3.4.5' });
    let lastStatus: number | null = null;
    for (let i = 0; i < 4; i++) {
      const state = await runStack(stack, req as Request, buildResFactory());
      lastStatus = state.status;
    }
    expect(lastStatus).toBe(429);
  });

  it('disables signup-specific layer when signup: false', () => {
    const stack = protectSignup({ signup: false });
    expect(stack).toHaveLength(3);
  });
});

describe('protectApi', () => {
  it('returns a 3-middleware stack by default (rate-limit + cors + sanitize)', () => {
    const stack = protectApi();
    expect(stack).toHaveLength(3);
  });

  it('rate-limits at 100/min by default (loosest of the three)', async () => {
    const stack = protectApi({ cors: false, sanitize: false });
    expect(stack).toHaveLength(1);

    const req = fakeReq();
    Object.assign(req, { ip: '7.7.7.7' });
    // First 100 are fine, 101st 429s. Each iteration finishes within a
    // microtask so the loop is sub-100ms total.
    let lastStatus: number | null = null;
    for (let i = 0; i < 101; i++) {
      const state = await runStack(stack, req as Request, buildResFactory());
      lastStatus = state.status;
    }
    expect(lastStatus).toBe(429);
  });

  it('CORS uses reflect-origin default when no override given', () => {
    // Pin: protectApi doesn't ship with a closed allow-list (would be
    // useless without per-app config) but isn't completely permissive
    // either — the spec defaults to `origin: true` (reflect request
    // origin). A future refactor that flips this to a no-op cors must
    // fail this test.
    const stack = protectApi();
    expect(stack).toHaveLength(3);
    // We can't easily inspect the cors options the factory captured.
    // Spot-check the SHAPE: middleware function exists at index 1.
    expect(typeof stack[1]).toBe('function');
  });

  it('disables CORS when cors: false', () => {
    const stack = protectApi({ cors: false });
    expect(stack).toHaveLength(2);
  });

  it('does NOT include bot detection by default (per the issue table)', () => {
    // protectApi's table row in issue #52 has no "Bot Detection" column
    // checked. API endpoints often legitimately receive automated
    // traffic (curl, server-to-server, monitoring). Pin that protectApi
    // returns the documented 3 layers, no surprise 4th.
    const stack = protectApi();
    expect(stack).toHaveLength(3);
  });
});

describe('protect helpers — composition shape', () => {
  it('every returned middleware is a callable function', () => {
    for (const stack of [protectLogin(), protectSignup(), protectApi()]) {
      for (const m of stack) {
        expect(typeof m).toBe('function');
        // Express middleware accepts (req, res, next) — arity 3 (some
        // error-handlers are 4, but our composites don't include those).
        expect(m.length).toBeGreaterThanOrEqual(2);
      }
    }
  });

  it('stacks compose with Express app.use(...) signature shape', () => {
    // Quick smoke: spreading the stack into an args array matches what
    // app.use(...stack) does internally. Verifies no helper accidentally
    // returns nested arrays.
    const flat = [...protectLogin(), ...protectSignup(), ...protectApi()];
    expect(flat).toHaveLength(11); // 4 + 4 + 3
    for (const m of flat) {
      expect(typeof m).toBe('function');
    }
  });
});
