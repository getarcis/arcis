/**
 * §1.4 — protectLogin / protectSignup / protectApi optionally consult
 * a CorrelationWindow. Mirrors
 * `tests/middleware/test_protect_correlation_wiring.py`.
 */
import { describe, it, expect } from 'vitest';
import { protectLogin, protectSignup, protectApi } from '../../src/middleware/protect';
import { CorrelationWindow } from '../../src/middleware/correlation';

function makeReq(overrides: Partial<any> = {}): any {
  return {
    method: 'POST',
    url: '/login',
    path: '/login',
    body: {},
    headers: {},
    socket: { remoteAddress: '1.2.3.4' },
    ...overrides,
  };
}

function makeRes() {
  const calls: any = {};
  const res: any = {
    status(code: number) {
      calls.status = code;
      return res;
    },
    json(payload: any) {
      calls.body = payload;
      return res;
    },
  };
  return { res, calls };
}

function runStack(handlers: any[], req: any, res: any): boolean {
  let advanced = true;
  for (const h of handlers) {
    advanced = false;
    h(req, res, () => {
      advanced = true;
    });
    if (!advanced) return false;
  }
  return advanced;
}

describe('protect helpers + correlation window', () => {
  it('records each login attempt in the supplied window', () => {
    const window = new CorrelationWindow();
    const stack = protectLogin({
      rateLimit: false,
      bot: false,
      csrf: false,
      sanitize: false,
      correlation: { window },
    });
    const req = makeReq({ body: { username: 'alice@x.com' } });
    const { res } = makeRes();
    runStack(stack, req, res);
    expect(window.stats().eventsInWindow).toBe(1);
  });

  it('blocks credential stuffing on /login', () => {
    const window = new CorrelationWindow({
      credentialStuffingDistinctValues: 3,
      windowSeconds: 60,
    });
    const stack = protectLogin({
      rateLimit: false,
      bot: false,
      csrf: false,
      sanitize: false,
      correlation: { window },
    });
    for (let i = 0; i < 2; i++) {
      const req = makeReq({ body: { username: `user${i}@x.com` } });
      const { res } = makeRes();
      expect(runStack(stack, req, res)).toBe(true);
    }
    const req = makeReq({ body: { username: 'user2@x.com' } });
    const { res, calls } = makeRes();
    expect(runStack(stack, req, res)).toBe(false);
    expect(calls.status).toBe(429);
    expect(calls.body.credential_stuffing).toBe(true);
  });

  it('records api requests under the api vector', () => {
    const window = new CorrelationWindow();
    const stack = protectApi({
      rateLimit: false,
      cors: false,
      sanitize: false,
      correlation: { window },
    });
    const req = makeReq({
      url: '/api/data',
      path: '/api/data',
      body: { hello: 'world' },
    });
    const { res } = makeRes();
    runStack(stack, req, res);
    expect(window.stats().eventsInWindow).toBe(1);
  });

  it('blocks scanner pattern across login + api on the same IP', () => {
    const window = new CorrelationWindow({
      scannerDistinctVectors: 2,
      scannerMinRequests: 3,
      windowSeconds: 60,
    });
    const loginStack = protectLogin({
      rateLimit: false,
      bot: false,
      csrf: false,
      sanitize: false,
      correlation: { window },
    });
    const apiStack = protectApi({
      rateLimit: false,
      cors: false,
      sanitize: false,
      correlation: { window },
    });
    // 1: login
    let { res } = makeRes();
    expect(
      runStack(loginStack, makeReq({ body: { username: 'a@x.com' } }), res),
    ).toBe(true);
    // 2: api (different vector tag)
    ({ res } = makeRes());
    expect(
      runStack(
        apiStack,
        makeReq({ url: '/api/data', path: '/api/data', body: {} }),
        res,
      ),
    ).toBe(true);
    // 3: third request crosses the threshold
    const { res: res3, calls } = makeRes();
    expect(
      runStack(
        apiStack,
        makeReq({ url: '/api/other', path: '/api/other', body: {} }),
        res3,
      ),
    ).toBe(false);
    expect(calls.status).toBe(429);
    expect(calls.body.scanner).toBe(true);
  });

  it('signup helper also takes correlation wiring', () => {
    const window = new CorrelationWindow();
    const stack = protectSignup({
      rateLimit: false,
      bot: false,
      sanitize: false,
      signup: false,
      correlation: { window },
    });
    const req = makeReq({ url: '/signup', path: '/signup', body: { email: 'a@x.com' } });
    const { res } = makeRes();
    runStack(stack, req, res);
    expect(window.stats().eventsInWindow).toBe(1);
  });

  it('omits correlation layer entirely when no option is passed', () => {
    const stack = protectLogin({
      rateLimit: false,
      bot: false,
      csrf: false,
      sanitize: false,
    });
    // With every layer disabled, the stack is empty.
    expect(stack.length).toBe(0);
  });
});
