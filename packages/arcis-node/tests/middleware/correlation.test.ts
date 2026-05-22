/**
 * Stateful per-IP correlation window (improvements.md §1.3).
 *
 * Mirrors `tests/middleware/test_correlation.py` in the Python SDK.
 * Both SDKs must accept the same base corpus per Pattern 7.
 */
import { describe, it, expect } from 'vitest';
import { CorrelationWindow } from '../../src/middleware/correlation';

describe('CorrelationWindow.record', () => {
  it('returns a detections object', () => {
    const w = new CorrelationWindow();
    const out = w.record('1.1.1.1', 'xss', '/api', 'POST');
    expect(out.requestsInWindow).toBe(1);
    expect(out.distinctVectors).toBe(1);
    expect(out.scanner).toBe(false);
  });

  it('treats empty IP as a no-op', () => {
    const w = new CorrelationWindow();
    const out = w.record('', 'xss', '/api');
    expect(out.requestsInWindow).toBe(0);
    expect(w.stats().trackedIps).toBe(0);
  });

  it('uses the explicit `now` when provided', () => {
    const w = new CorrelationWindow({ windowSeconds: 60 });
    w.record('a', 'xss', '/x', 'GET', undefined, 1000);
    w.record('a', 'sql', '/x', 'GET', undefined, 1001);
    const out = w.record('a', 'path', '/x', 'GET', undefined, 1002);
    expect(out.distinctVectors).toBe(3);
    expect(out.requestsInWindow).toBe(3);
  });
});

describe('scanner detection', () => {
  it('needs distinct vectors AND minimum requests', () => {
    const w = new CorrelationWindow({
      scannerDistinctVectors: 3,
      scannerMinRequests: 10,
      windowSeconds: 60,
    });
    let out;
    for (let i = 0; i < 10; i++) {
      out = w.record('a', 'xss', '/x', 'GET', undefined, 1000 + i);
    }
    expect(out!.scanner).toBe(false);

    const w2 = new CorrelationWindow({
      scannerDistinctVectors: 3,
      scannerMinRequests: 10,
      windowSeconds: 60,
    });
    const vectors = ['xss', 'sql', 'path', 'command'];
    let out2;
    for (let i = 0; i < 20; i++) {
      out2 = w2.record('a', vectors[i % vectors.length], '/x', 'GET', undefined, 1000 + i);
    }
    expect(out2!.scanner).toBe(true);
    expect(out2!.distinctVectors).toBeGreaterThanOrEqual(3);
  });

  it('resets when the window expires', () => {
    const w = new CorrelationWindow({
      scannerDistinctVectors: 2,
      scannerMinRequests: 3,
      windowSeconds: 10,
    });
    w.record('a', 'xss', '/x', 'GET', undefined, 1000);
    w.record('a', 'sql', '/x', 'GET', undefined, 1000.5);
    let out = w.record('a', 'path', '/x', 'GET', undefined, 1001);
    expect(out.scanner).toBe(true);
    out = w.record('a', 'xss', '/x', 'GET', undefined, 1100);
    expect(out.scanner).toBe(false);
  });
});

describe('credential stuffing detection', () => {
  it('counts distinct values per route', () => {
    const w = new CorrelationWindow({
      credentialStuffingDistinctValues: 5,
      windowSeconds: 60,
    });
    let out;
    for (let i = 0; i < 4; i++) {
      out = w.record('a', 'login', '/login', 'POST', `user${i}@x.com`, 1000 + i);
    }
    expect(out!.credentialStuffing).toBe(false);
    out = w.record('a', 'login', '/login', 'POST', 'user4@x.com', 1005);
    expect(out!.credentialStuffing).toBe(true);
  });

  it('does not cross routes', () => {
    const w = new CorrelationWindow({
      credentialStuffingDistinctValues: 3,
      windowSeconds: 60,
    });
    w.record('a', 'login', '/login', 'POST', 'x@y.com', 1000);
    w.record('a', 'login', '/login', 'POST', 'y@y.com', 1001);
    const out = w.record('a', 'login', '/admin/login', 'POST', 'z@y.com', 1002);
    expect(out.credentialStuffing).toBe(false);
  });

  it('does not count repeats of the same value', () => {
    const w = new CorrelationWindow({
      credentialStuffingDistinctValues: 3,
      windowSeconds: 60,
    });
    let out;
    for (let i = 0; i < 10; i++) {
      out = w.record('a', 'login', '/login', 'POST', 'same@x.com', 1000 + i);
    }
    expect(out!.credentialStuffing).toBe(false);
  });
});

describe('race window detection', () => {
  it('detects pre-registered pair within threshold', () => {
    const w = new CorrelationWindow({
      windowSeconds: 60,
      raceWindowMs: 200,
      racePairs: [['/transfer', '/balance']],
    });
    w.record('a', 'request', '/transfer', 'POST', undefined, 1000);
    const out = w.record('a', 'request', '/balance', 'GET', undefined, 1000.15);
    expect(out.raceWindow).toBe(true);
  });

  it('rejects pair outside threshold', () => {
    const w = new CorrelationWindow({
      windowSeconds: 60,
      raceWindowMs: 200,
      racePairs: [['/transfer', '/balance']],
    });
    w.record('a', 'request', '/transfer', 'POST', undefined, 1000);
    const out = w.record('a', 'request', '/balance', 'GET', undefined, 1000.5);
    expect(out.raceWindow).toBe(false);
  });

  it('supports ad-hoc detectRaceWindow without pre-registration', () => {
    const w = new CorrelationWindow({ windowSeconds: 60, raceWindowMs: 200 });
    w.record('a', 'request', '/foo', 'POST', undefined, 1000);
    w.record('a', 'request', '/bar', 'GET', undefined, 1000.05);
    expect(w.detectRaceWindow('a', ['/foo', '/bar'], 1000.06)).toBe(true);
    expect(w.detectRaceWindow('a', ['/foo', '/baz'], 1000.06)).toBe(false);
  });
});

describe('eviction and memory bounds', () => {
  it('evicts oldest IP when maxIps is exceeded', () => {
    const w = new CorrelationWindow({ maxIps: 3 });
    w.record('a', 'xss', '/x');
    w.record('b', 'xss', '/x');
    w.record('c', 'xss', '/x');
    w.record('d', 'xss', '/x');
    expect(w.stats().trackedIps).toBe(3);
    expect(w.detectScanner('a')).toBe(false);
  });

  it('enforces per-IP event cap', () => {
    const w = new CorrelationWindow({ maxEventsPerIp: 5, windowSeconds: 3600 });
    for (let i = 0; i < 20; i++) {
      w.record('a', 'xss', '/x', 'GET', undefined, 1000 + i);
    }
    expect(w.stats().eventsInWindow).toBe(5);
  });

  it('drops events outside the window', () => {
    const w = new CorrelationWindow({ windowSeconds: 10 });
    w.record('a', 'xss', '/x', 'GET', undefined, 1000);
    w.record('a', 'sql', '/x', 'GET', undefined, 1003);
    let out = w.record('a', 'path', '/x', 'GET', undefined, 1009);
    expect(out.requestsInWindow).toBe(3);
    out = w.record('a', 'command', '/x', 'GET', undefined, 1109);
    expect(out.requestsInWindow).toBe(1);
  });
});

describe('reset and read-only API', () => {
  it('clears state for a single IP', () => {
    const w = new CorrelationWindow();
    w.record('a', 'xss', '/x');
    w.record('b', 'xss', '/x');
    w.reset('a');
    expect(w.detectScanner('a')).toBe(false);
    expect(w.stats().trackedIps).toBe(1);
  });

  it('clears every IP when called without an argument', () => {
    const w = new CorrelationWindow();
    w.record('a', 'xss', '/x');
    w.record('b', 'xss', '/x');
    w.reset();
    expect(w.stats().trackedIps).toBe(0);
  });

  it('detectScanner does not mutate state', () => {
    const w = new CorrelationWindow({
      scannerDistinctVectors: 2,
      scannerMinRequests: 3,
    });
    for (const v of ['xss', 'sql', 'path']) {
      w.record('a', v, '/x', 'GET', undefined, 1000);
    }
    const before = w.stats().eventsInWindow;
    w.detectScanner('a', 1001);
    expect(w.stats().eventsInWindow).toBe(before);
  });
});

describe('constructor validation', () => {
  it('rejects non-positive windowSeconds', () => {
    expect(() => new CorrelationWindow({ windowSeconds: 0 })).toThrow();
  });
  it('rejects maxIps < 1', () => {
    expect(() => new CorrelationWindow({ maxIps: 0 })).toThrow();
  });
  it('rejects maxEventsPerIp < 1', () => {
    expect(() => new CorrelationWindow({ maxEventsPerIp: 0 })).toThrow();
  });
});

describe('distinctValues bookkeeping', () => {
  it('counts only the current route', () => {
    const w = new CorrelationWindow({ windowSeconds: 60 });
    w.record('a', 'login', '/login', 'POST', 'x@y.com', 1000);
    w.record('a', 'login', '/admin/login', 'POST', 'y@y.com', 1001);
    const out = w.record('a', 'login', '/login', 'POST', 'z@y.com', 1002);
    expect(out.distinctValues).toBe(2);
  });
});
