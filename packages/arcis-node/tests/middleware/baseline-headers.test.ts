/**
 * Baseline header profile: shared wire fixtures plus a differential suite
 * against the real helmet package. Every helmet_compatible fixture is
 * re-checked against Helmet on each run, so the fixtures cannot drift from
 * Helmet's actual output.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import helmet from 'helmet';
import type { Request, Response } from 'express';
import { createHeaders } from '../../src/middleware/headers';
import { dangerouslyDisableDefaultSrc } from '../../src/middleware/csp';
import type { HeaderOptions } from '../../src/core/types';

interface FixtureCase {
  name: string;
  helmet_compatible: boolean;
  options: Record<string, unknown>;
  expected_headers: Record<string, string>;
  expected_absent: string[];
  removes_x_powered_by: boolean;
}

interface InvalidCase {
  name: string;
  helmet_compatible: boolean;
  options: Record<string, unknown>;
  error_contains: string;
}

const vectors = JSON.parse(
  readFileSync(resolve(__dirname, '../../../../spec/TEST_VECTORS.json'), 'utf-8'),
);
const baseline = vectors.security_headers.baseline as {
  cases: FixtureCase[];
  invalid: InvalidCase[];
  nonce: { options: Record<string, unknown>; script_src_pattern: string };
  route_header_wins: { route_sets: Record<string, string>; expected_headers: Record<string, string> };
};

type Middleware = (req: Request, res: Response, next: (err?: unknown) => void) => void;

interface Captured {
  headers: Record<string, string>;
  locals: Record<string, unknown>;
  error: unknown;
}

/** Run a Connect-style middleware against a minimal response that records headers. */
function run(middleware: Middleware, request: Partial<Request> = {}): Captured {
  const headers = new Map<string, [string, string]>([['x-powered-by', ['X-Powered-By', 'Express']]]);
  const locals: Record<string, unknown> = {};
  const res = {
    locals,
    setHeader(name: string, value: string) {
      headers.set(name.toLowerCase(), [name, String(value)]);
    },
    removeHeader(name: string) {
      headers.delete(name.toLowerCase());
    },
    getHeader(name: string) {
      return headers.get(name.toLowerCase())?.[1];
    },
  } as unknown as Response;
  const req = { headers: {}, secure: false, method: 'GET', url: '/', ...request } as Request;
  let error: unknown;
  middleware(req, res, (err?: unknown) => {
    error = err;
  });
  const result: Record<string, string> = {};
  for (const [, [name, value]] of headers) result[name] = value;
  return { headers: result, locals, error };
}

const arcis = (options: Record<string, unknown>): Middleware =>
  createHeaders({ profile: 'baseline', ...options } as HeaderOptions) as unknown as Middleware;
const realHelmet = (options: Record<string, unknown>): Middleware =>
  helmet(options as Parameters<typeof helmet>[0]) as unknown as Middleware;

function lowerKeys(headers: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
}

describe('baseline profile: shared fixtures', () => {
  it('loads the fixture set', () => {
    expect(baseline.cases.length).toBeGreaterThanOrEqual(27);
    expect(baseline.invalid.length).toBeGreaterThanOrEqual(30);
  });

  describe.each(baseline.cases.map((c) => [c.name, c] as const))('%s', (_name, fixture) => {
    it('produces the expected headers', () => {
      const { headers, error } = run(arcis(fixture.options));
      expect(error).toBeUndefined();
      const got = lowerKeys(headers);
      for (const [name, value] of Object.entries(fixture.expected_headers)) {
        expect(got[name.toLowerCase()], name).toBe(value);
      }
      for (const name of fixture.expected_absent) {
        expect(got[name.toLowerCase()], name).toBeUndefined();
      }
      expect('x-powered-by' in got).toBe(!fixture.removes_x_powered_by);
    });

    if (fixture.helmet_compatible) {
      it('matches real helmet header for header', () => {
        const ours = lowerKeys(run(arcis(fixture.options)).headers);
        const theirs = lowerKeys(run(realHelmet(fixture.options)).headers);
        expect(ours).toEqual(theirs);
      });
    }
  });

  describe.each(baseline.invalid.map((c) => [c.name, c] as const))('rejects %s', (_name, fixture) => {
    it('throws at construction', () => {
      expect(() => arcis(fixture.options)).toThrow(fixture.error_contains);
    });

    if (fixture.helmet_compatible) {
      it('is also rejected by helmet', () => {
        expect(() => realHelmet(fixture.options)).toThrow(fixture.error_contains);
      });
    }
  });
});

describe('baseline profile: differential against helmet', () => {
  it("removes default-src with each library's own dangerouslyDisableDefaultSrc", () => {
    const disable = (symbol: symbol) => ({ contentSecurityPolicy: { directives: { defaultSrc: symbol } } });
    const ours = run(arcis(disable(dangerouslyDisableDefaultSrc))).headers;
    const theirs = run(realHelmet(disable(helmet.contentSecurityPolicy.dangerouslyDisableDefaultSrc))).headers;
    expect(ours['Content-Security-Policy']).toBe(theirs['Content-Security-Policy']);
    expect(ours['Content-Security-Policy']).not.toContain('default-src');
  });

  const differential: Array<[string, Record<string, unknown>]> = [
    ['Set values', { contentSecurityPolicy: { directives: { imgSrc: new Set(["'self'", 'cdn.example.com']) } } }],
    ['many options together', {
      contentSecurityPolicy: { useDefaults: false, reportOnly: true, directives: { defaultSrc: "'none'", connectSrc: ["'self'", 'wss://api.example.com'] } },
      crossOriginEmbedderPolicy: { policy: 'unsafe-none' },
      referrerPolicy: { policy: ['no-referrer', 'strict-origin-when-cross-origin'] },
      hsts: { maxAge: 15552000, includeSubDomains: false, preload: true },
      frameguard: { action: 'DENY' },
      dnsPrefetchControl: { allow: false },
      permittedCrossDomainPolicies: { permittedPolicies: 'by-content-type' },
      hidePoweredBy: true,
      noSniff: true,
      ieNoOpen: false,
      xssFilter: false,
    }],
    ['true for every option', {
      contentSecurityPolicy: true, crossOriginEmbedderPolicy: true, crossOriginOpenerPolicy: true,
      crossOriginResourcePolicy: true, originAgentCluster: true, referrerPolicy: true,
      strictTransportSecurity: true, xContentTypeOptions: true, xDnsPrefetchControl: true,
      xDownloadOptions: true, xFrameOptions: true, xPermittedCrossDomainPolicies: true,
      xPoweredBy: true, xXssProtection: true,
    }],
  ];

  it.each(differential)('%s', (_name, options) => {
    const ours = run(arcis(options));
    const theirs = run(realHelmet(options));
    expect(ours.error).toBeUndefined();
    expect(lowerKeys(ours.headers)).toEqual(lowerKeys(theirs.headers));
  });

  it('evaluates function values per response with (req, res), like helmet', () => {
    const options = {
      contentSecurityPolicy: {
        directives: { scriptSrc: ["'self'", (_req: unknown, res: Response) => `'nonce-${res.locals.n}'`] },
      },
    };
    const withNonce = (middleware: Middleware) => {
      const before: Middleware = (req, res, next) => {
        res.locals.n = 'abc123';
        middleware(req, res, next);
      };
      return run(before).headers['Content-Security-Policy'];
    };
    expect(withNonce(arcis(options))).toBe(withNonce(realHelmet(options)));
    expect(withNonce(arcis(options))).toContain("script-src 'self' 'nonce-abc123'");
  });

  it.each([
    ['an unquoted keyword', () => 'nonce-abc123', 'should be quoted'],
    ['an injected directive', () => 'evil.example.com; script-src *', 'invalid directive value'],
  ])('passes a function value returning %s to next(err), like helmet', (_name, fn, message) => {
    const options = { contentSecurityPolicy: { directives: { scriptSrc: ["'self'", fn] } } };
    for (const middleware of [arcis(options), realHelmet(options)]) {
      const { error, headers } = run(middleware);
      expect(String((error as Error)?.message)).toContain(message);
      expect(headers['Content-Security-Policy']).toBeUndefined();
    }
  });

  it('passes an exception thrown by a function value to next(err)', () => {
    const boom = new Error('boom');
    const options = { contentSecurityPolicy: { directives: { scriptSrc: [() => { throw boom; }] } } };
    expect(run(arcis(options)).error).toBe(boom);
  });
});

describe('baseline profile: nonce extension', () => {
  const pattern = new RegExp(baseline.nonce.script_src_pattern);

  function scriptSrc(csp: string): string {
    return csp.split(';').find((d) => d.startsWith('script-src ')) ?? '';
  }

  it('exposes a fresh per-response nonce that matches the header', () => {
    const middleware = arcis(baseline.nonce.options);
    const first = run(middleware);
    const second = run(middleware);

    const firstMatch = pattern.exec(scriptSrc(first.headers['Content-Security-Policy']!));
    const secondMatch = pattern.exec(scriptSrc(second.headers['Content-Security-Policy']!));
    expect(firstMatch?.[1]).toBe(first.locals.cspNonce);
    expect(secondMatch?.[1]).toBe(second.locals.cspNonce);
    expect(first.locals.cspNonce).not.toBe(second.locals.cspNonce);
  });

  it('leaves every other directive and header equal to the defaults', () => {
    const defaults = baseline.cases.find((c) => c.name === 'defaults')!.expected_headers;
    const { headers } = run(arcis(baseline.nonce.options));
    const withoutNonce = headers['Content-Security-Policy']!.replace(/ 'nonce-[^']+'/, '');
    expect(withoutNonce).toBe(defaults['Content-Security-Policy']);
    expect(headers['Content-Security-Policy']).toContain("style-src 'self' https: 'unsafe-inline'");
    for (const [name, value] of Object.entries(defaults)) {
      if (name !== 'Content-Security-Policy') expect(headers[name], name).toBe(value);
    }
  });

  it('lets function values read the nonce from res.locals', () => {
    const { headers, locals } = run(
      arcis({
        contentSecurityPolicy: {
          nonce: true,
          directives: { styleSrc: ["'self'", (_req: unknown, res: Response) => `'nonce-${res.locals.cspNonce}'`] },
        },
      }),
    );
    expect(headers['Content-Security-Policy']).toContain(`style-src 'self' 'nonce-${locals.cspNonce}'`);
  });

  it('does not set res.locals.cspNonce when the extension is off', () => {
    expect(run(arcis({})).locals.cspNonce).toBeUndefined();
  });
});

describe('baseline profile: request handling', () => {
  it('sends HSTS over plain HTTP, like helmet', () => {
    expect(run(arcis({}), { secure: false }).headers['Strict-Transport-Security']).toBe(
      'max-age=31536000; includeSubDomains',
    );
  });

  it('sets headers before the handler, so a route-set header wins', () => {
    const route = baseline.route_header_wins;
    const withRoute: Middleware = (req, res, next) =>
      arcis({})(req, res, (err) => {
        for (const [name, value] of Object.entries(route.route_sets)) res.setHeader(name, value);
        next(err);
      });
    const { headers } = run(withRoute);
    for (const [name, value] of Object.entries(route.expected_headers)) expect(headers[name]).toBe(value);
  });

  it('rejects an unknown profile name', () => {
    expect(() => createHeaders({ profile: 'strict' } as unknown as HeaderOptions)).toThrow('unknown profile');
  });

  it('keeps the legacy profile as the default', () => {
    const { headers } = run(createHeaders() as unknown as Middleware);
    expect(headers['X-Frame-Options']).toBe('DENY');
    expect(headers['Cache-Control']).toBeDefined();
    expect(headers['X-Download-Options']).toBeUndefined();
  });
});

describe('baseline profile: real Express server through arcis()', () => {
  async function serve(app: import('express').Express): Promise<{ url: string; close: () => Promise<void> }> {
    const server = await new Promise<import('node:http').Server>((resolveServer) => {
      const s = app.listen(0, '127.0.0.1', () => resolveServer(s));
    });
    const { port } = server.address() as import('node:net').AddressInfo;
    return {
      url: `http://127.0.0.1:${port}`,
      close: () => new Promise((done) => server.close(() => done())),
    };
  }

  it('sends the Helmet default headers on the wire and exposes the nonce to the route', async () => {
    const { default: express } = await import('express');
    const { arcis: arcisMiddleware } = await import('../../src/middleware/main');
    const app = express();
    app.use(
      arcisMiddleware({
        headers: { profile: 'baseline', contentSecurityPolicy: { nonce: true } },
        rateLimit: false,
      }),
    );
    app.get('/', (_req, res) => {
      res.json({ nonce: res.locals.cspNonce });
    });

    const server = await serve(app);
    try {
      const response = await fetch(server.url + '/');
      const body = (await response.json()) as { nonce: string };
      const defaults = baseline.cases.find((c) => c.name === 'defaults')!.expected_headers;
      for (const [name, value] of Object.entries(defaults)) {
        if (name === 'Content-Security-Policy') continue;
        expect(response.headers.get(name), name).toBe(value);
      }
      expect(response.headers.get('content-security-policy')).toContain(`script-src 'self' 'nonce-${body.nonce}'`);
      expect(response.headers.get('x-powered-by')).toBeNull();
      expect(response.headers.get('cache-control')).toBeNull();
    } finally {
      await server.close();
    }
  });
});
