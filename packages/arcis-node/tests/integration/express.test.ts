/**
 * Express Integration Tests for @arcis/node
 *
 * These tests spin up real Express servers and make actual HTTP requests
 * to verify Arcis protections work correctly end-to-end.
 */

import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import type { Request, Response } from 'express';
import arcis, {
  createSanitizer,
  createRateLimiter,
  createHeaders,
  validate,
  errorHandler,
  createSafeLogger,
} from '../../src/index';
import { createTestServer, TestServer, XSS_VECTORS, SQL_VECTORS, PATH_VECTORS } from '../setup';

describe('Integration: Full Arcis Middleware', () => {
  let testServer: TestServer;
  let arcisMiddleware: ReturnType<typeof arcis>;

  beforeAll(async () => {
    arcisMiddleware = arcis({ rateLimit: { max: 100, windowMs: 60000 } });

    try {
      testServer = await createTestServer((app) => {
        app.use(...arcisMiddleware);

        app.post('/echo', (req: Request, res: Response) => {
          res.json({ received: req.body, keys: Object.keys(req.body) });
        });

        app.get('/ping', (_req: Request, res: Response) => {
          res.json({ pong: true });
        });
      });
    } catch (err) {
      arcisMiddleware.close();
      throw err;
    }
  });

  afterAll(async () => {
    arcisMiddleware?.close();
    await testServer?.close();
  });

  it('should apply all security headers', async () => {
    // Simulate HTTPS via x-forwarded-proto so HSTS header is included.
    const res = await fetch(`${testServer.url}/ping`, {
      headers: { 'x-forwarded-proto': 'https' },
    });

    expect(res.headers.get('Content-Security-Policy')).toBeTruthy();
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(res.headers.get('X-Frame-Options')).toBe('DENY');
    expect(res.headers.get('X-XSS-Protection')).toBe('0');
    expect(res.headers.get('Strict-Transport-Security')).toContain('max-age=');
    expect(res.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');
    expect(res.headers.get('X-Powered-By')).toBeNull();
  });

  it('should set rate limit headers', async () => {
    const res = await fetch(`${testServer.url}/ping`);
    
    expect(res.headers.get('X-RateLimit-Limit')).toBe('100');
    expect(res.headers.get('X-RateLimit-Remaining')).toBeTruthy();
    expect(res.headers.get('X-RateLimit-Reset')).toBeTruthy();
  });

  it('should sanitize XSS in request body', async () => {
    const res = await fetch(`${testServer.url}/echo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: '<script>alert("xss")</script>' }),
    });
    
    const data = await res.json();
    expect(data.received.name).not.toContain('<script>');
  });

  it('should sanitize SQL injection in request body', async () => {
    const res = await fetch(`${testServer.url}/echo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: "'; DROP TABLE users; --" }),
    });

    // Default arcis() uses reject mode — SQL injection returns 400.
    // arcis() does not include errorHandler, so the response may be HTML (Express default).
    // We verify: (a) status is 400, (b) the /echo route was NOT reached (no JSON body).
    expect(res.status).toBe(400);
    const body = await res.text();
    // The echo route returns { received, keys } — if sanitizer blocked correctly,
    // that JSON must not be present in the response.
    expect(body).not.toContain('"received"');
  });

  it('should block prototype pollution', async () => {
    const res = await fetch(`${testServer.url}/echo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        __proto__: { admin: true },
        constructor: { prototype: { admin: true } },
        name: 'test' 
      }),
    });
    
    const data = await res.json();
    expect(data.keys).not.toContain('__proto__');
    expect(data.keys).not.toContain('constructor');
    expect(data.keys).toContain('name');
  });

  it('should block NoSQL injection operators', async () => {
    const res = await fetch(`${testServer.url}/echo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        $gt: '',
        $where: 'function() { return true }',
        name: 'test' 
      }),
    });
    
    const data = await res.json();
    expect(data.received.$gt).toBeUndefined();
    expect(data.received.$where).toBeUndefined();
    expect(data.received.name).toBe('test');
  });
});

describe('Integration: Sanitizer Middleware', () => {
  let testServer: TestServer;

  beforeAll(async () => {
    testServer = await createTestServer((app) => {
      app.use(createSanitizer({ mode: 'sanitize' }));

      app.post('/body', (req: Request, res: Response) => {
        res.json({ body: req.body });
      });

      app.get('/query', (req: Request, res: Response) => {
        res.json({ query: req.query });
      });

      app.get('/params/:id', (req: Request, res: Response) => {
        res.json({ params: req.params });
      });
    });
  });

  afterAll(async () => {
    await testServer?.close();
  });

  it('should sanitize body - XSS vectors', async () => {
    for (const { input, check } of XSS_VECTORS) {
      const res = await fetch(`${testServer.url}/body`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value: input }),
      });
      
      const data = await res.json();
      expect(check(data.body.value), `Failed for input: ${input}`).toBe(true);
    }
  });

  it('should sanitize body - SQL injection vectors', async () => {
    for (const input of SQL_VECTORS) {
      const res = await fetch(`${testServer.url}/body`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: input }),
      });
      
      const data = await res.json();
      const sanitized = data.body.query.toUpperCase();
      
      expect(sanitized).not.toContain('DROP');
      expect(sanitized).not.toContain('SELECT');
      expect(sanitized).not.toContain('DELETE');
      expect(sanitized).not.toContain('UNION');
    }
  });

  it('should sanitize body - path traversal vectors', async () => {
    for (const input of PATH_VECTORS) {
      const res = await fetch(`${testServer.url}/body`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: input }),
      });
      
      const data = await res.json();
      expect(data.body.path).not.toContain('../');
      expect(data.body.path).not.toContain('..\\');
    }
  });

  it('should sanitize query parameters', async () => {
    const res = await fetch(`${testServer.url}/query?search=${encodeURIComponent("<script>alert(1)</script>")}`);
    
    const data = await res.json();
    expect(data.query.search).not.toContain('<script>');
  });

  it('should handle nested objects', async () => {
    const res = await fetch(`${testServer.url}/body`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user: {
          profile: {
            bio: '<script>xss</script>',
            links: ['<img onerror="evil()">', 'https://safe.com'],
          },
        },
      }),
    });
    
    const data = await res.json();
    expect(data.body.user.profile.bio).not.toContain('<script>');
    expect(data.body.user.profile.links[0]).not.toContain('onerror');
    expect(data.body.user.profile.links[1]).toContain('https://safe.com');
  });
});

describe('Integration: Rate Limiter Middleware', () => {
  let testServer: TestServer;
  let rateLimiter: ReturnType<typeof createRateLimiter>;

  afterEach(async () => {
    rateLimiter?.close();
    await testServer?.close();
  });

  it('should allow requests under the limit', async () => {
    rateLimiter = createRateLimiter({ max: 5, windowMs: 60000 });
    testServer = await createTestServer((app) => {
      app.use(rateLimiter);
      app.get('/api', (_req: Request, res: Response) => res.json({ ok: true }));
    });

    for (let i = 0; i < 3; i++) {
      const res = await fetch(`${testServer.url}/api`);
      expect(res.status).toBe(200);
    }
  });

  it('should block requests over the limit', async () => {
    rateLimiter = createRateLimiter({ max: 2, windowMs: 60000 });
    testServer = await createTestServer((app) => {
      app.use(rateLimiter);
      app.get('/limited', (_req, res) => res.json({ ok: true }));
    });

    // First 2 requests should pass
    expect((await fetch(`${testServer.url}/limited`)).status).toBe(200);
    expect((await fetch(`${testServer.url}/limited`)).status).toBe(200);
    
    // Third request should be blocked
    const res = await fetch(`${testServer.url}/limited`);
    expect(res.status).toBe(429);
    
    const data = await res.json();
    expect(data.error).toBeTruthy();
    expect(res.headers.get('Retry-After')).toBeTruthy();
  });

  it('should respect skip function', async () => {
    rateLimiter = createRateLimiter({ 
      max: 1, 
      windowMs: 60000,
      skip: (req) => req.path === '/health',
    });
    testServer = await createTestServer((app) => {
      app.use(rateLimiter);
      app.get('/health', (_req, res) => res.json({ healthy: true }));
      app.get('/api', (_req, res) => res.json({ ok: true }));
    });

    // Health check should always pass
    for (let i = 0; i < 5; i++) {
      const res = await fetch(`${testServer.url}/health`);
      expect(res.status).toBe(200);
    }
    
    // But /api should still be rate limited
    await fetch(`${testServer.url}/api`); // Use up limit
    const res = await fetch(`${testServer.url}/api`);
    expect(res.status).toBe(429);
  });

  it('should use custom key generator', async () => {
    rateLimiter = createRateLimiter({ 
      max: 2, 
      windowMs: 60000,
      keyGenerator: (req) => req.headers['x-api-key'] as string || 'anonymous',
    });
    testServer = await createTestServer((app) => {
      app.use(rateLimiter);
      app.get('/api', (_req, res) => res.json({ ok: true }));
    });

    // User A makes 2 requests (uses up their limit)
    await fetch(`${testServer.url}/api`, { headers: { 'x-api-key': 'user-a' } });
    await fetch(`${testServer.url}/api`, { headers: { 'x-api-key': 'user-a' } });
    
    // User A is now blocked
    const resA = await fetch(`${testServer.url}/api`, { headers: { 'x-api-key': 'user-a' } });
    expect(resA.status).toBe(429);
    
    // But User B can still make requests
    const resB = await fetch(`${testServer.url}/api`, { headers: { 'x-api-key': 'user-b' } });
    expect(resB.status).toBe(200);
  });
});

describe('Integration: Security Headers Middleware', () => {
  let testServer: TestServer;

  afterEach(async () => {
    await testServer?.close();
  });

  it('should set all default security headers', async () => {
    testServer = await createTestServer((app) => {
      app.use(createHeaders());
      app.get('/', (_req, res) => res.json({ ok: true }));
    });

    // Simulate HTTPS via x-forwarded-proto so HSTS header is included.
    const res = await fetch(`${testServer.url}/`, {
      headers: { 'x-forwarded-proto': 'https' },
    });

    // CSP
    const csp = res.headers.get('Content-Security-Policy');
    expect(csp).toBeTruthy();
    expect(csp).toContain("default-src 'self'");
    
    // XSS Protection
    expect(res.headers.get('X-XSS-Protection')).toBe('0');
    
    // Content Type Options
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
    
    // Frame Options
    expect(res.headers.get('X-Frame-Options')).toBe('DENY');
    
    // HSTS
    const hsts = res.headers.get('Strict-Transport-Security');
    expect(hsts).toContain('max-age=');
    expect(hsts).toContain('includeSubDomains');
    
    // Referrer Policy
    expect(res.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');
    
    // Should NOT have X-Powered-By
    expect(res.headers.get('X-Powered-By')).toBeNull();
  });

  it('should allow custom CSP', async () => {
    const customCSP = "default-src 'none'; script-src 'self'";
    testServer = await createTestServer((app) => {
      app.use(createHeaders({ contentSecurityPolicy: customCSP }));
      app.get('/', (_req, res) => res.json({ ok: true }));
    });

    const res = await fetch(`${testServer.url}/`);
    expect(res.headers.get('Content-Security-Policy')).toBe(customCSP);
  });

  it('should allow disabling specific headers', async () => {
    testServer = await createTestServer((app) => {
      app.use(createHeaders({ 
        contentSecurityPolicy: false as any,
        xssFilter: false,
        frameOptions: false,
      }));
      app.get('/', (_req, res) => res.json({ ok: true }));
    });

    const res = await fetch(`${testServer.url}/`);
    expect(res.headers.get('Content-Security-Policy')).toBeNull();
    expect(res.headers.get('X-XSS-Protection')).toBeNull();
    expect(res.headers.get('X-Frame-Options')).toBeNull();
    // Other headers should still be set
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
  });
});

describe('Integration: Validator Middleware', () => {
  let testServer: TestServer;

  beforeAll(async () => {
    testServer = await createTestServer((app) => {
      app.post('/users', 
        validate({
          email: { type: 'email', required: true },
          name: { type: 'string', min: 2, max: 50 },
          age: { type: 'number', min: 0, max: 150 },
          role: { type: 'string', enum: ['user', 'admin'] },
        }),
        (req: Request, res: Response) => {
          res.status(201).json({ user: req.body });
        }
      );
      
      app.get('/search',
        validate({ q: { type: 'string', required: true, min: 1 } }, 'query'),
        (req: Request, res: Response) => {
          res.json({ query: req.query });
        }
      );
    });
  });

  afterAll(async () => {
    await testServer?.close();
  });

  it('should validate required fields', async () => {
    const res = await fetch(`${testServer.url}/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'John' }), // Missing email
    });
    
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.errors).toContain('email is required');
  });

  it('should validate email format', async () => {
    const res = await fetch(`${testServer.url}/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'not-an-email' }),
    });
    
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.errors.some((e: string) => e.includes('valid email'))).toBe(true);
  });

  it('should prevent mass assignment', async () => {
    const res = await fetch(`${testServer.url}/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        email: 'test@test.com',
        isAdmin: true,       // Not in schema
        secretField: 'hack', // Not in schema
      }),
    });
    
    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.user.email).toBe('test@test.com');
    expect(data.user.isAdmin).toBeUndefined();
    expect(data.user.secretField).toBeUndefined();
  });

  it('should pass valid data through', async () => {
    const res = await fetch(`${testServer.url}/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        email: 'john@example.com',
        name: 'John Doe',
        age: 25,
        role: 'user',
      }),
    });
    
    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.user.email).toBe('john@example.com');
    expect(data.user.age).toBe(25);
    expect(data.user.role).toBe('user');
  });
});

describe('Integration: Error Handler Middleware', () => {
  let testServer: TestServer;

  afterEach(async () => {
    await testServer?.close();
  });

  it('should hide error details in production mode', async () => {
    testServer = await createTestServer((app) => {
      app.get('/error', () => {
        throw new Error('Database connection failed at server 10.0.0.1');
      });
      app.use(errorHandler(false)); // Production mode
    });

    const res = await fetch(`${testServer.url}/error`);
    
    expect(res.status).toBe(500);
    const data = await res.json();
    expect(data.error).toBe('Internal Server Error');
    expect(data.stack).toBeUndefined();
    expect(JSON.stringify(data)).not.toContain('10.0.0.1');
  });

  it('should show error details in development mode', async () => {
    testServer = await createTestServer((app) => {
      app.get('/error', () => {
        throw new Error('Something broke');
      });
      app.use(errorHandler(true)); // Dev mode
    });

    const res = await fetch(`${testServer.url}/error`);
    
    expect(res.status).toBe(500);
    const data = await res.json();
    expect(data.stack).toBeDefined();
    expect(data.details).toBe('Something broke');
  });

  it('should use custom status codes from errors', async () => {
    testServer = await createTestServer((app) => {
      app.get('/not-found', () => {
        const error: any = new Error('Resource not found');
        error.statusCode = 404;
        error.expose = true; // opt-in to exposing this message to clients
        throw error;
      });
      app.use(errorHandler(false));
    });

    const res = await fetch(`${testServer.url}/not-found`);

    expect(res.status).toBe(404);
    const data = await res.json();
    expect(data.error).toBe('Resource not found');
  });
});

describe('Integration: Combined Real-World Scenarios', () => {
  let testServer: TestServer;
  let rateLimiter: ReturnType<typeof createRateLimiter>;

  afterEach(async () => {
    rateLimiter?.close();
    await testServer?.close();
  });

  it('should protect a complete API endpoint', async () => {
    rateLimiter = createRateLimiter({ max: 100, windowMs: 60000 });
    testServer = await createTestServer((app) => {
      app.use(createHeaders());
      app.use(rateLimiter);
      app.use(createSanitizer());
      
      app.post('/api/comments',
        validate({
          text: { type: 'string', required: true, min: 1, max: 1000 },
          authorId: { type: 'uuid' },
        }),
        (req: Request, res: Response) => {
          res.status(201).json({ comment: req.body });
        }
      );
      
      app.use(errorHandler(false));
    });

    // Test 1: Valid request with XSS in text (should be sanitized)
    const res1 = await fetch(`${testServer.url}/api/comments`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        text: '<script>alert("xss")</script>Great post!',
        authorId: '123e4567-e89b-12d3-a456-426614174000',
      }),
    });
    
    expect(res1.status).toBe(201);
    const data1 = await res1.json();
    expect(data1.comment.text).not.toContain('<script>');
    expect(data1.comment.text).toContain('Great post!');
    
    // Verify headers are set
    expect(res1.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(res1.headers.get('X-RateLimit-Limit')).toBe('100');
    
    // Test 2: Invalid UUID format
    const res2 = await fetch(`${testServer.url}/api/comments`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        text: 'Hello',
        authorId: 'not-a-uuid',
      }),
    });
    
    expect(res2.status).toBe(400);
    
    // Test 3: Mass assignment attempt
    const res3 = await fetch(`${testServer.url}/api/comments`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        text: 'Normal comment',
        isApproved: true,  // Not in schema
        adminFlag: true,   // Not in schema
      }),
    });
    
    expect(res3.status).toBe(201);
    const data3 = await res3.json();
    expect(data3.comment.isApproved).toBeUndefined();
    expect(data3.comment.adminFlag).toBeUndefined();
  });

  it('should handle form-urlencoded data', async () => {
    testServer = await createTestServer((app) => {
      app.use(createSanitizer());
      
      app.post('/form', (req: Request, res: Response) => {
        res.json({ data: req.body });
      });
    });

    const res = await fetch(`${testServer.url}/form`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'name=<script>evil</script>&email=test@test.com',
    });
    
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.data.name).not.toContain('<script>');
  });
});
