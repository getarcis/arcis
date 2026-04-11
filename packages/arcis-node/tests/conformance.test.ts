/**
 * Conformance Tests
 * These tests verify Arcis implementation matches TEST_VECTORS.json spec
 * 
 * All SDK implementations must pass these tests to be considered conformant.
 */

import { describe, it, expect, beforeEach, afterAll, vi } from 'vitest';
import type { Request, Response } from 'express';
import {
  sanitizeString,
  sanitizeObject,
  createRateLimiter,
  createHeaders,
  validate,
  createSafeLogger,
  errorHandler,
} from '../src/index';
import { createTestServer, TestServer } from './setup';

// =============================================================================
// SANITIZE STRING CONFORMANCE
// =============================================================================

describe('Conformance: sanitizeString', () => {
  describe('XSS Prevention', () => {
    it('must not contain <script> tags', () => {
      const result = sanitizeString("<script>alert('xss')</script>");
      expect(result).not.toContain('<script>');
    });

    it('must not contain event handlers (onerror)', () => {
      const result = sanitizeString('<img onerror="alert(1)" src="x">');
      expect(result).not.toContain('onerror');
    });

    it('must not contain javascript: protocol', () => {
      const result = sanitizeString('javascript:alert(1)');
      expect(result.toLowerCase()).not.toContain('javascript:');
    });

    it('must not contain <iframe> tags', () => {
      const result = sanitizeString('<iframe src="evil.com">');
      expect(result).not.toContain('<iframe');
    });

    it('must encode < and > as HTML entities when htmlEncode is enabled', () => {
      // htmlEncode is opt-in — REST APIs should not encode stored data.
      // Use { htmlEncode: true } only when rendering into HTML templates.
      const result = sanitizeString('Hello <b>World</b>', { htmlEncode: true });
      expect(result).toContain('&lt;');
      expect(result).toContain('&gt;');
    });

    it('must not contain data: URIs', () => {
      const result = sanitizeString('data:text/html,<script>alert(1)</script>');
      expect(result).not.toContain('data:');
    });
  });

  describe('SQL Injection Prevention', () => {
    // Default mode is 'sanitize' — sanitizeString strips threats and returns clean string.
    // Pass { mode: 'reject' } to throw SecurityThreatError instead.
    it('must strip DROP keyword (default sanitize mode)', () => {
      const result = sanitizeString("'; DROP TABLE users; --");
      expect(result.toUpperCase()).not.toContain('DROP');
    });

    it('must strip DROP keyword (explicit sanitize mode)', () => {
      const result = sanitizeString("'; DROP TABLE users; --", { mode: 'sanitize' });
      expect(result.toUpperCase()).not.toContain('DROP');
    });

    it('must reject DROP keyword (reject mode)', () => {
      expect(() => sanitizeString("'; DROP TABLE users; --", { mode: 'reject' })).toThrow();
    });

    it('must reject OR 1=1 pattern (reject mode)', () => {
      expect(() => sanitizeString('1 OR 1=1', { mode: 'reject' })).toThrow();
    });

    it('must reject SELECT keyword (reject mode)', () => {
      expect(() => sanitizeString('SELECT * FROM users', { mode: 'reject' })).toThrow();
    });

    it('must reject DELETE keyword (reject mode)', () => {
      expect(() => sanitizeString('1; DELETE FROM users', { mode: 'reject' })).toThrow();
    });

    it('must reject -- comment syntax (reject mode)', () => {
      expect(() => sanitizeString("admin'--", { mode: 'reject' })).toThrow();
    });

    it('must reject UNION and /* comment */ (reject mode)', () => {
      expect(() => sanitizeString('1 /* comment */ UNION SELECT', { mode: 'reject' })).toThrow();
    });
  });

  describe('Path Traversal Prevention', () => {
    it('must not contain ../', () => {
      const result = sanitizeString('../../etc/passwd');
      expect(result).not.toContain('../');
    });

    it('must not contain ..\\', () => {
      const result = sanitizeString('..\\..\\windows\\system32');
      expect(result).not.toContain('..\\');
    });

    it('must not contain URL-encoded traversal', () => {
      const result = sanitizeString('%2e%2e%2f%2e%2e%2f');
      expect(result.toLowerCase()).not.toContain('%2e%2e');
    });

    it('safe input should pass through (with encoding)', () => {
      const result = sanitizeString('file.txt');
      // May be encoded but should preserve the content
      expect(result).toContain('file');
      expect(result).toContain('txt');
    });
  });
});

// =============================================================================
// SANITIZE OBJECT CONFORMANCE
// =============================================================================

describe('Conformance: sanitizeObject', () => {
  describe('Prototype Pollution Prevention', () => {
    it('result must not have __proto__ key', () => {
      const result = sanitizeObject({ __proto__: { admin: true }, name: 'test' }) as Record<string, unknown>;
      expect(Object.hasOwn(result, '__proto__')).toBe(false);
      expect(result.name).toBe('test');
    });

    it('result must not have constructor key', () => {
      const result = sanitizeObject({ constructor: { prototype: {} }, email: 'test@test.com' }) as Record<string, unknown>;
      expect(Object.hasOwn(result, 'constructor')).toBe(false);
      expect(result.email).toBe('test@test.com');
    });

    it('result must not have prototype key', () => {
      const result = sanitizeObject({ prototype: { isAdmin: true }, value: 123 }) as Record<string, unknown>;
      expect(Object.hasOwn(result, 'prototype')).toBe(false);
      expect(result.value).toBe(123);
    });
  });

  describe('NoSQL Injection Prevention', () => {
    it('result must not have $gt key', () => {
      const result = sanitizeObject({ $gt: '', name: 'test' }) as Record<string, unknown>;
      expect(result.$gt).toBeUndefined();
      expect(result.name).toBe('test');
    });

    it('result must not have $where key', () => {
      const result = sanitizeObject({ $where: 'function(){ return true; }', id: 1 }) as Record<string, unknown>;
      expect(result.$where).toBeUndefined();
      expect(result.id).toBe(1);
    });

    it('result must not have $ne or $or keys', () => {
      const result = sanitizeObject({ $ne: null, $or: [], valid: true }) as Record<string, unknown>;
      expect(result.$ne).toBeUndefined();
      expect(result.$or).toBeUndefined();
      expect(result.valid).toBe(true);
    });
  });

  describe('Nested Objects', () => {
    it('nested string values must be sanitized', () => {
      const result = sanitizeObject({ user: { name: '<script>xss</script>' } }) as { user: { name: string } };
      expect(result.user.name).not.toContain('<script>');
    });

    it('array items must be sanitized', () => {
      const result = sanitizeObject({ items: ['<script>alert(1)</script>', 'normal'] }) as { items: string[] };
      expect(result.items[0]).not.toContain('<script>');
      expect(result.items[1]).toBe('normal');
    });
  });
});

// =============================================================================
// RATE LIMITER CONFORMANCE
// =============================================================================

describe('Conformance: Rate Limiter', () => {
  let testServer: TestServer;
  let rateLimiter: ReturnType<typeof createRateLimiter>;

  afterAll(async () => {
    rateLimiter?.close();
    await testServer?.close();
  });

  describe('Basic Functionality', () => {
    beforeEach(() => {
      vi.clearAllMocks();
    });

    it('should allow requests under the limit (max: 5, requests: 3)', async () => {
      rateLimiter = createRateLimiter({ max: 5, windowMs: 60000 });
      testServer = await createTestServer((app) => {
        app.use(rateLimiter);
        app.get('/test', (_req, res) => res.json({ ok: true }));
      });

      for (let i = 0; i < 3; i++) {
        const res = await fetch(`${testServer.url}/test`);
        expect(res.status).toBe(200);
      }
      
      rateLimiter.close();
      await testServer.close();
    });

    it('should block requests over the limit (max: 3, requests: 5)', async () => {
      rateLimiter = createRateLimiter({ max: 3, windowMs: 60000 });
      testServer = await createTestServer((app) => {
        app.use(rateLimiter);
        app.get('/test', (_req, res) => res.json({ ok: true }));
      });

      // First 3 should pass
      for (let i = 0; i < 3; i++) {
        const res = await fetch(`${testServer.url}/test`);
        expect(res.status).toBe(200);
      }
      
      // 4th and 5th should be blocked
      for (let i = 0; i < 2; i++) {
        const res = await fetch(`${testServer.url}/test`);
        expect(res.status).toBe(429);
        const data = await res.json();
        expect(data.error).toBeDefined();
      }
      
      rateLimiter.close();
      await testServer.close();
    });
  });

  describe('Required Headers', () => {
    it('should set X-RateLimit-Limit header', async () => {
      rateLimiter = createRateLimiter({ max: 100, windowMs: 60000 });
      testServer = await createTestServer((app) => {
        app.use(rateLimiter);
        app.get('/test', (_req, res) => res.json({ ok: true }));
      });

      const res = await fetch(`${testServer.url}/test`);
      expect(res.headers.get('X-RateLimit-Limit')).toBe('100');
      
      rateLimiter.close();
      await testServer.close();
    });

    it('should set X-RateLimit-Remaining header', async () => {
      rateLimiter = createRateLimiter({ max: 100, windowMs: 60000 });
      testServer = await createTestServer((app) => {
        app.use(rateLimiter);
        app.get('/test', (_req, res) => res.json({ ok: true }));
      });

      const res = await fetch(`${testServer.url}/test`);
      expect(res.headers.get('X-RateLimit-Remaining')).toBeTruthy();
      
      rateLimiter.close();
      await testServer.close();
    });

    it('should set X-RateLimit-Reset header', async () => {
      rateLimiter = createRateLimiter({ max: 100, windowMs: 60000 });
      testServer = await createTestServer((app) => {
        app.use(rateLimiter);
        app.get('/test', (_req, res) => res.json({ ok: true }));
      });

      const res = await fetch(`${testServer.url}/test`);
      expect(res.headers.get('X-RateLimit-Reset')).toBeTruthy();

      rateLimiter.close();
      await testServer.close();
    });
  });

  describe('Per-IP Isolation', () => {
    it('should track limits independently per IP', async () => {
      // Use a custom keyGenerator so we can simulate two different "IPs"
      // without needing real network interfaces.
      let callCount = 0;
      rateLimiter = createRateLimiter({
        max: 2,
        windowMs: 60000,
        keyGenerator: (_req) => {
          // Alternate between two keys on successive calls
          callCount++;
          return callCount <= 2 ? 'ip-A' : 'ip-B';
        },
      });
      testServer = await createTestServer((app) => {
        app.use(rateLimiter);
        app.get('/test', (_req, res) => res.json({ ok: true }));
      });

      // First two requests are keyed to ip-A — both should pass (max: 2)
      const r1 = await fetch(`${testServer.url}/test`);
      const r2 = await fetch(`${testServer.url}/test`);
      expect(r1.status).toBe(200);
      expect(r2.status).toBe(200);

      // Next two requests are keyed to ip-B — should also pass (separate bucket)
      const r3 = await fetch(`${testServer.url}/test`);
      const r4 = await fetch(`${testServer.url}/test`);
      expect(r3.status).toBe(200);
      expect(r4.status).toBe(200);

      rateLimiter.close();
      await testServer.close();
    });
  });
});

// =============================================================================
// SECURITY HEADERS CONFORMANCE
// =============================================================================

describe('Conformance: Security Headers', () => {
  it('should set Content-Security-Policy', async () => {
    const testServer = await createTestServer((app) => {
      app.use(createHeaders());
      app.get('/', (_req, res) => res.json({ ok: true }));
    });

    const res = await fetch(`${testServer.url}/`);
    expect(res.headers.get('Content-Security-Policy')).toBeTruthy();
    
    await testServer.close();
  });

  it('should set X-XSS-Protection to "0" (disabled - legacy auditor was itself an attack vector)', async () => {
    const testServer = await createTestServer((app) => {
      app.use(createHeaders());
      app.get('/', (_req, res) => res.json({ ok: true }));
    });

    const res = await fetch(`${testServer.url}/`);
    expect(res.headers.get('X-XSS-Protection')).toBe('0');

    await testServer.close();
  });

  it('should set X-Content-Type-Options to "nosniff"', async () => {
    const testServer = await createTestServer((app) => {
      app.use(createHeaders());
      app.get('/', (_req, res) => res.json({ ok: true }));
    });

    const res = await fetch(`${testServer.url}/`);
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
    
    await testServer.close();
  });

  it('should set X-Frame-Options to "DENY"', async () => {
    const testServer = await createTestServer((app) => {
      app.use(createHeaders());
      app.get('/', (_req, res) => res.json({ ok: true }));
    });

    const res = await fetch(`${testServer.url}/`);
    expect(res.headers.get('X-Frame-Options')).toBe('DENY');
    
    await testServer.close();
  });

  it('should set Strict-Transport-Security with max-age over HTTPS', async () => {
    // HSTS is only sent over HTTPS — simulate via x-forwarded-proto header.
    const testServer = await createTestServer((app) => {
      app.use(createHeaders());
      app.get('/', (_req, res) => res.json({ ok: true }));
    });

    const res = await fetch(`${testServer.url}/`, {
      headers: { 'x-forwarded-proto': 'https' },
    });
    expect(res.headers.get('Strict-Transport-Security')).toContain('max-age=');

    await testServer.close();
  });

  it('should set Referrer-Policy to "strict-origin-when-cross-origin"', async () => {
    const testServer = await createTestServer((app) => {
      app.use(createHeaders());
      app.get('/', (_req, res) => res.json({ ok: true }));
    });

    const res = await fetch(`${testServer.url}/`);
    expect(res.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');
    
    await testServer.close();
  });

  it('should set Permissions-Policy', async () => {
    const testServer = await createTestServer((app) => {
      app.use(createHeaders());
      app.get('/', (_req, res) => res.json({ ok: true }));
    });

    const res = await fetch(`${testServer.url}/`);
    expect(res.headers.get('Permissions-Policy')).toBeTruthy();
    
    await testServer.close();
  });

  it('should remove X-Powered-By header', async () => {
    const testServer = await createTestServer((app) => {
      app.use(createHeaders());
      app.get('/', (_req, res) => res.json({ ok: true }));
    });

    const res = await fetch(`${testServer.url}/`);
    expect(res.headers.get('X-Powered-By')).toBeNull();
    
    await testServer.close();
  });
});

// =============================================================================
// VALIDATOR CONFORMANCE
// =============================================================================

describe('Conformance: Validator', () => {
  describe('Required Fields', () => {
    it('should return 400 with "email is required" error', async () => {
      const testServer = await createTestServer((app) => {
        app.post('/test', validate({ email: { type: 'email', required: true } }), (req, res) => {
          res.json({ ok: true });
        });
      });

      const res = await fetch(`${testServer.url}/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      
      expect(res.status).toBe(400);
      const data = await res.json();
      expect(data.errors.some((e: string) => e.includes('email is required'))).toBe(true);
      
      await testServer.close();
    });
  });

  describe('Email Validation', () => {
    it('should reject invalid email format', async () => {
      const testServer = await createTestServer((app) => {
        app.post('/test', validate({ email: { type: 'email', required: true } }), (req, res) => {
          res.json({ ok: true });
        });
      });

      const res = await fetch(`${testServer.url}/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'invalid' }),
      });
      
      expect(res.status).toBe(400);
      const data = await res.json();
      expect(data.errors.some((e: string) => e.includes('valid email'))).toBe(true);
      
      await testServer.close();
    });

    it('should accept valid email format', async () => {
      const testServer = await createTestServer((app) => {
        app.post('/test', validate({ email: { type: 'email', required: true } }), (req, res) => {
          res.json({ ok: true });
        });
      });

      const res = await fetch(`${testServer.url}/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com' }),
      });
      
      expect(res.status).toBe(200);
      
      await testServer.close();
    });
  });

  describe('String Length', () => {
    it('should reject string below min length', async () => {
      const testServer = await createTestServer((app) => {
        app.post('/test', validate({ name: { type: 'string', min: 3, max: 10 } }), (req, res) => {
          res.json({ ok: true });
        });
      });

      const res = await fetch(`${testServer.url}/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'ab' }),
      });
      
      expect(res.status).toBe(400);
      const data = await res.json();
      expect(data.errors.some((e: string) => e.includes('at least 3'))).toBe(true);
      
      await testServer.close();
    });

    it('should reject string above max length', async () => {
      const testServer = await createTestServer((app) => {
        app.post('/test', validate({ name: { type: 'string', min: 3, max: 10 } }), (req, res) => {
          res.json({ ok: true });
        });
      });

      const res = await fetch(`${testServer.url}/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'this is way too long' }),
      });
      
      expect(res.status).toBe(400);
      const data = await res.json();
      expect(data.errors.some((e: string) => e.includes('at most 10'))).toBe(true);
      
      await testServer.close();
    });
  });

  describe('Number Range', () => {
    it('should reject number below min', async () => {
      const testServer = await createTestServer((app) => {
        app.post('/test', validate({ age: { type: 'number', min: 0, max: 150 } }), (req, res) => {
          res.json({ ok: true });
        });
      });

      const res = await fetch(`${testServer.url}/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ age: -5 }),
      });
      
      expect(res.status).toBe(400);
      const data = await res.json();
      expect(data.errors.some((e: string) => e.includes('at least 0'))).toBe(true);
      
      await testServer.close();
    });

    it('should reject number above max', async () => {
      const testServer = await createTestServer((app) => {
        app.post('/test', validate({ age: { type: 'number', min: 0, max: 150 } }), (req, res) => {
          res.json({ ok: true });
        });
      });

      const res = await fetch(`${testServer.url}/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ age: 200 }),
      });
      
      expect(res.status).toBe(400);
      const data = await res.json();
      expect(data.errors.some((e: string) => e.includes('at most 150'))).toBe(true);
      
      await testServer.close();
    });
  });

  describe('Enum Validation', () => {
    it('should reject value not in enum', async () => {
      const testServer = await createTestServer((app) => {
        app.post('/test', validate({ role: { type: 'string', enum: ['user', 'admin'] } }), (req, res) => {
          res.json({ ok: true });
        });
      });

      const res = await fetch(`${testServer.url}/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: 'superadmin' }),
      });
      
      expect(res.status).toBe(400);
      const data = await res.json();
      expect(data.errors.some((e: string) => e.includes('one of'))).toBe(true);
      
      await testServer.close();
    });
  });

  describe('Mass Assignment Prevention', () => {
    it('should strip fields not in schema', async () => {
      const testServer = await createTestServer((app) => {
        app.post('/test', validate({ email: { type: 'email', required: true } }), (req, res) => {
          res.json({ data: req.body, keys: Object.keys(req.body) });
        });
      });

      const res = await fetch(`${testServer.url}/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@test.com', isAdmin: true, role: 'admin' }),
      });
      
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.keys).toContain('email');
      expect(data.keys).not.toContain('isAdmin');
      expect(data.keys).not.toContain('role');
      
      await testServer.close();
    });
  });
});

// =============================================================================
// SAFE LOGGER CONFORMANCE
// =============================================================================

describe('Conformance: Safe Logger', () => {
  describe('Redaction', () => {
    it('should redact password but keep email visible', () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      const logger = createSafeLogger();

      logger.info('Test', { email: 'test@test.com', password: 'secret123' });

      const logOutput = JSON.parse(consoleSpy.mock.calls[0][0]);
      expect(logOutput.data.password).toBe('[REDACTED]');
      expect(logOutput.data.email).toBe('test@test.com');
      
      consoleSpy.mockRestore();
    });

    it('should redact token and apiKey but keep user visible', () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      const logger = createSafeLogger();

      logger.info('Test', { user: 'john', token: 'abc123', apiKey: 'key123' });

      const logOutput = JSON.parse(consoleSpy.mock.calls[0][0]);
      expect(logOutput.data.token).toBe('[REDACTED]');
      expect(logOutput.data.apiKey).toBe('[REDACTED]');
      expect(logOutput.data.user).toBe('john');
      
      consoleSpy.mockRestore();
    });
  });

  describe('Log Injection Prevention', () => {
    it('should not contain newline in output', () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      const logger = createSafeLogger();

      logger.info('User: attacker\nAdmin logged in: true');

      const logOutput = JSON.parse(consoleSpy.mock.calls[0][0]);
      expect(logOutput.message).not.toContain('\n');
      
      consoleSpy.mockRestore();
    });

    it('should not contain carriage return in output', () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      const logger = createSafeLogger();

      logger.info('Normal log\r\nFake entry');

      const logOutput = JSON.parse(consoleSpy.mock.calls[0][0]);
      expect(logOutput.message).not.toContain('\r');
      expect(logOutput.message).not.toContain('\n');
      
      consoleSpy.mockRestore();
    });
  });

  describe('Truncation', () => {
    it('should truncate long messages and include [TRUNCATED]', () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      const logger = createSafeLogger({ maxLength: 50 });

      const longMessage = 'a'.repeat(100);
      logger.info(longMessage);

      const logOutput = JSON.parse(consoleSpy.mock.calls[0][0]);
      expect(logOutput.message.length).toBeLessThan(100);
      expect(logOutput.message).toContain('[TRUNCATED]');
      
      consoleSpy.mockRestore();
    });
  });
});

// =============================================================================
// ERROR HANDLER CONFORMANCE
// =============================================================================

describe('Conformance: Error Handler', () => {
  describe('Production Mode', () => {
    it('should return generic error and hide details', async () => {
      const testServer = await createTestServer((app) => {
        app.get('/error', () => {
          throw new Error('Database connection failed');
        });
        app.use(errorHandler(false)); // Production mode
      });

      const res = await fetch(`${testServer.url}/error`);
      
      expect(res.status).toBe(500);
      const data = await res.json();
      expect(data.error).toBe('Internal Server Error');
      expect(data.stack).toBeUndefined();
      expect(JSON.stringify(data)).not.toContain('Database');
      
      await testServer.close();
    });
  });

  describe('Development Mode', () => {
    it('should include error details', async () => {
      const testServer = await createTestServer((app) => {
        app.get('/error', () => {
          throw new Error('Something broke');
        });
        app.use(errorHandler(true)); // Dev mode
      });

      const res = await fetch(`${testServer.url}/error`);
      
      expect(res.status).toBe(500);
      const data = await res.json();
      expect(data.details).toBe('Something broke');
      
      await testServer.close();
    });
  });
});
