/**
 * Security Headers Middleware Tests
 * Tests for src/middleware/headers.ts
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Request, Response } from 'express';
import { createHeaders, securityHeaders } from '../../src/middleware/headers';
import { mockRequest, mockResponse, mockNext, createTestServer, TestServer } from '../setup';

describe('createHeaders', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Default Headers', () => {
    it('should set Content-Security-Policy', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders();

      headers(req as Request, res as Response, mockNext);

      expect(res.setHeader).toHaveBeenCalledWith('Content-Security-Policy', expect.any(String));
    });

    it('should set X-XSS-Protection', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders();

      headers(req as Request, res as Response, mockNext);

      expect(res.setHeader).toHaveBeenCalledWith('X-XSS-Protection', '0');
    });

    it('should set X-Content-Type-Options', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders();

      headers(req as Request, res as Response, mockNext);

      expect(res.setHeader).toHaveBeenCalledWith('X-Content-Type-Options', 'nosniff');
    });

    it('should set X-Frame-Options to DENY by default', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders();

      headers(req as Request, res as Response, mockNext);

      expect(res.setHeader).toHaveBeenCalledWith('X-Frame-Options', 'DENY');
    });

    it('should set Strict-Transport-Security over HTTPS', () => {
      const req = mockRequest({ secure: true });
      const res = mockResponse();
      const headers = createHeaders();

      headers(req as Request, res as Response, mockNext);

      expect(res.setHeader).toHaveBeenCalledWith(
        'Strict-Transport-Security',
        expect.stringContaining('max-age=')
      );
    });

    it('should set Referrer-Policy', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders();

      headers(req as Request, res as Response, mockNext);

      expect(res.setHeader).toHaveBeenCalledWith('Referrer-Policy', 'strict-origin-when-cross-origin');
    });

    it('should set Permissions-Policy', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders();

      headers(req as Request, res as Response, mockNext);

      expect(res.setHeader).toHaveBeenCalledWith('Permissions-Policy', expect.any(String));
    });

    it('should remove X-Powered-By', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders();

      headers(req as Request, res as Response, mockNext);

      expect(res.removeHeader).toHaveBeenCalledWith('X-Powered-By');
    });

    it('should call next()', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders();

      headers(req as Request, res as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Custom CSP', () => {
    it('should allow custom CSP string', () => {
      const customCSP = "default-src 'none'; script-src 'self'";
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders({ contentSecurityPolicy: customCSP });

      headers(req as Request, res as Response, mockNext);

      expect(res.setHeader).toHaveBeenCalledWith('Content-Security-Policy', customCSP);
    });

    it('should allow disabling CSP', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders({ contentSecurityPolicy: false });

      headers(req as Request, res as Response, mockNext);

      const calls = res.setHeader.mock.calls.map((c: unknown[]) => c[0]);
      expect(calls).not.toContain('Content-Security-Policy');
    });
  });

  describe('Frame Options', () => {
    it('should allow SAMEORIGIN', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders({ frameOptions: 'SAMEORIGIN' });

      headers(req as Request, res as Response, mockNext);

      expect(res.setHeader).toHaveBeenCalledWith('X-Frame-Options', 'SAMEORIGIN');
    });

    it('should allow disabling frame options', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders({ frameOptions: false });

      headers(req as Request, res as Response, mockNext);

      const calls = res.setHeader.mock.calls.map((c: unknown[]) => c[0]);
      expect(calls).not.toContain('X-Frame-Options');
    });
  });

  describe('HSTS Configuration', () => {
    it('should allow custom maxAge', () => {
      const req = mockRequest({ secure: true });
      const res = mockResponse();
      const headers = createHeaders({ hsts: { maxAge: 86400 } });

      headers(req as Request, res as Response, mockNext);

      expect(res.setHeader).toHaveBeenCalledWith(
        'Strict-Transport-Security',
        expect.stringContaining('max-age=86400')
      );
    });

    it('should support preload directive', () => {
      const req = mockRequest({ secure: true });
      const res = mockResponse();
      const headers = createHeaders({ hsts: { maxAge: 31536000, preload: true } });

      headers(req as Request, res as Response, mockNext);

      expect(res.setHeader).toHaveBeenCalledWith(
        'Strict-Transport-Security',
        expect.stringContaining('preload')
      );
    });

    it('should allow disabling includeSubDomains', () => {
      const req = mockRequest({ secure: true });
      const res = mockResponse();
      const headers = createHeaders({ hsts: { maxAge: 31536000, includeSubDomains: false } });

      headers(req as Request, res as Response, mockNext);

      const hstsCall = res.setHeader.mock.calls.find(
        (c: unknown[]) => c[0] === 'Strict-Transport-Security'
      );
      expect(hstsCall?.[1]).not.toContain('includeSubDomains');
    });

    it('should allow disabling HSTS', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders({ hsts: false });

      headers(req as Request, res as Response, mockNext);

      const calls = res.setHeader.mock.calls.map((c: unknown[]) => c[0]);
      expect(calls).not.toContain('Strict-Transport-Security');
    });
  });

  describe('Disabling Individual Headers', () => {
    it('should allow disabling XSS filter', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders({ xssFilter: false });

      headers(req as Request, res as Response, mockNext);

      const calls = res.setHeader.mock.calls.map((c: unknown[]) => c[0]);
      expect(calls).not.toContain('X-XSS-Protection');
    });

    it('should allow disabling noSniff', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders({ noSniff: false });

      headers(req as Request, res as Response, mockNext);

      const calls = res.setHeader.mock.calls.map((c: unknown[]) => c[0]);
      expect(calls).not.toContain('X-Content-Type-Options');
    });

    it('should allow disabling referrer policy', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders({ referrerPolicy: false });

      headers(req as Request, res as Response, mockNext);

      const calls = res.setHeader.mock.calls.map((c: unknown[]) => c[0]);
      expect(calls).not.toContain('Referrer-Policy');
    });
  });

  describe('Cross-Origin Isolation Headers', () => {
    it('should set Cross-Origin-Opener-Policy to same-origin by default', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders();
      headers(req as Request, res as Response, mockNext);
      expect(res.setHeader).toHaveBeenCalledWith('Cross-Origin-Opener-Policy', 'same-origin');
    });

    it('should set Cross-Origin-Resource-Policy to same-origin by default', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders();
      headers(req as Request, res as Response, mockNext);
      expect(res.setHeader).toHaveBeenCalledWith('Cross-Origin-Resource-Policy', 'same-origin');
    });

    it('should set Cross-Origin-Embedder-Policy to require-corp by default', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders();
      headers(req as Request, res as Response, mockNext);
      expect(res.setHeader).toHaveBeenCalledWith('Cross-Origin-Embedder-Policy', 'require-corp');
    });

    it('should allow custom COOP value', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders({ crossOriginOpenerPolicy: 'same-origin-allow-popups' });
      headers(req as Request, res as Response, mockNext);
      expect(res.setHeader).toHaveBeenCalledWith('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
    });

    it('should allow custom CORP value', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders({ crossOriginResourcePolicy: 'cross-origin' });
      headers(req as Request, res as Response, mockNext);
      expect(res.setHeader).toHaveBeenCalledWith('Cross-Origin-Resource-Policy', 'cross-origin');
    });

    it('should allow custom COEP value', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders({ crossOriginEmbedderPolicy: 'credentialless' });
      headers(req as Request, res as Response, mockNext);
      expect(res.setHeader).toHaveBeenCalledWith('Cross-Origin-Embedder-Policy', 'credentialless');
    });

    it('should allow disabling COOP', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders({ crossOriginOpenerPolicy: false });
      headers(req as Request, res as Response, mockNext);
      const calls = res.setHeader.mock.calls.map((c: unknown[]) => c[0]);
      expect(calls).not.toContain('Cross-Origin-Opener-Policy');
    });

    it('should allow disabling CORP', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders({ crossOriginResourcePolicy: false });
      headers(req as Request, res as Response, mockNext);
      const calls = res.setHeader.mock.calls.map((c: unknown[]) => c[0]);
      expect(calls).not.toContain('Cross-Origin-Resource-Policy');
    });

    it('should allow disabling COEP', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders({ crossOriginEmbedderPolicy: false });
      headers(req as Request, res as Response, mockNext);
      const calls = res.setHeader.mock.calls.map((c: unknown[]) => c[0]);
      expect(calls).not.toContain('Cross-Origin-Embedder-Policy');
    });
  });

  describe('Origin-Agent-Cluster', () => {
    it('should set Origin-Agent-Cluster to ?1 by default', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders();
      headers(req as Request, res as Response, mockNext);
      expect(res.setHeader).toHaveBeenCalledWith('Origin-Agent-Cluster', '?1');
    });

    it('should allow disabling Origin-Agent-Cluster', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders({ originAgentCluster: false });
      headers(req as Request, res as Response, mockNext);
      const calls = res.setHeader.mock.calls.map((c: unknown[]) => c[0]);
      expect(calls).not.toContain('Origin-Agent-Cluster');
    });
  });

  describe('X-DNS-Prefetch-Control', () => {
    it('should set X-DNS-Prefetch-Control to off by default', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders();
      headers(req as Request, res as Response, mockNext);
      expect(res.setHeader).toHaveBeenCalledWith('X-DNS-Prefetch-Control', 'off');
    });

    it('should allow disabling X-DNS-Prefetch-Control', () => {
      const req = mockRequest();
      const res = mockResponse();
      const headers = createHeaders({ dnsPrefetchControl: false });
      headers(req as Request, res as Response, mockNext);
      const calls = res.setHeader.mock.calls.map((c: unknown[]) => c[0]);
      expect(calls).not.toContain('X-DNS-Prefetch-Control');
    });
  });
});

describe('securityHeaders', () => {
  it('should be an alias for createHeaders', () => {
    expect(securityHeaders).toBe(createHeaders);
  });
});

describe('Integration: Security Headers', () => {
  let testServer: TestServer;

  it('should set all default headers on HTTPS response', async () => {
    testServer = await createTestServer((app) => {
      app.use(createHeaders());
      app.get('/', (_req, res) => res.json({ ok: true }));
    });

    // Simulate HTTPS via x-forwarded-proto so HSTS header is included.
    const res = await fetch(`${testServer.url}/`, {
      headers: { 'x-forwarded-proto': 'https' },
    });

    expect(res.headers.get('Content-Security-Policy')).toBeTruthy();
    expect(res.headers.get('X-XSS-Protection')).toBe('0');
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(res.headers.get('X-Frame-Options')).toBe('DENY');
    expect(res.headers.get('Strict-Transport-Security')).toContain('max-age=');
    expect(res.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');
    expect(res.headers.get('X-Powered-By')).toBeNull();

    await testServer.close();
  });
});
