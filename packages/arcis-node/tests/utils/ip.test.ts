/**
 * IP Detection Tests
 * Tests for src/utils/ip.ts
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { detectClientIp, isPrivateIp, _resetPlatformCache } from '../../src/utils/ip';

/** Helper to build a mock request */
function makeReq(overrides: {
  headers?: Record<string, string | string[] | undefined>;
  socket?: { remoteAddress?: string };
  connection?: { remoteAddress?: string };
  ip?: string;
} = {}) {
  return {
    headers: overrides.headers ?? {},
    socket: overrides.socket ?? { remoteAddress: '10.0.0.1' },
    connection: overrides.connection,
    ip: overrides.ip,
  };
}

describe('detectClientIp', () => {
  beforeEach(() => {
    _resetPlatformCache();
  });

  afterEach(() => {
    _resetPlatformCache();
    vi.unstubAllEnvs();
  });

  describe('Platform: Cloudflare', () => {
    it('should read cf-connecting-ip header', () => {
      const req = makeReq({
        headers: { 'cf-connecting-ip': '203.0.113.50' },
      });
      const ip = detectClientIp(req, { platform: 'cloudflare' });
      expect(ip).toBe('203.0.113.50');
    });

    it('should auto-detect Cloudflare via CF_PAGES env', () => {
      vi.stubEnv('CF_PAGES', '1');
      const req = makeReq({
        headers: { 'cf-connecting-ip': '203.0.113.50' },
      });
      const ip = detectClientIp(req);
      expect(ip).toBe('203.0.113.50');
    });

    it('should auto-detect Cloudflare via CF_WORKERS env', () => {
      vi.stubEnv('CF_WORKERS', '1');
      const req = makeReq({
        headers: { 'cf-connecting-ip': '1.2.3.4' },
      });
      const ip = detectClientIp(req);
      expect(ip).toBe('1.2.3.4');
    });

    it('should trim whitespace from header value', () => {
      const req = makeReq({
        headers: { 'cf-connecting-ip': '  203.0.113.50  ' },
      });
      const ip = detectClientIp(req, { platform: 'cloudflare' });
      expect(ip).toBe('203.0.113.50');
    });
  });

  describe('Platform: Vercel', () => {
    it('should read x-real-ip header', () => {
      const req = makeReq({
        headers: { 'x-real-ip': '198.51.100.10' },
      });
      const ip = detectClientIp(req, { platform: 'vercel' });
      expect(ip).toBe('198.51.100.10');
    });

    it('should auto-detect Vercel via VERCEL env', () => {
      vi.stubEnv('VERCEL', '1');
      const req = makeReq({
        headers: { 'x-real-ip': '198.51.100.10' },
      });
      const ip = detectClientIp(req);
      expect(ip).toBe('198.51.100.10');
    });
  });

  describe('Platform: Fly.io', () => {
    it('should read fly-client-ip header', () => {
      const req = makeReq({
        headers: { 'fly-client-ip': '100.64.0.1' },
      });
      const ip = detectClientIp(req, { platform: 'flyio' });
      expect(ip).toBe('100.64.0.1');
    });

    it('should auto-detect Fly.io via FLY_APP_NAME env', () => {
      vi.stubEnv('FLY_APP_NAME', 'my-app');
      const req = makeReq({
        headers: { 'fly-client-ip': '100.64.0.1' },
      });
      const ip = detectClientIp(req);
      expect(ip).toBe('100.64.0.1');
    });
  });

  describe('Platform: Render', () => {
    it('should read x-render-client-ip header', () => {
      const req = makeReq({
        headers: { 'x-render-client-ip': '5.6.7.8' },
      });
      const ip = detectClientIp(req, { platform: 'render' });
      expect(ip).toBe('5.6.7.8');
    });

    it('should auto-detect Render via RENDER env', () => {
      vi.stubEnv('RENDER', 'true');
      const req = makeReq({
        headers: { 'x-render-client-ip': '5.6.7.8' },
      });
      const ip = detectClientIp(req);
      expect(ip).toBe('5.6.7.8');
    });
  });

  describe('Platform: Firebase / App Engine', () => {
    it('should read x-appengine-user-ip header', () => {
      const req = makeReq({
        headers: { 'x-appengine-user-ip': '9.10.11.12' },
      });
      const ip = detectClientIp(req, { platform: 'firebase' });
      expect(ip).toBe('9.10.11.12');
    });

    it('should auto-detect via FIREBASE_CONFIG env', () => {
      vi.stubEnv('FIREBASE_CONFIG', '{}');
      const req = makeReq({
        headers: { 'x-appengine-user-ip': '9.10.11.12' },
      });
      const ip = detectClientIp(req);
      expect(ip).toBe('9.10.11.12');
    });

    it('should auto-detect via GCLOUD_PROJECT env', () => {
      vi.stubEnv('GCLOUD_PROJECT', 'my-project');
      const req = makeReq({
        headers: { 'x-appengine-user-ip': '9.10.11.12' },
      });
      const ip = detectClientIp(req);
      expect(ip).toBe('9.10.11.12');
    });
  });

  describe('Platform: AWS ALB', () => {
    it('should parse X-Forwarded-For from the right with trustedProxyCount=1', () => {
      const req = makeReq({
        headers: { 'x-forwarded-for': '1.1.1.1, 2.2.2.2, 3.3.3.3' },
      });
      const ip = detectClientIp(req, { platform: 'aws-alb' });
      // 3 IPs, trustedProxyCount=1 => client at index 2 (length 3 - 1 = 2)
      expect(ip).toBe('3.3.3.3');
    });

    it('should parse X-Forwarded-For with trustedProxyCount=2', () => {
      const req = makeReq({
        headers: { 'x-forwarded-for': '1.1.1.1, 2.2.2.2, 3.3.3.3' },
      });
      const ip = detectClientIp(req, { platform: 'aws-alb', trustedProxyCount: 2 });
      // 3 IPs, trustedProxyCount=2 => client at index 1
      expect(ip).toBe('2.2.2.2');
    });

    it('should auto-detect AWS via AWS_EXECUTION_ENV', () => {
      vi.stubEnv('AWS_EXECUTION_ENV', 'AWS_Lambda_nodejs18.x');
      const req = makeReq({
        headers: { 'x-forwarded-for': '1.1.1.1, 2.2.2.2' },
      });
      const ip = detectClientIp(req);
      expect(ip).toBe('2.2.2.2');
    });

    it('should auto-detect AWS via AWS_LAMBDA_FUNCTION_NAME', () => {
      vi.stubEnv('AWS_LAMBDA_FUNCTION_NAME', 'my-func');
      const req = makeReq({
        headers: { 'x-forwarded-for': '8.8.8.8' },
      });
      const ip = detectClientIp(req);
      expect(ip).toBe('8.8.8.8');
    });
  });

  describe('Platform: generic', () => {
    it('should not read platform-specific headers in generic mode', () => {
      const req = makeReq({
        headers: { 'cf-connecting-ip': '1.1.1.1' },
        ip: '2.2.2.2',
      });
      const ip = detectClientIp(req, { platform: 'generic' });
      // generic skips platform headers, falls through to req.ip
      expect(ip).toBe('2.2.2.2');
    });
  });

  describe('Fallback chain', () => {
    it('should fall back to req.ip when platform header is missing', () => {
      const req = makeReq({
        headers: {},
        ip: '44.55.66.77',
      });
      const ip = detectClientIp(req, { platform: 'cloudflare' });
      expect(ip).toBe('44.55.66.77');
    });

    it('should fall back to X-Forwarded-For when req.ip is missing', () => {
      const req = makeReq({
        headers: { 'x-forwarded-for': '88.99.11.22, 33.44.55.66' },
        ip: undefined,
      });
      const ip = detectClientIp(req, { platform: 'generic' });
      // trustedProxyCount=1, 2 IPs => index 1
      expect(ip).toBe('33.44.55.66');
    });

    it('should fall back to X-Real-IP when X-Forwarded-For is missing', () => {
      const req = makeReq({
        headers: { 'x-real-ip': '77.88.99.00' },
        ip: undefined,
      });
      const ip = detectClientIp(req, { platform: 'generic' });
      expect(ip).toBe('77.88.99.00');
    });

    it('should fall back to socket.remoteAddress', () => {
      const req = makeReq({
        headers: {},
        ip: undefined,
        socket: { remoteAddress: '127.0.0.1' },
      });
      const ip = detectClientIp(req, { platform: 'generic' });
      expect(ip).toBe('127.0.0.1');
    });

    it('should fall back to connection.remoteAddress', () => {
      const req = {
        headers: {},
        socket: { remoteAddress: undefined },
        connection: { remoteAddress: '192.168.1.100' },
      };
      const ip = detectClientIp(req, { platform: 'generic' });
      expect(ip).toBe('192.168.1.100');
    });

    it('should return "unknown" when nothing is available', () => {
      const req = {
        headers: {},
        ip: undefined,
        socket: undefined,
        connection: undefined,
      };
      const ip = detectClientIp(req as any, { platform: 'generic' });
      expect(ip).toBe('unknown');
    });
  });

  describe('X-Forwarded-For parsing', () => {
    it('should parse single IP', () => {
      const req = makeReq({
        headers: { 'x-forwarded-for': '1.2.3.4' },
        ip: undefined,
      });
      const ip = detectClientIp(req, { platform: 'generic' });
      expect(ip).toBe('1.2.3.4');
    });

    it('should handle whitespace in XFF entries', () => {
      const req = makeReq({
        headers: { 'x-forwarded-for': '  1.1.1.1 ,  2.2.2.2  ' },
        ip: undefined,
      });
      const ip = detectClientIp(req, { platform: 'generic' });
      expect(ip).toBe('2.2.2.2');
    });

    it('should handle many proxies in the chain', () => {
      const req = makeReq({
        headers: { 'x-forwarded-for': '1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4, 5.5.5.5' },
        ip: undefined,
      });
      // trustedProxyCount=1: client at index 4
      expect(detectClientIp(req, { platform: 'generic' })).toBe('5.5.5.5');
      // trustedProxyCount=3: client at index 2
      expect(detectClientIp(req, { platform: 'generic', trustedProxyCount: 3 })).toBe('3.3.3.3');
    });

    it('should clamp to index 0 when trustedProxyCount exceeds chain length', () => {
      const req = makeReq({
        headers: { 'x-forwarded-for': '1.1.1.1' },
        ip: undefined,
      });
      const ip = detectClientIp(req, { platform: 'generic', trustedProxyCount: 10 });
      expect(ip).toBe('1.1.1.1');
    });

    it('should handle array header values', () => {
      const req = makeReq({
        headers: { 'x-forwarded-for': ['1.1.1.1, 2.2.2.2', '3.3.3.3'] as any },
        ip: undefined,
      });
      const ip = detectClientIp(req, { platform: 'generic' });
      // getHeader returns first element of array
      expect(ip).toBe('2.2.2.2');
    });
  });

  describe('Platform cache', () => {
    it('should cache the detected platform', () => {
      vi.stubEnv('CF_PAGES', '1');
      const req1 = makeReq({ headers: { 'cf-connecting-ip': '1.1.1.1' } });
      expect(detectClientIp(req1)).toBe('1.1.1.1');

      // Even after removing the env var, cache persists until reset
      vi.unstubAllEnvs();
      const req2 = makeReq({ headers: { 'cf-connecting-ip': '2.2.2.2' } });
      expect(detectClientIp(req2)).toBe('2.2.2.2');
    });

    it('should re-detect after _resetPlatformCache', () => {
      vi.stubEnv('VERCEL', '1');
      const req1 = makeReq({ headers: { 'x-real-ip': '1.1.1.1' } });
      expect(detectClientIp(req1)).toBe('1.1.1.1');

      _resetPlatformCache();
      vi.unstubAllEnvs();

      // Now auto should resolve to generic, x-real-ip is only a fallback
      const req2 = makeReq({ headers: {}, ip: '3.3.3.3' });
      expect(detectClientIp(req2)).toBe('3.3.3.3');
    });
  });
});

describe('isPrivateIp', () => {
  describe('IPv4 loopback', () => {
    it('should detect 127.x.x.x as private', () => {
      expect(isPrivateIp('127.0.0.1')).toBe(true);
      expect(isPrivateIp('127.255.255.255')).toBe(true);
    });
  });

  describe('IPv4 Class A private (10.x)', () => {
    it('should detect 10.x.x.x as private', () => {
      expect(isPrivateIp('10.0.0.0')).toBe(true);
      expect(isPrivateIp('10.255.255.255')).toBe(true);
      expect(isPrivateIp('10.0.0.1')).toBe(true);
    });
  });

  describe('IPv4 Class B private (172.16-31.x)', () => {
    it('should detect 172.16-31.x.x as private', () => {
      expect(isPrivateIp('172.16.0.0')).toBe(true);
      expect(isPrivateIp('172.31.255.255')).toBe(true);
      expect(isPrivateIp('172.20.0.1')).toBe(true);
    });

    it('should not flag 172.15.x.x or 172.32.x.x as private', () => {
      expect(isPrivateIp('172.15.0.1')).toBe(false);
      expect(isPrivateIp('172.32.0.1')).toBe(false);
    });
  });

  describe('IPv4 Class C private (192.168.x)', () => {
    it('should detect 192.168.x.x as private', () => {
      expect(isPrivateIp('192.168.0.1')).toBe(true);
      expect(isPrivateIp('192.168.255.255')).toBe(true);
    });
  });

  describe('IPv4 link-local (169.254.x)', () => {
    it('should detect 169.254.x.x as private', () => {
      expect(isPrivateIp('169.254.0.1')).toBe(true);
      expect(isPrivateIp('169.254.169.254')).toBe(true);
    });
  });

  describe('IPv4 current network (0.x)', () => {
    it('should detect 0.x.x.x as private', () => {
      expect(isPrivateIp('0.0.0.0')).toBe(true);
      expect(isPrivateIp('0.1.2.3')).toBe(true);
    });
  });

  describe('IPv6', () => {
    it('should detect ::1 (loopback) as private', () => {
      expect(isPrivateIp('::1')).toBe(true);
    });

    it('should detect fe80: (link-local) as private', () => {
      expect(isPrivateIp('fe80::1')).toBe(true);
      expect(isPrivateIp('FE80::abcd')).toBe(true);
    });

    it('should detect fc00: (unique local) as private', () => {
      expect(isPrivateIp('fc00::1')).toBe(true);
      expect(isPrivateIp('FC00::1')).toBe(true);
    });

    it('should detect fd (unique local) as private', () => {
      expect(isPrivateIp('fd00::1')).toBe(true);
      expect(isPrivateIp('FD12:3456::1')).toBe(true);
    });
  });

  describe('Public IPs', () => {
    it('should not flag public IPv4 as private', () => {
      expect(isPrivateIp('8.8.8.8')).toBe(false);
      expect(isPrivateIp('203.0.113.1')).toBe(false);
      expect(isPrivateIp('1.1.1.1')).toBe(false);
      expect(isPrivateIp('44.55.66.77')).toBe(false);
    });

    it('should not flag public IPv6 as private', () => {
      expect(isPrivateIp('2001:db8::1')).toBe(false);
      expect(isPrivateIp('2607:f8b0:4004:800::200e')).toBe(false);
    });
  });
});
