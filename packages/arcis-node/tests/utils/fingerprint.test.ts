/**
 * Request Fingerprint Tests
 * Tests for src/utils/fingerprint.ts
 */

import { describe, it, expect } from 'vitest';
import { createHash } from 'crypto';
import { fingerprint } from '../../src/utils/fingerprint';

/** Helper to build a mock request */
function makeReq(overrides: {
  headers?: Record<string, string | string[] | undefined>;
  socket?: { remoteAddress?: string };
  ip?: string;
} = {}) {
  return {
    headers: {
      'user-agent': 'Mozilla/5.0',
      'accept': 'text/html',
      'accept-language': 'en-US',
      'accept-encoding': 'gzip, deflate',
      ...overrides.headers,
    },
    socket: overrides.socket ?? { remoteAddress: '10.0.0.1' },
    ip: overrides.ip,
  };
}

/** Compute expected hash from components */
function expectedHash(components: string[]): string {
  const sorted = [...components].sort();
  return createHash('sha256').update(sorted.join('|')).digest('hex');
}

describe('fingerprint', () => {
  describe('Deterministic output', () => {
    it('should return the same hash for the same request', () => {
      const req = makeReq();
      const fp1 = fingerprint(req);
      const fp2 = fingerprint(req);
      expect(fp1).toBe(fp2);
    });

    it('should return a 64-character hex string (SHA-256)', () => {
      const fp = fingerprint(makeReq());
      expect(fp).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should produce different hashes for different IPs', () => {
      const req1 = makeReq({ socket: { remoteAddress: '1.1.1.1' } });
      const req2 = makeReq({ socket: { remoteAddress: '2.2.2.2' } });
      expect(fingerprint(req1)).not.toBe(fingerprint(req2));
    });

    it('should produce different hashes for different user agents', () => {
      const req1 = makeReq({ headers: { 'user-agent': 'Chrome/100' } });
      const req2 = makeReq({ headers: { 'user-agent': 'Firefox/99' } });
      expect(fingerprint(req1)).not.toBe(fingerprint(req2));
    });
  });

  describe('Default components', () => {
    it('should include ip, user-agent, accept, accept-language, accept-encoding by default', () => {
      const req = makeReq({
        ip: undefined,
        socket: { remoteAddress: '10.0.0.1' },
        headers: {
          'user-agent': 'TestAgent',
          'accept': 'text/html',
          'accept-language': 'en-US',
          'accept-encoding': 'gzip',
        },
      });
      const fp = fingerprint(req);
      // The IP comes from detectClientIp which falls through to socket
      const expected = expectedHash([
        'ip:10.0.0.1',
        'ua:TestAgent',
        'accept:text/html',
        'lang:en-US',
        'enc:gzip',
      ]);
      expect(fp).toBe(expected);
    });
  });

  describe('Option toggling', () => {
    it('should exclude IP when ip=false', () => {
      const req = makeReq({ headers: { 'user-agent': 'A', 'accept': 'B', 'accept-language': 'C', 'accept-encoding': 'D' } });
      const withIp = fingerprint(req, { ip: true });
      const withoutIp = fingerprint(req, { ip: false });
      expect(withIp).not.toBe(withoutIp);
    });

    it('should exclude user-agent when userAgent=false', () => {
      const req = makeReq();
      const with_ = fingerprint(req, { userAgent: true });
      const without_ = fingerprint(req, { userAgent: false });
      expect(with_).not.toBe(without_);
    });

    it('should exclude accept when accept=false', () => {
      const req = makeReq();
      const with_ = fingerprint(req, { accept: true });
      const without_ = fingerprint(req, { accept: false });
      expect(with_).not.toBe(without_);
    });

    it('should exclude accept-language when acceptLanguage=false', () => {
      const req = makeReq();
      const with_ = fingerprint(req, { acceptLanguage: true });
      const without_ = fingerprint(req, { acceptLanguage: false });
      expect(with_).not.toBe(without_);
    });

    it('should exclude accept-encoding when acceptEncoding=false', () => {
      const req = makeReq();
      const with_ = fingerprint(req, { acceptEncoding: true });
      const without_ = fingerprint(req, { acceptEncoding: false });
      expect(with_).not.toBe(without_);
    });

    it('should produce a hash even with all standard options disabled', () => {
      const req = makeReq();
      const fp = fingerprint(req, {
        ip: false,
        userAgent: false,
        accept: false,
        acceptLanguage: false,
        acceptEncoding: false,
      });
      expect(fp).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('Custom components', () => {
    it('should include custom string components', () => {
      const req = makeReq();
      const fpBase = fingerprint(req);
      const fpCustom = fingerprint(req, { custom: ['user-123'] });
      expect(fpBase).not.toBe(fpCustom);
    });

    it('should skip null and undefined custom components', () => {
      const req = makeReq();
      const fpNoCustom = fingerprint(req, { custom: [] });
      const fpNullCustom = fingerprint(req, { custom: [null as unknown as string, undefined as unknown as string] });
      expect(fpNoCustom).toBe(fpNullCustom);
    });

    it('should include multiple custom components', () => {
      const req = makeReq();
      const fp1 = fingerprint(req, { custom: ['a', 'b'] });
      const fp2 = fingerprint(req, { custom: ['b', 'a'] });
      // Components are sorted, so order should not matter
      expect(fp1).toBe(fp2);
    });

    it('should produce different hashes for different custom values', () => {
      const req = makeReq();
      const fp1 = fingerprint(req, { custom: ['plan:free'] });
      const fp2 = fingerprint(req, { custom: ['plan:pro'] });
      expect(fp1).not.toBe(fp2);
    });
  });

  describe('Missing headers', () => {
    it('should use empty string for missing headers', () => {
      const req = { headers: {}, socket: { remoteAddress: '1.2.3.4' } };
      const fp = fingerprint(req);
      // Should not throw, uses empty strings
      expect(fp).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should handle array header values', () => {
      const req = makeReq({
        headers: { 'user-agent': ['Agent1', 'Agent2'] as any },
      });
      const fp = fingerprint(req);
      expect(fp).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('IP options passthrough', () => {
    it('should pass ipOptions to detectClientIp', () => {
      const req = makeReq({
        headers: { 'cf-connecting-ip': '203.0.113.1' },
      });
      const fpCloudflare = fingerprint(req, { ipOptions: { platform: 'cloudflare' } });
      const fpGeneric = fingerprint(req, { ipOptions: { platform: 'generic' } });
      // Different IP detection yields different fingerprints
      expect(fpCloudflare).not.toBe(fpGeneric);
    });
  });

  describe('Component sorting', () => {
    it('should produce the same hash regardless of internal ordering', () => {
      // This tests that components.sort() is applied.
      // Two requests with same data should always match.
      const req1 = makeReq({
        ip: undefined,
        socket: { remoteAddress: '10.0.0.1' },
        headers: {
          'user-agent': 'UA',
          'accept': 'A',
          'accept-language': 'L',
          'accept-encoding': 'E',
        },
      });
      const req2 = makeReq({
        ip: undefined,
        socket: { remoteAddress: '10.0.0.1' },
        headers: {
          'accept-encoding': 'E',
          'accept-language': 'L',
          'accept': 'A',
          'user-agent': 'UA',
        },
      });
      expect(fingerprint(req1)).toBe(fingerprint(req2));
    });
  });
});
