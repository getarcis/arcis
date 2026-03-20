/**
 * SSRF Prevention — URL Validation Tests
 * Tests for src/validation/url.ts
 */

import { describe, it, expect } from 'vitest';
import { validateUrl, isUrlSafe } from '../../src/validation/url';

describe('validateUrl', () => {
  describe('Safe URLs', () => {
    it('should allow https URL', () => {
      const result = validateUrl('https://api.example.com/data');
      expect(result.safe).toBe(true);
    });

    it('should allow http URL', () => {
      const result = validateUrl('http://example.com/path');
      expect(result.safe).toBe(true);
    });

    it('should allow URL with port', () => {
      const result = validateUrl('https://api.example.com:8443/data');
      expect(result.safe).toBe(true);
    });

    it('should allow URL with query params', () => {
      const result = validateUrl('https://api.example.com/search?q=test&page=1');
      expect(result.safe).toBe(true);
    });

    it('should allow URL with fragment', () => {
      const result = validateUrl('https://example.com/page#section');
      expect(result.safe).toBe(true);
    });

    it('should allow public IP addresses', () => {
      const result = validateUrl('http://8.8.8.8/api');
      expect(result.safe).toBe(true);
    });
  });

  describe('Invalid URLs', () => {
    it('should reject empty string', () => {
      const result = validateUrl('');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('empty');
    });

    it('should reject non-string input', () => {
      const result = validateUrl(123 as unknown as string);
      expect(result.safe).toBe(false);
    });

    it('should reject malformed URLs', () => {
      const result = validateUrl('not-a-url');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('failed to parse');
    });

    it('should reject whitespace-only string', () => {
      const result = validateUrl('   ');
      expect(result.safe).toBe(false);
    });
  });

  describe('Dangerous Protocols', () => {
    it('should block file:// protocol', () => {
      const result = validateUrl('file:///etc/passwd');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('disallowed protocol');
      expect(result.reason).toContain('file:');
    });

    it('should block ftp:// protocol', () => {
      const result = validateUrl('ftp://internal.server/data');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('disallowed protocol');
    });

    it('should block javascript: protocol', () => {
      const result = validateUrl('javascript:alert(1)');
      expect(result.safe).toBe(false);
    });

    it('should block data: protocol', () => {
      const result = validateUrl('data:text/html,<script>alert(1)</script>');
      expect(result.safe).toBe(false);
    });

    it('should allow custom protocols when configured', () => {
      const result = validateUrl('ftp://files.example.com/data', {
        allowedProtocols: ['http:', 'https:', 'ftp:'],
      });
      expect(result.safe).toBe(true);
    });
  });

  describe('Localhost / Loopback', () => {
    it('should block localhost', () => {
      const result = validateUrl('http://localhost/admin');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('loopback');
    });

    it('should block 127.0.0.1', () => {
      const result = validateUrl('http://127.0.0.1/admin');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('loopback');
    });

    it('should block 127.x.x.x range', () => {
      const result = validateUrl('http://127.0.0.2/api');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('loopback');
    });

    it('should block 127.255.255.255', () => {
      const result = validateUrl('http://127.255.255.255/api');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('loopback');
    });

    it('should block [::1]', () => {
      const result = validateUrl('http://[::1]/admin');
      expect(result.safe).toBe(false);
    });

    it('should block 0.0.0.0', () => {
      const result = validateUrl('http://0.0.0.0/admin');
      expect(result.safe).toBe(false);
    });

    it('should block subdomain of localhost', () => {
      const result = validateUrl('http://evil.localhost/admin');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('loopback');
    });

    it('should allow localhost when explicitly enabled', () => {
      const result = validateUrl('http://localhost:3000/api', {
        allowLocalhost: true,
      });
      expect(result.safe).toBe(true);
    });
  });

  describe('Private IP Ranges', () => {
    it('should block 10.0.0.0/8', () => {
      const result = validateUrl('http://10.0.0.1/internal');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('10.0.0.0/8');
    });

    it('should block 10.255.255.255', () => {
      const result = validateUrl('http://10.255.255.255/api');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('10.0.0.0/8');
    });

    it('should block 172.16.0.0/12', () => {
      const result = validateUrl('http://172.16.0.1/internal');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('172.16.0.0/12');
    });

    it('should block 172.31.255.255', () => {
      const result = validateUrl('http://172.31.255.255/api');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('172.16.0.0/12');
    });

    it('should allow 172.15.x.x (not private)', () => {
      const result = validateUrl('http://172.15.0.1/api');
      expect(result.safe).toBe(true);
    });

    it('should allow 172.32.x.x (not private)', () => {
      const result = validateUrl('http://172.32.0.1/api');
      expect(result.safe).toBe(true);
    });

    it('should block 192.168.0.0/16', () => {
      const result = validateUrl('http://192.168.1.1/router');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('192.168.0.0/16');
    });

    it('should block 192.168.255.255', () => {
      const result = validateUrl('http://192.168.255.255/api');
      expect(result.safe).toBe(false);
    });

    it('should allow private IPs when explicitly enabled', () => {
      const result = validateUrl('http://10.0.0.1/api', {
        allowPrivate: true,
      });
      expect(result.safe).toBe(true);
    });
  });

  describe('Link-Local / Cloud Metadata', () => {
    it('should block AWS metadata endpoint', () => {
      const result = validateUrl('http://169.254.169.254/latest/meta-data/');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('link-local');
    });

    it('should block any 169.254.x.x address', () => {
      const result = validateUrl('http://169.254.0.1/');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('link-local');
    });

    it('should block GCP metadata hostname', () => {
      const result = validateUrl('http://metadata.google.internal/computeMetadata/v1/');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('cloud metadata');
    });

    it('should block 0.x.x.x (current network)', () => {
      const result = validateUrl('http://0.1.2.3/api');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('current network');
    });
  });

  describe('IPv6 Private Ranges', () => {
    it('should block fc00::/7 (unique local)', () => {
      const result = validateUrl('http://[fc00::1]/api');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('private IPv6');
    });

    it('should block fd00::/8 (unique local)', () => {
      const result = validateUrl('http://[fd12::1]/api');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('private IPv6');
    });

    it('should block fe80::/10 (link-local)', () => {
      const result = validateUrl('http://[fe80::1]/api');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('private IPv6');
    });
  });

  describe('Decimal IP Bypass', () => {
    // Note: Node's URL parser auto-resolves decimal IPs to dotted notation,
    // so the existing loopback/private checks catch these automatically.
    it('should block 127.0.0.1 as decimal (2130706433)', () => {
      const result = validateUrl('http://2130706433/');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('loopback');
    });

    it('should block 10.0.0.1 as decimal (167772161)', () => {
      const result = validateUrl('http://167772161/');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('private');
    });

    it('should block 192.168.1.1 as decimal (3232235777)', () => {
      const result = validateUrl('http://3232235777/');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('private');
    });

    it('should block 169.254.169.254 as decimal (2852039166)', () => {
      const result = validateUrl('http://2852039166/');
      expect(result.safe).toBe(false);
    });

    it('should allow safe decimal IPs', () => {
      // 8.8.8.8 = 134744072
      const result = validateUrl('http://134744072/');
      expect(result.safe).toBe(true);
    });
  });

  describe('Octal IP Bypass', () => {
    // Note: Node's URL parser auto-resolves octal IPs to dotted notation.
    it('should block 0177.0.0.1 (octal 127.0.0.1)', () => {
      const result = validateUrl('http://0177.0.0.1/');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('loopback');
    });

    it('should block 012.0.0.1 (octal 10.0.0.1)', () => {
      const result = validateUrl('http://012.0.0.1/');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('private');
    });

    it('should block 0300.0250.01.01 (octal 192.168.1.1)', () => {
      const result = validateUrl('http://0300.0250.01.01/');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('private');
    });

    it('should block hex notation 0x7f.0.0.1 (127.0.0.1)', () => {
      const result = validateUrl('http://0x7f.0.0.1/');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('loopback');
    });
  });

  describe('IPv6-Mapped IPv4', () => {
    // Node normalizes ::ffff:127.0.0.1 to ::ffff:7f00:1 (hex form)
    it('should block ::ffff:127.0.0.1', () => {
      const result = validateUrl('http://[::ffff:127.0.0.1]/');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('IPv6-mapped');
    });

    it('should block ::ffff:10.0.0.1', () => {
      const result = validateUrl('http://[::ffff:10.0.0.1]/');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('IPv6-mapped');
    });

    it('should block ::ffff:169.254.169.254', () => {
      const result = validateUrl('http://[::ffff:169.254.169.254]/');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('IPv6-mapped');
    });
  });

  describe('Azure Metadata', () => {
    it('should block Azure metadata hostname', () => {
      const result = validateUrl('http://metadata.azure.internal/metadata/instance');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('cloud metadata');
    });
  });

  describe('URL Credentials', () => {
    it('should block URL with username', () => {
      const result = validateUrl('http://admin@internal.server/');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('credentials');
    });

    it('should block URL with username and password', () => {
      const result = validateUrl('http://admin:password@internal.server/');
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('credentials');
    });
  });

  describe('Blocked Hosts', () => {
    it('should block custom blocked hosts', () => {
      const result = validateUrl('https://internal-api.corp.net/data', {
        blockedHosts: ['internal-api.corp.net'],
      });
      expect(result.safe).toBe(false);
      expect(result.reason).toContain('blocked host');
    });

    it('should be case-insensitive for blocked hosts', () => {
      const result = validateUrl('https://INTERNAL-API.Corp.Net/data', {
        blockedHosts: ['internal-api.corp.net'],
      });
      expect(result.safe).toBe(false);
    });
  });

  describe('Allowed Hosts', () => {
    it('should allow hosts on the allowlist even if they look private', () => {
      const result = validateUrl('http://10.0.0.1/api', {
        allowedHosts: ['10.0.0.1'],
      });
      expect(result.safe).toBe(true);
    });

    it('should be case-insensitive for allowed hosts', () => {
      const result = validateUrl('http://INTERNAL.service.local/api', {
        allowedHosts: ['internal.service.local'],
      });
      expect(result.safe).toBe(true);
    });
  });
});

describe('isUrlSafe', () => {
  it('should return true for safe URLs', () => {
    expect(isUrlSafe('https://example.com')).toBe(true);
  });

  it('should return false for private IPs', () => {
    expect(isUrlSafe('http://10.0.0.1')).toBe(false);
  });

  it('should return false for localhost', () => {
    expect(isUrlSafe('http://localhost')).toBe(false);
  });

  it('should pass options through', () => {
    expect(isUrlSafe('http://localhost:3000', { allowLocalhost: true })).toBe(true);
  });
});
