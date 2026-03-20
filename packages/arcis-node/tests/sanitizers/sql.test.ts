/**
 * SQL Injection Sanitizer Tests
 * Tests for src/sanitizers/sql.ts
 */

import { describe, it, expect } from 'vitest';
import { sanitizeSql, detectSql } from '../../src/sanitizers/sql';

describe('sanitizeSql', () => {
  describe('Dangerous Keywords', () => {
    it('should block DROP keyword', () => {
      const result = sanitizeSql("'; DROP TABLE users; --");
      expect(result.toUpperCase()).not.toContain('DROP');
    });

    it('should block SELECT keyword', () => {
      const result = sanitizeSql('SELECT * FROM users');
      expect(result.toUpperCase()).not.toContain('SELECT');
    });

    it('should block DELETE keyword', () => {
      const result = sanitizeSql('DELETE FROM users WHERE 1=1');
      expect(result.toUpperCase()).not.toContain('DELETE');
    });

    it('should block INSERT keyword', () => {
      const result = sanitizeSql("INSERT INTO users VALUES ('hacker')");
      expect(result.toUpperCase()).not.toContain('INSERT');
    });

    it('should block UPDATE keyword', () => {
      const result = sanitizeSql("UPDATE users SET admin=1 WHERE 1=1");
      expect(result.toUpperCase()).not.toContain('UPDATE');
    });

    it('should block UNION keyword', () => {
      const result = sanitizeSql('1 UNION SELECT password FROM users');
      expect(result.toUpperCase()).not.toContain('UNION');
    });

    it('should block EXEC/EXECUTE keywords', () => {
      const result = sanitizeSql('EXEC xp_cmdshell');
      expect(result.toUpperCase()).not.toContain('EXEC');
    });
  });

  describe('SQL Comment Removal', () => {
    it('should block -- comments', () => {
      const result = sanitizeSql("admin'--");
      expect(result).not.toContain('--');
    });

    // Note: # comments are NOT in current SQL_PATTERNS
    // Current comment pattern: /(--|\/\*|\*\/)/g
    // Add /#/g to SQL_PATTERNS in constants.ts if needed

    it('should block /* */ comments', () => {
      const result = sanitizeSql('1 /* comment */ OR 1=1');
      expect(result).not.toContain('/*');
    });
  });

  describe('Time-based Blind Injection', () => {
    it('should block SLEEP(5)', () => {
      const result = sanitizeSql("1 AND SLEEP(5)");
      expect(result.toUpperCase()).not.toMatch(/SLEEP/);
    });

    it('should block pg_sleep(5)', () => {
      const result = sanitizeSql("1; SELECT pg_sleep(5)");
      expect(result).not.toMatch(/pg_sleep/i);
    });

    it('should block WAITFOR DELAY', () => {
      const result = sanitizeSql("1; WAITFOR DELAY '0:0:5'");
      expect(result.toUpperCase()).not.toMatch(/WAITFOR/);
    });

    it('should block BENCHMARK()', () => {
      const result = sanitizeSql("1 AND BENCHMARK(10000000, SHA1('test'))");
      expect(result.toUpperCase()).not.toMatch(/BENCHMARK/);
    });
  });

  describe('Boolean-based Injection', () => {
    it('should block OR 1=1 pattern', () => {
      const result = sanitizeSql('1 OR 1=1');
      expect(result.toUpperCase()).not.toMatch(/OR\s+1/);
    });

    it('should block AND 1=1 pattern', () => {
      const result = sanitizeSql("' AND 1=1");
      expect(result.toUpperCase()).not.toMatch(/AND\s+1/);
    });
  });

  describe('Threat Collection', () => {
    it('should collect threat info when requested', () => {
      const result = sanitizeSql("'; DROP TABLE users; --", true);
      expect(result.wasSanitized).toBe(true);
      expect(result.threats.length).toBeGreaterThan(0);
      expect(result.threats[0].type).toBe('sql_injection');
    });

    it('should return no threats for safe input', () => {
      const result = sanitizeSql('normal text', true);
      expect(result.wasSanitized).toBe(false);
      expect(result.threats).toHaveLength(0);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty string', () => {
      const result = sanitizeSql('');
      expect(result).toBe('');
    });

    it('should handle non-string input', () => {
      const result = sanitizeSql(123 as unknown as string);
      expect(result).toBe('123');
    });

    it('should preserve safe content', () => {
      const result = sanitizeSql('John Doe');
      expect(result).toBe('John Doe');
    });

    it('should handle mixed case keywords', () => {
      const result = sanitizeSql('SeLeCt * FrOm users');
      expect(result.toUpperCase()).not.toContain('SELECT');
    });
  });
});

describe('detectSql', () => {
  it('should detect DROP keyword', () => {
    expect(detectSql('DROP TABLE users')).toBe(true);
  });

  it('should detect SELECT keyword', () => {
    expect(detectSql('SELECT * FROM users')).toBe(true);
  });

  it('should detect comment syntax', () => {
    expect(detectSql("admin'--")).toBe(true);
  });

  it('should detect UNION keyword', () => {
    expect(detectSql('UNION SELECT')).toBe(true);
  });

  it('should detect SLEEP()', () => {
    expect(detectSql('1 AND SLEEP(5)')).toBe(true);
  });

  it('should detect pg_sleep()', () => {
    expect(detectSql('SELECT pg_sleep(10)')).toBe(true);
  });

  it('should detect WAITFOR DELAY', () => {
    expect(detectSql("WAITFOR DELAY '0:0:5'")).toBe(true);
  });

  it('should detect BENCHMARK()', () => {
    expect(detectSql("BENCHMARK(10000000, SHA1('test'))")).toBe(true);
  });

  it('should return false for safe input', () => {
    expect(detectSql('Hello World')).toBe(false);
  });

  it('should handle non-string input', () => {
    expect(detectSql(123 as unknown as string)).toBe(false);
  });
});
