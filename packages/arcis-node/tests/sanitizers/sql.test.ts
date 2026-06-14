/**
 * SQL Injection Sanitizer Tests
 * Tests for src/sanitizers/sql.ts
 */

import { describe, it, expect } from 'vitest';
import { sanitizeSql, detectSql } from '../../src/sanitizers/sql';

describe('sanitizeSql', () => {
  // Updated 2026-06-07 (benchmark FP class B3): bare SQL keywords
  // (SELECT, INSERT, UPDATE, DELETE, UNION, DROP, etc.) no longer
  // trigger removal because they false-positive on natural English
  // ("please select an option", "I'll update you tomorrow"). The
  // current SQL_PATTERNS rule requires multi-token attack shapes
  // (UNION SELECT, DROP TABLE, INTO OUTFILE, etc.).
  describe('Multi-token SQL attack shapes', () => {
    it('should block DROP TABLE shape', () => {
      const result = sanitizeSql("'; DROP TABLE users; --");
      expect(result.toUpperCase()).not.toContain('DROP TABLE');
    });

    it('should block TRUNCATE TABLE shape', () => {
      const result = sanitizeSql('1; TRUNCATE TABLE logs --');
      expect(result.toUpperCase()).not.toContain('TRUNCATE TABLE');
    });

    it('should block UNION SELECT shape', () => {
      const result = sanitizeSql('1 UNION SELECT password FROM users');
      expect(result.toUpperCase()).not.toContain('UNION SELECT');
    });

    it('should block UNION ALL SELECT shape', () => {
      const result = sanitizeSql('1 UNION ALL SELECT * FROM users');
      expect(result.toUpperCase()).not.toContain('UNION ALL SELECT');
    });

    it('should block INTO OUTFILE shape', () => {
      const result = sanitizeSql("1 UNION SELECT 'pwn' INTO OUTFILE '/var/www/shell.php'");
      expect(result.toUpperCase()).not.toContain('INTO OUTFILE');
    });

    it('should block ATTACH DATABASE (SQLite)', () => {
      const result = sanitizeSql("1; ATTACH DATABASE '/tmp/evil.db' AS evil --");
      expect(result.toUpperCase()).not.toContain('ATTACH DATABASE');
    });

    it('should block CREATE USER (privilege escalation)', () => {
      const result = sanitizeSql("'; CREATE USER hacker --");
      expect(result.toUpperCase()).not.toContain('CREATE USER');
    });

    it('should block GRANT ALL', () => {
      const result = sanitizeSql("'; GRANT ALL ON *.* TO 'hacker'");
      expect(result.toUpperCase()).not.toContain('GRANT ALL');
    });

    it('should block xp_cmdshell (SQL Server RCE)', () => {
      const result = sanitizeSql('1; EXEC xp_cmdshell');
      expect(result.toLowerCase()).not.toContain('xp_cmdshell');
    });

    it('should block sp_executesql', () => {
      const result = sanitizeSql("EXEC sp_executesql @sql");
      expect(result.toLowerCase()).not.toContain('sp_executesql');
    });

    it('should block SHUTDOWN', () => {
      const result = sanitizeSql("'; SHUTDOWN --");
      expect(result.toUpperCase()).not.toContain('SHUTDOWN');
    });
  });

  describe('Benign SQL-shaped content is preserved (FP regression — B3)', () => {
    it('does not strip the word "select" in plain English', () => {
      const input = 'please select an option from the dropdown';
      expect(sanitizeSql(input)).toBe(input);
    });

    it('does not strip "update" in plain English', () => {
      const input = "I'll update you tomorrow about the meeting";
      expect(sanitizeSql(input)).toBe(input);
    });

    it('does not strip "delete" in plain English', () => {
      const input = 'You can delete this file from the trash folder';
      expect(sanitizeSql(input)).toBe(input);
    });

    it('does not strip code-snippet SELECT * FROM (shared as content)', () => {
      // User pastes example SQL in a chat/issue/comment. App uses
      // parameterized queries — middleware shouldn't fight the content.
      const input = 'SELECT * FROM users WHERE id = ?';
      expect(sanitizeSql(input)).toBe(input);
    });

    it('does not strip DROP shipping notification', () => {
      // Real-world string from logistics apps.
      const input = 'Please drop off the package at the location.';
      expect(sanitizeSql(input)).toBe(input);
    });
  });

  describe('SQL Comment Removal', () => {
    it('should block -- comments', () => {
      const result = sanitizeSql("admin'--");
      expect(result).not.toContain('--');
    });

    it('should block /* */ comments', () => {
      const result = sanitizeSql('1 /* comment */ OR 1=1');
      expect(result).not.toContain('/*');
    });

    it('does NOT block markdown # heading (FP regression — B1)', () => {
      // MySQL # comment was removed from SQL_PATTERNS 2026-06-07
      // because it false-positived on every hex color, hashtag,
      // issue ref, and markdown heading.
      const input = '# Heading';
      expect(sanitizeSql(input)).toBe(input);
    });

    it('does NOT block hex colors (FP regression — B1)', () => {
      const input = '#FF5300 is the primary brand color';
      expect(sanitizeSql(input)).toBe(input);
    });

    it('does NOT block hashtags (FP regression — B1)', () => {
      const input = 'Just shipped v1.7 #releaseday #buildinpublic';
      expect(sanitizeSql(input)).toBe(input);
    });

    it('does NOT block issue references (FP regression — B1)', () => {
      const input = 'see issue #123 and PR-456';
      expect(sanitizeSql(input)).toBe(input);
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

    // Quoted-boolean tautology: the closing quote is unterminated because the
    // app's own quote completes it (`1' OR '1'='1`). Previously missed because
    // the boolean-string rule required both operands fully quote-closed.
    it.each([
      "1' OR '1'='1",
      "' OR '1'='1",
      "admin' OR '1'='1",
      "' OR 'a'='a",
      '1" OR "1"="1',
      "x' AND '1'='1",
    ])('detects quoted-boolean tautology: %s', (payload) => {
      expect(detectSql(payload)).toBe(true);
    });

    it.each([
      "O'Brien",
      "it's a test",
      "Sam's OR Jill's pick",
      "author = 'John'",
      "status OR priority",
    ])('does NOT flag benign quoted text: %s', (text) => {
      expect(detectSql(text)).toBe(false);
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

    it('should handle mixed case attack shapes', () => {
      // Updated 2026-06-07 (B3): bare `SeLeCt * FrOm` is no longer
      // treated as injection. Use a real multi-token attack shape.
      const result = sanitizeSql('1 uNiOn SeLeCt password FROM users');
      expect(result.toUpperCase()).not.toContain('UNION SELECT');
    });
  });
});

describe('detectSql', () => {
  it('should detect DROP TABLE shape', () => {
    expect(detectSql('DROP TABLE users')).toBe(true);
  });

  it('should detect UNION SELECT shape', () => {
    // Updated 2026-06-07 (B3): bare `SELECT * FROM` no longer flagged.
    // UNION SELECT remains the canonical SQLi exfiltration shape.
    expect(detectSql('1 UNION SELECT password FROM users')).toBe(true);
  });

  it('should NOT detect bare SELECT * FROM (FP regression — B3)', () => {
    // Pasting example SQL in a chat/issue/comment shouldn't trigger.
    // App responsibility: use parameterized queries. Middleware
    // responsibility: catch obvious attacker shapes, not all SQL syntax.
    expect(detectSql('SELECT * FROM users WHERE id = ?')).toBe(false);
  });

  it('should detect comment syntax', () => {
    expect(detectSql("admin'--")).toBe(true);
  });

  it('should not flag HTML comments as SQL (the -- inside <!--)', () => {
    expect(detectSql('<!-- TODO fix later -->')).toBe(false);
    expect(detectSql('<!-- a longer note: see the ticket -->')).toBe(false);
    // a real trailing SQL comment is still caught
    expect(detectSql("admin'-- ")).toBe(true);
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
