import { describe, it, expect } from 'vitest';
import { sanitizeLdapFilter, sanitizeLdapDn, detectLdapInjection } from '../../src/sanitizers/ldap';

describe('sanitizeLdapFilter', () => {
  it('escapes wildcard *', () => {
    expect(sanitizeLdapFilter('admin*')).toBe('admin\\2a');
  });

  it('escapes opening parenthesis (', () => {
    expect(sanitizeLdapFilter('(admin')).toBe('\\28admin');
  });

  it('escapes closing parenthesis )', () => {
    expect(sanitizeLdapFilter('admin)')).toBe('admin\\29');
  });

  it('escapes backslash', () => {
    expect(sanitizeLdapFilter('ad\\min')).toBe('ad\\5cmin');
  });

  it('escapes NUL byte', () => {
    expect(sanitizeLdapFilter('ad\x00min')).toBe('ad\\00min');
  });

  it('escapes full OR bypass payload', () => {
    const payload = '*)(uid=*))(|(uid=*';
    const result = sanitizeLdapFilter(payload);
    expect(result).not.toContain('*');
    expect(result).not.toContain('(');
    expect(result).not.toContain(')');
  });

  it('leaves safe input unchanged', () => {
    expect(sanitizeLdapFilter('johndoe')).toBe('johndoe');
    expect(sanitizeLdapFilter('john.doe@example.com')).toBe('john.doe@example.com');
  });

  it('handles empty string', () => {
    expect(sanitizeLdapFilter('')).toBe('');
  });

  it('handles non-string input', () => {
    expect(sanitizeLdapFilter(123 as any)).toBe('123');
  });
});

describe('sanitizeLdapDn', () => {
  it('escapes comma', () => {
    expect(sanitizeLdapDn('cn=admin,dc=example')).toContain('\\2c');
  });

  it('escapes equals sign', () => {
    expect(sanitizeLdapDn('cn=admin')).toContain('\\3d');
  });

  it('escapes plus sign', () => {
    expect(sanitizeLdapDn('a+b')).toContain('\\2b');
  });

  it('escapes semicolon', () => {
    expect(sanitizeLdapDn('a;b')).toContain('\\3b');
  });

  it('escapes angle brackets', () => {
    expect(sanitizeLdapDn('<admin>')).toContain('\\3c');
    expect(sanitizeLdapDn('<admin>')).toContain('\\3e');
  });

  it('leaves safe input unchanged', () => {
    expect(sanitizeLdapDn('johndoe')).toBe('johndoe');
  });

  it('handles empty string', () => {
    expect(sanitizeLdapDn('')).toBe('');
  });
});

describe('detectLdapInjection', () => {
  // Wildcard in filter value context — `=*` shape only, not bare `*`.
  // Updated 2026-06-07 (benchmark FP class B2): bare `*` was too broad.
  it('detects wildcard value in filter context: =*', () => {
    expect(detectLdapInjection('(uid=*)')).toBe(true);
  });

  it('detects wildcard value with whitespace: = *', () => {
    expect(detectLdapInjection('uid = *')).toBe(true);
  });

  it('detects OR bypass payload', () => {
    expect(detectLdapInjection('*)(uid=*))(|(uid=*')).toBe(true);
  });

  it('detects parentheses break-out: )(', () => {
    expect(detectLdapInjection('admin)(&(password=*)')).toBe(true);
  });

  it('detects NUL byte (LDAP query truncation)', () => {
    expect(detectLdapInjection('ad\x00min')).toBe(true);
  });

  // improvements.md Q8 — LDAP NOT-operator bypass corpus.
  it('detects NOT-bypass after OR escape: )(!', () => {
    expect(detectLdapInjection('*)(uid=*)(!(uid=admin))')).toBe(true);
  });

  it('detects NOT-bypass after AND: &(!', () => {
    expect(detectLdapInjection('foo&(!(role=anon))')).toBe(true);
  });

  it('detects NOT-bypass after pipe: |(!', () => {
    expect(detectLdapInjection('foo|(!(deleted=true))')).toBe(true);
  });

  it('returns false for safe input', () => {
    expect(detectLdapInjection('johndoe')).toBe(false);
    expect(detectLdapInjection('john.doe@example.com')).toBe(false);
    expect(detectLdapInjection('John Doe')).toBe(false);
  });

  // Benchmark FP class B2 — false-positive regression guards.
  // These payloads previously triggered LDAP detection via the
  // overly-broad `[*()\\\x00]` rule and would block every markdown
  // editor, math expression, and parenthetical comment.
  it('returns false for markdown bold (**)', () => {
    expect(detectLdapInjection('this is **bold** text')).toBe(false);
  });

  it('returns false for markdown italic (*)', () => {
    expect(detectLdapInjection('hello *world* hi')).toBe(false);
  });

  it('returns false for math expression with asterisk', () => {
    expect(detectLdapInjection('area = x * y')).toBe(false);
  });

  it('returns false for parenthetical text', () => {
    expect(detectLdapInjection('one (two) three')).toBe(false);
  });

  it('returns false for single backslash in text', () => {
    // Single `\` is escape syntax — only meaningful adjacent to a real
    // LDAP special. Bare `\` in middle of text is legitimate (e.g.
    // Windows-style file paths shared in a comment).
    expect(detectLdapInjection('ad\\min')).toBe(false);
  });

  it('returns false for empty string', () => {
    expect(detectLdapInjection('')).toBe(false);
  });

  it('returns false for non-string', () => {
    expect(detectLdapInjection(123 as any)).toBe(false);
  });
});
