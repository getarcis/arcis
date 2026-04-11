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
  it('detects wildcard injection', () => {
    expect(detectLdapInjection('*')).toBe(true);
  });

  it('detects OR bypass payload', () => {
    expect(detectLdapInjection('*)(uid=*))(|(uid=*')).toBe(true);
  });

  it('detects parentheses', () => {
    expect(detectLdapInjection('admin)(&(password=*)')).toBe(true);
  });

  it('detects backslash', () => {
    expect(detectLdapInjection('ad\\min')).toBe(true);
  });

  it('detects NUL byte', () => {
    expect(detectLdapInjection('ad\x00min')).toBe(true);
  });

  it('returns false for safe input', () => {
    expect(detectLdapInjection('johndoe')).toBe(false);
    expect(detectLdapInjection('john.doe@example.com')).toBe(false);
    expect(detectLdapInjection('John Doe')).toBe(false);
  });

  it('returns false for empty string', () => {
    expect(detectLdapInjection('')).toBe(false);
  });

  it('returns false for non-string', () => {
    expect(detectLdapInjection(123 as any)).toBe(false);
  });
});
