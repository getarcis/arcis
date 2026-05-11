/**
 * XPath Injection Tests
 * Tests for src/sanitizers/xpath.ts (detectXpathInjection + sanitizeXpath)
 * and the wiring into scanThreats so block-mode middleware catches XPath
 * payloads.
 */

import { describe, it, expect } from 'vitest';
import { detectXpathInjection, sanitizeXpath } from '../../src/sanitizers/xpath';
import { scanThreats } from '../../src/sanitizers/sanitize';

describe('detectXpathInjection', () => {
  describe('Detects classic injection patterns', () => {
    it('boolean-OR injection breaking out of a string literal', () => {
      // The textbook XPath-injection payload: `' or '1'='1`. Inside an
      // expression like `//user[name='${input}' and pass='${pw}']` it
      // turns the predicate into a tautology and returns every row.
      expect(detectXpathInjection("' or '1'='1")).toBe(true);
    });

    it('double-quote variant of the OR injection', () => {
      expect(detectXpathInjection('" or "1"="1')).toBe(true);
    });

    it('paren-wrapped boolean injection', () => {
      // `) or (` is the shape attackers use against XPath functions
      // like `position()` — closes the call early, opens a new one.
      expect(detectXpathInjection(') or (')).toBe(true);
    });

    it('union expression injection (|/)', () => {
      // The XPath union operator `|` lets an attacker concatenate a
      // second result set onto the original query.
      expect(detectXpathInjection("john' | /users/*")).toBe(true);
    });

    it('AND-form injection (real-world variant)', () => {
      expect(detectXpathInjection("' and '1'='1")).toBe(true);
    });
  });

  describe('Does NOT trigger on benign input', () => {
    it('plain alphanumeric usernames', () => {
      expect(detectXpathInjection('alice')).toBe(false);
      expect(detectXpathInjection('alice42')).toBe(false);
      expect(detectXpathInjection('alice_bob')).toBe(false);
    });

    it('emails', () => {
      expect(detectXpathInjection('alice@example.com')).toBe(false);
    });

    it('strings with quotes BUT no boolean-injection shape (false-positive guard)', () => {
      // Conservative: a quote alone is not enough to fire. The shape
      // requires a boolean / union / paren-toggle pattern as well so
      // a name like `O'Brien` doesn't read as injection.
      expect(detectXpathInjection("O'Brien")).toBe(false);
      expect(detectXpathInjection('"Hello"')).toBe(false);
    });

    it('empty string + non-string input', () => {
      expect(detectXpathInjection('')).toBe(false);
      expect(detectXpathInjection(null as unknown as string)).toBe(false);
      expect(detectXpathInjection(undefined as unknown as string)).toBe(false);
      expect(detectXpathInjection(42 as unknown as string)).toBe(false);
    });
  });
});

describe('sanitizeXpath', () => {
  it('strips quote control characters', () => {
    expect(sanitizeXpath("' or '1'='1")).toBe(' or 1=1');
  });

  it('strips union pipe', () => {
    expect(sanitizeXpath('john| /users')).toBe('john /users');
  });

  it('passes plain strings through unchanged', () => {
    expect(sanitizeXpath('alice')).toBe('alice');
  });

  it('coerces non-string input to string', () => {
    expect(sanitizeXpath(42 as unknown as string)).toBe('42');
    expect(sanitizeXpath(null as unknown as string)).toBe('null');
  });

  it('lossy on legitimate apostrophes (documented tradeoff)', () => {
    // O'Brien → OBrien. This is a deliberate v1 tradeoff: lossless
    // handling requires bound parameters at the underlying XPath lib.
    // sanitizeXpath is for migration; new code should use bindings.
    expect(sanitizeXpath("O'Brien")).toBe('OBrien');
  });
});

describe('scanThreats integration — XPath + LDAP wiring', () => {
  it('reports vector="xpath" for an XPath injection payload', () => {
    const hit = scanThreats({ name: "' or '1'='1" });
    expect(hit?.vector).toBe('xpath');
    expect(hit?.rule).toBe('xpath/match');
    expect(hit?.matchedPattern).toContain("' or '1'='1");
  });

  it('reports vector="ldap" for an LDAP injection payload', () => {
    // Pins the LDAP wiring into scanThreats — the existing detect
    // function was already exported but block-mode (which uses
    // scanThreats) didn't catch LDAP until this commit. Payload chosen
    // to avoid `|` (would hit command detection first); `*)(uid=*)` is
    // a textbook LDAP-only injection shape (RFC 4515 paren-toggle plus
    // wildcard) that nothing else matches.
    const hit = scanThreats({ filter: 'admin)(uid=*)' });
    expect(hit?.vector).toBe('ldap');
    expect(hit?.rule).toBe('ldap/match');
  });

  it('returns null on a clean object (no false positives)', () => {
    expect(scanThreats({ name: 'alice', email: 'alice@example.com' })).toBeNull();
  });

  it('finds nested-object XPath injection', () => {
    // scanThreats walks objects + arrays recursively. Pin: nested
    // structures (request body shapes) still surface the hit.
    const hit = scanThreats({
      filter: { user: { name: "' or '1'='1" } },
    });
    expect(hit?.vector).toBe('xpath');
  });

  it('attributes path-traversal payloads to "path", not "ldap"', () => {
    // Regression: `../` contains a backslash-free path that should NOT
    // be misattributed to LDAP. The vector ordering in scanThreats
    // intentionally puts path/command before ldap/xpath so this is
    // resolved.
    const hit = scanThreats({ file: '../../etc/passwd' });
    expect(hit?.vector).toBe('path');
  });
});
