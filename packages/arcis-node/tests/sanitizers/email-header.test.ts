/**
 * Email-header injection tests (sdk-vectors.md tier 1 #24).
 *
 * Email-header injection shares the same wire-level threat as HTTP-header
 * injection — `\r\n` in a value that gets concatenated into a header lets
 * an attacker inject extra headers (Bcc, From spoofing, etc.). The
 * email-header surface is exposed as an alias of the HTTP-header sanitizer
 * but tested independently to pin the contact-form / form-to-email
 * use case.
 */

import { describe, it, expect } from 'vitest';
import {
  detectEmailHeaderInjection,
  sanitizeEmailHeader,
} from '../../src/sanitizers/headers';
import { scanThreats } from '../../src/sanitizers/sanitize';

describe('detectEmailHeaderInjection', () => {
  it('detects CRLF Bcc-injection in a To: field', () => {
    // The textbook payload: contact form passes `to=victim@host` to a
    // mailer; attacker submits `victim@host\r\nBcc: spammer@host` to
    // turn the form into a spam relay.
    expect(detectEmailHeaderInjection('victim@host\r\nBcc: spammer@host')).toBe(true);
  });

  it('detects bare LF (\\n) — some MTAs normalize it to CRLF', () => {
    expect(detectEmailHeaderInjection('victim@host\nBcc: spammer@host')).toBe(true);
  });

  it('detects bare CR (\\r)', () => {
    expect(detectEmailHeaderInjection('victim@host\rBcc: spammer@host')).toBe(true);
  });

  it('detects null-byte truncation', () => {
    expect(detectEmailHeaderInjection('victim@host\0Bcc: spammer@host')).toBe(true);
  });

  it('passes legitimate email values through', () => {
    expect(detectEmailHeaderInjection('alice@example.com')).toBe(false);
    expect(detectEmailHeaderInjection('Alice Smith <alice@example.com>')).toBe(false);
    expect(detectEmailHeaderInjection('Subject: Order #123')).toBe(false);
  });

  it('handles non-string input safely', () => {
    expect(detectEmailHeaderInjection(null as unknown as string)).toBe(false);
    expect(detectEmailHeaderInjection(undefined as unknown as string)).toBe(false);
    expect(detectEmailHeaderInjection(42 as unknown as string)).toBe(false);
  });
});

describe('sanitizeEmailHeader', () => {
  it('strips CRLF from a Bcc-injection payload', () => {
    const raw = 'victim@host\r\nBcc: spammer@host';
    const cleaned = sanitizeEmailHeader(raw);
    expect(cleaned).not.toContain('\r');
    expect(cleaned).not.toContain('\n');
    // Bcc string itself isn't dangerous once the CRLF is gone — the
    // header concatenation can no longer inject a new header line.
    expect(cleaned).toBe('victim@hostBcc: spammer@host');
  });

  it('strips bare LF', () => {
    expect(sanitizeEmailHeader('alice@host\nx')).toBe('alice@hostx');
  });

  it('strips null bytes', () => {
    expect(sanitizeEmailHeader('alice@host\0x')).toBe('alice@hostx');
  });

  it('passes legitimate emails through unchanged', () => {
    expect(sanitizeEmailHeader('alice@example.com')).toBe('alice@example.com');
  });
});

describe('scanThreats integration — email-header CRLF', () => {
  it('reports vector="header" for CRLF in a body field', () => {
    // Pin: block-mode middleware now catches email-header injection
    // via scanThreats, which routes any CRLF-bearing value to the
    // header vector. Same shape works for HTTP response splitting.
    const hit = scanThreats({ to: 'victim@host\r\nBcc: spammer@host' });
    expect(hit?.vector).toBe('header');
    expect(hit?.rule).toBe('header/match');
  });

  it('reports header vector even on bare LF (no carriage return)', () => {
    const hit = scanThreats({ subject: 'Test\nBcc: a@b' });
    expect(hit?.vector).toBe('header');
  });

  it('does not fire on a clean email field', () => {
    expect(scanThreats({ to: 'alice@example.com' })).toBeNull();
  });

  it('attributes a CRLF-bearing XSS payload to xss, not header', () => {
    // The vector ordering puts xss first, so a payload that's both
    // (XSS + a stray newline) reads as XSS, which is the stronger
    // signal. Pinning here so a future reorder doesn't silently
    // reattribute.
    const hit = scanThreats({ q: '<script>alert(1)</script>\n' });
    expect(hit?.vector).toBe('xss');
  });
});
