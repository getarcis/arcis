import { describe, it, expect } from 'vitest';
import { validateHost, isHostAllowed } from '../../src/validation/host-header';

describe('validateHost (V41 Host-header poisoning)', () => {
  const allow = ['app.example.com', '*.tenant.example.com'];

  it.each([
    ['app.example.com'],
    ['app.example.com:443'], // port stripped
    ['APP.EXAMPLE.COM'], // case-insensitive
    ['a.tenant.example.com'], // one-level wildcard
    ['b.tenant.example.com:8080'],
  ])('allows %s', (host) => {
    expect(validateHost(host, allow).safe).toBe(true);
  });

  it.each([
    ['attacker.com'],
    ['evil.example.com'], // not under the wildcard
    ['a.b.tenant.example.com'], // two levels — wildcard is single-level
    ['tenant.example.com'], // wildcard requires a label
    ['app.example.com.attacker.com'], // suffix-spoof
  ])('rejects %s', (host) => {
    expect(validateHost(host, allow).safe).toBe(false);
  });

  it('default-denies with an empty allowlist (opt-in semantics)', () => {
    const r = validateHost('app.example.com', []);
    expect(r.safe).toBe(false);
    expect(r.reason).toContain('default-deny');
  });

  it('rejects a missing/empty Host', () => {
    expect(validateHost('', allow).safe).toBe(false);
    // @ts-expect-error runtime guard
    expect(validateHost(undefined, allow).safe).toBe(false);
  });

  it('isHostAllowed mirrors validateHost.safe', () => {
    expect(isHostAllowed('app.example.com', allow)).toBe(true);
    expect(isHostAllowed('evil.com', allow)).toBe(false);
  });
});
