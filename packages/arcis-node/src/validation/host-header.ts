/**
 * @module @arcis/node/validation/host-header
 * Host-header validation (V41 — Host-header poisoning / subdomain-takeover).
 *
 * Apps that reflect the `Host` header into password-reset links, absolute
 * redirects, share URLs, or cache keys are vulnerable when an attacker sends
 * `Host: attacker.com`. This validator checks the Host against a configured
 * allowlist.
 *
 * Default-deny by construction: an empty allowlist rejects everything, so this
 * is OPT-IN — only meaningful once the app passes its real allowlist. That
 * avoids false positives on multi-tenant apps that legitimately serve many
 * Hosts (they either don't use this, or list their tenants).
 */

export interface ValidateHostResult {
  /** True when the Host header is in the allowlist. */
  safe: boolean;
  /** Human-readable reason when not safe. */
  reason?: string;
}

/** Strip a trailing `:port` and lowercase. IPv6 literals are expected in
 * bracket form (`[::1]`), which this leaves intact. */
function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/:\d+$/, '');
}

/**
 * Validate a Host header against an allowlist. Case-insensitive, port-stripped.
 * Supports a single-level leading `*.` wildcard: `*.example.com` matches
 * `a.example.com` but not `example.com` or `a.b.example.com`.
 *
 * @example
 * validateHost('app.example.com:443', ['app.example.com']) // { safe: true }
 * validateHost('evil.com', ['app.example.com'])            // { safe: false }
 * validateHost('a.example.com', ['*.example.com'])          // { safe: true }
 * validateHost('x', [])                                     // { safe: false } (default-deny)
 */
export function validateHost(host: string, allowlist: string[]): ValidateHostResult {
  if (typeof host !== 'string' || host.trim().length === 0) {
    return { safe: false, reason: 'missing Host header' };
  }
  if (!Array.isArray(allowlist) || allowlist.length === 0) {
    return { safe: false, reason: 'no Host allowlist configured (default-deny)' };
  }
  const h = normalizeHost(host);
  for (const entry of allowlist) {
    const a = String(entry).trim().toLowerCase();
    if (!a) continue;
    if (a.startsWith('*.')) {
      const suffix = a.slice(1); // ".example.com"
      const label = h.endsWith(suffix) ? h.slice(0, h.length - suffix.length) : null;
      // one-level wildcard: exactly one label before the suffix, no extra dots
      if (label !== null && label.length > 0 && !label.includes('.')) {
        return { safe: true };
      }
    } else if (h === a) {
      return { safe: true };
    }
  }
  return { safe: false, reason: `Host not in allowlist: ${h}` };
}

/** Boolean convenience wrapper around {@link validateHost}. */
export function isHostAllowed(host: string, allowlist: string[]): boolean {
  return validateHost(host, allowlist).safe;
}
