/**
 * @module @arcis/node/middleware/security-headers
 * Framework-agnostic security header planning.
 *
 * Every adapter (Express, Fastify, Koa, Hono, Next.js, SvelteKit, Astro, Nuxt,
 * Bun) computes the same plan here and only applies it with its own response
 * API. This keeps wire output identical across adapters.
 */

import { HEADERS } from '../core/constants';
import type { HeaderOptions, HstsOptions } from '../core/types';

/** Ordered header assignments plus headers to strip from the response. */
export interface SecurityHeaderPlan {
  /** Header name/value pairs, in emission order. */
  readonly set: ReadonlyArray<readonly [name: string, value: string]>;
  /** Header names to remove (fingerprinting headers). */
  readonly remove: readonly string[];
}

/** Request facts an adapter supplies; the planner never reads a request. */
export interface SecurityHeaderContext {
  /** True when the request arrived over HTTPS, as determined by the adapter. */
  readonly isHttps: boolean;
}

/**
 * Parse the first `X-Forwarded-Proto` entry. Only the exact values `http`
 * and `https` are accepted; anything else is treated as absent.
 */
export function parseForwardedProto(value: string | null | undefined): 'http' | 'https' | undefined {
  const first = value?.split(',')[0]?.trim().toLowerCase();
  return first === 'https' || first === 'http' ? first : undefined;
}

/** Apply a plan to a Fetch API `Headers` object (Hono, Next.js, SvelteKit, Astro, Bun). */
export function applyPlanToHeaders(headers: Headers, plan: SecurityHeaderPlan): void {
  for (const [name, value] of plan.set) headers.set(name, value);
  for (const name of plan.remove) headers.delete(name);
}

/** Build the HSTS value from options. */
export function hstsValue(hsts: true | HstsOptions): string {
  const options: HstsOptions = typeof hsts === 'object' ? hsts : {};
  let value = `max-age=${options.maxAge ?? HEADERS.HSTS_MAX_AGE}`;
  if (options.includeSubDomains !== false) value += '; includeSubDomains';
  if (options.preload === true) value += '; preload';
  return value;
}

/**
 * Compute the security headers for one response.
 *
 * @param options - Header configuration (same shape as `createHeaders`)
 * @param context - Request facts supplied by the adapter
 * @returns The ordered headers to set and the headers to remove
 */
export function planSecurityHeaders(
  options: HeaderOptions,
  context: SecurityHeaderContext,
): SecurityHeaderPlan {
  const {
    contentSecurityPolicy = true,
    xssFilter = true,
    noSniff = true,
    frameOptions = HEADERS.FRAME_OPTIONS,
    hsts = true,
    referrerPolicy = HEADERS.REFERRER_POLICY,
    permissionsPolicy = HEADERS.PERMISSIONS_POLICY,
    cacheControl = true,
    crossOriginOpenerPolicy = 'same-origin',
    crossOriginResourcePolicy = 'same-origin',
    crossOriginEmbedderPolicy = 'require-corp',
    originAgentCluster = true,
    dnsPrefetchControl = true,
  } = options;

  const set: Array<readonly [string, string]> = [];

  if (contentSecurityPolicy) {
    set.push([
      'Content-Security-Policy',
      typeof contentSecurityPolicy === 'string' ? contentSecurityPolicy : HEADERS.DEFAULT_CSP,
    ]);
  }
  // '0' disables the legacy XSS auditor, which was itself an attack vector.
  if (xssFilter) set.push(['X-XSS-Protection', '0']);
  if (noSniff) set.push(['X-Content-Type-Options', HEADERS.CONTENT_TYPE_OPTIONS]);
  if (frameOptions) set.push(['X-Frame-Options', frameOptions]);
  if (hsts && context.isHttps) set.push(['Strict-Transport-Security', hstsValue(hsts)]);
  if (referrerPolicy) set.push(['Referrer-Policy', referrerPolicy]);
  if (permissionsPolicy) set.push(['Permissions-Policy', permissionsPolicy]);
  if (crossOriginOpenerPolicy) set.push(['Cross-Origin-Opener-Policy', crossOriginOpenerPolicy]);
  if (crossOriginResourcePolicy) set.push(['Cross-Origin-Resource-Policy', crossOriginResourcePolicy]);
  if (crossOriginEmbedderPolicy) set.push(['Cross-Origin-Embedder-Policy', crossOriginEmbedderPolicy]);
  if (originAgentCluster) set.push(['Origin-Agent-Cluster', '?1']);
  if (dnsPrefetchControl) set.push(['X-DNS-Prefetch-Control', 'off']);
  set.push(['X-Permitted-Cross-Domain-Policies', 'none']);

  if (cacheControl) {
    set.push(['Cache-Control', typeof cacheControl === 'string' ? cacheControl : HEADERS.CACHE_CONTROL]);
    set.push(['Pragma', 'no-cache']);
    set.push(['Expires', '0']);
  }

  return { set, remove: ['X-Powered-By'] };
}
