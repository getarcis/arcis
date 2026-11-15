/**
 * @module @arcis/node/middleware/security-headers
 * Framework-agnostic security header planning.
 *
 * Every adapter (Express, Fastify, Koa, Hono, Next.js, SvelteKit, Astro, Nuxt,
 * Bun) compiles its options once with `compileSecurityHeaders` and applies the
 * per-response plan through its own response API, so wire output is identical
 * across adapters. See spec/API_SPEC.md "Security Headers".
 */

import { HEADERS } from '../core/constants';
import type {
  BaselineHeaderOptions,
  HeaderOptions,
  HstsOptions,
  LegacyHeaderOptions,
  ReferrerPolicyToken,
} from '../core/types';
import { generateCspNonce, normalizeCsp, renderCsp, type NormalizedCsp } from './csp';

/** Ordered header assignments plus headers to strip from the response. */
export interface SecurityHeaderPlan {
  /** Header name/value pairs, in emission order. */
  readonly set: ReadonlyArray<readonly [name: string, value: string]>;
  /** Header names to remove (fingerprinting headers). */
  readonly remove: readonly string[];
  /** The CSP nonce used for this response, when the nonce extension is on. */
  readonly nonce?: string;
}

/** Request facts an adapter supplies; the planner never parses a request itself. */
export interface SecurityHeaderContext {
  /** True when the request arrived over HTTPS, as determined by the adapter. */
  readonly isHttps: boolean;
  /** Adapter-native request, passed to CSP function values. */
  readonly request?: unknown;
  /** Adapter-native response, passed to CSP function values. */
  readonly response?: unknown;
  /** Pre-generated nonce. When omitted and the nonce extension is on, one is generated. */
  readonly nonce?: string;
}

/** Options validated once; `plan` runs per response. */
export interface CompiledSecurityHeaders {
  readonly profile: 'legacy' | 'baseline';
  /** True when the CSP nonce extension is enabled. */
  readonly usesNonce: boolean;
  plan(context: SecurityHeaderContext): SecurityHeaderPlan;
}

export interface CompileOptions {
  /**
   * Adapters that apply headers after the handler has rendered cannot make a
   * nonce available to templates. They pass the adapter name here so a nonce
   * request fails at startup instead of producing an unusable nonce.
   */
  readonly nonceUnsupportedBy?: string;
}

/**
 * Parse the first `X-Forwarded-Proto` entry. Only the exact values `http`
 * and `https` are accepted; anything else is treated as absent.
 */
export function parseForwardedProto(value: string | null | undefined): 'http' | 'https' | undefined {
  const first = value?.split(',')[0]?.trim().toLowerCase();
  return first === 'https' || first === 'http' ? first : undefined;
}

/**
 * Apply a plan after the route handler has produced a response. In the
 * baseline profile a header the route already set is kept, which matches
 * Helmet, whose headers are set before the handler and can be overridden by
 * it. The legacy profile keeps its historical overwrite behavior.
 */
export interface PostHandlerTarget {
  has(name: string): boolean;
  set(name: string, value: string): void;
  remove(name: string): void;
}

export function applyPlanAfterHandler(
  target: PostHandlerTarget,
  policy: CompiledSecurityHeaders,
  plan: SecurityHeaderPlan,
): void {
  const keepExisting = policy.profile === 'baseline';
  for (const [name, value] of plan.set) {
    if (keepExisting && target.has(name)) continue;
    target.set(name, value);
  }
  for (const name of plan.remove) target.remove(name);
}

/** Apply a plan to a Fetch API `Headers` object (Hono, Next.js, SvelteKit, Astro, Bun). */
export function applyPlanToHeaders(
  headers: Headers,
  policy: CompiledSecurityHeaders,
  plan: SecurityHeaderPlan,
): void {
  applyPlanAfterHandler(
    {
      has: (name) => headers.has(name),
      set: (name, value) => headers.set(name, value),
      remove: (name) => headers.delete(name),
    },
    policy,
    plan,
  );
}

/**
 * Validate header options and return a reusable planner.
 * Throws on invalid configuration, so mistakes surface at startup.
 */
export function compileSecurityHeaders(
  options: HeaderOptions = {},
  compileOptions: CompileOptions = {},
): CompiledSecurityHeaders {
  if (options.profile === 'baseline') return compileBaseline(options, compileOptions);
  if (options.profile !== undefined && options.profile !== 'legacy') {
    throw new Error(`Security headers received an unknown profile ${JSON.stringify(options.profile)}`);
  }
  return compileLegacy(options);
}

// ─── Legacy profile (historical Arcis defaults) ─────────────────────────

function legacyHstsValue(hsts: true | HstsOptions): string {
  const options: HstsOptions = typeof hsts === 'object' ? hsts : {};
  let value = `max-age=${options.maxAge ?? HEADERS.HSTS_MAX_AGE}`;
  if (options.includeSubDomains !== false) value += '; includeSubDomains';
  if (options.preload === true) value += '; preload';
  return value;
}

function compileLegacy(options: LegacyHeaderOptions): CompiledSecurityHeaders {
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

  return {
    profile: 'legacy',
    usesNonce: false,
    plan(context) {
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
      if (hsts && context.isHttps) set.push(['Strict-Transport-Security', legacyHstsValue(hsts)]);
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
    },
  };
}

// ─── Baseline profile (Helmet 8 compatible + Arcis extensions) ─────────

/** Helmet semantics: undefined uses the default, true enables, false disables, object configures. */
function choose<T>(value: T | boolean | undefined, enabledByDefault: boolean): { enabled: boolean; config: T | undefined } {
  if (value === undefined) return { enabled: enabledByDefault, config: undefined };
  if (value === true) return { enabled: true, config: undefined };
  if (value === false) return { enabled: false, config: undefined };
  return { enabled: true, config: value as T };
}

/** Read an option that also has a Helmet legacy alias. Setting both throws, as in Helmet. */
function pick<T>(
  options: BaselineHeaderOptions,
  header: string,
  name: keyof BaselineHeaderOptions,
  alias: keyof BaselineHeaderOptions,
): T | undefined {
  const primary = options[name] as T | undefined;
  const legacy = options[alias] as T | undefined;
  if (primary !== undefined && legacy !== undefined) {
    throw new Error(`${header} option was specified twice. Remove the \`${String(alias)}\` option to fix this error.`);
  }
  return primary ?? legacy;
}

function oneOf(header: string, value: string, allowed: readonly string[]): string {
  if (!allowed.includes(value)) {
    throw new Error(`${header} does not support the ${JSON.stringify(value)} policy`);
  }
  return value;
}

const REFERRER_TOKENS: ReadonlySet<string> = new Set<ReferrerPolicyToken>([
  'no-referrer',
  'no-referrer-when-downgrade',
  'same-origin',
  'origin',
  'strict-origin',
  'origin-when-cross-origin',
  'strict-origin-when-cross-origin',
  'unsafe-url',
  '',
]);

function referrerPolicyValue(config: { policy?: string | string[] } | undefined): string {
  const policy = config?.policy ?? ['no-referrer'];
  const tokens = typeof policy === 'string' ? [policy] : policy;
  if (tokens.length === 0) throw new Error('Referrer-Policy received no policy tokens');
  const seen = new Set<string>();
  for (const token of tokens) {
    if (!REFERRER_TOKENS.has(token)) {
      throw new Error(`Referrer-Policy received an unexpected policy token ${JSON.stringify(token)}`);
    }
    if (seen.has(token)) {
      throw new Error(`Referrer-Policy received a duplicate policy token ${JSON.stringify(token)}`);
    }
    seen.add(token);
  }
  return tokens.join(',');
}

function hstsValue(config: (HstsOptions & Record<string, unknown>) | undefined): string {
  const options = config ?? {};
  if ('maxage' in options) {
    throw new Error('Strict-Transport-Security received an unsupported property, `maxage`. Did you mean to pass `maxAge`?');
  }
  if ('includeSubdomains' in options) {
    throw new Error(
      'Strict-Transport-Security middleware should use `includeSubDomains` instead of `includeSubdomains`. (The correct one has an uppercase "D".)',
    );
  }
  const maxAge = options.maxAge ?? HEADERS.HSTS_MAX_AGE;
  if (!(maxAge >= 0 && Number.isFinite(maxAge))) {
    throw new Error(
      `Strict-Transport-Security: ${JSON.stringify(maxAge)} is not a valid value for maxAge. Please choose a positive integer.`,
    );
  }
  const directives = [`max-age=${Math.floor(maxAge)}`];
  if (options.includeSubDomains === undefined || options.includeSubDomains) directives.push('includeSubDomains');
  if (options.preload) directives.push('preload');
  return directives.join('; ');
}

function frameOptionsValue(config: { action?: string } | undefined): string {
  const action = config?.action ?? 'sameorigin';
  const normalized = typeof action === 'string' ? action.toUpperCase() : action;
  if (normalized === 'SAME-ORIGIN') return 'SAMEORIGIN';
  if (normalized === 'DENY' || normalized === 'SAMEORIGIN') return normalized;
  throw new Error(`X-Frame-Options received an invalid action ${JSON.stringify(action)}`);
}

function crossDomainValue(config: { permittedPolicies?: string } | undefined): string {
  const value = config?.permittedPolicies ?? 'none';
  if (!['none', 'master-only', 'by-content-type', 'all'].includes(value)) {
    throw new Error(`X-Permitted-Cross-Domain-Policies does not support ${JSON.stringify(value)}`);
  }
  return value;
}

// Permissions-Policy is a structured-field dictionary: feature=(allowlist).
const FEATURE_NAME = /^[a-z][a-z0-9-]*$/;

function permissionsPolicyValue(policy: Record<string, readonly string[]>): string {
  const entries = Object.entries(policy);
  if (entries.length === 0) throw new Error('Permissions-Policy received no features');
  return entries
    .map(([feature, allowlist]) => {
      if (!FEATURE_NAME.test(feature)) {
        throw new Error(`Permissions-Policy received an invalid feature name ${JSON.stringify(feature)}`);
      }
      const items = allowlist.map((item) => {
        if (item === 'self' || item === 'src' || item === '*') return item;
        return `"${parseOrigin('Permissions-Policy', item)}"`;
      });
      return `${feature}=(${items.join(' ')})`;
    })
    .join(', ');
}

// SECURITY: origins are emitted inside a quoted structured-field string, so
// they must be plain serialized origins with no quotes, spaces or delimiters.
function parseOrigin(header: string, value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${header} received an invalid origin ${JSON.stringify(value)}`);
  }
  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.origin !== value) {
    throw new Error(`${header} received an invalid origin ${JSON.stringify(value)}`);
  }
  return url.origin;
}

const ENDPOINT_NAME = /^[a-z][a-z0-9_-]*$/;

function reportingEndpointsValue(endpoints: Record<string, string>): string {
  const entries = Object.entries(endpoints);
  if (entries.length === 0) throw new Error('Reporting-Endpoints received no endpoints');
  return entries
    .map(([name, url]) => {
      if (!ENDPOINT_NAME.test(name)) {
        throw new Error(`Reporting-Endpoints received an invalid endpoint name ${JSON.stringify(name)}`);
      }
      let parsed: URL;
      try {
        parsed = new URL(url);
      } catch {
        throw new Error(`Reporting-Endpoints received an invalid URL for ${JSON.stringify(name)}`);
      }
      // Browsers only deliver reports to secure endpoints.
      if (parsed.protocol !== 'https:' || /["\\\s]/.test(url)) {
        throw new Error(`Reporting-Endpoints requires an https URL for ${JSON.stringify(name)}`);
      }
      return `${name}="${url}"`;
    })
    .join(', ');
}

function compileBaseline(options: BaselineHeaderOptions, compileOptions: CompileOptions): CompiledSecurityHeaders {
  const set: Array<readonly [string, string]> = [];
  let csp: NormalizedCsp | undefined;
  let cspIndex = -1;

  const cspChoice = choose(options.contentSecurityPolicy, true);
  if (cspChoice.enabled) {
    csp = normalizeCsp(cspChoice.config);
    cspIndex = set.length;
    set.push([csp.headerName, '']); // rendered per response
  }

  const coep = choose(options.crossOriginEmbedderPolicy, false);
  if (coep.enabled) {
    set.push([
      'Cross-Origin-Embedder-Policy',
      oneOf('Cross-Origin-Embedder-Policy', coep.config?.policy ?? 'require-corp', [
        'require-corp',
        'credentialless',
        'unsafe-none',
      ]),
    ]);
  }

  const coop = choose(options.crossOriginOpenerPolicy, true);
  if (coop.enabled) {
    set.push([
      'Cross-Origin-Opener-Policy',
      oneOf('Cross-Origin-Opener-Policy', coop.config?.policy ?? 'same-origin', [
        'same-origin',
        'same-origin-allow-popups',
        'noopener-allow-popups',
        'unsafe-none',
      ]),
    ]);
  }

  const corp = choose(options.crossOriginResourcePolicy, true);
  if (corp.enabled) {
    set.push([
      'Cross-Origin-Resource-Policy',
      oneOf('Cross-Origin-Resource-Policy', corp.config?.policy ?? 'same-origin', [
        'same-origin',
        'same-site',
        'cross-origin',
      ]),
    ]);
  }

  if (options.originAgentCluster !== false) set.push(['Origin-Agent-Cluster', '?1']);

  const referrer = choose(options.referrerPolicy, true);
  if (referrer.enabled) set.push(['Referrer-Policy', referrerPolicyValue(referrer.config)]);

  // Sent on every response, like Helmet. Browsers ignore HSTS received over
  // plain HTTP (RFC 6797 section 8.1), so no HTTPS detection is needed.
  const hsts = choose(pick<BaselineHeaderOptions['strictTransportSecurity']>(options, 'Strict-Transport-Security', 'strictTransportSecurity', 'hsts'), true);
  if (hsts.enabled) {
    set.push(['Strict-Transport-Security', hstsValue(hsts.config as (HstsOptions & Record<string, unknown>) | undefined)]);
  }

  if (pick<boolean>(options, 'X-Content-Type-Options', 'xContentTypeOptions', 'noSniff') !== false) {
    set.push(['X-Content-Type-Options', 'nosniff']);
  }

  const dns = choose(pick<BaselineHeaderOptions['xDnsPrefetchControl']>(options, 'X-DNS-Prefetch-Control', 'xDnsPrefetchControl', 'dnsPrefetchControl'), true);
  if (dns.enabled) {
    const config = dns.config as { allow?: boolean } | undefined;
    set.push(['X-DNS-Prefetch-Control', config?.allow ? 'on' : 'off']);
  }

  if (pick<boolean>(options, 'X-Download-Options', 'xDownloadOptions', 'ieNoOpen') !== false) set.push(['X-Download-Options', 'noopen']);

  const frame = choose(pick<BaselineHeaderOptions['xFrameOptions']>(options, 'X-Frame-Options', 'xFrameOptions', 'frameguard'), true);
  if (frame.enabled) set.push(['X-Frame-Options', frameOptionsValue(frame.config as { action?: string } | undefined)]);

  const crossDomain = choose(
    pick<BaselineHeaderOptions['xPermittedCrossDomainPolicies']>(
      options,
      'X-Permitted-Cross-Domain-Policies',
      'xPermittedCrossDomainPolicies',
      'permittedCrossDomainPolicies',
    ),
    true,
  );
  if (crossDomain.enabled) {
    set.push([
      'X-Permitted-Cross-Domain-Policies',
      crossDomainValue(crossDomain.config as { permittedPolicies?: string } | undefined),
    ]);
  }

  const remove = pick<boolean>(options, 'X-Powered-By', 'xPoweredBy', 'hidePoweredBy') !== false ? ['X-Powered-By'] : [];

  if (pick<boolean>(options, 'X-XSS-Protection', 'xXssProtection', 'xssFilter') !== false) set.push(['X-XSS-Protection', '0']);

  if (options.permissionsPolicy) set.push(['Permissions-Policy', permissionsPolicyValue(options.permissionsPolicy)]);
  if (options.reportingEndpoints) set.push(['Reporting-Endpoints', reportingEndpointsValue(options.reportingEndpoints)]);

  const usesNonce = csp?.nonce === true;
  if (usesNonce && compileOptions.nonceUnsupportedBy) {
    throw new Error(
      `Content-Security-Policy nonce is not available in the ${compileOptions.nonceUnsupportedBy} adapter, which sets headers after the response is rendered. Use the framework's own CSP nonce support or a function directive value.`,
    );
  }

  return {
    profile: 'baseline',
    usesNonce,
    plan(context) {
      if (!csp) return { set, remove };
      const nonce = usesNonce ? (context.nonce ?? generateCspNonce()) : undefined;
      const perResponse = set.slice();
      perResponse[cspIndex] = [csp.headerName, renderCsp(csp, context.request, context.response, nonce)];
      return nonce ? { set: perResponse, remove, nonce } : { set: perResponse, remove };
    },
  };
}
