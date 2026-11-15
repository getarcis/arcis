/**
 * @module @arcis/node/middleware/csp
 * Content-Security-Policy construction for the `baseline` header profile.
 *
 * Directive handling follows the Helmet 8 option surface so existing Helmet
 * configurations produce the same header: camelCase or kebab-case directive
 * names, default directives merged unless `useDefaults: false`, `null` to drop
 * a default directive, `dangerouslyDisableDefaultSrc`, per-request function
 * values and `reportOnly`. Arcis adds an optional per-request nonce.
 * See spec/API_SPEC.md "Security Headers" for the shared contract.
 */

/** Marker that removes `default-src`, mirroring Helmet's symbol of the same name. */
export const dangerouslyDisableDefaultSrc: unique symbol = Symbol('dangerouslyDisableDefaultSrc');

/**
 * A directive value entry. Functions run once per response and receive the
 * adapter's native request and response objects (Express: `req`, `res`).
 */
export type CspDirectiveValueEntry = string | ((request: unknown, response: unknown) => string);

export type CspDirectiveValue =
  | null
  | string
  | Iterable<CspDirectiveValueEntry>
  | typeof dangerouslyDisableDefaultSrc;

export interface ContentSecurityPolicyOptions {
  /** Merge the default directives into `directives`. Default: true. */
  useDefaults?: boolean;
  /** Directive map. camelCase names are converted to kebab-case. */
  directives?: Record<string, CspDirectiveValue>;
  /** Send `Content-Security-Policy-Report-Only` instead of enforcing. Default: false. */
  reportOnly?: boolean;
  /**
   * Arcis extension: generate a fresh 128-bit nonce per response and append
   * `'nonce-<value>'` to `script-src`. The value is exposed to the application
   * by the adapter (Express: `res.locals.cspNonce`). Default: false.
   *
   * Only `script-src` receives it: a nonce makes browsers ignore
   * `'unsafe-inline'`, so adding it to the default `style-src` would block
   * every inline style. Add a style nonce explicitly with a function value.
   */
  nonce?: boolean;
}

// Keywords that are only valid quoted. Helmet rejects them unquoted because a
// bare `self` is a host name, silently weakening the intended policy.
const SHOULD_BE_QUOTED = new Set([
  'none',
  'self',
  'strict-dynamic',
  'report-sample',
  'inline-speculation-rules',
  'unsafe-inline',
  'unsafe-eval',
  'unsafe-hashes',
  'wasm-unsafe-eval',
]);

/** Default directives, identical to Helmet 8's. */
export function getDefaultCspDirectives(): Record<string, string[]> {
  return {
    'default-src': ["'self'"],
    'base-uri': ["'self'"],
    'font-src': ["'self'", 'https:', 'data:'],
    'form-action': ["'self'"],
    'frame-ancestors': ["'self'"],
    'img-src': ["'self'", 'data:'],
    'object-src': ["'none'"],
    'script-src': ["'self'"],
    'script-src-attr': ["'none'"],
    'style-src': ["'self'", 'https:', "'unsafe-inline'"],
    'upgrade-insecure-requests': [],
  };
}

const dashify = (name: string): string =>
  name.replace(/[A-Z]/g, (capital) => '-' + capital.toLowerCase());

// Helmet's directive name rule: lowercase first letter, no trailing hyphen.
const DIRECTIVE_NAME = /^[a-z](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/;

function assertValueIsValid(directive: string, value: string): void {
  // SECURITY: ';' or ',' would let a value inject extra directives or policies.
  // Control characters (CR/LF included) would make every response fail when
  // the header is written; Arcis rejects them up front.
  if (/[;,\x00-\x1f\x7f]/.test(value)) {
    throw new Error(
      `Content-Security-Policy received an invalid directive value for ${JSON.stringify(directive)}`,
    );
  }
}

function assertEntryIsQuoted(directive: string, entry: string): void {
  if (
    SHOULD_BE_QUOTED.has(entry) ||
    entry.startsWith('nonce-') ||
    entry.startsWith('sha256-') ||
    entry.startsWith('sha384-') ||
    entry.startsWith('sha512-')
  ) {
    throw new Error(
      `Content-Security-Policy received an invalid directive value for ${JSON.stringify(directive)}. ${JSON.stringify(entry)} should be quoted`,
    );
  }
}

/** Validated directives, ready to render per response. */
export interface NormalizedCsp {
  readonly headerName: 'Content-Security-Policy' | 'Content-Security-Policy-Report-Only';
  readonly directives: ReadonlyMap<string, readonly CspDirectiveValueEntry[]>;
  readonly nonce: boolean;
}

/**
 * Validate and normalize CSP options once, at middleware construction.
 * Throws on invalid configuration so mistakes fail at startup, not per request.
 */
export function normalizeCsp(options: ContentSecurityPolicyOptions = {}): NormalizedCsp {
  const { useDefaults = true, directives: rawDirectives = {} } = options;

  // Start from the defaults so an override keeps the default's position and
  // new directives are appended, giving the same header string as Helmet.
  const result = new Map<string, readonly CspDirectiveValueEntry[]>(
    useDefaults ? Object.entries(getDefaultCspDirectives()) : [],
  );
  const seen = new Set<string>();
  let defaultSrcDisabled = false;

  for (const rawName of Object.keys(rawDirectives)) {
    if (!DIRECTIVE_NAME.test(rawName)) {
      throw new Error(`Content-Security-Policy received an invalid directive name ${JSON.stringify(rawName)}`);
    }
    const name = dashify(rawName);
    if (seen.has(name)) {
      throw new Error(`Content-Security-Policy received a duplicate directive ${JSON.stringify(name)}`);
    }
    seen.add(name);

    const rawValue = rawDirectives[rawName];
    let value: readonly CspDirectiveValueEntry[];
    if (rawValue === null) {
      if (name === 'default-src') {
        throw new Error(
          'Content-Security-Policy needs a default-src but it was set to `null`. If you really want to disable it, set it to `contentSecurityPolicy.dangerouslyDisableDefaultSrc`.',
        );
      }
      result.delete(name);
      continue;
    } else if (typeof rawValue === 'string') {
      value = [rawValue];
    } else if (!rawValue) {
      throw new Error(`Content-Security-Policy received an invalid directive value for ${JSON.stringify(name)}`);
    } else if (rawValue === dangerouslyDisableDefaultSrc) {
      if (name !== 'default-src') {
        throw new Error(
          `Content-Security-Policy: tried to disable ${JSON.stringify(name)} as if it were default-src; simply omit the key`,
        );
      }
      result.delete('default-src');
      defaultSrcDisabled = true;
      continue;
    } else {
      value = [...rawValue];
    }

    for (const entry of value) {
      if (typeof entry !== 'string') continue;
      assertValueIsValid(name, entry);
      assertEntryIsQuoted(name, entry);
    }
    result.set(name, value);
  }

  if (result.size === 0) {
    throw new Error('Content-Security-Policy has no directives. Either set some or disable the header');
  }
  if (!result.has('default-src') && !defaultSrcDisabled) {
    throw new Error(
      'Content-Security-Policy needs a default-src but none was provided. If you really want to disable it, set it to `contentSecurityPolicy.dangerouslyDisableDefaultSrc`.',
    );
  }

  if (options.nonce === true && !result.has('script-src')) {
    throw new Error('Content-Security-Policy nonce requires a script-src directive');
  }

  return {
    headerName: options.reportOnly ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy',
    directives: result,
    nonce: options.nonce === true,
  };
}


/**
 * Render the header value for one response.
 *
 * @param csp - Output of `normalizeCsp`
 * @param request - Adapter-native request passed to function values
 * @param response - Adapter-native response passed to function values
 * @param nonce - Per-response nonce when `csp.nonce` is enabled
 */
export function renderCsp(
  csp: NormalizedCsp,
  request: unknown,
  response: unknown,
  nonce?: string,
): string {
  const parts: string[] = [];
  for (const [name, entries] of csp.directives) {
    let value = '';
    for (const entry of entries) {
      if (typeof entry === 'function') {
        const computed = entry(request, response);
        assertEntryIsQuoted(name, computed);
        value += ' ' + computed;
      } else {
        value += ' ' + entry;
      }
    }
    if (nonce && name === 'script-src') value += ` 'nonce-${nonce}'`;
    if (value) {
      assertValueIsValid(name, value);
      parts.push(`${name}${value}`);
    } else {
      parts.push(name);
    }
  }
  return parts.join(';');
}

/** Generate a base64 nonce from 16 random bytes using Web Crypto (Node 18+, edge runtimes). */
export function generateCspNonce(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
