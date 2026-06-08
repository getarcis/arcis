/**
 * @module @arcis/node/sanitizers/mass-assignment
 * v1.7 W4. Denylist detection of privilege-escalation fields in a body.
 *
 * The classic mass-assignment attack smuggles a sensitive field into a
 * request body that the handler blindly spreads onto a model:
 *
 *     user.update({ ...req.body })   // attacker set isAdmin: true
 *
 * The allowlist approach (`applyMassAssignFilter` / `MassAssignMiddleware`)
 * is the robust fix but needs a per-route field list, so it cannot be
 * default-on. This detector is the default-on complement: it scans the
 * body for a curated set of privilege/auth field NAMES that a normal
 * client request almost never sets, and blocks when one appears.
 *
 * Scope: detection only. It does not strip or rewrite. Recurses into
 * nested objects and arrays so `{ profile: { permissions: [...] } }` is
 * caught. Value-agnostic: the presence of the key is the signal.
 *
 * False-positive note: `role` and `permissions` DO appear in legitimate
 * admin APIs. Apps with such routes opt out via `arcis({ massAssign: false })`
 * or scope the check off for those paths, then use the allowlist filter
 * (`applyMassAssignFilter`) on the routes that legitimately accept them.
 */

export interface MassAssignDetectOptions {
  /**
   * Sensitive field names to detect (overrides the default set entirely).
   * Compared case-insensitively after stripping `_` and `-`, so
   * `is_admin`, `isAdmin`, and `is-admin` all match a `isadmin` entry.
   */
  sensitiveFields?: string[];
  /** Max recursion depth into nested objects/arrays. Default: 8. */
  maxDepth?: number;
}

export interface MassAssignDetectResult {
  /** True if a sensitive field name was found anywhere in the body. */
  detected: boolean;
  /** The offending field name (original casing) or null. */
  field: string | null;
}

/**
 * Default privilege-escalation field names. Stored in normalized form
 * (lowercased, separators stripped). These are fields a profile/signup
 * update should never carry from the client. `role` / `permissions` are
 * the canonical mass-assignment fields and the FP-risk ones, kept in by
 * default; opt out per-route if your admin API legitimately accepts them.
 */
export const SENSITIVE_FIELD_NAMES: ReadonlySet<string> = new Set([
  'isadmin',
  'issuperuser',
  'superuser',
  'issuperadmin',
  'superadmin',
  'isstaff',
  'isverified',
  'isroot',
  'isowner',
  'role',
  'roles',
  'userrole',
  'permission',
  'permissions',
  'privilege',
  'privileges',
  'accesslevel',
  'accounttype',
  'isactive',
  'emailverified',
]);

/** Normalize a key: lowercase, strip `_` and `-`. */
function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[_-]/g, '');
}

/**
 * Recursively scan a parsed JSON body for sensitive field names.
 * Returns the first hit (original-cased key) or `{ detected: false }`.
 */
export function detectMassAssignment(
  body: unknown,
  options: MassAssignDetectOptions = {},
): MassAssignDetectResult {
  const maxDepth = options.maxDepth ?? 8;
  const sensitive = options.sensitiveFields
    ? new Set(options.sensitiveFields.map(normalizeKey))
    : SENSITIVE_FIELD_NAMES;

  function walk(value: unknown, depth: number): string | null {
    if (depth > maxDepth || value === null || typeof value !== 'object') {
      return null;
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        const hit = walk(item, depth + 1);
        if (hit) return hit;
      }
      return null;
    }
    for (const key of Object.keys(value as Record<string, unknown>)) {
      if (sensitive.has(normalizeKey(key))) {
        return key;
      }
      const hit = walk((value as Record<string, unknown>)[key], depth + 1);
      if (hit) return hit;
    }
    return null;
  }

  const field = walk(body, 0);
  return { detected: field !== null, field };
}
