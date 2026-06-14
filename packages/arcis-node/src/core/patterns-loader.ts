/**
 * @module @arcis/node/core/patterns-loader
 *
 * Loads the shared security regex patterns from the bundled
 * `data/patterns.json` (a copy of the canonical `packages/core/patterns.json`,
 * kept byte-identical by the CI data-sync-check). This is the Node counterpart
 * of Go's `sanitizers/loader.go` and Python's `core/constants.load_patterns` +
 * `_compile_rules`.
 *
 * Why this exists: pre-migration, Node hardcoded every regex in `constants.ts`,
 * so each pattern edit was a manual dual-write against patterns.json (which
 * Python + Go already load at runtime). That is a Pattern 2 violation
 * (Shared Pattern Repository). Sourcing the arrays from patterns.json here
 * makes patterns.json the single source for all three SDKs.
 *
 * The JSON is a static `import`, so tsup inlines it into the CJS + ESM bundles
 * at build time (same as `bot-detection.ts` does with `bot-patterns.json`); no
 * runtime filesystem access. resolveJsonModule is already enabled in tsconfig.
 */

import patternsData from '../data/patterns.json';

interface PatternRule {
  id: string;
  pattern: string;
  pattern_safe?: string;
  flags?: string;
}

interface PatternCategory {
  rules?: PatternRule[];
  dangerous_keys?: string[];
}

interface PatternsSpec {
  version: string;
  patterns: Record<string, PatternCategory>;
}

const spec = patternsData as unknown as PatternsSpec;

/** Valid JavaScript RegExp flags. patterns.json uses g/i/m; anything else is dropped. */
const VALID_JS_FLAGS = new Set(['g', 'i', 'm', 's', 'u', 'y']);

function normalizeFlags(flags: string | undefined): string {
  if (!flags) return '';
  let out = '';
  for (const ch of flags) {
    if (VALID_JS_FLAGS.has(ch) && !out.includes(ch)) out += ch;
  }
  return out;
}

/**
 * Compile every rule in a patterns.json category into a RegExp array, in file
 * order. Prefers the ReDoS-safe `pattern_safe` variant when present (parity
 * with Go's compileCategory / Python's _compile_rules). A category with no
 * rules returns an empty array.
 */
export function compileCategory(category: string): RegExp[] {
  const cat = spec.patterns[category];
  if (!cat?.rules) return [];
  const out: RegExp[] = [];
  for (const rule of cat.rules) {
    const raw = rule.pattern_safe || rule.pattern;
    if (!raw) continue;
    out.push(new RegExp(raw, normalizeFlags(rule.flags)));
  }
  return out;
}

/**
 * Compile a single named rule from a category into one RegExp, or undefined if
 * the rule id is absent. Used where Node consumes a single pattern rather than
 * a list (e.g. the string-form NoSQL operator check).
 */
export function compileRule(category: string, id: string, flags?: string): RegExp | undefined {
  const rule = spec.patterns[category]?.rules?.find((r) => r.id === id);
  if (!rule) return undefined;
  const raw = rule.pattern_safe || rule.pattern;
  if (!raw) return undefined;
  return new RegExp(raw, normalizeFlags(flags ?? rule.flags));
}

/**
 * Return the `dangerous_keys` list for a category (e.g. `nosql_injection`,
 * `prototype_pollution`), or an empty array if the category has none.
 */
export function dangerousKeysFor(category: string): string[] {
  return spec.patterns[category]?.dangerous_keys ?? [];
}

/** The version string from the bundled patterns.json. Used by tests/diagnostics. */
export const PATTERNS_VERSION = spec.version;
