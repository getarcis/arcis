/**
 * @module @arcis/node/core/warn-once
 * Once-per-process configuration warnings.
 */

const warned = new Set<string>();

/**
 * Print `message` with `console.warn` the first time `code` is seen in this
 * process, and never again.
 */
export function warnOnce(code: string, message: string): void {
  if (warned.has(code)) return;
  warned.add(code);
  // eslint-disable-next-line no-console
  console.warn(`[arcis] ${message}`);
}

/** Forget every warning already printed. Test helper. */
export function _resetWarnings(): void {
  warned.clear();
}
