/**
 * @module @arcis/node/sanitizers/xxe
 * XML External Entity (XXE) injection prevention
 */

import type { SanitizeResult, ThreatInfo } from '../core/types';

/**
 * XXE detection patterns (ReDoS-safe).
 *
 * Covers DOCTYPE declarations, ENTITY definitions, SYSTEM/PUBLIC references,
 * parameter entities, and CDATA abuse.
 */
/**
 * Billion-laughs defense: cap raw XML input length and the count of
 * entity references. A valid document rarely needs more than a handful of
 * entities; thousands of `&foo;` references is the classic bomb shape.
 */
const MAX_XXE_INPUT_BYTES = 1_000_000; // 1 MB — above any reasonable config/SOAP payload
const MAX_ENTITY_REFERENCES = 64;

const XXE_DETECT_PATTERNS = [
  /** DOCTYPE declaration */
  /<!DOCTYPE\b/gi,
  /** ENTITY declaration */
  /<!ENTITY\b/gi,
  /** SYSTEM keyword with URI */
  /\bSYSTEM\s+["']/gi,
  /** PUBLIC keyword with URI */
  /\bPUBLIC\s+["']/gi,
  /** Parameter entity reference (%entity;) */
  /%\s*\w+\s*;/g,
  /** CDATA section (often used to smuggle payloads) */
  /<!\[CDATA\[/gi,
] as const;

/** Removal patterns — strip the dangerous XML constructs */
const XXE_REMOVE_PATTERNS = [
  /** Full DOCTYPE block with optional internal subset: <!DOCTYPE ... [...]> */
  /<!DOCTYPE\s[^[>]*(?:\[[^\]]*\]\s*)?>|<!DOCTYPE\s[^>]*>/gi,
  /** Full ENTITY declaration: <!ENTITY ... > */
  /<!ENTITY[^>]*>/gi,
  /** CDATA sections: <![CDATA[ ... ]]> */
  /<!\[CDATA\[[\s\S]*?\]\]>/gi,
] as const;

/**
 * Sanitizes a string to prevent XXE attacks.
 * Removes DOCTYPE, ENTITY, and CDATA constructs.
 */
export function sanitizeXxe(input: string, collectThreats?: false): string;
export function sanitizeXxe(input: string, collectThreats: true): SanitizeResult;
export function sanitizeXxe(input: string, collectThreats = false): string | SanitizeResult {
  if (typeof input !== 'string') {
    return collectThreats
      ? { value: String(input), wasSanitized: false, threats: [] }
      : String(input);
  }

  const threats: ThreatInfo[] = [];
  let value = input;
  let wasSanitized = false;

  // Billion-laughs defense: oversize input or many entity refs → flatten to empty.
  // Safer to discard than to attempt partial sanitization of a bomb payload.
  if (value.length > MAX_XXE_INPUT_BYTES) {
    if (collectThreats) {
      threats.push({ type: 'xxe', pattern: 'oversize_input', original: `length=${value.length}` });
    }
    return collectThreats ? { value: '', wasSanitized: true, threats } : '';
  }
  const entityRefs = value.match(/&\w+;/g);
  if (entityRefs && entityRefs.length > MAX_ENTITY_REFERENCES) {
    if (collectThreats) {
      threats.push({ type: 'xxe', pattern: 'entity_expansion', original: `count=${entityRefs.length}` });
    }
    return collectThreats ? { value: '', wasSanitized: true, threats } : '';
  }

  for (const pattern of XXE_REMOVE_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(value)) {
      pattern.lastIndex = 0;

      if (collectThreats) {
        const matches = value.match(pattern);
        if (matches) {
          for (const match of matches) {
            threats.push({
              type: 'xxe',
              pattern: pattern.source,
              original: match,
            });
          }
        }
      }

      value = value.replace(pattern, '');
      wasSanitized = true;
    }
  }

  if (collectThreats) {
    return { value, wasSanitized, threats };
  }

  return value;
}

/**
 * Checks if a string contains XXE patterns.
 * Does not sanitize — use sanitizeXxe() for that.
 *
 * @param input - The string to check
 * @returns True if XXE patterns detected
 */
export function detectXxe(input: string): boolean {
  if (typeof input !== 'string') return false;

  for (const pattern of XXE_DETECT_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(input)) {
      return true;
    }
  }

  return false;
}
