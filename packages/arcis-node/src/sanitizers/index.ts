/**
 * @module @arcis/node/sanitizers
 * All sanitization functions for Arcis
 */

// Main sanitizer functions
export { sanitizeString, sanitizeObject, createSanitizer } from './sanitize';

// Individual sanitizers
export { sanitizeXss, detectXss } from './xss';
export { sanitizeSql, detectSql } from './sql';
export { sanitizePath, detectPathTraversal } from './path';
export { sanitizeCommand, detectCommandInjection } from './command';

// NoSQL protection
export { isDangerousNoSqlKey, detectNoSqlInjection, getDangerousOperators } from './nosql';

// Prototype pollution protection
export { isDangerousProtoKey, detectPrototypePollution, getDangerousProtoKeys } from './prototype';

// SSTI (Server-Side Template Injection) protection
export { sanitizeSsti, detectSsti } from './ssti';

// XXE (XML External Entity) protection
export { sanitizeXxe, detectXxe } from './xxe';

// JSONP callback sanitization
export { sanitizeJsonpCallback, detectJsonpInjection } from './jsonp';

// HTTP Header Injection protection
export { sanitizeHeaderValue, sanitizeHeaders, detectHeaderInjection } from './headers';

// PII detection and redaction
export { scanPii, detectPii, redactPii, scanObjectPii, redactObjectPii } from './pii';

// Utilities
export { encodeHtmlEntities, isPlainObject } from './utils';
