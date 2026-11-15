/**
 * parse5 entry point for the ES module build. A missing parse5 surfaces as
 * the runtime's own "cannot find package 'parse5'" error: an ES module
 * cannot catch a failed static import without top-level await, which would
 * break `require()` of this module. The CommonJS build swaps this file for
 * load-parse5.cjs.ts (see tsup.config.ts), which reports the install command.
 */
export { parse } from 'parse5';
