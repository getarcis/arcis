/**
 * parse5 entry point for the CommonJS build (selected in tsup.config.ts).
 * parse5 8 is an ES module, so `require` needs a runtime that can load ES
 * modules synchronously (Node 20.19+ or 22.12+). Failures name the fix.
 */
import type * as Parse5 from 'parse5';

declare const require: (id: string) => unknown;

function errorCode(error: unknown): unknown {
  return typeof error === 'object' && error !== null ? (error as { code?: unknown }).code : undefined;
}

function loadParse5(): typeof Parse5 {
  try {
    return require('parse5') as typeof Parse5;
  } catch (error) {
    const code = errorCode(error);
    if (code === 'MODULE_NOT_FOUND') {
      throw new Error('@arcis/node/html needs the parse5 package. Install it with: npm install parse5');
    }
    if (code === 'ERR_REQUIRE_ESM' || code === 'ERR_REQUIRE_ASYNC_MODULE') {
      throw new Error(
        '@arcis/node/html could not load parse5 with require(): parse5 is an ES module, which ' +
          'require() loads on Node 20.19+ or 22.12+. Upgrade Node, or use import instead.',
      );
    }
    throw error;
  }
}

export const { parse } = loadParse5();
