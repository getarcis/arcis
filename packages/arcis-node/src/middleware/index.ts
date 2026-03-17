/**
 * @module @arcis/node/middleware
 * All middleware for Arcis
 */

// Main middleware factory
export { arcis, arcisFunction } from './main';
export { default } from './main';

// Individual middleware
export { createRateLimiter, rateLimit } from './rate-limit';
export { createSlidingWindowLimiter } from './rate-limit-sliding';
export { createTokenBucketLimiter } from './rate-limit-token';
export { createHeaders, securityHeaders } from './headers';
export { errorHandler, createErrorHandler } from './error-handler';
export { safeCors, createCors } from './cors';
export { secureCookieDefaults, createSecureCookies, enforceSecureCookie } from './cookies';
export { botProtection, detectBot } from './bot-detection';
export { csrfProtection, createCsrf, generateCsrfToken, validateCsrfToken } from './csrf';
