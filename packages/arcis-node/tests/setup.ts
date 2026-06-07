/**
 * Test Setup & Helpers
 * Shared utilities for all Arcis tests
 */

import { vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import express, { Express } from 'express';
import { createServer, Server } from 'http';
import { NOSQL_DANGEROUS_KEYS, DANGEROUS_PROTO_KEYS } from '../src/core/constants';

// =============================================================================
// MOCK EXPRESS OBJECTS
// =============================================================================

/**
 * Creates a mock Express Request object
 */
export const mockRequest = (overrides: Record<string, unknown> = {}): Partial<Request> => ({
  body: {},
  query: {},
  params: {},
  ip: '127.0.0.1',
  path: '/',
  method: 'GET',
  headers: {},
  socket: { remoteAddress: '127.0.0.1' } as never,
  ...overrides,
});

/**
 * Creates a mock Express Response object with spied methods
 */
export const mockResponse = (): Partial<Response> & {
  status: ReturnType<typeof vi.fn>;
  json: ReturnType<typeof vi.fn>;
  setHeader: ReturnType<typeof vi.fn>;
  removeHeader: ReturnType<typeof vi.fn>;
  send: ReturnType<typeof vi.fn>;
  end: ReturnType<typeof vi.fn>;
} => {
  const res: Record<string, unknown> = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  res.setHeader = vi.fn().mockReturnValue(res);
  res.removeHeader = vi.fn().mockReturnValue(res);
  res.send = vi.fn().mockReturnValue(res);
  res.end = vi.fn().mockReturnValue(res);
  return res as ReturnType<typeof mockResponse>;
};

/**
 * Creates a mock NextFunction
 */
export const mockNext: NextFunction = vi.fn() as unknown as NextFunction;

// =============================================================================
// TEST SERVER UTILITIES
// =============================================================================

export interface TestServer {
  app: Express;
  server: Server;
  url: string;
  close: () => Promise<void>;
}

/**
 * Creates a test server with the provided route setup
 */
export async function createTestServer(setupRoutes: (app: Express) => void): Promise<TestServer> {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  
  setupRoutes(app);
  
  return new Promise((resolve) => {
    const server = createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address() as { port: number };
      const url = `http://127.0.0.1:${address.port}`;
      resolve({
        app,
        server,
        url,
        close: () => new Promise<void>((res) => server.close(() => res())),
      });
    });
  });
}

// =============================================================================
// TEST DATA
// =============================================================================

/** Common XSS attack vectors for testing */
export const XSS_VECTORS = [
  { input: '<script>alert(1)</script>', check: (s: string) => !s.includes('<script>') },
  { input: '<img onerror="alert(1)">', check: (s: string) => !s.includes('onerror') },
  { input: 'javascript:alert(1)', check: (s: string) => !s.toLowerCase().includes('javascript:') },
  { input: '<iframe src="evil.com">', check: (s: string) => !s.includes('<iframe') },
  { input: '<svg onload="alert(1)">', check: (s: string) => !s.includes('onload') },
  { input: 'data:text/html,<script>', check: (s: string) => !s.includes('data:') },
];

// Updated 2026-06-07 (benchmark FP class B3): bare-keyword payloads
// (`SELECT * FROM`, `1; DELETE FROM`) replaced with multi-token attack
// shapes. Standalone SELECT/INSERT/UPDATE/DELETE no longer trigger
// sanitization because they false-positive on code snippets and
// natural English. UNION SELECT, DROP TABLE, INTO OUTFILE etc. stay.
export const SQL_VECTORS = [
  "'; DROP TABLE users; --",
  "1 OR 1=1",
  "1 UNION SELECT password FROM users",
  "1; TRUNCATE TABLE logs",
  "admin'--",
  "1 /* comment */ UNION SELECT",
];

/** Path traversal vectors for testing */
export const PATH_VECTORS = [
  '../../etc/passwd',
  '..\\..\\windows\\system32',
  '%2e%2e%2f%2e%2e%2f',
];

/** Prototype pollution payloads */
export const PROTO_POLLUTION_PAYLOADS = [
  { __proto__: { admin: true }, name: 'test' },
  { constructor: { prototype: { admin: true } }, email: 'test@test.com' },
  { prototype: { isAdmin: true }, value: 123 },
];

/** NoSQL injection payloads */
export const NOSQL_PAYLOADS = [
  { $gt: '', name: 'test' },
  { $where: 'function() { return true }', id: 1 },
  { $ne: null, $or: [], valid: true },
];

// =============================================================================
// ASSERTION HELPERS
// =============================================================================

/**
 * Checks if a sanitized string is safe (no dangerous patterns)
 */
export function isSanitized(input: string): boolean {
  const dangerousPatterns = [
    /<script/i,
    /onerror\s*=/i,
    /onclick\s*=/i,
    /javascript:/i,
    /\bDROP\b/i,
    /\bSELECT\b/i,
    /\bDELETE\b/i,
    /\bUNION\b/i,
    /\.\.\//,
    /\.\.\\/,
  ];
  
  return !dangerousPatterns.some(pattern => pattern.test(input));
}

/**
 * Checks if an object is free of dangerous keys
 */
export function hasDangerousKeys(obj: Record<string, unknown>): boolean {
  const keys = Object.keys(obj);
  return keys.some(key => NOSQL_DANGEROUS_KEYS.has(key) || DANGEROUS_PROTO_KEYS.has(key));
}
