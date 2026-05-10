/**
 * Error Handler Middleware Tests
 * Tests for src/middleware/error-handler.ts
 */

import { describe, it, expect, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { errorHandler, createErrorHandler, containsSensitiveInfo } from '../../src/middleware/error-handler';
import { mockRequest, mockResponse, createTestServer, TestServer } from '../setup';

describe('errorHandler', () => {
  describe('Production Mode (isDev: false)', () => {
    it('should hide error details', () => {
      const req = mockRequest();
      const res = mockResponse();
      const next = vi.fn();
      const handler = errorHandler(false);
      const error = new Error('Database connection failed at 10.0.0.1');

      handler(error, req as Request, res as Response, next as NextFunction);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Internal Server Error',
        })
      );
      
      // Should not contain sensitive details
      const jsonCall = res.json.mock.calls[0][0];
      expect(jsonCall.stack).toBeUndefined();
      expect(jsonCall.details).toBeUndefined();
      expect(JSON.stringify(jsonCall)).not.toContain('10.0.0.1');
    });

    it('should use error statusCode if provided', () => {
      const req = mockRequest();
      const res = mockResponse();
      const next = vi.fn();
      const handler = errorHandler(false);
      const error: Error & { statusCode?: number; expose?: boolean } = new Error('Not found');
      error.statusCode = 404;
      error.expose = true;

      handler(error, req as Request, res as Response, next as NextFunction);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Not found',
        })
      );
    });

    it('should use error status if statusCode not provided', () => {
      const req = mockRequest();
      const res = mockResponse();
      const next = vi.fn();
      const handler = errorHandler(false);
      const error: Error & { status?: number } = new Error('Forbidden');
      error.status = 403;

      handler(error, req as Request, res as Response, next as NextFunction);

      expect(res.status).toHaveBeenCalledWith(403);
    });

    it('should clamp out-of-range statusCode to 500 (regression)', () => {
      // Regression: previously any err.statusCode passed through directly,
      // so a thrown error with statusCode -1 or 99999 would set an invalid
      // HTTP status on the response, breaking proxies and clients.
      for (const bogus of [-1, 0, 99, 600, 9999, NaN, Infinity]) {
        const req = mockRequest();
        const res = mockResponse();
        const next = vi.fn();
        const handler = errorHandler(false);
        const error: Error & { statusCode?: number } = new Error('boom');
        error.statusCode = bogus;
        handler(error, req as Request, res as Response, next as NextFunction);
        expect(res.status).toHaveBeenCalledWith(500);
      }
    });

    it('should default to 500 status', () => {
      const req = mockRequest();
      const res = mockResponse();
      const next = vi.fn();
      const handler = errorHandler(false);
      const error = new Error('Unknown error');

      handler(error, req as Request, res as Response, next as NextFunction);

      expect(res.status).toHaveBeenCalledWith(500);
    });
  });

  describe('Development Mode (isDev: true)', () => {
    it('should include error details', () => {
      const req = mockRequest();
      const res = mockResponse();
      const next = vi.fn();
      const handler = errorHandler(true);
      const error = new Error('Something broke');

      handler(error, req as Request, res as Response, next as NextFunction);

      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          details: 'Something broke',
        })
      );
    });

    it('should include stack trace', () => {
      const req = mockRequest();
      const res = mockResponse();
      const next = vi.fn();
      const handler = errorHandler(true);
      const error = new Error('Error with stack');

      handler(error, req as Request, res as Response, next as NextFunction);

      const jsonCall = res.json.mock.calls[0][0];
      expect(jsonCall.stack).toBeDefined();
    });
  });

  describe('Boolean Shorthand', () => {
    it('should accept false for production mode', () => {
      const handler = errorHandler(false);
      expect(typeof handler).toBe('function');
    });

    it('should accept true for development mode', () => {
      const handler = errorHandler(true);
      expect(typeof handler).toBe('function');
    });
  });
});

describe('createErrorHandler', () => {
  it('should accept options object', () => {
    const handler = createErrorHandler({ isDev: false });
    expect(typeof handler).toBe('function');
  });

  it('should respect isDev option', () => {
    const req = mockRequest();
    const res = mockResponse();
    const next = vi.fn();
    const handler = createErrorHandler({ isDev: true });
    const error = new Error('Test error');

    handler(error, req as Request, res as Response, next as NextFunction);

    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        details: 'Test error',
      })
    );
  });

  it('should log errors when logErrors is true', () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const req = mockRequest();
    const res = mockResponse();
    const next = vi.fn();
    const handler = createErrorHandler({ isDev: false, logErrors: true });
    const error = new Error('Logged error');

    handler(error, req as Request, res as Response, next as NextFunction);

    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });
});

describe('containsSensitiveInfo', () => {
  it('should detect SQL database errors', () => {
    expect(containsSensitiveInfo('SQLSTATE[42S02]: Base table or view not found')).toBe(true);
    expect(containsSensitiveInfo('ORA-00942: table or view does not exist')).toBe(true);
    expect(containsSensitiveInfo('SQLITE_ERROR: no such table: users')).toBe(true);
    expect(containsSensitiveInfo('syntax error at or near "SELECT"')).toBe(true);
    expect(containsSensitiveInfo('relation "users" does not exist')).toBe(true);
    expect(containsSensitiveInfo('column "email" does not exist')).toBe(true);
    expect(containsSensitiveInfo('duplicate key value violates unique constraint "users_pkey"')).toBe(true);
    expect(containsSensitiveInfo("table users doesn't exist")).toBe(true);
    expect(containsSensitiveInfo('unknown column "password" in field list')).toBe(true);
  });

  it('should detect MongoDB errors', () => {
    expect(containsSensitiveInfo('MongoError: E11000 duplicate key')).toBe(true);
    expect(containsSensitiveInfo('MongoServerError: bad auth')).toBe(true);
    expect(containsSensitiveInfo('MongoNetworkError: connection refused')).toBe(true);
    expect(containsSensitiveInfo('E11000 duplicate key error')).toBe(true);
  });

  it('should detect Redis errors', () => {
    expect(containsSensitiveInfo('WRONGTYPE Operation against a key')).toBe(true);
    expect(containsSensitiveInfo('ReplyError: CLUSTERDOWN')).toBe(true);
    expect(containsSensitiveInfo('READONLY You can\'t write against a read only replica')).toBe(true);
  });

  it('should detect connection strings', () => {
    expect(containsSensitiveInfo('Failed to connect to mongodb://admin:pass@10.0.0.1/db')).toBe(true);
    expect(containsSensitiveInfo('postgres://user:pass@host/db')).toBe(true);
    expect(containsSensitiveInfo('mysql://root@localhost/app')).toBe(true);
    expect(containsSensitiveInfo('redis://default:pass@cache:6379')).toBe(true);
    expect(containsSensitiveInfo('mongodb+srv://user:' + 'pass@example.mongodb.net')).toBe(true);
  });

  it('should detect stack traces with file paths', () => {
    expect(containsSensitiveInfo('at UserService.findById (src/services/user.ts:42')).toBe(true);
    expect(containsSensitiveInfo('at Object.<anonymous> (app.js:15')).toBe(true);
  });

  it('should detect internal IP addresses', () => {
    expect(containsSensitiveInfo('Connection refused 127.0.0.1:5432')).toBe(true);
    expect(containsSensitiveInfo('Timeout connecting to 10.0.1.55')).toBe(true);
    expect(containsSensitiveInfo('ECONNREFUSED 192.168.1.100:3306')).toBe(true);
    expect(containsSensitiveInfo('Failed at 172.16.0.5:27017')).toBe(true);
  });

  it('should not flag generic messages', () => {
    expect(containsSensitiveInfo('Not found')).toBe(false);
    expect(containsSensitiveInfo('Invalid email format')).toBe(false);
    expect(containsSensitiveInfo('Rate limit exceeded')).toBe(false);
    expect(containsSensitiveInfo('Unauthorized')).toBe(false);
    expect(containsSensitiveInfo('Bad request')).toBe(false);
  });
});

describe('Sensitive Error Scrubbing', () => {
  it('should scrub DB errors even when expose is true (production)', () => {
    const req = mockRequest();
    const res = mockResponse();
    const next = vi.fn();
    const handler = errorHandler(false);
    const error: Error & { statusCode?: number; expose?: boolean } = new Error(
      'relation "users" does not exist'
    );
    error.statusCode = 500;
    error.expose = true;

    handler(error, req as Request, res as Response, next as NextFunction);

    const jsonCall = res.json.mock.calls[0][0];
    expect(jsonCall.error).toBe('Internal Server Error');
  });

  it('should show DB errors in dev mode even if sensitive', () => {
    const req = mockRequest();
    const res = mockResponse();
    const next = vi.fn();
    const handler = errorHandler(true);
    const error = new Error('relation "users" does not exist');

    handler(error, req as Request, res as Response, next as NextFunction);

    const jsonCall = res.json.mock.calls[0][0];
    expect(jsonCall.error).toContain('relation');
    expect(jsonCall.details).toContain('relation');
  });

  it('should scrub connection strings in error messages', () => {
    const req = mockRequest();
    const res = mockResponse();
    const next = vi.fn();
    const handler = errorHandler(false);
    const error: Error & { expose?: boolean } = new Error(
      'Failed to connect to mongodb://admin:secret@10.0.0.1:27017/production'
    );
    error.expose = true;

    handler(error, req as Request, res as Response, next as NextFunction);

    const jsonCall = res.json.mock.calls[0][0];
    expect(jsonCall.error).toBe('Internal Server Error');
    expect(JSON.stringify(jsonCall)).not.toContain('mongodb://');
    expect(JSON.stringify(jsonCall)).not.toContain('10.0.0.1');
  });

  it('should allow safe exposed messages through', () => {
    const req = mockRequest();
    const res = mockResponse();
    const next = vi.fn();
    const handler = errorHandler(false);
    const error: Error & { statusCode?: number; expose?: boolean } = new Error('Email already registered');
    error.statusCode = 409;
    error.expose = true;

    handler(error, req as Request, res as Response, next as NextFunction);

    const jsonCall = res.json.mock.calls[0][0];
    expect(jsonCall.error).toBe('Email already registered');
  });
});

describe('Integration: Error Handler', () => {
  let testServer: TestServer;

  it('should handle errors in production mode', async () => {
    testServer = await createTestServer((app) => {
      app.get('/error', () => {
        throw new Error('Database connection failed');
      });
      app.use(errorHandler(false));
    });

    const res = await fetch(`${testServer.url}/error`);

    expect(res.status).toBe(500);
    const data = await res.json();
    expect(data.error).toBe('Internal Server Error');
    expect(data.stack).toBeUndefined();
    expect(JSON.stringify(data)).not.toContain('Database');

    await testServer.close();
  });

  it('should handle errors in development mode', async () => {
    testServer = await createTestServer((app) => {
      app.get('/error', () => {
        throw new Error('Something broke');
      });
      app.use(errorHandler(true));
    });

    const res = await fetch(`${testServer.url}/error`);

    expect(res.status).toBe(500);
    const data = await res.json();
    expect(data.details).toBe('Something broke');

    await testServer.close();
  });

  it('should handle custom status codes', async () => {
    testServer = await createTestServer((app) => {
      app.get('/not-found', () => {
        const error: Error & { statusCode?: number } = new Error('Resource not found');
        error.statusCode = 404;
        throw error;
      });
      app.use(errorHandler(false));
    });

    const res = await fetch(`${testServer.url}/not-found`);

    expect(res.status).toBe(404);

    await testServer.close();
  });
});
