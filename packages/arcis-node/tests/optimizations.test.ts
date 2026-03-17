/**
 * Phase 3 Optimization Tests
 * Tests for Object.freeze and early-exit log levels
 */

import { describe, it, expect, vi } from 'vitest';
import { sanitizeObject } from '../src/sanitizers/sanitize';
import { createSafeLogger } from '../src/logging/redactor';

// ─── Object.freeze ───────────────────────────────────────────────────────────

describe('Object.freeze optimization', () => {
  it('should not freeze by default', () => {
    const result = sanitizeObject({ name: 'John' }) as Record<string, unknown>;
    expect(Object.isFrozen(result)).toBe(false);
    result.name = 'Jane'; // should work
    expect(result.name).toBe('Jane');
  });

  it('should freeze when freeze option is true', () => {
    const result = sanitizeObject({ name: 'John' }, { freeze: true }) as Record<string, unknown>;
    expect(Object.isFrozen(result)).toBe(true);
  });

  it('should prevent mutation on frozen object', () => {
    const result = sanitizeObject({ name: 'John', age: 30 }, { freeze: true }) as Record<string, unknown>;
    expect(() => {
      'use strict';
      result.name = 'Jane';
    }).toThrow();
  });

  it('should freeze sanitized objects with stripped keys', () => {
    const input = JSON.parse('{"name": "John", "__proto__": {"admin": true}}');
    const result = sanitizeObject(input, { freeze: true }) as Record<string, unknown>;
    expect(Object.isFrozen(result)).toBe(true);
    expect(result).toEqual({ name: 'John' });
  });

  it('should work with string input (no freeze needed)', () => {
    const result = sanitizeObject('hello', { freeze: true });
    expect(result).toBe('hello');
  });

  it('should work with null/undefined', () => {
    expect(sanitizeObject(null, { freeze: true })).toBe(null);
    expect(sanitizeObject(undefined, { freeze: true })).toBe(undefined);
  });
});

// ─── Early-exit log levels ───────────────────────────────────────────────────

describe('Early-exit log levels', () => {
  it('should log all levels when level is debug (default)', () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const logger = createSafeLogger();

    logger.debug('debug msg');
    logger.info('info msg');
    logger.warn('warn msg');
    logger.error('error msg');

    expect(spy).toHaveBeenCalledTimes(4);
    spy.mockRestore();
  });

  it('should skip debug when level is info', () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const logger = createSafeLogger({ level: 'info' });

    logger.debug('debug msg');
    logger.info('info msg');
    logger.warn('warn msg');
    logger.error('error msg');

    expect(spy).toHaveBeenCalledTimes(3);
    // Verify debug was skipped
    const calls = spy.mock.calls.map(c => c[0]);
    expect(calls.every(c => !c.includes('"level":"debug"'))).toBe(true);
    spy.mockRestore();
  });

  it('should skip debug and info when level is warn', () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const logger = createSafeLogger({ level: 'warn' });

    logger.debug('debug msg');
    logger.info('info msg');
    logger.warn('warn msg');
    logger.error('error msg');

    expect(spy).toHaveBeenCalledTimes(2);
    spy.mockRestore();
  });

  it('should only log errors when level is error', () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const logger = createSafeLogger({ level: 'error' });

    logger.debug('debug msg');
    logger.info('info msg');
    logger.warn('warn msg');
    logger.error('error msg');

    expect(spy).toHaveBeenCalledTimes(1);
    spy.mockRestore();
  });

  it('should log nothing when level is silent', () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const logger = createSafeLogger({ level: 'silent' });

    logger.debug('debug msg');
    logger.info('info msg');
    logger.warn('warn msg');
    logger.error('error msg');

    expect(spy).toHaveBeenCalledTimes(0);
    spy.mockRestore();
  });

  it('should not perform redaction for skipped levels', () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const logger = createSafeLogger({ level: 'error' });

    // This should return immediately without doing redaction work
    const start = performance.now();
    for (let i = 0; i < 10000; i++) {
      logger.debug('password=secret', { password: 'secret123', token: 'abc' });
    }
    const elapsed = performance.now() - start;

    // 10k skipped calls should be very fast (< 50ms)
    expect(elapsed).toBeLessThan(50);
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });
});
