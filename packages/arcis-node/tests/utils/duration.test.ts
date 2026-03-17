/**
 * Duration Parser Tests
 * Tests for src/utils/duration.ts
 */

import { describe, it, expect } from 'vitest';
import { parseDuration, formatDuration } from '../../src/utils/duration';

describe('parseDuration', () => {
  describe('Number passthrough', () => {
    it('should pass through positive integers', () => {
      expect(parseDuration(0)).toBe(0);
      expect(parseDuration(1)).toBe(1);
      expect(parseDuration(60000)).toBe(60000);
      expect(parseDuration(1000000)).toBe(1000000);
    });

    it('should floor decimal numbers', () => {
      expect(parseDuration(1.5)).toBe(1);
      expect(parseDuration(99.9)).toBe(99);
      expect(parseDuration(0.7)).toBe(0);
    });

    it('should throw on negative numbers', () => {
      expect(() => parseDuration(-1)).toThrow('Invalid duration');
      expect(() => parseDuration(-1000)).toThrow('Invalid duration');
    });

    it('should throw on NaN', () => {
      expect(() => parseDuration(NaN)).toThrow('Invalid duration');
    });

    it('should throw on Infinity', () => {
      expect(() => parseDuration(Infinity)).toThrow('Invalid duration');
      expect(() => parseDuration(-Infinity)).toThrow('Invalid duration');
    });

    it('should clamp to MAX_DURATION_MS', () => {
      const MAX = 4_294_967_295;
      expect(parseDuration(MAX)).toBe(MAX);
      expect(parseDuration(MAX + 1)).toBe(MAX);
      expect(parseDuration(Number.MAX_SAFE_INTEGER)).toBe(MAX);
    });
  });

  describe('Milliseconds (ms)', () => {
    it('should parse milliseconds', () => {
      expect(parseDuration('500ms')).toBe(500);
      expect(parseDuration('0ms')).toBe(0);
      expect(parseDuration('1ms')).toBe(1);
    });

    it('should parse decimal milliseconds', () => {
      expect(parseDuration('1.5ms')).toBe(1);
      expect(parseDuration('0.9ms')).toBe(0);
    });
  });

  describe('Seconds (s)', () => {
    it('should parse seconds', () => {
      expect(parseDuration('1s')).toBe(1000);
      expect(parseDuration('30s')).toBe(30000);
      expect(parseDuration('0s')).toBe(0);
    });

    it('should parse decimal seconds', () => {
      expect(parseDuration('1.5s')).toBe(1500);
      expect(parseDuration('0.5s')).toBe(500);
    });
  });

  describe('Minutes (m)', () => {
    it('should parse minutes', () => {
      expect(parseDuration('1m')).toBe(60000);
      expect(parseDuration('5m')).toBe(300000);
      expect(parseDuration('15m')).toBe(900000);
    });

    it('should parse decimal minutes', () => {
      expect(parseDuration('1.5m')).toBe(90000);
      expect(parseDuration('0.5m')).toBe(30000);
    });
  });

  describe('Hours (h)', () => {
    it('should parse hours', () => {
      expect(parseDuration('1h')).toBe(3600000);
      expect(parseDuration('2h')).toBe(7200000);
      expect(parseDuration('24h')).toBe(86400000);
    });

    it('should parse decimal hours', () => {
      expect(parseDuration('1.5h')).toBe(5400000);
      expect(parseDuration('0.5h')).toBe(1800000);
    });
  });

  describe('Days (d)', () => {
    it('should parse days', () => {
      expect(parseDuration('1d')).toBe(86400000);
      expect(parseDuration('7d')).toBe(604800000);
    });

    it('should parse decimal days', () => {
      expect(parseDuration('0.5d')).toBe(43200000);
    });
  });

  describe('Case insensitivity', () => {
    it('should handle uppercase units', () => {
      expect(parseDuration('5S')).toBe(5000);
      expect(parseDuration('5M')).toBe(300000);
      expect(parseDuration('1H')).toBe(3600000);
      expect(parseDuration('1D')).toBe(86400000);
      expect(parseDuration('100MS')).toBe(100);
    });

    it('should handle mixed case', () => {
      expect(parseDuration('100Ms')).toBe(100);
      expect(parseDuration('100mS')).toBe(100);
    });
  });

  describe('Whitespace handling', () => {
    it('should trim leading and trailing whitespace', () => {
      expect(parseDuration('  5m  ')).toBe(300000);
      expect(parseDuration('\t1h\t')).toBe(3600000);
    });

    it('should allow whitespace between number and unit', () => {
      expect(parseDuration('5 m')).toBe(300000);
      expect(parseDuration('1  h')).toBe(3600000);
    });
  });

  describe('Overflow protection', () => {
    it('should throw on values exceeding MAX_DURATION_MS', () => {
      expect(() => parseDuration('50d')).toThrow('exceeds maximum');
      expect(() => parseDuration('99999h')).toThrow('exceeds maximum');
    });
  });

  describe('Invalid inputs', () => {
    it('should throw on empty string', () => {
      expect(() => parseDuration('')).toThrow('Invalid duration');
    });

    it('should throw on whitespace-only string', () => {
      expect(() => parseDuration('   ')).toThrow('Invalid duration');
    });

    it('should throw on missing unit', () => {
      expect(() => parseDuration('100')).toThrow('Invalid duration');
    });

    it('should throw on missing number', () => {
      expect(() => parseDuration('ms')).toThrow('Invalid duration');
      expect(() => parseDuration('h')).toThrow('Invalid duration');
    });

    it('should throw on invalid unit', () => {
      expect(() => parseDuration('5x')).toThrow('Invalid duration');
      expect(() => parseDuration('5min')).toThrow('Invalid duration');
      expect(() => parseDuration('5sec')).toThrow('Invalid duration');
    });

    it('should throw on negative string values', () => {
      expect(() => parseDuration('-5m')).toThrow('Invalid duration');
      expect(() => parseDuration('-1h')).toThrow('Invalid duration');
    });

    it('should throw on non-string non-number types', () => {
      expect(() => parseDuration(null as unknown as string)).toThrow('Invalid duration');
      expect(() => parseDuration(undefined as unknown as string)).toThrow('Invalid duration');
    });

    it('should throw on garbage strings', () => {
      expect(() => parseDuration('abc')).toThrow('Invalid duration');
      expect(() => parseDuration('five minutes')).toThrow('Invalid duration');
    });
  });
});

describe('formatDuration', () => {
  describe('Milliseconds', () => {
    it('should format sub-second values', () => {
      expect(formatDuration(0)).toBe('0ms');
      expect(formatDuration(1)).toBe('1ms');
      expect(formatDuration(500)).toBe('500ms');
      expect(formatDuration(999)).toBe('999ms');
    });
  });

  describe('Seconds', () => {
    it('should format seconds', () => {
      expect(formatDuration(1000)).toBe('1s');
      expect(formatDuration(30000)).toBe('30s');
    });
  });

  describe('Minutes', () => {
    it('should format minutes', () => {
      expect(formatDuration(60000)).toBe('1m');
      expect(formatDuration(300000)).toBe('5m');
    });

    it('should format minutes and seconds', () => {
      expect(formatDuration(90000)).toBe('1m 30s');
      expect(formatDuration(65000)).toBe('1m 5s');
    });
  });

  describe('Hours', () => {
    it('should format hours', () => {
      expect(formatDuration(3600000)).toBe('1h');
      expect(formatDuration(7200000)).toBe('2h');
    });

    it('should format hours with minutes', () => {
      expect(formatDuration(5400000)).toBe('1h 30m');
    });

    it('should format hours, minutes, seconds', () => {
      expect(formatDuration(3661000)).toBe('1h 1m 1s');
    });
  });

  describe('Days', () => {
    it('should format days', () => {
      expect(formatDuration(86400000)).toBe('1d');
      expect(formatDuration(172800000)).toBe('2d');
    });

    it('should format days with smaller units', () => {
      expect(formatDuration(90000000)).toBe('1d 1h');
      expect(formatDuration(86400000 + 3600000 + 60000 + 1000)).toBe('1d 1h 1m 1s');
    });
  });

  describe('Edge cases', () => {
    it('should return 0ms for negative values', () => {
      expect(formatDuration(-1)).toBe('0ms');
      expect(formatDuration(-1000)).toBe('0ms');
    });

    it('should handle exact boundaries', () => {
      expect(formatDuration(1000)).toBe('1s');
      expect(formatDuration(60000)).toBe('1m');
      expect(formatDuration(3600000)).toBe('1h');
      expect(formatDuration(86400000)).toBe('1d');
    });
  });

  describe('Roundtrip', () => {
    it('should roundtrip clean duration values', () => {
      const durations = ['500ms', '5s', '1m', '2h', '1d'];
      for (const d of durations) {
        const ms = parseDuration(d);
        const formatted = formatDuration(ms);
        expect(parseDuration(formatted)).toBe(ms);
      }
    });
  });
});
