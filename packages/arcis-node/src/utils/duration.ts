/**
 * @module @arcis/node/utils/duration
 * Parse human-readable duration strings into milliseconds.
 *
 * Supports: ms, s, m, h, d
 *
 * @example
 * parseDuration('5m')    // 300000
 * parseDuration('2h')    // 7200000
 * parseDuration(60000)   // 60000 (passthrough)
 * parseDuration('500ms') // 500
 */

/** Maximum duration: ~49.7 days (uint32 max in ms) */
const MAX_DURATION_MS = 4_294_967_295;

const DURATION_REGEX = /^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)$/i;

const UNIT_TO_MS: Record<string, number> = {
  ms: 1,
  s: 1_000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
};

/**
 * Parse a duration string or number into milliseconds.
 *
 * @param value - Duration string (e.g. "5m", "2h", "30s") or number (ms)
 * @returns Duration in milliseconds
 * @throws {Error} If the value is not a valid duration
 *
 * @example
 * parseDuration('15m')   // 900000
 * parseDuration('1d')    // 86400000
 * parseDuration('500ms') // 500
 * parseDuration(60000)   // 60000
 */
export function parseDuration(value: string | number): number {
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || value < 0) {
      throw new Error(`Invalid duration: ${value}. Must be a non-negative finite number.`);
    }
    return Math.min(Math.floor(value), MAX_DURATION_MS);
  }

  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`Invalid duration: "${value}". Expected a duration string (e.g. "5m", "2h") or number.`);
  }

  const match = value.trim().match(DURATION_REGEX);
  if (!match) {
    throw new Error(
      `Invalid duration: "${value}". Expected format: <number><unit> where unit is ms, s, m, h, or d.`
    );
  }

  const amount = parseFloat(match[1]);
  const unit = match[2].toLowerCase();
  const ms = Math.floor(amount * UNIT_TO_MS[unit]);

  if (ms < 0 || ms > MAX_DURATION_MS) {
    throw new Error(`Duration "${value}" exceeds maximum allowed (${MAX_DURATION_MS}ms / ~49.7 days).`);
  }

  return ms;
}

/**
 * Format milliseconds into a human-readable duration string.
 *
 * @param ms - Duration in milliseconds
 * @returns Human-readable string (e.g. "5m", "2h 30m")
 */
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '0ms';

  if (ms < 1000) return `${ms}ms`;

  const days = Math.floor(ms / 86_400_000);
  const hours = Math.floor((ms % 86_400_000) / 3_600_000);
  const minutes = Math.floor((ms % 3_600_000) / 60_000);
  const seconds = Math.floor((ms % 60_000) / 1_000);

  const parts: string[] = [];
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  if (seconds > 0) parts.push(`${seconds}s`);

  return parts.join(' ') || '0ms';
}
