/**
 * @module @arcis/node/utils
 * Utility functions for Arcis
 */

export { parseDuration, formatDuration } from './duration';
export { detectClientIp, isPrivateIp } from './ip';
export { fingerprint } from './fingerprint';
export type { Platform, DetectIpOptions } from './ip';
export type { FingerprintOptions } from './fingerprint';
