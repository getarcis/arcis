/**
 * @module @arcis/node/utils
 * Utility functions for Arcis
 */

export { parseDuration, formatDuration } from './duration';
export { detectClientIp, isPrivateIp } from './ip';
export { fingerprint } from './fingerprint';
export {
  resolveClientIp,
  ipKeyGenerator,
  normalizeIp,
  DEFAULT_TRUSTED_PROXIES,
} from './client-ip';
export type { ClientIpOptions } from './client-ip';
export type { Platform, DetectIpOptions } from './ip';
export type { FingerprintOptions } from './fingerprint';
