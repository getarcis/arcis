/**
 * @module @arcis/node/intelligence
 * Optional cloud intelligence: IP reputation refresh from the Arcis
 * intelligence service. Opt-in, fail-open, locally cached.
 */

export { IntelligenceClient, reputationSeverityTier } from './client';
export type { IntelligenceOptions, IpReputation, CloudDecision } from './types';
