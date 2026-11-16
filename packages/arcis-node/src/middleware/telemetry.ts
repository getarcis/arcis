/**
 * @module @arcis/node/middleware/telemetry
 * Bridges Arcis middleware decisions to a TelemetryClient.
 * Pattern 3 (two-layer): the client owns transport; this layer owns Express plumbing.
 */

import type { Request, RequestHandler } from 'express';
import type { TelemetryClient } from '../telemetry/client';
import type { TelemetryEvent, TelemetryDecision, TelemetrySeverity } from '../telemetry/types';
import { SecurityThreatError } from '../core/errors';
import { createNodeClientIp } from '../utils/client-ip';

/** Marker that inner middleware writes to and the emitter reads from. */
export interface ArcisTelemetryMarker {
  vector?: string;
  rule?: string;
  severity?: TelemetrySeverity;
  matchedPattern?: string;
  reason?: string;
  /** Explicit Arcis decision. If absent, the request passed through Arcis. */
  decision?: TelemetryDecision;
}

declare module 'express-serve-static-core' {
  interface Request {
    /** Per-request marker populated by Arcis middlewares for telemetry attribution. */
    __arcis?: ArcisTelemetryMarker;
  }
}

const THREAT_TO_VECTOR: Record<string, string> = {
  xss: 'xss',
  sql_injection: 'sql',
  nosql_injection: 'nosql',
  path_traversal: 'path',
  command_injection: 'command',
  prototype_pollution: 'prototype',
  header_injection: 'header',
  ssti: 'ssti',
  xxe: 'xxe',
};

/**
 * Express middleware that records a telemetry event for every request.
 * Captures latency from entry and the actual final status on `finish`.
 * Security decisions come only from Arcis markers, never application status.
 *
 * @param client - Telemetry transport
 * @param clientIp - Resolves the event `ip`. Default: the Arcis resolver with
 *   the default trust set.
 */
export function createTelemetryEmitter(
  client: TelemetryClient,
  clientIp: (req: Request) => string | null = createNodeClientIp(),
): RequestHandler {
  return (req, res, next) => {
    const start = performance.now();

    res.on('finish', () => {
      try {
        const event = buildEvent(req, res.statusCode, performance.now() - start, clientIp(req));
        client.record(event);
      } catch {
        // emit must never break the response — fail-open
      }
    });

    next();
  };
}

/**
 * Wraps the sanitizer middleware so SecurityThreatError → req.__arcis marker.
 * The emitter on `finish` will then have vector/rule/severity attribution.
 */
export function tapSanitizerThreats(handler: RequestHandler): RequestHandler {
  return (req, res, next) => {
    handler(req, res, (err?: unknown) => {
      if (err instanceof SecurityThreatError) {
        const vector = THREAT_TO_VECTOR[err.threatType] ?? err.threatType;
        req.__arcis = {
          vector,
          rule: `${vector}/match`,
          severity: 'high',
          matchedPattern: err.pattern,
          reason: err.message,
          decision: 'deny',
        };
      }
      next(err);
    });
  };
}

function buildEvent(req: Request, status: number, latencyMs: number, ip: string | null): TelemetryEvent {
  const marker = req.__arcis;
  const decision = marker?.decision ?? 'allow';

  // Application errors and Arcis decisions are independent outcomes.
  return {
    ts: new Date().toISOString(),
    ip: ip ?? '0.0.0.0',
    method: (req.method ?? 'GET').toUpperCase(),
    path: req.path ?? req.url ?? '/',
    decision,
    vector: marker?.vector,
    rule: marker?.rule,
    severity: marker?.severity,
    userAgent: typeof req.headers?.['user-agent'] === 'string' ? req.headers['user-agent'] : '',
    reason: marker?.reason,
    status,
    matchedPattern: marker?.matchedPattern,
    latencyMs: Math.max(0, latencyMs),
  };
}
