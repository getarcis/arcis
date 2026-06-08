/**
 * @module @arcis/node/middleware/bot-detection
 * Local-only bot detection using User-Agent and behavioral signals.
 *
 * Categorizes requests into bot types and allows/denies based on config.
 * No cloud calls — everything runs locally.
 *
 * @example
 * // Block automated tools, allow search engines
 * app.use(botProtection({
 *   allow: ['SEARCH_ENGINE', 'SOCIAL', 'MONITORING'],
 *   deny: ['AUTOMATED', 'SCRAPER'],
 * }));
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import BOT_PATTERN_DATA from '../data/bot-patterns.json';

// =============================================================================
// BOT CATEGORIES
// =============================================================================

export type BotCategory =
  | 'SEARCH_ENGINE'
  | 'SOCIAL'
  | 'MONITORING'
  | 'AI_CRAWLER'
  | 'SCRAPER'
  | 'SECURITY_SCANNER'
  | 'AUTOMATED'
  | 'UNKNOWN'
  | 'HUMAN';

export interface BotDetectionResult {
  /** Whether the request appears to be from a bot */
  isBot: boolean;
  /** Bot category */
  category: BotCategory;
  /** Matched bot name (e.g. 'Googlebot', 'curl') or null */
  name: string | null;
  /** Confidence score: 0-1 */
  confidence: number;
  /** Behavioral signals detected */
  signals: string[];
}

export interface BotProtectionOptions {
  /** Categories to explicitly allow. Default: ['SEARCH_ENGINE', 'SOCIAL', 'MONITORING'] */
  allow?: BotCategory[];
  /** Categories to explicitly deny. Default: ['AUTOMATED'] */
  deny?: BotCategory[];
  /** Action for categories not in allow or deny. Default: 'allow' */
  defaultAction?: 'allow' | 'deny';
  /** HTTP status code for denied bots. Default: 403 */
  statusCode?: number;
  /** Error message for denied bots */
  message?: string;
  /** Enable behavioral signal detection. Default: true */
  detectBehavior?: boolean;
  /** Custom handler called on detection (instead of default deny response) */
  onDetected?: (req: Request, res: Response, result: BotDetectionResult) => void;
}

// =============================================================================
// BOT DATABASE
// =============================================================================

interface BotPattern {
  /** Compiled regex(es) to match against the User-Agent. ANY match counts. */
  patterns: RegExp[];
  /** Compiled forbidden patterns. If ANY matches, this entry is rejected. */
  forbidden: RegExp[];
  /** Bot name (e.g. 'Googlebot') */
  name: string;
  /** Category */
  category: BotCategory;
  /** Stable identifier from the source corpus */
  id: string;
}

/**
 * Source data for the bot corpus — `packages/core/bot-patterns.json`, derived
 * from arcjet/well-known-bots (MIT) plus a supplementary list of browser
 * automation tools the upstream doesn't separately track. Regenerate via
 * `python packages/core/generate-bot-patterns.py` after upgrading the source.
 */
interface BotPatternData {
  id: string;
  name: string;
  category: string;
  patterns: string[];
  forbidden: string[];
}

function compilePattern(source: string): RegExp {
  // Patterns from the corpus are JS-style regex bodies (no enclosing /.../ ).
  // Compile case-insensitive: matches Arcis's documented contract that bot
  // detection ignores UA case (`GPTBOT` and `gptbot` match the same entry).
  // This is additive on top of Arcjet's explicit character classes like
  // `[wW]get` — the `i` flag doesn't conflict with character ranges.
  return new RegExp(source, 'i');
}

const BOT_PATTERNS: BotPattern[] = (BOT_PATTERN_DATA as BotPatternData[]).map((entry) => ({
  id: entry.id,
  name: entry.name,
  category: entry.category as BotCategory,
  patterns: entry.patterns.map(compilePattern),
  forbidden: entry.forbidden.map(compilePattern),
}));


// =============================================================================
// DETECTION ENGINE
// =============================================================================

/**
 * Detect behavioral signals that suggest a bot.
 */
function detectBehavioralSignals(req: Request): string[] {
  const signals: string[] = [];
  const headers = req.headers;

  // Missing User-Agent
  if (!headers['user-agent']) {
    signals.push('missing_user_agent');
  }

  // Missing Accept header (browsers always send this)
  if (!headers['accept']) {
    signals.push('missing_accept');
  }

  // Missing Accept-Language (browsers always send this)
  if (!headers['accept-language']) {
    signals.push('missing_accept_language');
  }

  // Missing Accept-Encoding (browsers always send this)
  if (!headers['accept-encoding']) {
    signals.push('missing_accept_encoding');
  }

  // Connection: close (browsers typically use keep-alive)
  if (headers['connection'] === 'close') {
    signals.push('connection_close');
  }

  return signals;
}

/**
 * Detect what kind of bot (if any) is making the request.
 *
 * @param req - HTTP request object
 * @returns Detection result with category, name, confidence, and signals
 *
 * @example
 * const result = detectBot(req);
 * if (result.isBot && result.category === 'AUTOMATED') {
 *   // Block automated tools
 * }
 */
export function detectBot(req: Request): BotDetectionResult {
  const rawUa = req.headers['user-agent'] ?? '';
  // SECURITY: A UA longer than 2048 chars is either buggy client or attempt to hide
  // a bot signature past a truncation boundary. Flag as suspicious bot directly —
  // don't silently truncate and continue.
  if (rawUa.length > 2048) {
    return {
      isBot: true,
      category: 'UNKNOWN',
      name: null,
      confidence: 0.9,
      signals: detectBehavioralSignals(req),
    };
  }
  const ua = rawUa;
  const signals = detectBehavioralSignals(req);

  // No User-Agent at all
  if (!ua) {
    return {
      isBot: true,
      category: 'UNKNOWN',
      name: null,
      confidence: 0.8,
      signals,
    };
  }

  // Match against known bot patterns. An entry matches when ALL of its
  // accepted patterns match AND none of its forbidden patterns matches.
  // ALL-of semantics makes multi-pattern entries (e.g. iMessage-Preview which
  // expects both `facebookexternalhit` and `Twitterbot` in the same UA) only
  // fire on real iMessage traffic, not on bare `Twitterbot/1.0` requests.
  // Single-pattern entries (the common case) reduce trivially to that one
  // pattern matching.
  for (const bot of BOT_PATTERNS) {
    let allMatched = bot.patterns.length > 0;
    for (const pattern of bot.patterns) {
      if (!pattern.test(ua)) {
        allMatched = false;
        break;
      }
    }
    if (!allMatched) continue;

    let forbidden = false;
    for (const pattern of bot.forbidden) {
      if (pattern.test(ua)) {
        forbidden = true;
        break;
      }
    }
    if (forbidden) continue;

    return {
      isBot: true,
      category: bot.category,
      name: bot.name,
      confidence: 0.95,
      signals,
    };
  }

  // Behavioral analysis for unrecognized UAs
  const behaviorScore = signals.length;

  // 3+ missing standard headers = likely bot
  if (behaviorScore >= 3) {
    return {
      isBot: true,
      category: 'UNKNOWN',
      name: null,
      confidence: Math.min(1.0, 0.6 + (behaviorScore * 0.1)),
      signals,
    };
  }

  return {
    isBot: false,
    category: 'HUMAN',
    name: null,
    confidence: Math.max(0.0, 1.0 - (behaviorScore * 0.15)),
    signals,
  };
}

/**
 * Create Express middleware for bot protection.
 *
 * @example
 * // Block automated tools and scrapers
 * app.use(botProtection({
 *   allow: ['SEARCH_ENGINE', 'SOCIAL', 'MONITORING'],
 *   deny: ['AUTOMATED', 'SCRAPER'],
 * }));
 *
 * @example
 * // Block everything except search engines
 * app.use(botProtection({
 *   allow: ['SEARCH_ENGINE'],
 *   defaultAction: 'deny',
 * }));
 *
 * @example
 * // Custom handler
 * app.use(botProtection({
 *   deny: ['AUTOMATED'],
 *   onDetected: (req, res, result) => {
 *     console.log(`Bot blocked: ${result.name} (${result.category})`);
 *     res.status(403).json({ error: 'Bots not allowed' });
 *   },
 * }));
 */
export function botProtection(options: BotProtectionOptions = {}): RequestHandler {
  const {
    allow = ['SEARCH_ENGINE', 'SOCIAL', 'MONITORING'],
    deny = ['AUTOMATED'],
    defaultAction = 'allow',
    statusCode = 403,
    message = 'Access denied.',
    onDetected,
  } = options;

  const allowSet = new Set(allow);
  const denySet = new Set(deny);

  return (req: Request, res: Response, next: NextFunction) => {
    const result = detectBot(req);

    // Attach result to request for downstream use
    (req as unknown as Record<string, unknown>).botDetection = result;

    // Humans always pass
    if (!result.isBot) {
      return next();
    }

    // Check explicit allow/deny lists
    if (allowSet.has(result.category)) {
      return next();
    }

    if (denySet.has(result.category)) {
      // Telemetry attribution: dashboard groups bot denials under vector=bot.
      req.__arcis = {
        vector: 'bot',
        rule: `bot/${result.category.toLowerCase()}`,
        severity: 'medium',
        reason: result.name ? `Bot detected: ${result.name}` : 'Bot detected',
        decision: 'deny',
      };
      if (onDetected) {
        return onDetected(req, res, result);
      }
      res.status(statusCode).json({ error: message });
      return;
    }

    // Default action for uncategorized bots
    if (defaultAction === 'deny') {
      req.__arcis = {
        vector: 'bot',
        rule: 'bot/uncategorized',
        severity: 'medium',
        reason: 'Uncategorized bot under defaultAction=deny',
        decision: 'deny',
      };
      if (onDetected) {
        return onDetected(req, res, result);
      }
      res.status(statusCode).json({ error: message });
      return;
    }

    next();
  };
}
