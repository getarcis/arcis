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

// =============================================================================
// BOT CATEGORIES
// =============================================================================

export type BotCategory =
  | 'SEARCH_ENGINE'
  | 'SOCIAL'
  | 'MONITORING'
  | 'AI_CRAWLER'
  | 'SCRAPER'
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
  /** Regex pattern to match against User-Agent */
  pattern: RegExp;
  /** Bot name */
  name: string;
  /** Category */
  category: BotCategory;
}

/**
 * Bot patterns ordered by specificity — more specific patterns first.
 * All patterns are case-insensitive and tested against the full UA string.
 */
const BOT_PATTERNS: BotPattern[] = [
  // --- SEARCH ENGINES (specific variants before generic) ---
  { pattern: /Googlebot-Image/i, name: 'Googlebot-Image', category: 'SEARCH_ENGINE' },
  { pattern: /Googlebot-Video/i, name: 'Googlebot-Video', category: 'SEARCH_ENGINE' },
  { pattern: /Googlebot-News/i, name: 'Googlebot-News', category: 'SEARCH_ENGINE' },
  { pattern: /Googlebot/i, name: 'Googlebot', category: 'SEARCH_ENGINE' },
  { pattern: /AdsBot-Google/i, name: 'AdsBot-Google', category: 'SEARCH_ENGINE' },
  { pattern: /Mediapartners-Google/i, name: 'Mediapartners-Google', category: 'SEARCH_ENGINE' },
  { pattern: /Bingbot/i, name: 'Bingbot', category: 'SEARCH_ENGINE' },
  { pattern: /msnbot/i, name: 'msnbot', category: 'SEARCH_ENGINE' },
  { pattern: /Slurp/i, name: 'Yahoo Slurp', category: 'SEARCH_ENGINE' },
  { pattern: /DuckDuckBot/i, name: 'DuckDuckBot', category: 'SEARCH_ENGINE' },
  { pattern: /Baiduspider/i, name: 'Baiduspider', category: 'SEARCH_ENGINE' },
  { pattern: /YandexBot/i, name: 'YandexBot', category: 'SEARCH_ENGINE' },
  { pattern: /YandexImages/i, name: 'YandexImages', category: 'SEARCH_ENGINE' },
  { pattern: /Sogou/i, name: 'Sogou', category: 'SEARCH_ENGINE' },
  { pattern: /Exabot/i, name: 'Exabot', category: 'SEARCH_ENGINE' },
  { pattern: /ia_archiver/i, name: 'Alexa', category: 'SEARCH_ENGINE' },
  { pattern: /Applebot/i, name: 'Applebot', category: 'SEARCH_ENGINE' },
  { pattern: /Qwantify/i, name: 'Qwantify', category: 'SEARCH_ENGINE' },
  { pattern: /PetalBot/i, name: 'PetalBot', category: 'SEARCH_ENGINE' },
  { pattern: /SeznamBot/i, name: 'SeznamBot', category: 'SEARCH_ENGINE' },

  // --- SOCIAL ---
  { pattern: /Twitterbot/i, name: 'Twitterbot', category: 'SOCIAL' },
  { pattern: /facebookexternalhit/i, name: 'Facebook', category: 'SOCIAL' },
  { pattern: /Facebot/i, name: 'Facebot', category: 'SOCIAL' },
  { pattern: /LinkedInBot/i, name: 'LinkedInBot', category: 'SOCIAL' },
  { pattern: /Pinterest/i, name: 'Pinterest', category: 'SOCIAL' },
  { pattern: /Slackbot/i, name: 'Slackbot', category: 'SOCIAL' },
  { pattern: /TelegramBot/i, name: 'TelegramBot', category: 'SOCIAL' },
  { pattern: /WhatsApp/i, name: 'WhatsApp', category: 'SOCIAL' },
  { pattern: /Discordbot/i, name: 'Discordbot', category: 'SOCIAL' },
  { pattern: /Redditbot/i, name: 'Redditbot', category: 'SOCIAL' },
  { pattern: /Embedly/i, name: 'Embedly', category: 'SOCIAL' },
  { pattern: /Quora Link Preview/i, name: 'Quora', category: 'SOCIAL' },
  { pattern: /Mastodon/i, name: 'Mastodon', category: 'SOCIAL' },

  // --- MONITORING ---
  { pattern: /UptimeRobot/i, name: 'UptimeRobot', category: 'MONITORING' },
  { pattern: /Pingdom/i, name: 'Pingdom', category: 'MONITORING' },
  { pattern: /Site24x7/i, name: 'Site24x7', category: 'MONITORING' },
  { pattern: /StatusCake/i, name: 'StatusCake', category: 'MONITORING' },
  { pattern: /Datadog/i, name: 'Datadog', category: 'MONITORING' },
  { pattern: /NewRelicPinger/i, name: 'New Relic', category: 'MONITORING' },
  { pattern: /Better Uptime Bot/i, name: 'Better Uptime', category: 'MONITORING' },
  { pattern: /GTmetrix/i, name: 'GTmetrix', category: 'MONITORING' },
  { pattern: /PageSpeed/i, name: 'PageSpeed Insights', category: 'MONITORING' },

  // --- AI CRAWLERS ---
  { pattern: /GPTBot/i, name: 'GPTBot', category: 'AI_CRAWLER' },
  { pattern: /ChatGPT-User/i, name: 'ChatGPT-User', category: 'AI_CRAWLER' },
  { pattern: /Claude-Web/i, name: 'Claude-Web', category: 'AI_CRAWLER' },
  { pattern: /ClaudeBot/i, name: 'ClaudeBot', category: 'AI_CRAWLER' },
  { pattern: /anthropic-ai/i, name: 'Anthropic', category: 'AI_CRAWLER' },
  { pattern: /Bytespider/i, name: 'Bytespider', category: 'AI_CRAWLER' },
  { pattern: /CCBot/i, name: 'CCBot', category: 'AI_CRAWLER' },
  { pattern: /cohere-ai/i, name: 'Cohere', category: 'AI_CRAWLER' },
  { pattern: /PerplexityBot/i, name: 'PerplexityBot', category: 'AI_CRAWLER' },
  { pattern: /YouBot/i, name: 'YouBot', category: 'AI_CRAWLER' },
  { pattern: /Google-Extended/i, name: 'Google-Extended', category: 'AI_CRAWLER' },
  { pattern: /Diffbot/i, name: 'Diffbot', category: 'AI_CRAWLER' },
  { pattern: /Amazonbot/i, name: 'Amazonbot', category: 'AI_CRAWLER' },
  { pattern: /meta-externalagent/i, name: 'Meta AI', category: 'AI_CRAWLER' },

  // --- AUTOMATED TOOLS (headless browsers, testing frameworks) ---
  { pattern: /HeadlessChrome/i, name: 'Headless Chrome', category: 'AUTOMATED' },
  { pattern: /PhantomJS/i, name: 'PhantomJS', category: 'AUTOMATED' },
  { pattern: /Selenium/i, name: 'Selenium', category: 'AUTOMATED' },
  { pattern: /Puppeteer/i, name: 'Puppeteer', category: 'AUTOMATED' },
  { pattern: /Playwright/i, name: 'Playwright', category: 'AUTOMATED' },
  { pattern: /Cypress/i, name: 'Cypress', category: 'AUTOMATED' },
  { pattern: /webdriver/i, name: 'WebDriver', category: 'AUTOMATED' },
  { pattern: /MSIE 6\.0/i, name: 'Fake IE6', category: 'AUTOMATED' },

  // --- SCRAPERS / CLI TOOLS ---
  { pattern: /^curl\//i, name: 'curl', category: 'SCRAPER' },
  { pattern: /^wget\//i, name: 'wget', category: 'SCRAPER' },
  { pattern: /^python-requests\//i, name: 'python-requests', category: 'SCRAPER' },
  { pattern: /^python-httpx\//i, name: 'python-httpx', category: 'SCRAPER' },
  { pattern: /^Python-urllib/i, name: 'Python-urllib', category: 'SCRAPER' },
  { pattern: /^aiohttp\//i, name: 'aiohttp', category: 'SCRAPER' },
  { pattern: /^Go-http-client/i, name: 'Go-http-client', category: 'SCRAPER' },
  { pattern: /^Java\//i, name: 'Java HttpClient', category: 'SCRAPER' },
  { pattern: /^Apache-HttpClient/i, name: 'Apache HttpClient', category: 'SCRAPER' },
  { pattern: /^okhttp\//i, name: 'OkHttp', category: 'SCRAPER' },
  { pattern: /^node-fetch\//i, name: 'node-fetch', category: 'SCRAPER' },
  { pattern: /^axios\//i, name: 'axios', category: 'SCRAPER' },
  { pattern: /^got\//i, name: 'got', category: 'SCRAPER' },
  { pattern: /^libwww-perl/i, name: 'libwww-perl', category: 'SCRAPER' },
  { pattern: /^Ruby/i, name: 'Ruby', category: 'SCRAPER' },
  { pattern: /^PHP\//i, name: 'PHP', category: 'SCRAPER' },
  { pattern: /Scrapy/i, name: 'Scrapy', category: 'SCRAPER' },
  { pattern: /^Postman/i, name: 'Postman', category: 'SCRAPER' },
  { pattern: /^Insomnia/i, name: 'Insomnia', category: 'SCRAPER' },
  { pattern: /^HTTPie\//i, name: 'HTTPie', category: 'SCRAPER' },
];

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

  // Match against known bot patterns
  for (const bot of BOT_PATTERNS) {
    if (bot.pattern.test(ua)) {
      return {
        isBot: true,
        category: bot.category,
        name: bot.name,
        confidence: 0.95,
        signals,
      };
    }
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
