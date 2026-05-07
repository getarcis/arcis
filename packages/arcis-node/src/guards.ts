/**
 * @module @arcis/node/guards
 *
 * Guards API. Same Arcis decisioning (rate limit, bot detect, prompt
 * injection, token budget) applied to non-HTTP contexts where there's no
 * `req`/`res` pair. Use this for:
 *
 *   - Job queue workers (BullMQ, agenda, sidekiq-style)
 *   - Agent tool-call handlers (Claude/OpenAI tool dispatch)
 *   - WebSocket / SSE / gRPC handlers
 *   - Background processors (cron jobs, scheduled tasks)
 *
 * Each call to `guards.run(input)` returns a structured decision: `ok` +
 * (when denied) the `vector`, `severity`, `reason`, and `retryAfterSeconds`
 * the deny was triggered by. The first vector that denies short-circuits
 * the rest, so denial latency stays bounded.
 *
 * @example
 * import { Guards } from '@arcis/node';
 *
 * const guards = new Guards({
 *   rateLimit: { max: 50, windowMs: 60_000 },
 *   tokenBudget: { maxTokens: 100_000, windowMs: 60 * 60 * 1000 },
 *   promptInjection: { redactLow: false },
 * });
 *
 * // In a job handler:
 * const decision = guards.run({
 *   key: jobUserId,
 *   tokens: estimateTokens(prompt),
 *   text: prompt,
 * });
 * if (!decision.ok) {
 *   throw new Error(`Job rejected (${decision.vector}): ${decision.reason}`);
 * }
 */

import { detectBot, type BotProtectionOptions } from './middleware/bot-detection';
import {
  detectPromptInjection,
  type PromptInjectionSeverity,
} from './sanitizers/prompt-injection';

// ─── Public types ──────────────────────────────────────────────────────────

export interface GuardsRateLimitOptions {
  /** Max events per window per key. Default: 100. */
  max?: number;
  /** Window length in milliseconds. Default: 60000 (1 minute). */
  windowMs?: number;
}

export interface GuardsTokenBudgetOptions {
  /** Max tokens a single key can spend in one window. Default: 100,000. */
  maxTokens?: number;
  /** Window length in milliseconds. Default: 60 * 60 * 1000 (1 hour). */
  windowMs?: number;
  /**
   * Optional per-call cap. When set, a single call with `tokens > maxRequestTokens`
   * denies BEFORE charging the window budget.
   */
  maxRequestTokens?: number;
}

export interface GuardsPromptInjectionOptions {
  /**
   * Minimum severity that triggers a deny. Default: 'medium' (HIGH and
   * MEDIUM matches deny; LOW matches still surface in `decision.matches`
   * but don't deny).
   */
  denyAt?: PromptInjectionSeverity;
}

export interface GuardsBotOptions {
  /** Categories that pass through. Default: SEARCH_ENGINE, SOCIAL, MONITORING. */
  allow?: BotProtectionOptions['allow'];
  /** Categories that always deny. Default: AUTOMATED. */
  deny?: BotProtectionOptions['deny'];
  /** Default for uncategorized bots. Default: 'allow'. */
  defaultAction?: BotProtectionOptions['defaultAction'];
}

export interface GuardsConfig {
  /** When set, every call is rate-limited per `input.key`. Omit to disable. */
  rateLimit?: GuardsRateLimitOptions;
  /** When set, calls with `input.tokens` charge a per-key sliding-window budget. */
  tokenBudget?: GuardsTokenBudgetOptions;
  /** When set, `input.text` is scanned for prompt-injection signatures. */
  promptInjection?: GuardsPromptInjectionOptions | true;
  /** When set, `input.userAgent` is matched against the bot corpus. */
  bot?: GuardsBotOptions | true;
}

export interface GuardsInput {
  /** Identifier for rate-limit / token-budget bucketing. Required. */
  key: string;
  /** Optional text payload for prompt-injection scanning. */
  text?: string;
  /** Optional token cost for token-budget accounting. */
  tokens?: number;
  /** Optional User-Agent string for bot detection. */
  userAgent?: string;
}

export type GuardsVector =
  | 'rate-limit'
  | 'token-budget'
  | 'prompt-injection'
  | 'bot';

export type GuardsSeverity = 'low' | 'medium' | 'high';

export interface GuardsDecision {
  /** True if the input passes every configured vector. */
  ok: boolean;
  /** Which vector denied. Undefined when `ok` is true. */
  vector?: GuardsVector;
  /** Human-readable reason for the deny. Undefined when `ok` is true. */
  reason?: string;
  /** Severity of the deny. Undefined when `ok` is true. */
  severity?: GuardsSeverity;
  /** How many seconds until the same key can retry (rate-limit / token-budget). */
  retryAfterSeconds?: number;
  /**
   * For prompt-injection: every signature that matched, even when the deny
   * threshold wasn't hit. Lets callers log low-severity matches without
   * blocking on them.
   */
  matches?: ReadonlyArray<{ rule: string; severity: GuardsSeverity }>;
}

// ─── Internal state ────────────────────────────────────────────────────────

interface RLEntry {
  count: number;
  resetTime: number;
}

interface TBEntry {
  used: number;
  resetTime: number;
}

const SEVERITY_RANK: Record<GuardsSeverity, number> = { low: 1, medium: 2, high: 3 };

const DEFAULT_BOT_ALLOW = new Set(['SEARCH_ENGINE', 'SOCIAL', 'MONITORING']);
const DEFAULT_BOT_DENY = new Set(['AUTOMATED']);

// ─── Public class ──────────────────────────────────────────────────────────

/**
 * Guards. Apply Arcis decisions to non-HTTP contexts. Construct once with
 * the vectors you care about, then call `.run(input)` per request/event.
 * Internal state (rate-limit buckets, token-budget buckets) lives on the
 * instance. Call `.close()` to release the periodic-cleanup interval.
 */
export class Guards {
  private readonly rl: GuardsRateLimitOptions | undefined;
  private readonly tb: GuardsTokenBudgetOptions | undefined;
  private readonly pi: GuardsPromptInjectionOptions | undefined;
  private readonly bot: GuardsBotOptions | undefined;
  private readonly rlStore: Record<string, RLEntry>;
  private readonly tbStore: Record<string, TBEntry>;
  private readonly cleanup: ReturnType<typeof setInterval> | null;
  private readonly piDenyRank: number;

  constructor(config: GuardsConfig = {}) {
    this.rl = config.rateLimit;
    this.tb = config.tokenBudget;
    this.pi = config.promptInjection === true ? {} : config.promptInjection;
    this.bot = config.bot === true ? {} : config.bot;

    const denyAt = (this.pi?.denyAt as GuardsSeverity | undefined) ?? 'medium';
    this.piDenyRank = SEVERITY_RANK[denyAt];

    this.rlStore = Object.create(null);
    this.tbStore = Object.create(null);

    // Sweep expired buckets only when rate-limit or token-budget is in play.
    const sweepInterval = this.rl?.windowMs ?? this.tb?.windowMs;
    if (sweepInterval) {
      this.cleanup = setInterval(() => this.sweepExpired(), sweepInterval);
      if (typeof this.cleanup.unref === 'function') this.cleanup.unref();
    } else {
      this.cleanup = null;
    }
  }

  /**
   * Evaluate every configured vector against `input`. Returns a structured
   * decision; the first denying vector short-circuits the rest.
   */
  run(input: GuardsInput): GuardsDecision {
    if (!input || typeof input.key !== 'string' || input.key.length === 0) {
      return { ok: false, reason: 'guards: missing required `input.key`' };
    }

    // 1. Rate limit
    if (this.rl) {
      const decision = this.checkRateLimit(input.key);
      if (!decision.ok) return decision;
    }

    // 2. Bot detection (if a UA was supplied)
    if (this.bot && input.userAgent) {
      const decision = this.checkBot(input.userAgent);
      if (!decision.ok) return decision;
    }

    // 3. Prompt injection (if text was supplied)
    let piMatches: ReadonlyArray<{ rule: string; severity: GuardsSeverity }> | undefined;
    if (this.pi !== undefined && typeof input.text === 'string' && input.text.length > 0) {
      const result = detectPromptInjection(input.text);
      piMatches = result.matches.map((m) => ({ rule: m.rule, severity: m.severity }));
      if (
        result.detected &&
        result.severity !== 'none' &&
        SEVERITY_RANK[result.severity] >= this.piDenyRank
      ) {
        const top = result.matches.find((m) => m.severity === result.severity)!;
        return {
          ok: false,
          vector: 'prompt-injection',
          severity: result.severity,
          reason: `Prompt injection detected (${top.rule}): ${top.description}`,
          matches: piMatches,
        };
      }
    }

    // 4. Token budget (always last so a denied request hasn't already charged)
    if (this.tb && typeof input.tokens === 'number') {
      const decision = this.checkTokenBudget(input.key, input.tokens);
      if (!decision.ok) return { ...decision, matches: piMatches };
    }

    return { ok: true, matches: piMatches };
  }

  /** Inspect rate-limit usage for a key. Useful for tests and telemetry. */
  inspectRateLimit(key: string): { count: number; resetTime: number } | null {
    const e = this.rlStore[key];
    return e ? { count: e.count, resetTime: e.resetTime } : null;
  }

  /** Inspect token-budget usage for a key. */
  inspectTokenBudget(key: string): { used: number; resetTime: number } | null {
    const e = this.tbStore[key];
    return e ? { used: e.used, resetTime: e.resetTime } : null;
  }

  /** Reset a single key's state, or all keys if `key` is omitted. */
  reset(key?: string): void {
    if (key === undefined) {
      for (const k of Object.keys(this.rlStore)) delete this.rlStore[k];
      for (const k of Object.keys(this.tbStore)) delete this.tbStore[k];
    } else {
      delete this.rlStore[key];
      delete this.tbStore[key];
    }
  }

  /** Release the periodic cleanup interval. Idempotent. */
  close(): void {
    if (this.cleanup !== null) clearInterval(this.cleanup);
  }

  // ─── internals ────────────────────────────────────────────────────────

  private checkRateLimit(key: string): GuardsDecision {
    const max = this.rl?.max ?? 100;
    const windowMs = this.rl?.windowMs ?? 60_000;
    const now = Date.now();
    let entry = this.rlStore[key];
    if (!entry || entry.resetTime < now) {
      entry = { count: 0, resetTime: now + windowMs };
      this.rlStore[key] = entry;
    }
    entry.count += 1;
    if (entry.count > max) {
      const retryAfterSeconds = Math.ceil((entry.resetTime - now) / 1000);
      return {
        ok: false,
        vector: 'rate-limit',
        severity: 'medium',
        reason: `Rate limit exceeded (${entry.count}/${max} per ${windowMs}ms)`,
        retryAfterSeconds: Math.max(0, retryAfterSeconds),
      };
    }
    return { ok: true };
  }

  private checkTokenBudget(key: string, tokens: number): GuardsDecision {
    const cost = Number.isFinite(tokens) && tokens >= 0 ? Math.floor(tokens) : 0;
    const max = this.tb?.maxTokens ?? 100_000;
    const windowMs = this.tb?.windowMs ?? 60 * 60 * 1000;
    const perReq = this.tb?.maxRequestTokens;

    if (perReq !== undefined && cost > perReq) {
      return {
        ok: false,
        vector: 'token-budget',
        severity: 'high',
        reason: `Per-call token budget exceeded (${cost} > ${perReq})`,
      };
    }

    const now = Date.now();
    let entry = this.tbStore[key];
    if (!entry || entry.resetTime < now) {
      entry = { used: 0, resetTime: now + windowMs };
      this.tbStore[key] = entry;
    }
    const projected = entry.used + cost;
    if (projected > max) {
      const retryAfterSeconds = Math.ceil((entry.resetTime - now) / 1000);
      return {
        ok: false,
        vector: 'token-budget',
        severity: 'medium',
        reason: `Window token budget exceeded (${entry.used} + ${cost} > ${max})`,
        retryAfterSeconds: Math.max(0, retryAfterSeconds),
      };
    }
    entry.used = projected;
    return { ok: true };
  }

  private checkBot(userAgent: string): GuardsDecision {
    const fakeReq = {
      headers: {
        'user-agent': userAgent,
        accept: 'text/html',
        'accept-language': 'en-US',
        'accept-encoding': 'gzip',
      },
    };
    const result = detectBot(fakeReq as never);
    if (!result.isBot) return { ok: true };

    const allow = this.bot?.allow ? new Set(this.bot.allow) : DEFAULT_BOT_ALLOW;
    const deny = this.bot?.deny ? new Set(this.bot.deny) : DEFAULT_BOT_DENY;
    const defaultAction = this.bot?.defaultAction ?? 'allow';

    if (allow.has(result.category as never)) return { ok: true };
    if (deny.has(result.category as never)) {
      return {
        ok: false,
        vector: 'bot',
        severity: 'medium',
        reason: result.name ? `Bot denied: ${result.name}` : `Bot denied (${result.category})`,
      };
    }
    if (defaultAction === 'deny') {
      return {
        ok: false,
        vector: 'bot',
        severity: 'low',
        reason: `Uncategorized bot under defaultAction=deny`,
      };
    }
    return { ok: true };
  }

  private sweepExpired(): void {
    const now = Date.now();
    for (const k of Object.keys(this.rlStore)) {
      if (this.rlStore[k].resetTime < now) delete this.rlStore[k];
    }
    for (const k of Object.keys(this.tbStore)) {
      if (this.tbStore[k].resetTime < now) delete this.tbStore[k];
    }
  }
}

export default Guards;
