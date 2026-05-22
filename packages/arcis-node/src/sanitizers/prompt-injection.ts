/**
 * @module @arcis/node/sanitizers/prompt-injection
 *
 * Pattern-based prompt-injection detection and sanitization for LLM-handler
 * endpoints. Catches the common signature classes — system-prompt overrides,
 * known jailbreak frameworks (DAN/STAN/DUDE), structural markers (fake
 * XML/Markdown delimiters that try to forge system messages), and known
 * encoding tricks. Does NOT defend against arbitrary novel attacks: that
 * needs the model itself to evaluate intent.
 *
 * Built as a signature library (Option A in `documents/plans/sdk-vectors.md`
 * vector #28) — MIT, fully transparent, no closed Wasm blobs.
 *
 * Common attack categories caught:
 *   - Direct override: "ignore previous instructions", "disregard the above"
 *   - Jailbreak frameworks: DAN, STAN, DUDE, "developer mode", "jailbroken"
 *   - Persona hijack: "you are now X", "pretend to be", "roleplay as"
 *   - System prompt extraction: "show me your prompt", "what are your rules"
 *   - Indirect injection: fake `<system>` tags, "BEGIN NEW INSTRUCTIONS"
 *   - Encoding tricks: Base64-prefixed payloads, ROT13 markers
 */

// ─── Severity model ────────────────────────────────────────────────────────

export type PromptInjectionSeverity = 'low' | 'medium' | 'high';

export interface PromptInjectionMatch {
  /** Stable identifier for the matched signature */
  rule: string;
  /** Severity of this signature */
  severity: PromptInjectionSeverity;
  /** Short human-readable description */
  description: string;
  /** First chars of the matched substring (for telemetry / logs) */
  match: string;
}

export interface DetectPromptInjectionResult {
  /** Did any signature match? */
  detected: boolean;
  /** All signatures that matched, in declaration order */
  matches: PromptInjectionMatch[];
  /** Highest severity across all matches; 'none' if nothing matched */
  severity: PromptInjectionSeverity | 'none';
}

// ─── Signatures ────────────────────────────────────────────────────────────
// Each signature: a regex + severity + a stable rule id + a description.
// Patterns target the common public attack corpora; specifically the OWASP
// LLM01 prompt-injection examples plus the well-known jailbreak frameworks
// shipped publicly between 2023–2025.

interface PromptInjectionSignature {
  rule: string;
  pattern: RegExp;
  severity: PromptInjectionSeverity;
  description: string;
}

const SIGNATURES: PromptInjectionSignature[] = [
  // --- HIGH severity: clear override / jailbreak attempts ---
  {
    rule: 'ignore-previous-instructions',
    // Two clauses:
    //  1. ignore|disregard|... + adjectives? + a target object word (like
    //     "instructions", "rules") — catches "ignore your safety rules".
    //  2. ignore|disregard|... + (the|all|any) + (previous|above|prior|...)
    //     with no trailing noun — catches "disregard the above".
    pattern: /\b(?:ignore|disregard|forget|override|bypass)\s+(?:(?:all|your|the|any|previous|prior|above|original|initial|system|safety)\s+)*(?:instructions?|rules?|directions?|guidelines?|prompts?|policies|directives|commands?|restrictions?|filters?|safety|content)\b|\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|the\s+|any\s+)?(?:previous|prior|above|preceding|earlier|original|initial)\b/i,
    severity: 'high',
    description: 'Direct instruction override attempt',
  },
  {
    rule: 'jailbreak-dan',
    pattern: /\b(?:DAN|STAN|DUDE|DAVE|JEDI|EvilBot|AIM|BetterDAN|AntiGPT|AntiClaude)\b(?:[\s.,!?]|mode|prompt|jailbreak|persona)/i,
    severity: 'high',
    description: 'Known jailbreak framework name (DAN/STAN/DUDE/etc.)',
  },
  {
    rule: 'do-anything-now',
    pattern: /\bdo\s+anything\s+now\b/i,
    severity: 'high',
    description: 'DAN ("Do Anything Now") jailbreak variant',
  },
  {
    rule: 'developer-mode',
    pattern: /\b(?:developer|debug|admin|sudo|root|god|maintenance|test)\s+mode\b(?:\s+(?:on|enabled|activated|engaged))?/i,
    severity: 'high',
    description: 'Fake "developer mode" / "debug mode" enablement',
  },
  {
    rule: 'jailbroken-claim',
    pattern: /\b(?:you\s+are\s+(?:now\s+)?)?(?:jailbroken|unrestricted|uncensored|unleashed|liberated|free\s+from\s+(?:rules|guidelines|restrictions))\b/i,
    severity: 'high',
    description: 'Claim that the model is jailbroken / unrestricted',
  },
  {
    rule: 'role-hijack',
    pattern: /\b(?:you\s+are\s+(?:now\s+)?(?:a\s+)?(?:different|new|another|evil|malicious|unrestricted|unfiltered)|act\s+as\s+(?:a\s+)?(?:different|new|another|evil|malicious|unrestricted|unfiltered))\b/i,
    severity: 'high',
    description: 'Persona hijack attempt',
  },
  {
    rule: 'pretend-to-be',
    pattern: /\bpretend\s+(?:to\s+be|you\s+are|that\s+you\s+(?:are|have))\b/i,
    severity: 'high',
    description: 'Persona-impersonation prompt',
  },
  {
    rule: 'roleplay-as',
    pattern: /\b(?:roleplay|role[\s-]?play|simulate|emulate)\s+(?:as|being|the\s+role\s+of)\b/i,
    severity: 'high',
    description: 'Roleplay-based jailbreak prefix',
  },
  {
    rule: 'no-restrictions',
    pattern: /\b(?:without\s+(?:any\s+)?(?:restrictions?|limits?|filters?|safety|guidelines?|moral|ethic\w*)|no\s+(?:restrictions?|limits?|filters?|safety|guidelines?))\b/i,
    severity: 'high',
    description: 'Explicit "no restrictions" qualifier',
  },

  // --- MEDIUM severity: system-prompt extraction & structural injection ---
  {
    rule: 'reveal-system-prompt',
    pattern: /\b(?:show|display|print|reveal|tell|give|repeat|output|expose)\s+(?:me\s+)?(?:your|the)\s+(?:(?:system|original|initial|full|complete|exact|raw)\s+)*(?:prompt|instructions?|directive|configuration|rules?|guidelines?)/i,
    severity: 'medium',
    description: 'System-prompt extraction attempt',
  },
  {
    rule: 'what-are-instructions',
    pattern: /\bwhat\s+(?:are|were|is)\s+(?:your|the)\s+(?:original\s+|initial\s+|system\s+)?(?:instructions?|directives?|rules?|prompts?|guidelines?)\b/i,
    severity: 'medium',
    description: 'Indirect system-prompt extraction',
  },
  {
    rule: 'fake-system-tag',
    pattern: /<\/?\s*(?:system|instructions?|prompt|admin|root|sudo|user_admin)\s*>/i,
    severity: 'medium',
    description: 'Forged XML-style system delimiter',
  },
  {
    rule: 'fake-system-marker',
    pattern: /(?:^|\n)\s*(?:#{1,3}\s*|\[\s*|\*\*\s*)?(?:SYSTEM|INSTRUCTIONS?|ADMIN|ROOT|PROMPT)\s*[:>=#]\s*/i,
    severity: 'medium',
    description: 'Forged Markdown/heading-style system marker',
  },
  {
    rule: 'begin-new-instructions',
    pattern: /\b(?:BEGIN|START|INITIATE)\s+(?:NEW\s+|UPDATED\s+|REPLACEMENT\s+)?(?:INSTRUCTIONS?|PROMPT|SYSTEM|RULES?|DIRECTIVES?)\b/i,
    severity: 'medium',
    description: '"BEGIN NEW INSTRUCTIONS" marker',
  },
  {
    rule: 'end-of-input-marker',
    pattern: /\[\s*(?:END|FINISH|TERMINATE|STOP|CLOSE)\s+(?:OF\s+)?(?:INPUT|USER|MESSAGE|CONVERSATION|CONTEXT)\s*\]/i,
    severity: 'medium',
    description: 'Fake "[END OF INPUT]" marker',
  },
  {
    rule: 'human-assistant-replay',
    pattern: /\n\s*(?:Human|User|Assistant|AI):\s*/i,
    severity: 'medium',
    description: 'Forged Human:/Assistant: turn marker',
  },
  {
    rule: 'output-after-marker',
    pattern: /\b(?:after\s+(?:this|the\s+\w+))\s*[,.]?\s*(?:output|print|say|respond|reply|return|generate)\b/i,
    severity: 'medium',
    description: 'Conditional output redirection',
  },
  {
    rule: 'translate-but-do-other',
    pattern: /\b(?:translate|summari[sz]e|paraphrase|rewrite)\s+.{0,80}\b(?:but|then|after|and)\s+(?:also\s+)?(?:do|say|output|tell|reveal|print)\b/i,
    severity: 'medium',
    description: 'Task-hijack via "translate X but Y"',
  },
  {
    rule: 'base64-suspicious',
    pattern: /\b(?:base64|b64|decode|encoded?\s+(?:in|as)\s+base64|atob)\b/i,
    severity: 'medium',
    description: 'Base64-decode hint (often used to smuggle jailbreaks)',
  },
  {
    rule: 'rot13-encoding',
    pattern: /\b(?:rot13|rot-13|caesar(?:\s+cipher)?)\b/i,
    severity: 'medium',
    description: 'ROT13 / Caesar-cipher decode hint',
  },

  // ── V32: AI agent toolcall injection (improvements.md §1.2) ────────
  // Modern LLM agents (Claude tool-use, OpenAI function-calling,
  // ReAct loops) read tool definitions from the system prompt and
  // JSON-shaped requests from the model. A malicious user can embed
  // those shapes in their input to make the host think they invoked
  // a tool, or to trick the model into echoing a synthesized
  // tool_call that the runtime then executes.
  //
  // Narrow patterns — match the literal JSON keys and inline
  // tool-name shapes. Won't false-positive on plain English text
  // discussing tools.
  {
    rule: 'agent-toolcall-marker',
    pattern: /"(?:tool_call|function_call|call_tool|tool_use|toolUse)"\s*:\s*\{/i,
    severity: 'high',
    description: 'Injected agent tool-call JSON shape (e.g. {"tool_call":{...}})',
  },
  {
    rule: 'agent-tool-name-spoof',
    pattern:
      /"name"\s*:\s*"(?:exec|shell|run_command|system|bash|cmd|python|eval|read_file|write_file|delete_file)"/i,
    severity: 'high',
    description: 'Forged tool-name attempting privileged tool invocation',
  },
  {
    rule: 'agent-tool-result-marker',
    pattern: /"(?:tool_result|function_result|tool_output)"\s*:\s*[\{\["]/i,
    severity: 'high',
    description: 'Injected fake tool-result block (trick agent into trusting fabricated output)',
  },
  {
    rule: 'ansi-escape-sequence',
    pattern: /\x1b\[/,
    severity: 'medium',
    description: 'ANSI escape sequence (terminal hijack / output spoofing on CLI agents)',
  },
  {
    rule: 'claude-tool-use-tags',
    pattern: /<\/?\s*(?:tool_use|tool_result|invoke|function_calls?|parameter)\b/i,
    severity: 'high',
    description: 'Claude/OpenAI tool-use XML-style tag forgery',
  },

  // --- LOW severity: ambiguous but worth flagging in strict mode ---
  {
    rule: 'from-now-on',
    pattern: /\bfrom\s+now\s+on\b\s*[,.]?\s*(?:you|always|never)/i,
    severity: 'low',
    description: 'Persistent-instruction prefix',
  },
  {
    rule: 'your-new-purpose',
    pattern: /\byour\s+(?:new|real|true|primary|only)\s+(?:purpose|role|task|goal|job|function)\s+is\b/i,
    severity: 'low',
    description: 'Persona/purpose redefinition',
  },
  {
    rule: 'forget-everything',
    pattern: /\bforget\s+(?:everything|all|the\s+(?:above|previous|prior))\b/i,
    severity: 'low',
    description: 'Memory-clear directive',
  },
  {
    rule: 'no-warnings',
    pattern: /\b(?:without|don'?t|do\s+not)\s+(?:add|include|provide|give|send|print)\s+(?:any\s+)?(?:warnings?|disclaimers?|caveats?|safety\s+notes?|legal\s+notice)/i,
    severity: 'low',
    description: 'Warning-suppression directive',
  },
  {
    rule: 'hypothetical-prefix',
    pattern: /\b(?:hypothetically|in\s+a\s+hypothetical\s+(?:world|scenario)|imagine\s+(?:a\s+)?(?:world|scenario|situation)\s+where)\b/i,
    severity: 'low',
    description: 'Hypothetical framing (common jailbreak prefix)',
  },
  {
    rule: 'just-a-story',
    pattern: /\b(?:just|only|merely)\s+(?:a\s+)?(?:story|fiction|hypothetical|thought\s+experiment|joke|game|test)\b/i,
    severity: 'low',
    description: 'Fictional framing escape',
  },
];

const SEVERITY_RANK: Record<PromptInjectionSeverity, number> = {
  low: 1,
  medium: 2,
  high: 3,
};

// ─── Public API ────────────────────────────────────────────────────────────

/**
 * Detect prompt-injection signatures in `text`. Returns all matches with
 * severity and the highest severity seen. Does not modify the input.
 *
 * @example
 * const r = detectPromptInjection('Ignore the previous instructions.');
 * if (r.detected && r.severity === 'high') return res.status(403).end();
 */
export function detectPromptInjection(text: string): DetectPromptInjectionResult {
  if (typeof text !== 'string' || text.length === 0) {
    return { detected: false, matches: [], severity: 'none' };
  }

  const matches: PromptInjectionMatch[] = [];
  let topRank = 0;
  let topSeverity: PromptInjectionSeverity | 'none' = 'none';

  for (const sig of SIGNATURES) {
    const m = sig.pattern.exec(text);
    if (m) {
      const matched = m[0].slice(0, 80);
      matches.push({
        rule: sig.rule,
        severity: sig.severity,
        description: sig.description,
        match: matched,
      });
      const rank = SEVERITY_RANK[sig.severity];
      if (rank > topRank) {
        topRank = rank;
        topSeverity = sig.severity;
      }
    }
  }

  return {
    detected: matches.length > 0,
    matches,
    severity: topSeverity,
  };
}

/**
 * Strip prompt-injection signatures from `text`. For HIGH and MEDIUM
 * severity matches the matched span is replaced with `[REDACTED]`. LOW
 * severity matches are left in place by default — toggle via `redactLow`.
 *
 * Returns the sanitized string. To inspect what was stripped, call
 * `detectPromptInjection` first or pass `collectMatches: true`.
 */
export function sanitizePromptInjection(
  text: string,
  options: { redactLow?: boolean; replacement?: string } = {},
): string {
  if (typeof text !== 'string' || text.length === 0) return text ?? '';

  const replacement = options.replacement ?? '[REDACTED]';
  const redactLow = options.redactLow ?? false;
  let value = text;

  for (const sig of SIGNATURES) {
    if (sig.severity === 'low' && !redactLow) continue;
    // Use a global flavor of the pattern so multiple occurrences are removed.
    const flags = sig.pattern.flags.includes('g') ? sig.pattern.flags : sig.pattern.flags + 'g';
    const globalPattern = new RegExp(sig.pattern.source, flags);
    value = value.replace(globalPattern, replacement);
  }

  return value;
}
