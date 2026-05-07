package sanitizers

import (
	"regexp"
)

// Pattern-based prompt-injection detection and sanitization for LLM-handler
// endpoints. Catches the common signature classes — system-prompt overrides,
// known jailbreak frameworks (DAN/STAN/DUDE), structural markers (fake
// XML/Markdown delimiters that try to forge system messages), and known
// encoding tricks. Does NOT defend against arbitrary novel attacks: that
// needs the model itself to evaluate intent.
//
// Built as a signature library (Option A in `documents/plans/sdk-vectors.md`
// vector #28) — MIT, fully transparent, no closed Wasm blobs. Mirrors the
// Node and Python implementations.

// PromptInjectionSeverity describes how confident a match is.
type PromptInjectionSeverity string

const (
	PromptInjectionLow    PromptInjectionSeverity = "low"
	PromptInjectionMedium PromptInjectionSeverity = "medium"
	PromptInjectionHigh   PromptInjectionSeverity = "high"
)

// PromptInjectionMatch is one signature hit.
type PromptInjectionMatch struct {
	Rule        string                  `json:"rule"`
	Severity    PromptInjectionSeverity `json:"severity"`
	Description string                  `json:"description"`
	Match       string                  `json:"match"`
}

// PromptInjectionResult is the combined detection result.
type PromptInjectionResult struct {
	Detected bool                   `json:"detected"`
	Matches  []PromptInjectionMatch `json:"matches"`
	// Severity is the highest severity seen across all matches, or "none"
	// when nothing matched.
	Severity string `json:"severity"`
}

type promptInjectionSignature struct {
	rule        string
	pattern     *regexp.Regexp
	severity    PromptInjectionSeverity
	description string
}

// All patterns are case-insensitive via the (?i) prefix. Go's regexp
// uses RE2 — no lookaround / backrefs / etc., but every signature here
// stays inside that subset.
var promptInjectionSignatures = []promptInjectionSignature{
	// --- HIGH severity: clear override / jailbreak attempts ---
	{
		rule: "ignore-previous-instructions",
		pattern: regexp.MustCompile(
			`(?i)\b(?:ignore|disregard|forget|override|bypass)\s+` +
				`(?:(?:all|your|the|any|previous|prior|above|original|initial|system|safety)\s+)*` +
				`(?:instructions?|rules?|directions?|guidelines?|prompts?|policies|directives|commands?|restrictions?|filters?|safety|content)\b` +
				`|(?i)\b(?:ignore|disregard|forget|override|bypass)\s+` +
				`(?:all\s+|the\s+|any\s+)?(?:previous|prior|above|preceding|earlier|original|initial)\b`,
		),
		severity:    PromptInjectionHigh,
		description: "Direct instruction override attempt",
	},
	{
		rule: "jailbreak-dan",
		pattern: regexp.MustCompile(
			`(?i)\b(?:DAN|STAN|DUDE|DAVE|JEDI|EvilBot|AIM|BetterDAN|AntiGPT|AntiClaude)\b` +
				`(?:[\s.,!?]|mode|prompt|jailbreak|persona)`,
		),
		severity:    PromptInjectionHigh,
		description: "Known jailbreak framework name (DAN/STAN/DUDE/etc.)",
	},
	{
		rule:        "do-anything-now",
		pattern:     regexp.MustCompile(`(?i)\bdo\s+anything\s+now\b`),
		severity:    PromptInjectionHigh,
		description: `DAN ("Do Anything Now") jailbreak variant`,
	},
	{
		rule: "developer-mode",
		pattern: regexp.MustCompile(
			`(?i)\b(?:developer|debug|admin|sudo|root|god|maintenance|test)\s+mode\b` +
				`(?:\s+(?:on|enabled|activated|engaged))?`,
		),
		severity:    PromptInjectionHigh,
		description: `Fake "developer mode" / "debug mode" enablement`,
	},
	{
		rule: "jailbroken-claim",
		pattern: regexp.MustCompile(
			`(?i)\b(?:you\s+are\s+(?:now\s+)?)?` +
				`(?:jailbroken|unrestricted|uncensored|unleashed|liberated|free\s+from\s+(?:rules|guidelines|restrictions))\b`,
		),
		severity:    PromptInjectionHigh,
		description: "Claim that the model is jailbroken / unrestricted",
	},
	{
		rule: "role-hijack",
		pattern: regexp.MustCompile(
			`(?i)\b(?:you\s+are\s+(?:now\s+)?(?:a\s+)?(?:different|new|another|evil|malicious|unrestricted|unfiltered)` +
				`|act\s+as\s+(?:a\s+)?(?:different|new|another|evil|malicious|unrestricted|unfiltered))\b`,
		),
		severity:    PromptInjectionHigh,
		description: "Persona hijack attempt",
	},
	{
		rule:        "pretend-to-be",
		pattern:     regexp.MustCompile(`(?i)\bpretend\s+(?:to\s+be|you\s+are|that\s+you\s+(?:are|have))\b`),
		severity:    PromptInjectionHigh,
		description: "Persona-impersonation prompt",
	},
	{
		rule:        "roleplay-as",
		pattern:     regexp.MustCompile(`(?i)\b(?:roleplay|role[\s-]?play|simulate|emulate)\s+(?:as|being|the\s+role\s+of)\b`),
		severity:    PromptInjectionHigh,
		description: "Roleplay-based jailbreak prefix",
	},
	{
		rule: "no-restrictions",
		pattern: regexp.MustCompile(
			`(?i)\b(?:without\s+(?:any\s+)?(?:restrictions?|limits?|filters?|safety|guidelines?|moral|ethic\w*)` +
				`|no\s+(?:restrictions?|limits?|filters?|safety|guidelines?))\b`,
		),
		severity:    PromptInjectionHigh,
		description: `Explicit "no restrictions" qualifier`,
	},

	// --- MEDIUM severity: system-prompt extraction & structural injection ---
	{
		rule: "reveal-system-prompt",
		pattern: regexp.MustCompile(
			`(?i)\b(?:show|display|print|reveal|tell|give|repeat|output|expose)\s+` +
				`(?:me\s+)?(?:your|the)\s+` +
				`(?:(?:system|original|initial|full|complete|exact|raw)\s+)*` +
				`(?:prompt|instructions?|directive|configuration|rules?|guidelines?)`,
		),
		severity:    PromptInjectionMedium,
		description: "System-prompt extraction attempt",
	},
	{
		rule: "what-are-instructions",
		pattern: regexp.MustCompile(
			`(?i)\bwhat\s+(?:are|were|is)\s+(?:your|the)\s+` +
				`(?:original\s+|initial\s+|system\s+)?` +
				`(?:instructions?|directives?|rules?|prompts?|guidelines?)\b`,
		),
		severity:    PromptInjectionMedium,
		description: "Indirect system-prompt extraction",
	},
	{
		rule:        "fake-system-tag",
		pattern:     regexp.MustCompile(`(?i)</?\s*(?:system|instructions?|prompt|admin|root|sudo|user_admin)\s*>`),
		severity:    PromptInjectionMedium,
		description: "Forged XML-style system delimiter",
	},
	{
		rule: "fake-system-marker",
		pattern: regexp.MustCompile(
			`(?i)(?:^|\n)\s*(?:#{1,3}\s*|\[\s*|\*\*\s*)?` +
				`(?:SYSTEM|INSTRUCTIONS?|ADMIN|ROOT|PROMPT)\s*[:>=#]\s*`,
		),
		severity:    PromptInjectionMedium,
		description: "Forged Markdown/heading-style system marker",
	},
	{
		rule: "begin-new-instructions",
		pattern: regexp.MustCompile(
			`(?i)\b(?:BEGIN|START|INITIATE)\s+(?:NEW\s+|UPDATED\s+|REPLACEMENT\s+)?` +
				`(?:INSTRUCTIONS?|PROMPT|SYSTEM|RULES?|DIRECTIVES?)\b`,
		),
		severity:    PromptInjectionMedium,
		description: `"BEGIN NEW INSTRUCTIONS" marker`,
	},
	{
		rule: "end-of-input-marker",
		pattern: regexp.MustCompile(
			`(?i)\[\s*(?:END|FINISH|TERMINATE|STOP|CLOSE)\s+(?:OF\s+)?` +
				`(?:INPUT|USER|MESSAGE|CONVERSATION|CONTEXT)\s*\]`,
		),
		severity:    PromptInjectionMedium,
		description: `Fake "[END OF INPUT]" marker`,
	},
	{
		rule:        "human-assistant-replay",
		pattern:     regexp.MustCompile(`(?i)\n\s*(?:Human|User|Assistant|AI):\s*`),
		severity:    PromptInjectionMedium,
		description: "Forged Human:/Assistant: turn marker",
	},
	{
		rule: "output-after-marker",
		pattern: regexp.MustCompile(
			`(?i)\b(?:after\s+(?:this|the\s+\w+))\s*[,.]?\s*` +
				`(?:output|print|say|respond|reply|return|generate)\b`,
		),
		severity:    PromptInjectionMedium,
		description: "Conditional output redirection",
	},
	{
		rule: "translate-but-do-other",
		pattern: regexp.MustCompile(
			`(?i)\b(?:translate|summari[sz]e|paraphrase|rewrite)\s+.{0,80}\b` +
				`(?:but|then|after|and)\s+(?:also\s+)?` +
				`(?:do|say|output|tell|reveal|print)\b`,
		),
		severity:    PromptInjectionMedium,
		description: `Task-hijack via "translate X but Y"`,
	},
	{
		rule: "base64-suspicious",
		pattern: regexp.MustCompile(
			`(?i)\b(?:base64|b64|decode|encoded?\s+(?:in|as)\s+base64|atob)\b`,
		),
		severity:    PromptInjectionMedium,
		description: "Base64-decode hint (often used to smuggle jailbreaks)",
	},
	{
		rule:        "rot13-encoding",
		pattern:     regexp.MustCompile(`(?i)\b(?:rot13|rot-13|caesar(?:\s+cipher)?)\b`),
		severity:    PromptInjectionMedium,
		description: "ROT13 / Caesar-cipher decode hint",
	},

	// --- LOW severity: ambiguous but worth flagging in strict mode ---
	{
		rule:        "from-now-on",
		pattern:     regexp.MustCompile(`(?i)\bfrom\s+now\s+on\b\s*[,.]?\s*(?:you|always|never)`),
		severity:    PromptInjectionLow,
		description: "Persistent-instruction prefix",
	},
	{
		rule: "your-new-purpose",
		pattern: regexp.MustCompile(
			`(?i)\byour\s+(?:new|real|true|primary|only)\s+` +
				`(?:purpose|role|task|goal|job|function)\s+is\b`,
		),
		severity:    PromptInjectionLow,
		description: "Persona/purpose redefinition",
	},
	{
		rule: "forget-everything",
		pattern: regexp.MustCompile(
			`(?i)\bforget\s+(?:everything|all|the\s+(?:above|previous|prior))\b`,
		),
		severity:    PromptInjectionLow,
		description: "Memory-clear directive",
	},
	{
		rule: "no-warnings",
		pattern: regexp.MustCompile(
			`(?i)\b(?:without|don'?t|do\s+not)\s+` +
				`(?:add|include|provide|give|send|print)\s+` +
				`(?:any\s+)?(?:warnings?|disclaimers?|caveats?|safety\s+notes?|legal\s+notice)`,
		),
		severity:    PromptInjectionLow,
		description: "Warning-suppression directive",
	},
	{
		rule: "hypothetical-prefix",
		pattern: regexp.MustCompile(
			`(?i)\b(?:hypothetically|in\s+a\s+hypothetical\s+(?:world|scenario)` +
				`|imagine\s+(?:a\s+)?(?:world|scenario|situation)\s+where)\b`,
		),
		severity:    PromptInjectionLow,
		description: "Hypothetical framing (common jailbreak prefix)",
	},
	{
		rule: "just-a-story",
		pattern: regexp.MustCompile(
			`(?i)\b(?:just|only|merely)\s+(?:a\s+)?` +
				`(?:story|fiction|hypothetical|thought\s+experiment|joke|game|test)\b`,
		),
		severity:    PromptInjectionLow,
		description: "Fictional framing escape",
	},
}

var severityRank = map[PromptInjectionSeverity]int{
	PromptInjectionLow:    1,
	PromptInjectionMedium: 2,
	PromptInjectionHigh:   3,
}

// DetectPromptInjection runs every signature against text and returns the
// list of matches plus the highest severity seen. Does not modify text.
func DetectPromptInjection(text string) PromptInjectionResult {
	if text == "" {
		return PromptInjectionResult{Detected: false, Matches: nil, Severity: "none"}
	}

	var matches []PromptInjectionMatch
	topRank := 0
	topSeverity := "none"

	for _, sig := range promptInjectionSignatures {
		loc := sig.pattern.FindStringIndex(text)
		if loc == nil {
			continue
		}
		matched := text[loc[0]:loc[1]]
		if len(matched) > 80 {
			matched = matched[:80]
		}
		matches = append(matches, PromptInjectionMatch{
			Rule:        sig.rule,
			Severity:    sig.severity,
			Description: sig.description,
			Match:       matched,
		})
		rank := severityRank[sig.severity]
		if rank > topRank {
			topRank = rank
			topSeverity = string(sig.severity)
		}
	}

	return PromptInjectionResult{
		Detected: len(matches) > 0,
		Matches:  matches,
		Severity: topSeverity,
	}
}

// SanitizePromptInjection redacts every HIGH and MEDIUM severity match in
// text. LOW severity matches are left in place unless redactLow is true.
// Replacement is the string substituted in for matched spans.
func SanitizePromptInjection(text string, redactLow bool, replacement string) string {
	if text == "" {
		return text
	}
	if replacement == "" {
		replacement = "[REDACTED]"
	}
	value := text
	for _, sig := range promptInjectionSignatures {
		if sig.severity == PromptInjectionLow && !redactLow {
			continue
		}
		value = sig.pattern.ReplaceAllString(value, replacement)
	}
	return value
}
