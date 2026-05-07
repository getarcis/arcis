"""
Pattern-based prompt-injection detection and sanitization for LLM-handler
endpoints. Catches the common signature classes — system-prompt overrides,
known jailbreak frameworks (DAN/STAN/DUDE), structural markers (fake
XML/Markdown delimiters that try to forge system messages), and known
encoding tricks. Does NOT defend against arbitrary novel attacks: that
needs the model itself to evaluate intent.

Built as a signature library (Option A in ``documents/plans/sdk-vectors.md``
vector #28) — MIT, fully transparent, no closed Wasm blobs.

Mirrors the Node API in ``packages/arcis-node/src/sanitizers/prompt-injection.ts``.
"""

import re
from dataclasses import dataclass, field
from typing import List, Literal, Union

PromptInjectionSeverity = Literal["low", "medium", "high"]


@dataclass
class PromptInjectionMatch:
    """A single signature match."""
    rule: str
    severity: PromptInjectionSeverity
    description: str
    match: str


@dataclass
class DetectPromptInjectionResult:
    """Combined detection result across all signatures."""
    detected: bool
    matches: List[PromptInjectionMatch] = field(default_factory=list)
    severity: Union[PromptInjectionSeverity, Literal["none"]] = "none"


# ─── Signatures ───────────────────────────────────────────────────────────
# Each signature: rule id + compiled regex + severity + description.
# Patterns target the common public attack corpora; specifically the OWASP
# LLM01 prompt-injection examples plus the well-known jailbreak frameworks
# shipped publicly between 2023–2025.

_SIGNATURES = [
    # --- HIGH severity: clear override / jailbreak attempts ---
    (
        "ignore-previous-instructions",
        # Two clauses (alternation):
        #  1. ignore|disregard|... + adjectives? + a target object word
        #     (like "instructions", "rules") — catches "ignore your safety rules".
        #  2. ignore|disregard|... + (the|all|any) + (previous|above|prior|...)
        #     with no trailing noun — catches "disregard the above".
        re.compile(
            r"\b(?:ignore|disregard|forget|override|bypass)\s+"
            r"(?:(?:all|your|the|any|previous|prior|above|original|initial|system|safety)\s+)*"
            r"(?:instructions?|rules?|directions?|guidelines?|prompts?|policies|directives|commands?|restrictions?|filters?|safety|content)\b"
            r"|\b(?:ignore|disregard|forget|override|bypass)\s+"
            r"(?:all\s+|the\s+|any\s+)?(?:previous|prior|above|preceding|earlier|original|initial)\b",
            re.IGNORECASE,
        ),
        "high",
        "Direct instruction override attempt",
    ),
    (
        "jailbreak-dan",
        re.compile(
            r"\b(?:DAN|STAN|DUDE|DAVE|JEDI|EvilBot|AIM|BetterDAN|AntiGPT|AntiClaude)\b"
            r"(?:[\s.,!?]|mode|prompt|jailbreak|persona)",
            re.IGNORECASE,
        ),
        "high",
        "Known jailbreak framework name (DAN/STAN/DUDE/etc.)",
    ),
    (
        "do-anything-now",
        re.compile(r"\bdo\s+anything\s+now\b", re.IGNORECASE),
        "high",
        'DAN ("Do Anything Now") jailbreak variant',
    ),
    (
        "developer-mode",
        re.compile(
            r"\b(?:developer|debug|admin|sudo|root|god|maintenance|test)\s+mode\b"
            r"(?:\s+(?:on|enabled|activated|engaged))?",
            re.IGNORECASE,
        ),
        "high",
        'Fake "developer mode" / "debug mode" enablement',
    ),
    (
        "jailbroken-claim",
        re.compile(
            r"\b(?:you\s+are\s+(?:now\s+)?)?"
            r"(?:jailbroken|unrestricted|uncensored|unleashed|liberated|free\s+from\s+(?:rules|guidelines|restrictions))\b",
            re.IGNORECASE,
        ),
        "high",
        "Claim that the model is jailbroken / unrestricted",
    ),
    (
        "role-hijack",
        re.compile(
            r"\b(?:you\s+are\s+(?:now\s+)?(?:a\s+)?(?:different|new|another|evil|malicious|unrestricted|unfiltered)"
            r"|act\s+as\s+(?:a\s+)?(?:different|new|another|evil|malicious|unrestricted|unfiltered))\b",
            re.IGNORECASE,
        ),
        "high",
        "Persona hijack attempt",
    ),
    (
        "pretend-to-be",
        re.compile(r"\bpretend\s+(?:to\s+be|you\s+are|that\s+you\s+(?:are|have))\b", re.IGNORECASE),
        "high",
        "Persona-impersonation prompt",
    ),
    (
        "roleplay-as",
        re.compile(
            r"\b(?:roleplay|role[\s-]?play|simulate|emulate)\s+(?:as|being|the\s+role\s+of)\b",
            re.IGNORECASE,
        ),
        "high",
        "Roleplay-based jailbreak prefix",
    ),
    (
        "no-restrictions",
        re.compile(
            r"\b(?:without\s+(?:any\s+)?(?:restrictions?|limits?|filters?|safety|guidelines?|moral|ethic\w*)"
            r"|no\s+(?:restrictions?|limits?|filters?|safety|guidelines?))\b",
            re.IGNORECASE,
        ),
        "high",
        'Explicit "no restrictions" qualifier',
    ),

    # --- MEDIUM severity: system-prompt extraction & structural injection ---
    (
        "reveal-system-prompt",
        re.compile(
            r"\b(?:show|display|print|reveal|tell|give|repeat|output|expose)\s+"
            r"(?:me\s+)?(?:your|the)\s+"
            r"(?:(?:system|original|initial|full|complete|exact|raw)\s+)*"
            r"(?:prompt|instructions?|directive|configuration|rules?|guidelines?)",
            re.IGNORECASE,
        ),
        "medium",
        "System-prompt extraction attempt",
    ),
    (
        "what-are-instructions",
        re.compile(
            r"\bwhat\s+(?:are|were|is)\s+(?:your|the)\s+"
            r"(?:original\s+|initial\s+|system\s+)?"
            r"(?:instructions?|directives?|rules?|prompts?|guidelines?)\b",
            re.IGNORECASE,
        ),
        "medium",
        "Indirect system-prompt extraction",
    ),
    (
        "fake-system-tag",
        re.compile(r"</?\s*(?:system|instructions?|prompt|admin|root|sudo|user_admin)\s*>", re.IGNORECASE),
        "medium",
        "Forged XML-style system delimiter",
    ),
    (
        "fake-system-marker",
        re.compile(
            r"(?:^|\n)\s*(?:#{1,3}\s*|\[\s*|\*\*\s*)?"
            r"(?:SYSTEM|INSTRUCTIONS?|ADMIN|ROOT|PROMPT)\s*[:>=#]\s*",
            re.IGNORECASE,
        ),
        "medium",
        "Forged Markdown/heading-style system marker",
    ),
    (
        "begin-new-instructions",
        re.compile(
            r"\b(?:BEGIN|START|INITIATE)\s+(?:NEW\s+|UPDATED\s+|REPLACEMENT\s+)?"
            r"(?:INSTRUCTIONS?|PROMPT|SYSTEM|RULES?|DIRECTIVES?)\b",
            re.IGNORECASE,
        ),
        "medium",
        '"BEGIN NEW INSTRUCTIONS" marker',
    ),
    (
        "end-of-input-marker",
        re.compile(
            r"\[\s*(?:END|FINISH|TERMINATE|STOP|CLOSE)\s+(?:OF\s+)?"
            r"(?:INPUT|USER|MESSAGE|CONVERSATION|CONTEXT)\s*\]",
            re.IGNORECASE,
        ),
        "medium",
        'Fake "[END OF INPUT]" marker',
    ),
    (
        "human-assistant-replay",
        re.compile(r"\n\s*(?:Human|User|Assistant|AI):\s*", re.IGNORECASE),
        "medium",
        "Forged Human:/Assistant: turn marker",
    ),
    (
        "output-after-marker",
        re.compile(
            r"\b(?:after\s+(?:this|the\s+\w+))\s*[,.]?\s*"
            r"(?:output|print|say|respond|reply|return|generate)\b",
            re.IGNORECASE,
        ),
        "medium",
        "Conditional output redirection",
    ),
    (
        "translate-but-do-other",
        re.compile(
            r"\b(?:translate|summari[sz]e|paraphrase|rewrite)\s+.{0,80}\b"
            r"(?:but|then|after|and)\s+(?:also\s+)?"
            r"(?:do|say|output|tell|reveal|print)\b",
            re.IGNORECASE,
        ),
        "medium",
        'Task-hijack via "translate X but Y"',
    ),
    (
        "base64-suspicious",
        re.compile(
            r"\b(?:base64|b64|decode|encoded?\s+(?:in|as)\s+base64|atob)\b",
            re.IGNORECASE,
        ),
        "medium",
        "Base64-decode hint (often used to smuggle jailbreaks)",
    ),
    (
        "rot13-encoding",
        re.compile(r"\b(?:rot13|rot-13|caesar(?:\s+cipher)?)\b", re.IGNORECASE),
        "medium",
        "ROT13 / Caesar-cipher decode hint",
    ),

    # --- LOW severity: ambiguous but worth flagging in strict mode ---
    (
        "from-now-on",
        re.compile(r"\bfrom\s+now\s+on\b\s*[,.]?\s*(?:you|always|never)", re.IGNORECASE),
        "low",
        "Persistent-instruction prefix",
    ),
    (
        "your-new-purpose",
        re.compile(
            r"\byour\s+(?:new|real|true|primary|only)\s+"
            r"(?:purpose|role|task|goal|job|function)\s+is\b",
            re.IGNORECASE,
        ),
        "low",
        "Persona/purpose redefinition",
    ),
    (
        "forget-everything",
        re.compile(
            r"\bforget\s+(?:everything|all|the\s+(?:above|previous|prior))\b",
            re.IGNORECASE,
        ),
        "low",
        "Memory-clear directive",
    ),
    (
        "no-warnings",
        re.compile(
            r"\b(?:without|don'?t|do\s+not)\s+"
            r"(?:add|include|provide|give|send|print)\s+"
            r"(?:any\s+)?(?:warnings?|disclaimers?|caveats?|safety\s+notes?|legal\s+notice)",
            re.IGNORECASE,
        ),
        "low",
        "Warning-suppression directive",
    ),
    (
        "hypothetical-prefix",
        re.compile(
            r"\b(?:hypothetically|in\s+a\s+hypothetical\s+(?:world|scenario)"
            r"|imagine\s+(?:a\s+)?(?:world|scenario|situation)\s+where)\b",
            re.IGNORECASE,
        ),
        "low",
        "Hypothetical framing (common jailbreak prefix)",
    ),
    (
        "just-a-story",
        re.compile(
            r"\b(?:just|only|merely)\s+(?:a\s+)?"
            r"(?:story|fiction|hypothetical|thought\s+experiment|joke|game|test)\b",
            re.IGNORECASE,
        ),
        "low",
        "Fictional framing escape",
    ),
]

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def detect_prompt_injection(text: str) -> DetectPromptInjectionResult:
    """Detect prompt-injection signatures in ``text``.

    Returns all matches with severity and the highest severity seen.
    Does not modify the input.

    Args:
        text: The text to inspect (usually a user-supplied LLM prompt).

    Returns:
        DetectPromptInjectionResult with `.detected`, `.matches`, `.severity`.

    Examples:
        >>> r = detect_prompt_injection('Ignore previous instructions.')
        >>> r.detected
        True
        >>> r.severity
        'high'
    """
    if not isinstance(text, str) or not text:
        return DetectPromptInjectionResult(detected=False, matches=[], severity="none")

    matches: List[PromptInjectionMatch] = []
    top_rank = 0
    top_severity: Union[PromptInjectionSeverity, Literal["none"]] = "none"

    for rule, pattern, severity, description in _SIGNATURES:
        m = pattern.search(text)
        if m is not None:
            matches.append(PromptInjectionMatch(
                rule=rule,
                severity=severity,
                description=description,
                match=m.group(0)[:80],
            ))
            rank = _SEVERITY_RANK[severity]
            if rank > top_rank:
                top_rank = rank
                top_severity = severity

    return DetectPromptInjectionResult(
        detected=bool(matches),
        matches=matches,
        severity=top_severity,
    )


def sanitize_prompt_injection(
    text: str,
    redact_low: bool = False,
    replacement: str = "[REDACTED]",
) -> str:
    """Strip prompt-injection signatures from ``text``.

    For HIGH and MEDIUM severity matches the matched span is replaced with
    ``replacement``. LOW severity matches are left in place by default —
    toggle via ``redact_low``.

    Args:
        text: The text to sanitize.
        redact_low: If True, also redact LOW severity matches (default False).
        replacement: The string to replace matched spans with.

    Returns:
        The sanitized string. Safe inputs pass through unchanged.
    """
    if not isinstance(text, str) or not text:
        return text or ""

    value = text
    for _rule, pattern, severity, _description in _SIGNATURES:
        if severity == "low" and not redact_low:
            continue
        value = pattern.sub(replacement, value)
    return value


__all__ = [
    "detect_prompt_injection",
    "sanitize_prompt_injection",
    "PromptInjectionMatch",
    "DetectPromptInjectionResult",
    "PromptInjectionSeverity",
]
