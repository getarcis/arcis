"""
arcis audit — static analysis security scanner for source code.

Scans Python and JavaScript/TypeScript files for dangerous patterns:
- Unsafe YAML loading
- subprocess with shell=True
- innerHTML / document.write sinks
- JSONP callback endpoints
- Angular security trust bypass
- Pickle / marshal / shelve deserialization on user input
- JWT without algorithm enforcement
- eval() / exec() on request data
- SQL query string concatenation
- ORM raw queries (Prisma $queryRaw, Sequelize, knex.raw)
- File system operations with user-controlled paths
- HTTP requests (fetch, axios, requests) with user-controlled URLs

Usage:
    arcis audit .
    arcis audit src/ --language python
    arcis audit app/ --severity high
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class Finding:
    """A single static analysis finding."""
    rule_id: str
    severity: str
    message: str
    file: str
    line: int
    snippet: str


# ── Rules ────────────────────────────────────────────────────────────────────

@dataclass
class Rule:
    """A static analysis detection rule."""
    id: str
    severity: str
    message: str
    pattern: re.Pattern
    languages: Tuple[str, ...]
    # Some rules need a negative lookahead (e.g., yaml.load WITH SafeLoader is ok)
    safe_pattern: Optional[re.Pattern] = None


RULES: List[Rule] = [
    # ── Python rules ──
    Rule(
        id="YAML-UNSAFE",
        severity="high",
        message="yaml.load() without SafeLoader — use yaml.safe_load() or yaml.load(data, Loader=SafeLoader)",
        pattern=re.compile(r"\byaml\.load\s*\("),
        languages=("python",),
        safe_pattern=re.compile(r"yaml\.load\s*\([^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader"),
    ),
    Rule(
        id="SHELL-TRUE",
        severity="high",
        message="subprocess call with shell=True — use shell=False with a list of arguments",
        pattern=re.compile(r"\bsubprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True"),
        languages=("python",),
    ),
    Rule(
        id="PICKLE-LOAD",
        severity="critical",
        message="pickle.loads() / pickle.load() on potentially untrusted data — use JSON or a safe serialization format",
        pattern=re.compile(r"\bpickle\.loads?\s*\("),
        languages=("python",),
    ),
    Rule(
        id="EVAL-EXEC",
        severity="critical",
        message="eval() or exec() detected — avoid dynamic code execution on user input",
        pattern=re.compile(r"\b(?:eval|exec)\s*\("),
        languages=("python", "javascript", "typescript"),
    ),

    # ── JavaScript/TypeScript rules ──
    Rule(
        id="INNERHTML",
        severity="high",
        message=".innerHTML assignment — use textContent or a sanitization library",
        pattern=re.compile(r"\.innerHTML\s*="),
        languages=("javascript", "typescript"),
    ),
    Rule(
        id="DOCUMENT-WRITE",
        severity="high",
        message="document.write() detected — use DOM manipulation instead",
        pattern=re.compile(r"\bdocument\.write(?:ln)?\s*\("),
        languages=("javascript", "typescript"),
    ),
    Rule(
        id="ANGULAR-TRUST",
        severity="high",
        message="bypassSecurityTrust*() — verify the input is truly trusted before bypassing Angular sanitization",
        pattern=re.compile(r"\bbypassSecurityTrust(?:Html|Style|Script|Url|ResourceUrl)\s*\("),
        languages=("typescript",),
    ),
    Rule(
        id="JWT-NO-ALG",
        severity="high",
        message="jwt.verify() / jwt.decode() without explicit algorithms — always specify algorithms to prevent alg:none attacks",
        pattern=re.compile(r"\bjwt\.(?:verify|decode)\s*\("),
        languages=("javascript", "typescript"),
        safe_pattern=re.compile(r"jwt\.(?:verify|decode)\s*\([^)]*algorithms"),
    ),

    # ── Cross-language rules ──
    Rule(
        id="JSONP-CALLBACK",
        severity="medium",
        message="JSONP callback parameter detected — validate callback names with sanitizeJsonpCallback()",
        pattern=re.compile(r"""(?:request\.(?:args|query|GET)\.get\s*\(\s*["']callback["']|req\.query\.callback|params\[["']callback["']\])"""),
        languages=("python", "javascript", "typescript"),
    ),

    # ── New rules (v1.4.0) ──

    Rule(
        id="SQL-CONCAT",
        severity="critical",
        message="SQL query built with string concatenation — use parameterized queries to prevent SQL injection",
        pattern=re.compile(
            r"""(?:cursor\.execute|db\.execute|connection\.execute|conn\.execute|query\.execute)\s*\(\s*(?:f["']|["'][^"']*["']\s*\+|["'][^"']*\+|["'][^"']*%\s*(?:request|req|params|data|input|user))"""
        ),
        languages=("python",),
    ),
    Rule(
        id="ORM-RAW",
        severity="high",
        message="Raw ORM query detected — verify no user input is interpolated into this query",
        pattern=re.compile(
            r"""(?:\$queryRaw|\.query\s*\(\s*["'`]|\bsequelize\.query\s*\(|typeorm.*\.query\s*\(|knex\.raw\s*\()"""
        ),
        languages=("javascript", "typescript"),
    ),
    Rule(
        id="FS-USER-PATH",
        severity="high",
        message="File system operation with potentially user-controlled path — use path.resolve() and validate against allowed directories",
        pattern=re.compile(
            r"""(?:fs\.(?:readFile|writeFile|appendFile|readFileSync|writeFileSync|unlink|unlinkSync|stat|statSync)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)|open\s*\(\s*(?:request\.|req\.|f["'].*\+))"""
        ),
        languages=("javascript", "typescript", "python"),
    ),
    Rule(
        id="FETCH-USER-URL",
        severity="high",
        message="HTTP request with potentially user-controlled URL — validate with validateUrl() to prevent SSRF",
        pattern=re.compile(
            r"""(?:fetch\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|`[^`]*\$\{)|(?:http|https|axios|got|superagent)\.(?:get|post|request)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)|requests\.(?:get|post|request)\s*\(\s*(?:request\.|req\.))"""
        ),
        languages=("javascript", "typescript", "python"),
    ),
    Rule(
        id="UNSAFE-DESERIALIZE",
        severity="critical",
        message="Unsafe deserialization detected — never deserialize untrusted data with marshal, shelve, or jsonpickle",
        pattern=re.compile(
            r"""\b(?:marshal\.loads?\s*\(|shelve\.open\s*\(|jsonpickle\.decode\s*\()"""
        ),
        languages=("python",),
    ),
]


# ── File scanning ────────────────────────────────────────────────────────────

LANGUAGE_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
    "env", ".env", "site-packages",
}


def _detect_language(filepath: str) -> Optional[str]:
    """Detect language from file extension."""
    _, ext = os.path.splitext(filepath)
    return LANGUAGE_MAP.get(ext.lower())


def _collect_files(path: str, language: Optional[str] = None) -> List[str]:
    """Collect scannable files under path."""
    files = []

    if os.path.isfile(path):
        lang = _detect_language(path)
        if lang and (language is None or lang == language):
            files.append(path)
        return files

    for root, dirs, filenames in os.walk(path):
        # Prune skipped directories
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for fname in filenames:
            filepath = os.path.join(root, fname)
            lang = _detect_language(filepath)
            if lang and (language is None or lang == language):
                files.append(filepath)

    return files


def scan_file(filepath: str, rules: Optional[List[Rule]] = None) -> List[Finding]:
    """Scan a single file for security issues."""
    lang = _detect_language(filepath)
    if not lang:
        return []

    applicable_rules = rules or RULES
    applicable_rules = [r for r in applicable_rules if lang in r.languages]
    if not applicable_rules:
        return []

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except (OSError, PermissionError):
        return []

    findings: List[Finding] = []

    for line_num, line in enumerate(lines, start=1):
        # Skip comment-only lines
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        for rule in applicable_rules:
            if rule.pattern.search(line):
                # Check safe pattern — if the line also matches safe, skip
                if rule.safe_pattern and rule.safe_pattern.search(line):
                    continue

                findings.append(Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    message=rule.message,
                    file=filepath,
                    line=line_num,
                    snippet=stripped[:120],
                ))

    return findings


def scan_directory(
    path: str,
    language: Optional[str] = None,
    severity: Optional[str] = None,
    rules: Optional[List[Rule]] = None,
) -> List[Finding]:
    """Scan a directory tree for security issues."""
    files = _collect_files(path, language)
    all_findings: List[Finding] = []

    for filepath in files:
        all_findings.extend(scan_file(filepath, rules))

    if severity:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold = severity_order.get(severity.lower(), 3)
        all_findings = [f for f in all_findings if severity_order.get(f.severity, 3) <= threshold]

    # Sort by severity (critical first), then file, then line
    severity_key = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_findings.sort(key=lambda f: (severity_key.get(f.severity, 9), f.file, f.line))

    return all_findings


# ── Output ───────────────────────────────────────────────────────────────────

def _print_findings(findings: List[Finding], no_color: bool = False) -> None:
    """Print findings to stdout."""
    if not findings:
        label = "No issues found." if no_color else "\033[32m✓ No issues found.\033[0m"
        print(label)
        return

    severity_colors = {
        "critical": "\033[91m",  # bright red
        "high": "\033[31m",      # red
        "medium": "\033[33m",    # yellow
        "low": "\033[36m",       # cyan
    }
    reset = "\033[0m"

    current_file = ""
    for f in findings:
        if f.file != current_file:
            current_file = f.file
            print(f"\n{current_file}")

        sev = f.severity.upper()
        if no_color:
            print(f"  L{f.line}  [{sev}] {f.rule_id}: {f.message}")
        else:
            color = severity_colors.get(f.severity, "")
            print(f"  L{f.line}  {color}[{sev}]{reset} {f.rule_id}: {f.message}")

        print(f"         {f.snippet}")

    print(f"\n{len(findings)} issue(s) found.")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="arcis audit",
        description="Static analysis security scanner for Python and JavaScript/TypeScript source code.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  arcis audit .
  arcis audit src/ --language python
  arcis audit app/ --severity high
  arcis audit . --no-color
        """,
    )

    parser.add_argument(
        "path",
        help="File or directory to scan",
    )
    parser.add_argument(
        "--language", "-l",
        choices=["python", "javascript", "typescript"],
        help="Only scan files of this language",
    )
    parser.add_argument(
        "--severity", "-s",
        choices=["critical", "high", "medium", "low"],
        help="Minimum severity to report (default: all)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable coloured terminal output",
    )

    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"arcis audit: path not found: {args.path}")
        sys.exit(1)

    findings = scan_directory(args.path, language=args.language, severity=args.severity)
    _print_findings(findings, no_color=args.no_color)

    sys.exit(1 if findings else 0)
