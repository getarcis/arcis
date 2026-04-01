"""
Arcis SCA — Supply Chain Attack Scanner.

Detects compromised packages from known supply chain attacks.
Scans local projects and environments for malicious package versions,
trojanized dependencies, and persistence artifacts (backdoors).

Currently covers:
  - axios npm (March 2026) — trojanized versions 1.14.1, 0.30.4
  - litellm PyPI (March 2026) — credential harvester versions 1.82.7, 1.82.8
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── Terminal formatting ──────────────────────────────────────────────────────

_SUPPORTS_UNICODE = bool(
    sys.stdout.encoding and sys.stdout.encoding.lower().startswith("utf")
)
LINE_CHAR = "\u2500" if _SUPPORTS_UNICODE else "-"
TICK = "\u2713" if _SUPPORTS_UNICODE else "[OK]"
CROSS = "\u2717" if _SUPPORTS_UNICODE else "[!]"
WARN = "\u26a0" if _SUPPORTS_UNICODE else "[?]"

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
WHITE = "\033[97m"

WIDTH = 64


def _c(*codes: str, text: str, no_color: bool = False) -> str:
    if no_color:
        return text
    return "".join(codes) + text + RESET


# ── Threat database ─────────────────────────────────────────────────────────

@dataclass
class CompromisedPackage:
    """A known compromised package version."""

    ecosystem: str  # "npm" or "pypi"
    name: str
    malicious_versions: List[str]
    attack_vector: str
    severity: str  # "critical" or "high"
    cve: str
    disclosure_date: str
    trojanized_deps: List[str] = field(default_factory=list)
    persistence_artifacts: List[str] = field(default_factory=list)
    remediation: str = ""


THREAT_DB: List[CompromisedPackage] = [
    CompromisedPackage(
        ecosystem="npm",
        name="axios",
        malicious_versions=["1.14.1", "0.30.4"],
        attack_vector=(
            "Trojanized dependency plain-crypto-js@4.2.1 deploys a "
            "remote access trojan (RAT) via postinstall script"
        ),
        severity="critical",
        cve="CVE-2026-XXXX",
        disclosure_date="2026-03-31",
        trojanized_deps=["plain-crypto-js"],
        persistence_artifacts=[],
        remediation=(
            "1. Run: npm uninstall axios && npm install axios@1.14.0\n"
            "   2. Delete node_modules and reinstall: rm -rf node_modules && npm install\n"
            "   3. Search for 'plain-crypto-js' in node_modules — if present, your system may be compromised\n"
            "   4. Rotate any credentials/tokens accessible from the affected machine"
        ),
    ),
    CompromisedPackage(
        ecosystem="pypi",
        name="litellm",
        malicious_versions=["1.82.7", "1.82.8"],
        attack_vector=(
            "Credential harvester exfiltrates environment variables and API keys. "
            "Installs persistent .pth backdoor in site-packages that survives pip uninstall"
        ),
        severity="critical",
        cve="CVE-2026-XXXX",
        disclosure_date="2026-03-24",
        trojanized_deps=[],
        persistence_artifacts=["*.pth"],
        remediation=(
            "1. Run: pip uninstall litellm && pip install litellm==1.82.6\n"
            "   2. Check site-packages for suspicious .pth files:\n"
            "      python -c \"import site; print(site.getsitepackages())\"\n"
            "      Look for .pth files you don't recognize — the backdoor survives uninstall\n"
            "   3. Rotate ALL API keys, tokens, and credentials from environment variables\n"
            "   4. Check ~/.local/lib and conda envs for the same .pth artifacts"
        ),
    ),
]


# ── Data models ──────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A single supply chain finding."""

    package: str
    ecosystem: str
    version: str
    severity: str
    location: str
    attack_vector: str
    remediation: str
    finding_type: str = "compromised_version"  # or "trojanized_dep", "persistence_artifact"


# ── npm / Node.js scanners ───────────────────────────────────────────────────


def _scan_package_lock(path: str) -> List[Finding]:
    """Scan package-lock.json for compromised packages."""
    findings: List[Finding] = []
    lockfile = os.path.join(path, "package-lock.json")
    if not os.path.isfile(lockfile):
        return findings

    try:
        with open(lockfile, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return findings

    # lockfile v2/v3: packages dict
    packages = data.get("packages", {})
    # lockfile v1: dependencies dict
    dependencies = data.get("dependencies", {})

    for threat in THREAT_DB:
        if threat.ecosystem != "npm":
            continue

        # Check v2/v3 packages
        for pkg_path, pkg_info in packages.items():
            pkg_name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else ""
            version = pkg_info.get("version", "")

            if pkg_name == threat.name and version in threat.malicious_versions:
                findings.append(Finding(
                    package=threat.name,
                    ecosystem="npm",
                    version=version,
                    severity=threat.severity,
                    location=lockfile,
                    attack_vector=threat.attack_vector,
                    remediation=threat.remediation,
                ))

            # Check for trojanized dependencies
            for dep_name in threat.trojanized_deps:
                if pkg_name == dep_name:
                    findings.append(Finding(
                        package=dep_name,
                        ecosystem="npm",
                        version=version,
                        severity=threat.severity,
                        location=lockfile,
                        attack_vector=f"Trojanized dependency of {threat.name}: {threat.attack_vector}",
                        remediation=threat.remediation,
                        finding_type="trojanized_dep",
                    ))

        # Check v1 dependencies
        for dep_name, dep_info in dependencies.items():
            version = dep_info.get("version", "")
            if dep_name == threat.name and version in threat.malicious_versions:
                findings.append(Finding(
                    package=threat.name,
                    ecosystem="npm",
                    version=version,
                    severity=threat.severity,
                    location=lockfile,
                    attack_vector=threat.attack_vector,
                    remediation=threat.remediation,
                ))

    return findings


def _scan_yarn_lock(path: str) -> List[Finding]:
    """Scan yarn.lock for compromised packages."""
    findings: List[Finding] = []
    lockfile = os.path.join(path, "yarn.lock")
    if not os.path.isfile(lockfile):
        return findings

    try:
        with open(lockfile, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError:
        return findings

    for threat in THREAT_DB:
        if threat.ecosystem != "npm":
            continue

        # yarn.lock format: "package@version": \n  version "x.y.z"
        for mal_ver in threat.malicious_versions:
            # Match both yarn v1 and v2+ formats
            pattern = rf'"{re.escape(threat.name)}@[^"]*".*?version\s+"({re.escape(mal_ver)})"'
            if re.search(pattern, content, re.DOTALL):
                findings.append(Finding(
                    package=threat.name,
                    ecosystem="npm",
                    version=mal_ver,
                    severity=threat.severity,
                    location=lockfile,
                    attack_vector=threat.attack_vector,
                    remediation=threat.remediation,
                ))

        for dep_name in threat.trojanized_deps:
            if dep_name in content:
                findings.append(Finding(
                    package=dep_name,
                    ecosystem="npm",
                    version="unknown",
                    severity=threat.severity,
                    location=lockfile,
                    attack_vector=f"Trojanized dependency of {threat.name}: {threat.attack_vector}",
                    remediation=threat.remediation,
                    finding_type="trojanized_dep",
                ))

    return findings


def _scan_node_modules(path: str) -> List[Finding]:
    """Scan node_modules for compromised packages on disk."""
    findings: List[Finding] = []
    nm_dir = os.path.join(path, "node_modules")
    if not os.path.isdir(nm_dir):
        return findings

    for threat in THREAT_DB:
        if threat.ecosystem != "npm":
            continue

        pkg_json = os.path.join(nm_dir, threat.name, "package.json")
        if os.path.isfile(pkg_json):
            try:
                with open(pkg_json, "r", encoding="utf-8") as f:
                    data = json.load(f)
                version = data.get("version", "")
                if version in threat.malicious_versions:
                    findings.append(Finding(
                        package=threat.name,
                        ecosystem="npm",
                        version=version,
                        severity=threat.severity,
                        location=pkg_json,
                        attack_vector=threat.attack_vector,
                        remediation=threat.remediation,
                    ))
            except (json.JSONDecodeError, OSError):
                pass

        # Check for trojanized deps on disk
        for dep_name in threat.trojanized_deps:
            dep_json = os.path.join(nm_dir, dep_name, "package.json")
            if os.path.isfile(dep_json):
                findings.append(Finding(
                    package=dep_name,
                    ecosystem="npm",
                    version="installed",
                    severity=threat.severity,
                    location=dep_json,
                    attack_vector=f"Trojanized dependency of {threat.name}: {threat.attack_vector}",
                    remediation=threat.remediation,
                    finding_type="trojanized_dep",
                ))

    return findings


# ── Python / PyPI scanners ───────────────────────────────────────────────────


def _scan_requirements(path: str) -> List[Finding]:
    """Scan requirements.txt, Pipfile.lock, poetry.lock for compromised versions."""
    findings: List[Finding] = []

    # requirements.txt variants
    for req_name in ["requirements.txt", "requirements-dev.txt", "requirements-prod.txt"]:
        req_file = os.path.join(path, req_name)
        if not os.path.isfile(req_file):
            continue
        try:
            with open(req_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    for threat in THREAT_DB:
                        if threat.ecosystem != "pypi":
                            continue
                        for mal_ver in threat.malicious_versions:
                            if re.match(
                                rf"^{re.escape(threat.name)}\s*==\s*{re.escape(mal_ver)}",
                                line,
                                re.IGNORECASE,
                            ):
                                findings.append(Finding(
                                    package=threat.name,
                                    ecosystem="pypi",
                                    version=mal_ver,
                                    severity=threat.severity,
                                    location=req_file,
                                    attack_vector=threat.attack_vector,
                                    remediation=threat.remediation,
                                ))
        except OSError:
            pass

    # poetry.lock
    poetry_lock = os.path.join(path, "poetry.lock")
    if os.path.isfile(poetry_lock):
        try:
            with open(poetry_lock, "r", encoding="utf-8") as f:
                content = f.read()
            for threat in THREAT_DB:
                if threat.ecosystem != "pypi":
                    continue
                for mal_ver in threat.malicious_versions:
                    pattern = (
                        rf'\[\[package\]\]\s*name\s*=\s*"{re.escape(threat.name)}"'
                        rf'\s*version\s*=\s*"{re.escape(mal_ver)}"'
                    )
                    if re.search(pattern, content, re.DOTALL):
                        findings.append(Finding(
                            package=threat.name,
                            ecosystem="pypi",
                            version=mal_ver,
                            severity=threat.severity,
                            location=poetry_lock,
                            attack_vector=threat.attack_vector,
                            remediation=threat.remediation,
                        ))
        except OSError:
            pass

    # Pipfile.lock
    pipfile_lock = os.path.join(path, "Pipfile.lock")
    if os.path.isfile(pipfile_lock):
        try:
            with open(pipfile_lock, "r", encoding="utf-8") as f:
                data = json.load(f)
            for section in ("default", "develop"):
                pkgs = data.get(section, {})
                for threat in THREAT_DB:
                    if threat.ecosystem != "pypi":
                        continue
                    pkg_info = pkgs.get(threat.name, {})
                    version = pkg_info.get("version", "").lstrip("=")
                    if version in threat.malicious_versions:
                        findings.append(Finding(
                            package=threat.name,
                            ecosystem="pypi",
                            version=version,
                            severity=threat.severity,
                            location=pipfile_lock,
                            attack_vector=threat.attack_vector,
                            remediation=threat.remediation,
                        ))
        except (json.JSONDecodeError, OSError):
            pass

    return findings


def _scan_pip_installed() -> List[Finding]:
    """Check currently installed pip packages for compromised versions."""
    findings: List[Finding] = []
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return findings
        packages = json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return findings

    for pkg in packages:
        pkg_name = pkg.get("name", "").lower()
        pkg_version = pkg.get("version", "")
        for threat in THREAT_DB:
            if threat.ecosystem != "pypi":
                continue
            if pkg_name == threat.name.lower() and pkg_version in threat.malicious_versions:
                findings.append(Finding(
                    package=threat.name,
                    ecosystem="pypi",
                    version=pkg_version,
                    severity=threat.severity,
                    location="pip (currently installed)",
                    attack_vector=threat.attack_vector,
                    remediation=threat.remediation,
                ))

    return findings


def _scan_pth_backdoors() -> List[Finding]:
    """Scan Python site-packages for suspicious .pth backdoor files."""
    findings: List[Finding] = []
    try:
        import site
        site_dirs = site.getsitepackages()
        user_site = site.getusersitepackages()
        if isinstance(user_site, str):
            site_dirs.append(user_site)
    except Exception:
        return findings

    # Known suspicious patterns in .pth files (code execution, imports)
    suspicious_patterns = [
        re.compile(r"import\s+os"),
        re.compile(r"import\s+subprocess"),
        re.compile(r"exec\s*\("),
        re.compile(r"eval\s*\("),
        re.compile(r"__import__"),
        re.compile(r"requests\."),
        re.compile(r"urllib"),
        re.compile(r"socket\."),
        re.compile(r"base64\."),
    ]

    for site_dir in site_dirs:
        if not os.path.isdir(site_dir):
            continue
        for pth_file in glob.glob(os.path.join(site_dir, "*.pth")):
            try:
                with open(pth_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                for pattern in suspicious_patterns:
                    if pattern.search(content):
                        findings.append(Finding(
                            package="unknown",
                            ecosystem="pypi",
                            version="n/a",
                            severity="critical",
                            location=pth_file,
                            attack_vector=(
                                "Suspicious .pth file with code execution detected. "
                                "This may be a persistence backdoor from the litellm supply chain attack. "
                                ".pth files in site-packages execute on every Python startup."
                            ),
                            remediation=(
                                f"1. Inspect the file: {pth_file}\n"
                                f"   2. If you don't recognize it, delete it immediately\n"
                                "   3. Rotate all credentials accessible from this machine"
                            ),
                            finding_type="persistence_artifact",
                        ))
                        break  # one finding per file is enough
            except OSError:
                pass

    return findings


# ── Unified scanner ──────────────────────────────────────────────────────────


def scan_project(path: str, check_system: bool = False) -> List[Finding]:
    """
    Run all supply chain checks against a project directory.

    Args:
        path: Project root directory to scan.
        check_system: If True, also check globally installed packages
                      and site-packages for backdoor artifacts.
    """
    findings: List[Finding] = []

    # npm / Node.js checks
    findings.extend(_scan_package_lock(path))
    findings.extend(_scan_yarn_lock(path))
    findings.extend(_scan_node_modules(path))

    # Python / PyPI checks
    findings.extend(_scan_requirements(path))

    # System-level checks
    if check_system:
        findings.extend(_scan_pip_installed())
        findings.extend(_scan_pth_backdoors())

    # Deduplicate by (package, version, location)
    seen = set()
    unique: List[Finding] = []
    for f in findings:
        key = (f.package, f.version, f.location)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


# ── Report printer ───────────────────────────────────────────────────────────


def print_sca_report(
    path: str,
    findings: List[Finding],
    duration: float,
    no_color: bool = False,
) -> None:
    line = LINE_CHAR * WIDTH
    c = lambda text, *codes: _c(*codes, text=text, no_color=no_color)

    print()
    print(c("  Arcis Supply Chain Scanner", BOLD, CYAN))
    print(c(f"  Target: {path}", DIM))
    print(c(line, DIM))

    if not findings:
        print()
        print(c(f"  {TICK}  No known supply chain compromises detected", GREEN, BOLD))
        print()
        print(c(line, DIM))
        print(f"  Duration          {duration:.1f}s")
        print(c(line, DIM))
        print()
        return

    # Group findings by ecosystem
    npm_findings = [f for f in findings if f.ecosystem == "npm"]
    pypi_findings = [f for f in findings if f.ecosystem == "pypi"]

    severity_color = {"critical": RED, "high": YELLOW}

    for group_name, group in [("npm", npm_findings), ("PyPI", pypi_findings)]:
        if not group:
            continue
        print()
        print(c(f"  {group_name}", BOLD, WHITE))

        for f in group:
            sev_col = severity_color.get(f.severity, YELLOW)
            sev_label = f.severity.upper()

            if f.finding_type == "trojanized_dep":
                type_label = "TROJANIZED DEPENDENCY"
            elif f.finding_type == "persistence_artifact":
                type_label = "BACKDOOR ARTIFACT"
            else:
                type_label = "COMPROMISED VERSION"

            print()
            print(c(f"    {CROSS}  [{sev_label}] {type_label}", sev_col, BOLD))
            print(f"       Package:  {f.package}@{f.version}")
            print(c(f"       Location: {f.location}", DIM))
            print()
            # Wrap attack vector text
            print(c("       Attack:", BOLD, WHITE))
            for av_line in _wrap(f.attack_vector, 55):
                print(f"         {av_line}")
            print()
            print(c("       Fix:", BOLD, GREEN))
            for rem_line in f.remediation.split("\n"):
                print(f"         {rem_line.strip()}")

    # Summary
    print()
    print(c(line, DIM))
    print()

    critical = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")

    print(f"  Findings          {len(findings)}")
    if critical:
        print(f"  Critical          {c(str(critical), RED, BOLD)}")
    if high:
        print(f"  High              {c(str(high), YELLOW, BOLD)}")
    print(f"  Duration          {duration:.1f}s")
    print()
    print(
        c(
            f"  {CROSS}  Supply chain compromise detected — follow remediation steps above",
            RED,
            BOLD,
        )
    )
    print()
    print(c(line, DIM))
    print()


def _wrap(text: str, width: int) -> List[str]:
    """Simple word-wrap."""
    words = text.split()
    lines: List[str] = []
    current = ""
    for word in words:
        if current and len(current) + 1 + len(word) > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}" if current else word
    if current:
        lines.append(current)
    return lines


# ── CLI entry point ──────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="arcis sca",
        description=(
            "Supply Chain Attack Scanner — detect compromised packages "
            "from known supply chain attacks (axios, litellm, and more)."
        ),
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Project directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--system",
        action="store_true",
        help="Also scan globally installed packages and site-packages for backdoor artifacts",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )

    args = parser.parse_args()
    path = os.path.abspath(args.path)

    if not os.path.isdir(path):
        print(f"arcis sca: path not found: {path}")
        sys.exit(1)

    start = time.time()
    findings = scan_project(path, check_system=args.system)
    duration = time.time() - start

    print_sca_report(path, findings, duration, no_color=args.no_color)

    sys.exit(1 if findings else 0)
