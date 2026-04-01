"""
Arcis CLI — command dispatcher.

Usage:
    arcis scan <url> [options]
    arcis audit <path> [options]
    arcis sca [path] [options]
"""

import sys


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage: arcis <command> [options]")
        print()
        print("Commands:")
        print("  scan    Scan HTTP endpoints for injection vulnerabilities")
        print("  audit   Static analysis security scanner for source code")
        print("  sca     Detect compromised packages from supply chain attacks")
        print()
        print("Run 'arcis <command> --help' for command-specific help.")
        sys.exit(0)

    command = sys.argv[1]
    # Remove the subcommand so the sub-parser sees clean argv
    sys.argv = [f"arcis {command}"] + sys.argv[2:]

    if command == "scan":
        from arcis.cli.scan import main as scan_main
        scan_main()
    elif command == "audit":
        from arcis.cli.audit import main as audit_main
        audit_main()
    elif command == "sca":
        from arcis.cli.sca import main as sca_main
        sca_main()
    else:
        print(f"arcis: unknown command '{command}'")
        print("Run 'arcis --help' for available commands.")
        sys.exit(1)
