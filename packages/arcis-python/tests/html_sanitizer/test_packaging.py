"""Packaging of arcis.html: the optional JustHTML dependency."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_PACKAGE_ROOT = Path(__file__).parents[2]


def _run_python(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=_PACKAGE_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_import_without_justhtml_names_the_install_command() -> None:
    result = _run_python(
        "import sys\n"
        "sys.modules['justhtml'] = None  # makes `import justhtml` fail\n"
        "try:\n"
        "    import arcis.html\n"
        "except ImportError as exc:\n"
        "    print(exc)\n"
        "else:\n"
        "    print('imported')\n"
    )
    assert result.returncode == 0, result.stderr
    assert 'pip install "arcis[html]"' in result.stdout


def test_importing_arcis_does_not_import_justhtml() -> None:
    result = _run_python("import sys, arcis\nprint('justhtml' in sys.modules)\n")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"
