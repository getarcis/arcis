"""
Arcis Core - Constants and pattern loading

Loads the shared security patterns from the bundled patterns.json.
"""

import json
from typing import Dict, Optional
from pathlib import Path


def _find_patterns_path() -> Optional[Path]:
    """Find patterns.json in development or installed locations."""
    # Development path: packages/arcis-python/arcis/core/constants.py -> packages/core/patterns.json
    dev_path = Path(__file__).parent.parent.parent.parent / "core" / "patterns.json"
    if dev_path.exists():
        return dev_path

    # Installed path: bundled in package data
    pkg_path = Path(__file__).parent.parent / "data" / "patterns.json"
    if pkg_path.exists():
        return pkg_path

    return None


def load_patterns() -> Dict:
    """Load security patterns from the bundled patterns.json.

    The wheel bundles ``arcis/data/patterns.json`` and the dev checkout has
    ``packages/core/patterns.json``, so one of these is always present in a
    working install.

    Raises:
        RuntimeError: if patterns.json cannot be found or parsed. Arcis fails
            loudly here rather than silently degrading to a partial pattern
            set, which would leave an application under-protected with no
            warning. A failure means the install is broken.
    """
    patterns_path = _find_patterns_path()
    if patterns_path is None:
        raise RuntimeError(
            "arcis: patterns.json not found (looked for the dev copy under "
            "packages/core/ and the bundled copy under arcis/data/). The arcis "
            "install is broken; reinstall the package."
        )
    try:
        with open(patterns_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"arcis: failed to load patterns.json at {patterns_path}: {exc}"
        ) from exc


PATTERNS = load_patterns()

# Constants
DEFAULT_MAX_INPUT_SIZE = 1_000_000  # 1MB
MAX_RECURSION_DEPTH = 10
DEFAULT_MAX_REQUESTS = 100
DEFAULT_WINDOW_MS = 60_000
DEFAULT_RATE_LIMIT_MESSAGE = "Too many requests, please try again later."
DEFAULT_LOG_MAX_LENGTH = 10_000
HSTS_DEFAULT_MAX_AGE = 31_536_000  # 1 year in seconds
