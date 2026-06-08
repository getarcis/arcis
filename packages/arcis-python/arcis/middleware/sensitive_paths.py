"""v1.7 W2 wire-up. Blocks well-known scanner probe paths.

Three buckets, almost never legitimate on a typical app:
    1. Dotfile / VCS leaks   /.env, /.git/*, /.svn/*, /.aws/, ...
    2. PHP/Wordpress probes  /wp-admin, /wp-login.php, /phpmyadmin, ...
    3. Diagnostic endpoints  /server-status, /phpinfo.php, /info.php, ...

Apps with legitimate overlapping routes (actual WordPress site, custom
/admin panel) opt out via Arcis(scanner_paths=False) / Arcis class +
ArcisMiddleware(scanner_paths=False).
"""

from __future__ import annotations

import re
from typing import List, Optional


SENSITIVE_PATH_PATTERNS: List[re.Pattern] = [
    # Dotfile / VCS leaks — should never be served on any app.
    re.compile(r"^/\.env(\.|/|$)", re.IGNORECASE),
    re.compile(r"^/\.git(/|$)", re.IGNORECASE),
    re.compile(r"^/\.svn(/|$)", re.IGNORECASE),
    re.compile(r"^/\.hg(/|$)", re.IGNORECASE),
    re.compile(r"^/\.bzr(/|$)", re.IGNORECASE),
    re.compile(r"^/\.aws(/|$)", re.IGNORECASE),
    re.compile(r"^/\.ssh(/|$)", re.IGNORECASE),
    re.compile(r"^/\.htaccess$", re.IGNORECASE),
    re.compile(r"^/\.htpasswd$", re.IGNORECASE),
    re.compile(r"^/\.npmrc$", re.IGNORECASE),
    re.compile(r"^/\.dockerenv$", re.IGNORECASE),

    # WordPress + PHP probes.
    re.compile(r"^/wp-admin(/|$)", re.IGNORECASE),
    re.compile(r"^/wp-login\.php$", re.IGNORECASE),
    re.compile(r"^/wp-config\.php$", re.IGNORECASE),
    re.compile(r"^/wordpress/wp-(admin|login)", re.IGNORECASE),
    re.compile(r"^/xmlrpc\.php$", re.IGNORECASE),

    # Generic admin / DB-admin probes.
    re.compile(r"^/admin/?$", re.IGNORECASE),
    re.compile(r"^/administrator/?$", re.IGNORECASE),
    re.compile(r"^/admin\.php$", re.IGNORECASE),
    re.compile(r"^/phpmyadmin(/|$)", re.IGNORECASE),
    re.compile(r"^/pma(/|$)", re.IGNORECASE),
    re.compile(r"^/myadmin(/|$)", re.IGNORECASE),
    re.compile(r"^/dbadmin(/|$)", re.IGNORECASE),
    re.compile(r"^/adminer\.php$", re.IGNORECASE),

    # Diagnostic / info-leak endpoints.
    re.compile(r"^/phpinfo\.php$", re.IGNORECASE),
    re.compile(r"^/info\.php$", re.IGNORECASE),
    re.compile(r"^/test\.php$", re.IGNORECASE),
    re.compile(r"^/shell\.php$", re.IGNORECASE),
    re.compile(r"^/server-status$", re.IGNORECASE),
    re.compile(r"^/server-info$", re.IGNORECASE),

    # Backup / dump leaks.
    re.compile(r"^/backup(\.|/)", re.IGNORECASE),
    re.compile(r"^/dump\.sql$", re.IGNORECASE),
    re.compile(r"^/database\.sql$", re.IGNORECASE),
]


def detect_sensitive_path(
    path: str,
    patterns: Optional[List[re.Pattern]] = None,
) -> Optional[str]:
    """Test a URL path against the sensitive-path list.

    Returns the first matching pattern's source string for logging /
    telemetry, or None if no match.
    """
    pats = patterns if patterns is not None else SENSITIVE_PATH_PATTERNS
    for pat in pats:
        if pat.search(path):
            return pat.pattern
    return None
