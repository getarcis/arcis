"""
Arcis Middleware — HTTP Parameter Pollution (HPP) Protection

Normalizes duplicate query/form parameters to their last value,
preventing attackers from bypassing validation by repeating parameters.

Attack:
    GET /search?role=user&role=admin
    Without HPP: request.args.getlist('role') = ['user', 'admin']
    With HPP:    request.args['role'] = 'admin'  (last wins)

Originals are preserved in g.query_polluted / g.form_polluted
for logging or auditing without blocking the request.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple


def _normalize_multidict(
    params: Dict[str, List[str]],
    whitelist: Set[str],
) -> Tuple[Dict[str, str], Dict[str, List[str]]]:
    """
    Normalize a key → [values] mapping into key → last_value.

    Returns:
        (clean, polluted) where polluted contains only the duplicated keys.
    """
    clean: Dict[str, object] = {}
    polluted: Dict[str, List[str]] = {}

    for key, values in params.items():
        if len(values) > 1:
            if key in whitelist:
                # Whitelisted — keep as list
                clean[key] = values
            else:
                # Duplicate — record originals, use last value
                polluted[key] = values
                clean[key] = values[-1]
        else:
            clean[key] = values[0] if values else ""

    return clean, polluted  # type: ignore[return-value]


class HppProtection:
    """
    HTTP Parameter Pollution protection.

    Example (Flask):
        hpp = HppProtection()

        @app.before_request
        def check_hpp():
            hpp.flask_before_request()

        # In routes — use g.query instead of request.args:
        from flask import g
        role = g.query.get('role')        # normalized single value
        dupes = g.query_polluted.get('role')  # original list if duplicated

    Example (generic normalization):
        clean, polluted = hpp.normalize({'role': ['user', 'admin']})
        # clean   = {'role': 'admin'}
        # polluted = {'role': ['user', 'admin']}
    """

    def __init__(
        self,
        whitelist: Optional[List[str]] = None,
        check_query: bool = True,
        check_body: bool = True,
        on_pollution: Optional[Callable[[Dict[str, List[str]]], None]] = None,
    ) -> None:
        self.whitelist: Set[str] = set(whitelist or [])
        self.check_query = check_query
        self.check_body = check_body
        # Optional callback fired when pollution is detected — useful for logging/alerting
        self.on_pollution = on_pollution

    def normalize(
        self,
        params: Dict[str, List[str]],
    ) -> Tuple[Dict[str, str], Dict[str, List[str]]]:
        """
        Normalize a multi-value parameter dict.

        Args:
            params: Dict of key → list of values (e.g., from request.args.lists())

        Returns:
            (clean, polluted) — clean has single values, polluted has the originals
        """
        return _normalize_multidict(params, self.whitelist)

    # ── Flask ──────────────────────────────────────────────────────────────

    def flask_before_request(self) -> None:
        """
        Flask before_request hook. Attaches normalized params to Flask g.

        Sets:
            g.query          — normalized query dict (use instead of request.args)
            g.query_polluted — dict of params that had duplicates (original lists)
            g.form           — normalized form dict (use instead of request.form)
            g.form_polluted  — dict of form params that had duplicates

        Example:
            @app.before_request
            def protect():
                hpp.flask_before_request()
        """
        from flask import g, request  # type: ignore[import]

        if self.check_query:
            raw = dict(request.args.lists())
            clean, polluted = _normalize_multidict(raw, self.whitelist)
            g.query = clean
            g.query_polluted = polluted
            if polluted and self.on_pollution:
                self.on_pollution(polluted)

        if self.check_body and request.method in ("POST", "PUT", "PATCH"):
            content_type = request.content_type or ""
            if "application/json" not in content_type:
                raw_form = dict(request.form.lists())
                clean_form, polluted_form = _normalize_multidict(raw_form, self.whitelist)
                g.form = clean_form
                g.form_polluted = polluted_form
                if polluted_form and self.on_pollution:
                    self.on_pollution(polluted_form)


def create_hpp(
    whitelist: Optional[List[str]] = None,
    check_query: bool = True,
    check_body: bool = True,
    on_pollution: Optional[Callable[[Dict[str, List[str]]], None]] = None,
) -> HppProtection:
    """
    Create an HPP protection instance.

    Args:
        whitelist:    Parameters that legitimately accept arrays (e.g., ['tags', 'ids'])
        check_query:  Normalize query string params. Default: True
        check_body:   Normalize form body params. Default: True
        on_pollution: Optional callback fired with polluted params dict when
                      duplicates are detected — useful for logging/alerting.

    Returns:
        HppProtection instance

    Example:
        hpp = create_hpp(whitelist=['tags', 'ids'])

        @app.before_request
        def protect():
            hpp.flask_before_request()
    """
    return HppProtection(
        whitelist=whitelist,
        check_query=check_query,
        check_body=check_body,
        on_pollution=on_pollution,
    )
