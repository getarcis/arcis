"""
Arcis Utilities - Request helpers

Shared helpers for extracting data from framework-agnostic request objects.
"""

from typing import Optional


def get_request_header(request, name: str, default: Optional[str] = None) -> Optional[str]:
    """
    Get a header value from various request types (Flask, Django, FastAPI).

    Args:
        request: HTTP request object.
        name: Header name (e.g. 'x-forwarded-for').
        default: Default value if header not found.

    Returns:
        Header value, or default if not found.
    """
    # Django — headers in META with HTTP_ prefix
    if hasattr(request, 'META'):
        meta_key = 'HTTP_' + name.upper().replace('-', '_')
        return request.META.get(meta_key, default)

    # Flask / FastAPI / Starlette — headers dict
    if hasattr(request, 'headers') and hasattr(request.headers, 'get'):
        return request.headers.get(name, default)

    return default
