"""
safe_error.py — CyberSentinel WAF
===================================
Helpers for returning safe, non-verbose error messages to API clients while
still logging the full exception details server-side.

Problem (MEDIUM-2 / CWE-209): several route handlers used
    raise HTTPException(status_code=500, detail=f"Failed to do X: {str(e)}")
which leaks internal details (file paths, DB hostnames, stack frames) directly
to the client. A bug bounty hunter would file this as an info-disclosure finding
on any platform.

Usage:
    from app.utils.safe_error import safe_http_error

    try:
        ...
    except Exception as e:
        raise safe_http_error(500, "Failed to fetch rules", e)

The client sees:  {"detail": "Failed to fetch rules"}
The server logs:  ERROR Failed to fetch rules: <full exception + traceback>
"""

import logging
from fastapi import HTTPException

logger = logging.getLogger(__name__)


def safe_http_error(
    status_code: int,
    public_message: str,
    exc: Exception | None = None,
    *,
    log_level: str = "error",
) -> HTTPException:
    """
    Build an HTTPException whose `detail` is safe to return to the client,
    while logging the full exception (with traceback) server-side.

    Args:
        status_code:    HTTP status code (e.g. 500, 400).
        public_message: Generic message sent to the client.
        exc:            The caught exception (used only for server-side logging).
        log_level:      Log level for the server-side entry ("error", "warning").

    Returns:
        An HTTPException ready to be raised by the caller.

    Example:
        try:
            ...
        except Exception as e:
            raise safe_http_error(500, "Rule update failed", e)
    """
    if exc is not None:
        log_fn = getattr(logger, log_level, logger.error)
        log_fn("%s: %s", public_message, exc, exc_info=True)
    return HTTPException(status_code=status_code, detail=public_message)


def safe_api_error(public_message: str, exc: Exception | None = None, *, log_level: str = "error") -> str:
    """
    String-returning variant of safe_http_error for call sites that build the
    HTTPException themselves: logs the full exception server-side and returns
    only the generic message for use as `detail=`.
    """
    if exc is not None:
        log_fn = getattr(logger, log_level, logger.error)
        log_fn("%s: %s", public_message, exc, exc_info=True)
    return public_message
