from fastapi import Request, HTTPException, status, Depends
import secrets

def verify_csrf_token(request: Request):
    """
    Dependency to verify the Double Submit Cookie CSRF token pattern.
    Requires that the XSRF-TOKEN-V3 cookie matches the X-XSRF-TOKEN header
    for state-changing methods (POST, PUT, DELETE, PATCH).
    """
    if request.method in ("GET", "HEAD", "OPTIONS", "TRACE"):
        return True

    # CSRF exists to stop a browser's *ambient* session cookie being
    # weaponized by a third-party page (the classic drive-by POST) — the
    # attack only works because the browser attaches waf_session_v3
    # automatically. A request with no session cookie isn't relying on any
    # ambient credential a malicious page could piggyback on: it's using
    # an Authorization: Bearer token or an X-API-Key header instead,
    # neither of which a cross-site page can attach to a request without
    # explicit CORS permission. So there's nothing here for CSRF to
    # protect against (P1-9 API keys rely on this to work at all, since a
    # non-browser script has no CSRF cookie/header pair to send) — the
    # request's own auth dependency still runs and rejects it if the
    # token/key itself is missing or invalid.
    if not request.cookies.get("waf_session_v3"):
        return True

    # 1. Read token from Http cookie
    csrf_cookie = request.cookies.get("XSRF-TOKEN-V3")
    csrf_header = request.headers.get("X-XSRF-TOKEN")
    
    if not csrf_cookie or not csrf_header:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing CSRF token in cookie or header"
        )
        
    # Constant-time comparison to prevent timing attacks
    if not secrets.compare_digest(csrf_cookie, csrf_header):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token mismatch"
        )
        
    return True
