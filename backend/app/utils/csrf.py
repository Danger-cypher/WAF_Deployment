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
