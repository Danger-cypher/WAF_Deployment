from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
import secrets
import logging
from app.services.auth import verify_password, create_access_token, get_current_user, TokenData
from app.services.settings_manager import settings_manager
from app.config.settings import settings
from app.utils.csrf import verify_csrf_token
from app.utils.rate_limiter import rate_limiter
from app.utils.security import security_audit_logger, get_client_ip

logger = logging.getLogger(__name__)
router = APIRouter()

class LoginResponse(BaseModel):
    message: str
    role: str

@router.post("/login", response_model=LoginResponse)
async def login_for_access_token(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends()
):
    username = form_data.username
    password = form_data.password

    # Get client IP (handle reverse proxy headers)
    client_ip = get_client_ip(request)
    
    # 1. Rate limit check
    is_allowed, rate_info = rate_limiter.check_rate_limit(client_ip)
    
    if not is_allowed:
        logger.warning(
            f"Rate limited login attempt from {client_ip} - "
            f"reason: {rate_info.get('block_reason', 'Unknown')}"
        )
        
        # Log rate limit trigger
        security_audit_logger.log_rate_limit_trigger(
            client_ip=client_ip,
            endpoint="/auth/login",
            attempts=rate_info.get("max_requests", 10),
            block_duration=rate_info.get("retry_after", 60)
        )
        
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=rate_info.get("block_reason", "Too many login attempts")
        )
    
    # 2. Validate credentials
    if username == "admin":
        current_hash = settings_manager.get_password_hash()
        role = "admin"
    elif username == "analyst":
        current_hash = settings_manager.get_analyst_password_hash()
        role = "analyst"
    else:
        # Record failed attempt
        security_audit_logger.log_auth_attempt(
            client_ip=client_ip,
            username=username,
            success=False,
            details={"reason": "Invalid username"}
        )
        rate_limiter.record_success(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )

    if not verify_password(password, current_hash):
        # Log failed authentication
        security_audit_logger.log_auth_attempt(
            client_ip=client_ip,
            username=username,
            success=False,
            details={"reason": "Invalid password"}
        )
        rate_limiter.record_success(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )

    # 3. Successful authentication
    rate_limiter.record_success(client_ip)
    security_audit_logger.log_auth_attempt(
        client_ip=client_ip,
        username=username,
        success=True,
        details={"role": role}
    )

    # 4. Generate JWT for the session
    access_token = create_access_token(data={"sub": username, "role": role})
    
    # 5. Generate a fresh CSRF token
    csrf_token = secrets.token_urlsafe(32)

    # Determine if the connection is HTTPS
    is_secure = request.headers.get("x-forwarded-proto", request.url.scheme) == "https"

    # Set JWT in an HttpOnly, Secure, SameSite=Strict cookie (prevents XSS theft)
    response.set_cookie(
        key="waf_session_v3",
        value=access_token,
        httponly=True,
        secure=is_secure, 
        samesite="strict",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
    
    # Set CSRF Token in a non-HttpOnly cookie (so JS can read it for the header)
    response.set_cookie(
        key="XSRF-TOKEN-V3",
        value=csrf_token,
        httponly=False,
        secure=is_secure,
        samesite="strict",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

    return {"message": "Login successful", "role": role}

@router.post("/logout", dependencies=[Depends(verify_csrf_token)])
async def logout(request: Request, response: Response):
    is_secure = request.headers.get("x-forwarded-proto", request.url.scheme) == "https"
    response.delete_cookie(key="waf_session_v3", secure=is_secure, samesite="strict")
    response.delete_cookie(key="XSRF-TOKEN-V3", secure=is_secure, samesite="strict")
    return {"message": "Logged out successfully"}

@router.get("/me", response_model=TokenData)
async def get_current_user_profile(current_user: TokenData = Depends(get_current_user)):
    return current_user
