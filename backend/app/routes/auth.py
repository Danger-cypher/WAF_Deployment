from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional
from datetime import timedelta
import secrets
import logging
import jwt
import pyotp
from app.services.auth import verify_password, create_access_token, decode_token, get_current_user, TokenData
from app.services.user_service import user_service
from app.services.settings_manager import settings_manager
from app.services import session_service
from app.models.user_models import MfaLoginRequest
from app.config.settings import settings
from app.utils.csrf import verify_csrf_token
from app.utils.rate_limiter import rate_limiter
from app.utils.security import security_audit_logger, get_client_ip, is_ip_in_networks

logger = logging.getLogger(__name__)
router = APIRouter()

MFA_PENDING_COOKIE = "waf_mfa_pending_v1"
MFA_PENDING_MINUTES = 5

class LoginResponse(BaseModel):
    message: str
    role: Optional[str] = None
    mfa_required: bool = False


def _enforce_login_ip_allowlist(client_ip: str, endpoint: str) -> None:
    """Rejects the request before any rate-limit accounting or username
    lookup if an admin-login IP allowlist is configured and enabled
    (P1-8 Part A). Applies to every dashboard account (admin/analyst/
    app_admin) uniformly rather than being conditioned on the
    authenticating user's role — that would require looking the user up
    first, and a role-dependent response would leak whether a given
    username exists via a differently-shaped error. No-op when disabled
    (the default), so this can never lock anyone out on a fresh install."""
    allowlist = settings_manager.get_admin_login_allowlist()
    if not allowlist.get("enabled", False):
        return
    if not is_ip_in_networks(client_ip, allowlist.get("allowed_networks", [])):
        security_audit_logger.log_ip_blocked_login(client_ip=client_ip, endpoint=endpoint)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access to the dashboard is not permitted from this network.",
        )


def _issue_session(request: Request, response: Response, user: dict) -> LoginResponse:
    """Completes authentication: issues the real session + CSRF cookies.
    Shared by the no-MFA login path and the MFA-verification endpoint."""
    role = user["role"]

    # Mint a per-session id (P1-8 Part B) so this specific session can be
    # revoked individually later without touching any of this account's
    # other sessions. Only added to the JWT if Redis actually accepted the
    # record — a sid with no backing record would make is_session_active()
    # reject this brand-new session immediately, exactly backwards for a
    # fail-open feature. Redis being unavailable here just means this one
    # session isn't individually revocable until Redis is back; login
    # itself is never blocked by it.
    ttl_seconds = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    sid = session_service.create_session(
        user["username"], get_client_ip(request), request.headers.get("user-agent", ""), ttl_seconds
    )
    token_claims = {"sub": user["username"], "role": role, "tv": user["session_version"]}
    if sid:
        token_claims["sid"] = sid
    access_token = create_access_token(data=token_claims)
    csrf_token = secrets.token_urlsafe(32)
    is_secure = request.headers.get("x-forwarded-proto", request.url.scheme) == "https"

    response.set_cookie(
        key="waf_session_v3",
        value=access_token,
        httponly=True,
        secure=is_secure,
        samesite="lax",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
    response.set_cookie(
        key="XSRF-TOKEN-V3",
        value=csrf_token,
        httponly=False,
        secure=is_secure,
        samesite="lax",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
    # Clear any leftover MFA-pending cookie now that the real session is live.
    response.delete_cookie(key=MFA_PENDING_COOKIE, secure=is_secure, samesite="lax")

    return LoginResponse(message="Login successful", role=role)


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

    # 0. Admin-login IP allowlist — checked first, before rate-limit
    # accounting or any username lookup (see docstring on the helper).
    _enforce_login_ip_allowlist(client_ip, "/auth/login")

    # 1. Rate limit check — both per-IP AND per-username. Per-IP alone lets a
    # distributed attacker (many source IPs) brute-force one specific
    # account at unlimited aggregate rate, since no single IP ever crosses
    # its own threshold. The username key is normalized/prefixed so it can
    # never collide with a real IP address in the same Redis/fallback
    # keyspace.
    username_key = f"user:{username.strip().lower()}"
    is_allowed, rate_info = rate_limiter.check_rate_limit(client_ip)
    if is_allowed:
        is_allowed, rate_info = rate_limiter.check_rate_limit(username_key)

    if not is_allowed:
        logger.warning(
            f"Rate limited login attempt for user='{username}' from {client_ip} - "
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

    # 2. Validate credentials against the users store (admin/analyst plus
    # any accounts created from Admin > Users)
    user = user_service.get_by_username(username)
    if user is None or not user["enabled"]:
        # Record failed attempt
        security_audit_logger.log_auth_attempt(
            client_ip=client_ip,
            username=username,
            success=False,
            details={"reason": "Invalid username" if user is None else "Account disabled"}
        )
        # NOTE: do NOT call record_success() here - it deletes the escalating
        # block counter that check_rate_limit()/_increment_failure() set for
        # this IP, which would let an attacker reset their own lockout by
        # simply failing again. Failure accounting for the sliding window is
        # already handled inside check_rate_limit() on every request.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )

    if not verify_password(password, user["password_hash"]):
        # Log failed authentication
        security_audit_logger.log_auth_attempt(
            client_ip=client_ip,
            username=username,
            success=False,
            details={"reason": "Invalid password"}
        )
        # See note above: must not reset the rate-limit block state on failure.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )

    # 3. Password verified.
    rate_limiter.record_success(client_ip)
    rate_limiter.record_success(username_key)

    if user["mfa_enabled"]:
        # Don't issue a full session yet — only a short-lived pending token
        # that /auth/login/mfa can redeem with a valid TOTP code. It carries
        # no "role" claim, so decode_token()/get_current_user() will never
        # accept it for any other endpoint.
        security_audit_logger.log_auth_attempt(
            client_ip=client_ip, username=username, success=True,
            details={"role": user["role"], "mfa_pending": True}
        )
        pending_token = create_access_token(
            data={"sub": username, "mfa_pending": True},
            expires_delta=timedelta(minutes=MFA_PENDING_MINUTES),
        )
        is_secure = request.headers.get("x-forwarded-proto", request.url.scheme) == "https"
        response.set_cookie(
            key=MFA_PENDING_COOKIE,
            value=pending_token,
            httponly=True,
            secure=is_secure,
            samesite="lax",
            max_age=MFA_PENDING_MINUTES * 60,
        )
        return LoginResponse(message="MFA code required", mfa_required=True)

    # 4. No MFA — log in immediately.
    user_service.update_last_login(user["id"])
    security_audit_logger.log_auth_attempt(
        client_ip=client_ip, username=username, success=True, details={"role": user["role"]}
    )
    return _issue_session(request, response, user)


@router.post("/login/mfa", response_model=LoginResponse)
async def verify_mfa_and_login(
    payload: MfaLoginRequest,
    request: Request,
    response: Response,
):
    client_ip = get_client_ip(request)

    # Defense in depth: a request could reach this endpoint directly with a
    # still-valid MFA-pending cookie even if the initial /auth/login call
    # that issued it came from a network that would now be blocked (e.g.
    # the allowlist was tightened in between) — re-check here too.
    _enforce_login_ip_allowlist(client_ip, "/auth/login/mfa")

    is_allowed, rate_info = rate_limiter.check_rate_limit(client_ip)
    if not is_allowed:
        security_audit_logger.log_rate_limit_trigger(
            client_ip=client_ip,
            endpoint="/auth/login/mfa",
            attempts=rate_info.get("max_requests", 10),
            block_duration=rate_info.get("retry_after", 60)
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=rate_info.get("block_reason", "Too many attempts")
        )

    pending_token = request.cookies.get(MFA_PENDING_COOKIE)
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="MFA session expired or invalid. Please log in again.",
    )
    if not pending_token:
        raise credentials_exception

    try:
        claims = jwt.decode(pending_token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except jwt.PyJWTError:
        raise credentials_exception
    if not claims.get("mfa_pending") or not claims.get("sub"):
        raise credentials_exception

    username = claims["sub"]
    user = user_service.get_by_username(username)
    if user is None or not user["enabled"] or not user["mfa_enabled"] or not user["mfa_secret"]:
        raise credentials_exception

    totp = pyotp.TOTP(user["mfa_secret"])
    if not totp.verify(payload.code, valid_window=1):
        security_audit_logger.log_auth_attempt(
            client_ip=client_ip, username=username, success=False,
            details={"reason": "Invalid MFA code"}
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code")

    rate_limiter.record_success(client_ip)
    user_service.update_last_login(user["id"])
    security_audit_logger.log_auth_attempt(
        client_ip=client_ip, username=username, success=True,
        details={"role": user["role"], "mfa_verified": True}
    )
    return _issue_session(request, response, user)


@router.post("/logout", dependencies=[Depends(verify_csrf_token)])
async def logout(request: Request, response: Response):
    is_secure = request.headers.get("x-forwarded-proto", request.url.scheme) == "https"

    # Best-effort server-side revocation of this specific session (P1-8
    # Part B) — previously /logout only cleared cookies client-side,
    # leaving the JWT itself (e.g. a copy captured via XSS, or manually
    # saved) fully valid until its natural expiry. Never blocks the
    # response: an already-expired/undecodable token just means there's
    # nothing to revoke, same lenient behavior logout has always had.
    try:
        token_data = decode_token(request.cookies.get("waf_session_v3"))
        if token_data and token_data.session_id:
            session_service.revoke_session(token_data.username, token_data.session_id)
    except Exception as e:
        logger.warning(f"Failed to revoke session during logout: {e}")

    response.delete_cookie(key="waf_session_v3", secure=is_secure, samesite="lax")
    response.delete_cookie(key="XSRF-TOKEN-V3", secure=is_secure, samesite="lax")
    return {"message": "Logged out successfully"}

@router.get("/me", response_model=TokenData)
async def get_current_user_profile(current_user: TokenData = Depends(get_current_user)):
    return current_user
