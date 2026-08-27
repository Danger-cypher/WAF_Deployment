"""
CyberSentinel WAF - SIEM SSO exchange endpoint.

Receiving side of the SIEM's mint-and-redirect SSO flow: the frontend's
/auth/sso landing page reads the JWT out of the URL fragment (never sent
to any server — see the frontend component) and POSTs it here. We verify
it (services/sso.py), JIT-provision or update the local account, and drop
the analyst straight into a normal session — no separate password, no
MFA prompt, since the SIEM has already authenticated them.
"""
import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel

from app.routes.auth import _issue_session
from app.services.sso import SsoTokenError, generate_sso_username, map_siem_role, verify_sso_exchange_token
from app.services.user_service import user_service
from app.utils.rate_limiter import rate_limiter
from app.utils.security import get_client_ip, security_audit_logger

logger = logging.getLogger(__name__)
router = APIRouter()


class SsoExchangeRequest(BaseModel):
    token: str


class SsoExchangeResponse(BaseModel):
    message: str
    role: Optional[str] = None


@router.post("/sso/exchange", response_model=SsoExchangeResponse)
async def sso_exchange(payload: SsoExchangeRequest, request: Request, response: Response):
    client_ip = get_client_ip(request)

    # Defense in depth: the token itself is short-lived and signed, so
    # brute-forcing it isn't realistic, but this still caps how hard the
    # endpoint (JWT verify + JIT DB writes) can be hammered from one IP.
    is_allowed, rate_info = rate_limiter.check_rate_limit(client_ip)
    if not is_allowed:
        security_audit_logger.log_rate_limit_trigger(
            client_ip=client_ip,
            endpoint="/auth/sso/exchange",
            attempts=rate_info.get("max_requests", 10),
            block_duration=rate_info.get("retry_after", 60),
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=rate_info.get("block_reason", "Too many attempts"),
        )

    try:
        # verify_sso_exchange_token is synchronous, and for an RS256 token
        # it does a blocking network fetch to the SIEM's JWKS endpoint
        # (services/sso.py — PyJWKClient uses urllib, not an async client).
        # This backend runs as a single uvicorn worker/event loop (no
        # --workers flag), so calling it directly here would stall every
        # other request — including unrelated ones — for up to the JWKS
        # client's 5s timeout on every exchange attempt. Worse, this
        # endpoint is unauthenticated by design, so that would be a live
        # DoS vector: anyone could freeze the whole backend by POSTing a
        # garbage RS256-header token repeatedly. Run it off the event loop.
        claims = await asyncio.to_thread(verify_sso_exchange_token, payload.token)
    except SsoTokenError as e:
        logger.warning(f"Rejected SSO exchange token from {client_ip}: {e}")
        security_audit_logger.log_auth_attempt(
            client_ip=client_ip, username="(sso)", success=False,
            details={"reason": "sso_token_invalid"},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired SSO token")

    sub = claims["sub"]
    email = claims.get("email")
    name = claims.get("name")

    user = user_service.get_by_sso_subject(sub)

    if user is None:
        # One-time adoption path for a pre-existing local account that
        # matches on email and has never been linked to an SSO subject —
        # covers migrating accounts created before SSO existed.
        candidate = user_service.get_by_email_unlinked(email) if email else None
        if candidate:
            user_service.adopt_sso_subject(candidate["id"], sub)
            user = user_service.get_by_id(candidate["id"])
        else:
            mapped_role = map_siem_role(claims)
            username = generate_sso_username(claims, user_service.username_exists)
            new_id = user_service.create_sso_user(
                username=username,
                sub=sub,
                role=mapped_role,
                display_name=name or None,
                email=email or None,
            )
            user = user_service.get_by_id(new_id)
            logger.info(f"JIT-provisioned SSO account '{username}' (role={mapped_role}) for sub={sub}")
    else:
        # SIEM is authoritative for role on every login — but only write
        # (and bump session_version, which invalidates this user's other
        # active sessions) when it actually changed.
        mapped_role = map_siem_role(claims)
        if mapped_role != user["role"]:
            user_service.update_user(user["id"], role=mapped_role)
            user = user_service.get_by_id(user["id"])

        profile_changed = (email and email != user.get("email")) or (name and name != user.get("display_name"))
        if profile_changed:
            user_service.update_user(
                user["id"],
                display_name=name or user.get("display_name"),
                email=email or user.get("email"),
            )
            user = user_service.get_by_id(user["id"])

    if not user["enabled"]:
        security_audit_logger.log_auth_attempt(
            client_ip=client_ip, username=user["username"], success=False,
            details={"reason": "Account disabled", "sso": True},
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")

    rate_limiter.record_success(client_ip)
    user_service.update_last_login(user["id"])
    security_audit_logger.log_auth_attempt(
        client_ip=client_ip, username=user["username"], success=True,
        details={"role": user["role"], "sso": True, "siem_sub": sub},
    )

    # SIEM already authenticated this analyst — go straight to a real
    # session, bypassing any locally-configured MFA the account may have.
    session = _issue_session(request, response, user)
    return SsoExchangeResponse(message=session.message, role=session.role)
