from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
import bcrypt
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

from app.config.settings import settings

# Password hashing is done directly with bcrypt
# OAuth2 scheme for dependency (kept for Swagger UI docs)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)


class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None
    # Set only when this request was authenticated via an API key (P1-9)
    # rather than a session cookie/Bearer JWT — additive fields, so every
    # existing call site that only reads username/role is unaffected.
    auth_method: Optional[str] = None
    api_key_id: Optional[int] = None
    # The session id ("sid") claim from a session JWT (P1-8 Part B) — None
    # for API-key auth, and also None for a session token minted before
    # this feature shipped (nothing to revoke individually for those).
    session_id: Optional[str] = None


def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), hashed_password.encode("utf-8")
    )


def get_password_hash(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt


def decode_token(token: Optional[str]) -> Optional[TokenData]:
    """Validate a raw JWT and return its TokenData, or None if invalid,
    expired, or the account no longer exists / is disabled. Shared by the
    HTTP dependency below and the WebSocket handshake (which has no
    Request object to hang a FastAPI Depends() off of)."""
    if not token:
        return None

    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        username: str = payload.get("sub")
        role: str = payload.get("role")
        token_version = payload.get("tv")
        session_id: Optional[str] = payload.get("sid")
        if username is None or role is None:
            return None
        token_data = TokenData(username=username, role=role, session_id=session_id)
    except jwt.PyJWTError:
        return None

    # Verify the account still exists, hasn't been disabled, and its
    # session_version still matches what was current when the token was
    # issued (role changes, enable/disable, and password changes/resets
    # all bump it). This makes those changes take effect immediately
    # instead of waiting out the token's remaining lifetime.
    from app.services.user_service import user_service

    user = user_service.get_by_username(token_data.username)
    if user is None or not user["enabled"] or user["session_version"] != token_version:
        return None

    # Source the role from the live DB record rather than the (now
    # revalidated, but still originally client-held) JWT claim.
    token_data.role = user["role"]

    # Fine-grained per-session revoke (P1-8 Part B), layered ON TOP of the
    # coarse session_version check above — a token must pass both. Only
    # applies when the token actually carries a "sid" (a session minted
    # before this feature existed has none, and skips this check entirely
    # until it naturally expires — zero-disruption rollout). Runs for both
    # the HTTP path (get_current_user() below) and the WebSocket handshake
    # (routes/ws.py calls decode_token() directly), so both benefit from
    # one implementation.
    if token_data.session_id:
        from app.services.session_service import is_session_active

        if not is_session_active(token_data.username, token_data.session_id):
            return None

    return token_data


def _resolve_api_key(raw_key: str, request: Request) -> Optional[TokenData]:
    """Resolves an X-API-Key header into a TokenData exactly like a session
    cookie/Bearer JWT resolves into one, so require_admin/require_any_role/
    require_app_*_access and every route reading current_user.username or
    .role keep working unmodified for a key-authenticated caller (P1-9)."""
    from app.services.api_key_service import api_key_service
    from app.utils.security import get_client_ip

    record = api_key_service.validate_key(raw_key, client_ip=get_client_ip(request))
    if record is None:
        return None
    return TokenData(
        username=f"apikey:{record['name']}",
        role=record["role"],
        auth_method="api_key",
        api_key_id=record["id"],
    )


async def get_current_user(request: Request) -> TokenData:
    # 1. Try to get token from HttpOnly cookie
    token = request.cookies.get("waf_session_v3")

    # 2. Fallback to Authorization header (for backward compatibility / Swagger UI)
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

    token_data = decode_token(token)

    # 3. Fallback to an API key (P1-9) — a machine credential, independent
    # of any human account's session/password lifecycle. Only consulted
    # when there was no valid session cookie/Bearer JWT, so this adds no
    # extra DB lookup to normal browser traffic.
    if token_data is None:
        api_key = request.headers.get("X-API-Key")
        if api_key:
            token_data = _resolve_api_key(api_key, request)

    if token_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

    return token_data


def require_admin(current_user: TokenData = Depends(get_current_user)) -> TokenData:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Admin role required.",
        )
    return current_user


def require_any_role(current_user: TokenData = Depends(get_current_user)) -> TokenData:
    return current_user


def _has_app_access(current_user: TokenData, app_id: int, allow_analyst: bool) -> bool:
    if current_user.role == "admin":
        return True
    if allow_analyst and current_user.role == "analyst":
        return True
    if current_user.role == "app_admin":
        from app.services import db_service

        return db_service.user_has_app_access(current_user.username, app_id)
    return False


def require_app_view_access(app_id: int, current_user: TokenData = Depends(get_current_user)) -> TokenData:
    """
    Gate for routes/apps.py's per-app_id READ route (GET /apps/{app_id}),
    RBAC item 7. FastAPI resolves `app_id` from the route's own {app_id}
    path segment by name, same as the route handler's own parameter.
    'admin' and 'analyst' behave exactly as before this feature existed
    (unrestricted view); only the new 'app_admin' role is actually scoped.
    """
    if _has_app_access(current_user, app_id, allow_analyst=True):
        return current_user
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Access denied: you are not scoped to this protected application.",
    )


def require_app_write_access(app_id: int, current_user: TokenData = Depends(get_current_user)) -> TokenData:
    """
    Gate for routes/apps.py's per-app_id WRITE routes (update/delete/toggle/
    ssl), RBAC item 7. 'analyst' is rejected here exactly as it always has
    been (these routes were require_admin-only before this feature
    existed) — only 'admin' (full access) or a scoped 'app_admin' pass.
    """
    if _has_app_access(current_user, app_id, allow_analyst=False):
        return current_user
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Access denied: you are not scoped to this protected application.",
    )
