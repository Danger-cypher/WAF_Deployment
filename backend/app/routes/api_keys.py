"""
CyberSentinel WAF - API Key Management Routes (P1-9)
Admin-only CRUD for machine credentials used to call the REST API without
an interactive session login. See app/services/api_key_service.py and
auth.py's get_current_user()/_resolve_api_key() for how a key is actually
authenticated on subsequent requests.
"""
import logging
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.services.api_key_service import api_key_service
from app.services.auth import require_admin, TokenData
from app.utils.audit import log_admin_action

logger = logging.getLogger(__name__)
router = APIRouter()


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    role: Literal["admin", "analyst"]
    # None = never expires. Capped at 10 years rather than left unbounded,
    # same reasoning as any other admin-facing numeric field: a typo
    # shouldn't be able to create a key with an absurd/unintended lifetime.
    expires_in_days: Optional[int] = Field(default=None, gt=0, le=3650)


class ApiKeyOut(BaseModel):
    id: int
    name: str
    key_prefix: str
    role: str
    enabled: bool
    created_by: Optional[str] = None
    created_at: Optional[str] = None
    expires_at: Optional[str] = None
    last_used_at: Optional[str] = None
    last_used_ip: Optional[str] = None


class ApiKeyCreateResponse(ApiKeyOut):
    # Shown exactly once — api_key_service never stores or returns this
    # again after this response (same "reveal once" pattern as MFA setup's
    # TOTP secret).
    api_key: str


@router.get("/api-keys", response_model=List[ApiKeyOut])
async def list_api_keys(current_user: TokenData = Depends(require_admin)):
    """List all API keys (Admin only). Never includes the raw secret."""
    return api_key_service.list_keys()


@router.post("/api-keys", response_model=ApiKeyCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(payload: ApiKeyCreate, current_user: TokenData = Depends(require_admin)):
    """Create a new API key (Admin only). The raw key is returned exactly
    once in this response — copy it now, it cannot be retrieved again."""
    record, raw_key = api_key_service.create_key(
        name=payload.name,
        role=payload.role,
        created_by=current_user.username,
        expires_in_days=payload.expires_in_days,
    )
    log_admin_action(
        "api_key", str(record["id"]), "create", current_user,
        details={"name": payload.name, "role": payload.role, "expires_in_days": payload.expires_in_days},
    )
    return {**record, "api_key": raw_key}


@router.post("/api-keys/{key_id}/revoke", response_model=ApiKeyOut)
async def revoke_api_key(key_id: int, current_user: TokenData = Depends(require_admin)):
    """Revoke an API key (Admin only). Takes effect immediately — the next
    request made with this key gets a 401, same as a disabled user account
    getting rejected on its next request rather than waiting out a TTL."""
    existing = api_key_service.get_by_id(key_id)
    if existing is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found.")

    api_key_service.revoke_key(key_id)
    log_admin_action("api_key", str(key_id), "revoke", current_user, details={"name": existing["name"]})
    return api_key_service.get_by_id(key_id)
