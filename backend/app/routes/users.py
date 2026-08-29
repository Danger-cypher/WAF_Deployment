"""
CyberSentinel WAF - User Management Routes
Admin-only account CRUD, plus self-service profile/password endpoints
available to any authenticated role.
"""
import base64
import io
import logging
from typing import List

import pyotp
import qrcode
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlite3 import IntegrityError

from app.models.user_models import (
    UserOut, UserCreate, UserUpdate, AdminPasswordReset,
    ProfileUpdate, SelfPasswordChange, NotificationPreferences,
    MfaStatus, MfaSetupResponse, MfaConfirmRequest, MfaDisableRequest,
    SessionOut,
)
from app.services.user_service import user_service
from app.services import db_service
from app.services import session_service
from app.services.auth import require_admin, require_any_role, verify_password, TokenData
from app.routes.auth import _issue_session
from app.utils.audit import log_admin_action

MFA_ISSUER = "CyberSentinel WAF"

logger = logging.getLogger(__name__)
router = APIRouter()


def _guard_last_admin(target: dict, will_demote: bool, will_disable: bool):
    """Prevent an action that would leave the system with zero enabled admins."""
    if target["role"] == "admin" and target["enabled"] and (will_demote or will_disable):
        if user_service.count_enabled_admins() <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot remove the last remaining administrator account.",
            )


def _enrich_with_app_ids(user: dict) -> dict:
    """UserOut.app_ids is only meaningful for role == 'app_admin' — the raw
    dicts user_service returns don't carry it at all (separate SQLite file,
    see db_service's app_user_access table)."""
    user = dict(user)
    user["app_ids"] = (
        db_service.get_app_ids_for_user(user["username"]) if user.get("role") == "app_admin" else []
    )
    return user


@router.get("/users", response_model=List[UserOut])
async def list_users(current_user: TokenData = Depends(require_admin)):
    """List all dashboard user accounts (Admin only)"""
    return [_enrich_with_app_ids(u) for u in user_service.list_users()]


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(payload: UserCreate, current_user: TokenData = Depends(require_admin)):
    """Create a new dashboard user account (Admin only)"""
    if user_service.get_by_username(payload.username):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Username already exists."
        )
    try:
        user_id = user_service.create_user(
            username=payload.username,
            password=payload.password,
            role=payload.role,
            display_name=payload.display_name,
            email=payload.email,
        )
    except IntegrityError:
        # The pre-check above isn't atomic with the INSERT, so a concurrent
        # request for the same username can still race past it.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Username already exists."
        )
    if payload.role == "app_admin" and payload.app_ids:
        db_service.set_app_access_for_user(payload.username, payload.app_ids)
    log_admin_action("user", str(user_id), "create", current_user, details={"username": payload.username, "role": payload.role, "app_ids": payload.app_ids})
    return _enrich_with_app_ids(user_service.get_by_id(user_id))


@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: int, payload: UserUpdate, current_user: TokenData = Depends(require_admin)
):
    """Update a user's role, enabled state, display name, or email (Admin only)"""
    target = user_service.get_by_id(user_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    will_demote = payload.role is not None and payload.role != "admin"
    will_disable = payload.enabled is False
    _guard_last_admin(target, will_demote, will_disable)

    result = user_service.update_user(
        user_id,
        role=payload.role,
        enabled=payload.enabled,
        display_name=payload.display_name,
        email=payload.email,
    )

    # Username is immutable (no rename support anywhere in this app), so
    # target["username"] is safe to key app_user_access on regardless of
    # what else changed here.
    effective_role = payload.role if payload.role is not None else target["role"]
    if effective_role != "app_admin":
        # Demoted away from app_admin (or was never one) — orphaned scoping
        # rows would be inert but confusing to leave lying around.
        db_service.set_app_access_for_user(target["username"], [])
    elif payload.app_ids is not None:
        db_service.set_app_access_for_user(target["username"], payload.app_ids)

    log_admin_action(
        "user", str(user_id), "update", current_user,
        details={"role": payload.role, "enabled": payload.enabled, "target_username": target["username"], "app_ids": payload.app_ids},
    )
    return _enrich_with_app_ids(result)


@router.post("/users/{user_id}/reset-password")
async def reset_password(
    user_id: int, payload: AdminPasswordReset, current_user: TokenData = Depends(require_admin)
):
    """Admin-issued password reset for another account (Admin only)"""
    target = user_service.get_by_id(user_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    user_service.set_password(user_id, payload.new_password)
    log_admin_action("user", str(user_id), "admin_reset_password", current_user, details={"target_username": target["username"]})
    return {"message": "Password reset successfully."}


@router.delete("/users/{user_id}")
async def delete_user(user_id: int, current_user: TokenData = Depends(require_admin)):
    """Delete a dashboard user account (Admin only)"""
    target = user_service.get_by_id(user_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    if target["username"] == current_user.username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot delete your own account."
        )
    _guard_last_admin(target, will_demote=False, will_disable=True)
    user_service.delete_user(user_id)
    db_service.set_app_access_for_user(target["username"], [])
    log_admin_action("user", str(user_id), "delete", current_user, details={"target_username": target["username"]})
    return {"message": "User deleted successfully."}


@router.get("/users/me/profile", response_model=UserOut)
async def get_my_profile(current_user: TokenData = Depends(require_any_role)):
    """Get the logged-in user's own profile (any role)"""
    user = user_service.get_by_username(current_user.username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return _enrich_with_app_ids(user)


@router.patch("/users/me/profile", response_model=UserOut)
async def update_my_profile(
    payload: ProfileUpdate, current_user: TokenData = Depends(require_any_role)
):
    """Update the logged-in user's own display name / email (any role)"""
    user = user_service.get_by_username(current_user.username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return user_service.update_user(
        user["id"], display_name=payload.display_name, email=payload.email
    )


@router.post("/users/me/password")
async def change_my_password(
    payload: SelfPasswordChange,
    request: Request,
    response: Response,
    current_user: TokenData = Depends(require_any_role),
):
    """Self-service password change for the logged-in user (any role)"""
    user = user_service.get_by_username(current_user.username)
    if not user or not verify_password(payload.current_password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect current password."
        )
    user_service.set_password(user["id"], payload.new_password)
    # set_password() bumps session_version, which would otherwise invalidate
    # the very session that just made this change on its next request —
    # re-issue a fresh cookie so the user isn't logged out by their own action.
    updated_user = user_service.get_by_id(user["id"])
    _issue_session(request, response, updated_user)
    return {"message": "Password updated successfully."}


@router.get("/users/me/sessions", response_model=List[SessionOut])
async def list_my_sessions(current_user: TokenData = Depends(require_any_role)):
    """List the logged-in user's own active sessions (any role) — every
    device/browser currently holding a valid, non-revoked login for this
    account. See session_service.py (P1-8 Part B)."""
    sessions = session_service.list_sessions(current_user.username)
    for s in sessions:
        s["is_current"] = s["session_id"] == current_user.session_id
    return sessions


@router.delete("/users/me/sessions/{session_id}")
async def revoke_my_session(session_id: str, current_user: TokenData = Depends(require_any_role)):
    """Revoke one of the logged-in user's own sessions (any role) — e.g. a
    laptop left logged in, or a session opened on a shared machine.
    Revoking your own CURRENT session is allowed and simply logs you out
    of it on its next request, same effect as a normal logout."""
    if not session_service.revoke_session(current_user.username, session_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")
    return {"message": "Session revoked."}


@router.get("/users/me/notification-preferences", response_model=NotificationPreferences)
async def get_my_notification_preferences(current_user: TokenData = Depends(require_any_role)):
    """Get the logged-in user's bell-notification mute preferences (any role)"""
    user = user_service.get_by_username(current_user.username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return user_service.get_notification_prefs(user["id"])


@router.patch("/users/me/notification-preferences", response_model=NotificationPreferences)
async def update_my_notification_preferences(
    payload: NotificationPreferences, current_user: TokenData = Depends(require_any_role)
):
    """Update the logged-in user's bell-notification mute preferences (any role)"""
    user = user_service.get_by_username(current_user.username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return user_service.update_notification_prefs(user["id"], payload.model_dump())


def _qr_png_base64(otpauth_uri: str) -> str:
    img = qrcode.make(otpauth_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


@router.get("/users/me/mfa/status", response_model=MfaStatus)
async def get_my_mfa_status(current_user: TokenData = Depends(require_any_role)):
    """Whether the logged-in user currently has TOTP MFA enabled (any role)"""
    user = user_service.get_by_username(current_user.username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return {"enabled": user["mfa_enabled"]}


@router.post("/users/me/mfa/setup", response_model=MfaSetupResponse)
async def setup_my_mfa(current_user: TokenData = Depends(require_any_role)):
    """Generates a new TOTP secret and QR code. MFA isn't enabled until the
    user proves they scanned it by calling /mfa/confirm with a valid code
    (any role)."""
    user = user_service.get_by_username(current_user.username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    if user["mfa_enabled"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled. Disable it first to generate a new secret.",
        )

    secret = pyotp.random_base32()
    user_service.set_pending_mfa_secret(user["id"], secret)

    otpauth_uri = pyotp.TOTP(secret).provisioning_uri(name=user["username"], issuer_name=MFA_ISSUER)
    return MfaSetupResponse(
        secret=secret,
        otpauth_uri=otpauth_uri,
        qr_code_png_base64=_qr_png_base64(otpauth_uri),
    )


@router.post("/users/me/mfa/confirm", response_model=MfaStatus)
async def confirm_my_mfa(
    payload: MfaConfirmRequest, current_user: TokenData = Depends(require_any_role)
):
    """Verifies the first code from a freshly-scanned authenticator and, if
    valid, actually enables MFA on the account (any role)."""
    user = user_service.get_by_username(current_user.username)
    if not user or not user["mfa_secret"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending MFA setup found. Call /mfa/setup first.",
        )

    totp = pyotp.TOTP(user["mfa_secret"])
    if not totp.verify(payload.code, valid_window=1):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid code.")

    user_service.confirm_mfa(user["id"])
    return {"enabled": True}


@router.post("/users/me/mfa/disable", response_model=MfaStatus)
async def disable_my_mfa(
    payload: MfaDisableRequest, current_user: TokenData = Depends(require_any_role)
):
    """Self-service MFA disable — requires both the current password and a
    valid TOTP code, so a stolen session cookie alone can't turn off 2FA
    (any role)."""
    user = user_service.get_by_username(current_user.username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    if not verify_password(payload.current_password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect current password.")
    if not user["mfa_enabled"] or not user["mfa_secret"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is not enabled.")
    if not pyotp.TOTP(user["mfa_secret"]).verify(payload.code, valid_window=1):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid code.")

    user_service.disable_mfa(user["id"])
    return {"enabled": False}


@router.post("/users/{user_id}/mfa/disable", response_model=MfaStatus)
async def admin_disable_user_mfa(user_id: int, current_user: TokenData = Depends(require_admin)):
    """Admin recovery path: force-disable MFA on another account (e.g. the
    user lost their authenticator device). No code/password needed since
    the admin is already authenticated and authorized (Admin only)."""
    target = user_service.get_by_id(user_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    user_service.disable_mfa(user_id)
    logger.warning(
        f"MFA force-disabled for user '{target['username']}' (id={user_id}) "
        f"by admin '{current_user.username}'."
    )
    log_admin_action("user", str(user_id), "admin_disable_mfa", current_user, details={"target_username": target["username"]})
    return {"enabled": False}


@router.get("/users/{user_id}/sessions", response_model=List[SessionOut])
async def list_user_sessions(user_id: int, current_user: TokenData = Depends(require_admin)):
    """Admin visibility into another account's active sessions (Admin
    only) — e.g. to check whether a suspicious login is still live before
    deciding whether to revoke it or the whole account."""
    target = user_service.get_by_id(user_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    sessions = session_service.list_sessions(target["username"])
    for s in sessions:
        s["is_current"] = (
            target["username"] == current_user.username and s["session_id"] == current_user.session_id
        )
    return sessions


@router.delete("/users/{user_id}/sessions/{session_id}")
async def revoke_user_session(
    user_id: int, session_id: str, current_user: TokenData = Depends(require_admin)
):
    """Admin revoke of one specific session on another account (Admin
    only) — kills that one login without disabling the account or forcing
    a password reset that would also kill every OTHER session of theirs."""
    target = user_service.get_by_id(user_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    if not session_service.revoke_session(target["username"], session_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")
    log_admin_action(
        "session", session_id, "revoke", current_user, details={"target_username": target["username"]}
    )
    return {"message": "Session revoked."}
