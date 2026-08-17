import asyncio
import time
from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional
from datetime import datetime
import base64
import json
from app.routes.settings import EncodedPayloadModel

from app.models.exclusion_model import (
    ExclusionCreateRequest,
    ExclusionPreviewRequest,
    ExclusionStatusUpdateRequest,
    ExclusionNoteUpdateRequest,
    ExclusionResponse,
)
from app.services import db_service, rule_manager
from app.services.auth import require_admin, require_any_role, TokenData

router = APIRouter()

# Cache for the nginx config-validity check backing "Global System Health" on
# the Exceptions page — that card used to just say "100%" unconditionally,
# regardless of whether the config nginx is actually running on is even
# valid. test_nginx_config() shells out to nginx/openresty (up to several
# subprocess attempts, each with its own timeout) so it's cached rather than
# re-run on every page load.
_config_health_cache: dict = {}
_CONFIG_HEALTH_CACHE_TTL = 30  # seconds


@router.post("/exclusions/preview")
async def preview_exclusion(
    encoded_payload: EncodedPayloadModel,
    current_user: TokenData = Depends(require_any_role),
):
    """Generates a preview of the ModSecurity exclusion rule without saving it."""
    try:
        # Payload is Base64-encoded JSON — see the comment on
        # update_positive_security in routes/settings.py for why this used
        # to need a "WAF_BYPASS_" prefix and why it doesn't anymore (the
        # dashboard vhost's own SecRuleRemoveById whitelist already covers
        # it — verified directly against a payload with SQLi/XSS/path-
        # traversal-shaped notes/uri content).
        json_str = base64.b64decode(encoded_payload.payload).decode("utf-8")
        request = ExclusionPreviewRequest(**json.loads(json_str))

        # Use the real next sequence ID so the preview accurately shows the rule that will be saved.
        # This is read-only — it does not reserve or consume the ID.
        preview_id = db_service.get_next_exclusion_sequence_id()
        rule_text = rule_manager.generate_modsec_rule(
            exclusion_type=request.exclusion_type,
            rule_id=request.rule_id,
            uri=request.uri,
            parameter_name=request.parameter_name,
            http_method=request.http_method,
            client_ip=request.client_ip,
            next_id=preview_id,
        )
        return {"modsec_rule": rule_text}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate preview: {e}")


@router.post(
    "/exclusions", response_model=ExclusionResponse, status_code=status.HTTP_201_CREATED
)
async def create_new_exclusion(
    encoded_payload: EncodedPayloadModel,
    current_user: TokenData = Depends(require_admin),
):
    """Creates a new targeted exclusion, generates the ModSec rule, and reloads NGINX WAF."""
    try:
        # Payload is Base64-encoded JSON — see preview_exclusion above / the
        # comment on update_positive_security in routes/settings.py for why
        # this no longer needs a "WAF_BYPASS_" prefix.
        json_str = base64.b64decode(encoded_payload.payload).decode("utf-8")
        request = ExclusionCreateRequest(**json.loads(json_str))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid payload")

    # Safety Check: Broad exclusion prevention
    if request.exclusion_type in (
        "uri",
        "uri_parameter",
        "endpoint_method",
        "ip_suppression",
    ):
        if not request.uri or request.uri.strip() == "/" or request.uri.strip() == "":
            raise HTTPException(
                status_code=400,
                detail="Broad exclusions on root path ('/') are rejected to prevent weakening overall WAF protection.",
            )
        if not request.uri.startswith("/"):
            raise HTTPException(
                status_code=400,
                detail="Target endpoint URI must start with a forward slash '/'.",
            )

    # Generate the rule first to validate inputs
    try:
        # BUG FIX: Use SQLite's internal monotonic sequence counter instead of len(existing)+1.
        # len(existing)+1 causes ModSecurity rule ID collisions after any exclusion is deleted:
        #   e.g. create rule→ID 10000001, delete it, create new rule→ID 10000001 again → CRASH.
        # get_next_exclusion_sequence_id() reads sqlite_sequence which NEVER decreases or reuses IDs.
        next_id = db_service.get_next_exclusion_sequence_id()

        modsec_rule_text = rule_manager.generate_modsec_rule(
            exclusion_type=request.exclusion_type,
            rule_id=request.rule_id,
            uri=request.uri,
            parameter_name=request.parameter_name,
            http_method=request.http_method,
            client_ip=request.client_ip,
            next_id=next_id,
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Resolve to the SQLite integer PK the false_positive_id FK column
    # actually needs — create_false_positive() returns a ClickHouse UUID
    # string as `id` whenever ClickHouse is available (the normal case),
    # not the SQLite row's real autoincrement integer. Passed through
    # unresolved, that UUID gets stored as literal text that can never
    # match false_positives.id — the FK link would silently do nothing.
    resolved_fp_id = (
        db_service.resolve_false_positive_sqlite_id(request.false_positive_id)
        if request.false_positive_id
        else None
    )

    # Store in database
    exclusion = db_service.create_exclusion(
        false_positive_id=resolved_fp_id,
        rule_id=request.rule_id,
        exclusion_type=request.exclusion_type,
        uri=request.uri,
        parameter_name=request.parameter_name,
        http_method=request.http_method,
        client_ip=request.client_ip,
        created_by=current_user.username,
        notes=request.notes,
        modsec_rule=modsec_rule_text,
        timestamp=timestamp,
    )

    if not exclusion:
        raise HTTPException(
            status_code=500,
            detail="Failed to write exception policy to SQLite registry.",
        )

    # Sync configuration file & reload NGINX WAF
    ok, msg = rule_manager.sync_rules_and_exclusions()
    if not ok:
        # Revert DB entry on failure to maintain consistency with actual WAF state
        db_service.delete_exclusion(exclusion["id"], "system", timestamp)
        raise HTTPException(
            status_code=400,
            detail=f"WAF compilation failed: {msg}. Exclusion was rolled back.",
        )

    return exclusion


@router.get("/exclusions", response_model=List[ExclusionResponse])
async def list_exclusions(
    status: Optional[str] = None,
    search: Optional[str] = None,
    current_user: TokenData = Depends(require_any_role),
):
    """Retrieves all exceptions and custom tuning rules."""
    return db_service.get_all_exclusions(status=status, search=search)


@router.get("/exclusions/analytics")
async def get_analytics(current_user: TokenData = Depends(require_any_role)):
    """Returns analytics data for exceptions and false positive rules triggers."""
    analytics = db_service.get_exclusions_analytics()

    now = time.monotonic()
    if "checked" not in _config_health_cache or (now - _config_health_cache.get("ts", 0)) > _CONFIG_HEALTH_CACHE_TTL:
        from app.services.nginx_manager import test_nginx_config
        valid, err = await asyncio.to_thread(test_nginx_config)
        _config_health_cache["checked"] = True
        _config_health_cache["valid"] = valid
        _config_health_cache["error"] = err
        _config_health_cache["ts"] = now

    analytics["config_valid"] = _config_health_cache["valid"]
    analytics["config_error"] = _config_health_cache["error"] or None
    return analytics


@router.get("/exclusions/history")
async def get_exclusions_history(current_user: TokenData = Depends(require_any_role)):
    """Retrieves edit/tuning history and historical overrides logs."""
    return db_service.get_exclusion_audit_history()


@router.post("/exclusions/{id}/status", response_model=ExclusionResponse)
async def update_status(
    id: int,
    request: ExclusionStatusUpdateRequest,
    current_user: TokenData = Depends(require_admin),
):
    """Enables or disables a specific exclusion and reloads WAF state."""
    if request.status not in ("Active", "Disabled"):
        raise HTTPException(
            status_code=400, detail="Exclusion status must be 'Active' or 'Disabled'."
        )

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    updated = db_service.update_exclusion_status(
        id, request.status, current_user.username, timestamp
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Exclusion record not found.")

    # Sync & reload NGINX WAF
    ok, msg = rule_manager.sync_rules_and_exclusions()
    if not ok:
        # Revert status on failure
        old_status = "Disabled" if request.status == "Active" else "Active"
        db_service.update_exclusion_status(id, old_status, "system", timestamp)
        raise HTTPException(
            status_code=400, detail=f"WAF reload failed: {msg}. Change rolled back."
        )

    return updated


@router.post("/exclusions/{id}/note", response_model=ExclusionResponse)
async def update_note(
    id: int,
    request: ExclusionNoteUpdateRequest,
    current_user: TokenData = Depends(require_admin),
):
    """Updates analyst justification note for a registered WAF exception."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    updated = db_service.update_exclusion_note(
        id, request.notes, current_user.username, timestamp
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Exclusion record not found.")
    return updated


# FIX 3: Use proper HTTP DELETE method with standard REST URL pattern
@router.delete("/exclusions/{id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_exclusion(id: int, current_user: TokenData = Depends(require_admin)):
    """Removes a rule exception and reloads WAF configs to activate the target rules."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Keep old copy in case reload fails and we need to restore it
    old_exclusion = db_service.get_exclusion_by_id(id)
    if not old_exclusion:
        raise HTTPException(status_code=404, detail="Exclusion record not found.")

    success = db_service.delete_exclusion(id, current_user.username, timestamp)
    if not success:
        raise HTTPException(
            status_code=500, detail="Failed to delete exclusion from registry."
        )

    # Sync & reload NGINX WAF
    ok, msg = rule_manager.sync_rules_and_exclusions()
    if not ok:
        # Restore on failure to keep WAF in sync with DB
        db_service.create_exclusion(
            false_positive_id=old_exclusion["false_positive_id"],
            rule_id=old_exclusion["rule_id"],
            exclusion_type=old_exclusion["exclusion_type"],
            uri=old_exclusion["uri"],
            parameter_name=old_exclusion["parameter_name"],
            http_method=old_exclusion["http_method"],
            client_ip=old_exclusion["client_ip"],
            created_by=old_exclusion["created_by"],
            notes=old_exclusion["notes"],
            modsec_rule=old_exclusion["modsec_rule"],
            timestamp=old_exclusion["created_at"],
        )
        raise HTTPException(
            status_code=400,
            detail=f"WAF reload failed: {msg}. Deletion aborted & rolled back.",
        )
    # 204 No Content — return nothing
