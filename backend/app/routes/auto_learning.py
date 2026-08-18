import json
import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status

from app.services import db_service, rule_manager, auto_learning
from app.services.auth import require_admin, require_any_role, TokenData

logger = logging.getLogger(__name__)
router = APIRouter()


def _serialize(row: dict) -> dict:
    row = dict(row)
    try:
        row["sample_false_positive_ids"] = json.loads(row["sample_false_positive_ids"])
    except Exception:
        row["sample_false_positive_ids"] = []
    return row


@router.get("/auto-learning/suggestions")
async def list_suggestions(
    status: Optional[str] = None,
    current_user: TokenData = Depends(require_any_role),
):
    """Lists Auto-Learning's pending/approved/rejected exclusion suggestions."""
    rows = db_service.get_all_auto_learning_suggestions(status=status)
    return [_serialize(r) for r in rows]


@router.post("/auto-learning/run")
async def run_now(current_user: TokenData = Depends(require_admin)):
    """
    Manually triggers an Auto-Learning scan cycle regardless of the
    enabled toggle in Settings — lets an admin see suggestions immediately
    instead of waiting for the next scheduled cycle.
    """
    result = auto_learning.compute_and_store_suggestions(force=True)
    return result


@router.post("/auto-learning/suggestions/{id}/approve")
async def approve_suggestion(id: int, current_user: TokenData = Depends(require_admin)):
    """
    Turns a Pending suggestion into a real WAF exclusion, through the exact
    same generate-rule -> write-to-db -> sync-and-reload pipeline used by
    the manual Exceptions flow (routes/exclusions.py's create_new_exclusion)
    — Auto-Learning never bypasses that safety/rollback path.
    """
    suggestion = db_service.get_auto_learning_suggestion_by_id(id)
    if not suggestion:
        raise HTTPException(status_code=404, detail="Suggestion not found.")
    if suggestion["status"] != "Pending":
        raise HTTPException(
            status_code=400,
            detail=f"Suggestion is already {suggestion['status']}, not Pending.",
        )

    exclusion_type = suggestion["exclusion_type"]
    uri = suggestion["uri"]
    parameter_name = suggestion["parameter_name"]

    if exclusion_type in ("uri", "uri_parameter", "endpoint_method", "ip_suppression"):
        if not uri or uri.strip() in ("", "/"):
            raise HTTPException(
                status_code=400,
                detail="Broad exclusions on the root path ('/') are rejected to prevent weakening overall WAF protection.",
            )

    try:
        next_id = db_service.get_next_exclusion_sequence_id()
        modsec_rule_text = rule_manager.generate_modsec_rule(
            exclusion_type=exclusion_type,
            rule_id=suggestion["rule_id"],
            uri=uri,
            parameter_name=parameter_name,
            http_method=None,
            client_ip=None,
            next_id=next_id,
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sample_ids = json.loads(suggestion["sample_false_positive_ids"])
    resolved_fp_id = None
    for fp_id in sample_ids:
        resolved_fp_id = db_service.resolve_false_positive_sqlite_id(fp_id)
        if resolved_fp_id:
            break

    exclusion = db_service.create_exclusion(
        false_positive_id=resolved_fp_id,
        rule_id=suggestion["rule_id"],
        exclusion_type=exclusion_type,
        uri=uri,
        parameter_name=parameter_name,
        http_method=None,
        client_ip=None,
        created_by=current_user.username,
        notes=f"Auto-Learning suggestion approved by {current_user.username} "
              f"({suggestion['occurrence_count']} occurrence(s), "
              f"{suggestion['confidence_score']}% confidence). {suggestion['reasoning']}",
        modsec_rule=modsec_rule_text,
        timestamp=timestamp,
    )
    if not exclusion:
        raise HTTPException(
            status_code=500,
            detail="Failed to write exception policy to SQLite registry.",
        )

    ok, msg = rule_manager.sync_rules_and_exclusions()
    if not ok:
        db_service.delete_exclusion(exclusion["id"], "system", timestamp)
        raise HTTPException(
            status_code=400,
            detail=f"WAF compilation failed: {msg}. Exclusion was rolled back.",
        )

    db_service.update_auto_learning_suggestion_status(
        id, "Approved", current_user.username, timestamp
    )
    logger.info(
        f"Auto-Learning suggestion {id} approved by {current_user.username} "
        f"-> exclusion {exclusion['id']}."
    )
    return {"suggestion_id": id, "exclusion": exclusion}


@router.post("/auto-learning/suggestions/{id}/reject")
async def reject_suggestion(id: int, current_user: TokenData = Depends(require_admin)):
    """Dismisses a suggestion. Rejected patterns are never re-suggested by a later cycle."""
    suggestion = db_service.get_auto_learning_suggestion_by_id(id)
    if not suggestion:
        raise HTTPException(status_code=404, detail="Suggestion not found.")
    if suggestion["status"] != "Pending":
        raise HTTPException(
            status_code=400,
            detail=f"Suggestion is already {suggestion['status']}, not Pending.",
        )

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    updated = db_service.update_auto_learning_suggestion_status(
        id, "Rejected", current_user.username, timestamp
    )
    logger.info(f"Auto-Learning suggestion {id} rejected by {current_user.username}.")
    return _serialize(updated)
