import json
import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status

from app.models.false_positive_model import (
    FalsePositiveCreateRequest,
    FalsePositiveStatusUpdateRequest,
    FalsePositiveNoteUpdateRequest,
    FalsePositiveResponse,
)
from app.services import db_service, rule_manager
from app.services.auth import require_admin, require_any_role, TokenData
from app.services.log_reader import get_all_logs


def _attach_suggestion(entry: dict) -> dict:
    entry["suggested_exclusion"] = rule_manager.suggest_exclusion(
        entry.get("raw_log"), entry.get("rule_id", ""), entry.get("uri")
    )
    return entry

logger = logging.getLogger(__name__)
router = APIRouter()


def _find_log_by_id(log_id: str):
    """
    Looks up a log entry by ID using the cached in-memory log list.
    Avoids a full disk re-scan per request by relying on get_all_logs() TTL cache.
    Uses a dict for O(1) lookup instead of O(n) linear search.
    """
    logs = get_all_logs()
    log_index = {log.id: log for log in logs}
    return log_index.get(log_id)


@router.post(
    "/false-positives",
    response_model=FalsePositiveResponse,
    status_code=status.HTTP_201_CREATED,
)
async def mark_log_as_false_positive(
    request: FalsePositiveCreateRequest,
    current_user: TokenData = Depends(require_any_role),
):
    """Marks an existing WAF audit log as a False Positive entry."""
    # Check if duplicate exists
    existing = db_service.get_false_positive_by_log_id(request.log_id)
    if existing:
        raise HTTPException(
            status_code=400,
            detail="This log entry is already marked as a false positive.",
        )

    # Find the log entry — uses TTL-cached index for efficiency (FIX 2)
    log_entry = _find_log_by_id(request.log_id)
    if not log_entry:
        raise HTTPException(
            status_code=404,
            detail="Log transaction ID not found in current audit logs.",
        )

    # Serialize raw_log payload to secure detailed JSON fields
    raw_log_dict = log_entry.raw_log or log_entry.model_dump()
    raw_log_json = json.dumps(raw_log_dict)

    created = db_service.create_false_positive(
        log_id=log_entry.id,
        rule_id=log_entry.rule_id,
        client_ip=log_entry.client_ip,
        uri=log_entry.uri,
        timestamp=log_entry.timestamp,
        severity=log_entry.severity,
        attack_type=log_entry.attack_type,
        analyst_note=request.analyst_note or "",
        raw_log=raw_log_json,
        created_by=current_user.username,  # FIX 10: store creator
    )
    if not created:
        raise HTTPException(
            status_code=500,
            detail="Failed to store false positive record inside local database.",
        )

    # Parse raw_log from string to dict for correct JSON serialization
    try:
        created["raw_log"] = json.loads(created["raw_log"])
    except Exception:
        created["raw_log"] = raw_log_dict
    _attach_suggestion(created)

    logger.info(
        f"Log {request.log_id} flagged as a false positive by {current_user.username}."
    )
    return created


@router.get("/false-positives", response_model=List[FalsePositiveResponse])
async def list_false_positives(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    rule_id: Optional[str] = None,
    search: Optional[str] = None,
    current_user: TokenData = Depends(require_any_role),
):
    """Retrieves all false positive entries, with sorting and filtering options."""
    entries = db_service.get_all_false_positives(
        status=status, severity=severity, rule_id=rule_id, search=search
    )
    # Parse raw_log strings to dictionaries
    for entry in entries:
        try:
            entry["raw_log"] = json.loads(entry["raw_log"])
        except Exception:
            entry["raw_log"] = {}
        _attach_suggestion(entry)
    return entries


@router.post("/false-positives/{id}/status", response_model=FalsePositiveResponse)
async def update_status(
    id: str,
    request: FalsePositiveStatusUpdateRequest,
    current_user: TokenData = Depends(require_any_role),
):
    """Updates review investigation status (Pending, Reviewed, Resolved)."""
    if request.status not in ("Pending", "Reviewed", "Resolved"):
        raise HTTPException(
            status_code=400,
            detail="Invalid status. Must be 'Pending', 'Reviewed', or 'Resolved'.",
        )

    # FIX 4: Only admins can mark a ticket as Resolved to prevent silent dismissal of real threats
    if request.status == "Resolved" and current_user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Only administrators can mark a false positive as 'Resolved'.",
        )

    updated = db_service.update_false_positive_status(id, request.status)
    if not updated:
        raise HTTPException(status_code=404, detail="False positive entry not found.")

    try:
        updated["raw_log"] = json.loads(updated["raw_log"])
    except Exception:
        updated["raw_log"] = {}

    logger.info(
        f"False positive {id} status updated to {request.status} by {current_user.username}."
    )
    return updated


@router.post("/false-positives/{id}/note", response_model=FalsePositiveResponse)
async def update_note(
    id: str,
    request: FalsePositiveNoteUpdateRequest,
    current_user: TokenData = Depends(require_any_role),
):
    """Edits or attaches new analyst review notes to a flagged event."""
    updated = db_service.update_false_positive_note(id, request.analyst_note)
    if not updated:
        raise HTTPException(status_code=404, detail="False positive entry not found.")

    try:
        updated["raw_log"] = json.loads(updated["raw_log"])
    except Exception:
        updated["raw_log"] = {}

    logger.info(
        f"Analyst notes for false positive {id} updated by {current_user.username}."
    )
    return updated


# FIX 3: Use proper HTTP DELETE method with standard REST URL pattern
@router.delete("/false-positives/{id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_false_positive(
    id: str, current_user: TokenData = Depends(require_any_role)
):
    """Removes a log from the false positive registry."""
    # FIX 10: Only admin or the original creator can delete a false positive record
    entry = db_service.get_false_positive_by_id(id)
    if not entry:
        raise HTTPException(
            status_code=404,
            detail="False positive entry not found.",
        )

    if current_user.role != "admin" and entry.get("created_by") != current_user.username:
        raise HTTPException(
            status_code=403,
            detail="You can only delete false positive records that you created.",
        )

    success = db_service.delete_false_positive(id)
    if not success:
        raise HTTPException(
            status_code=500,
            detail="False positive entry could not be removed.",
        )

    logger.info(f"False positive {id} removed from DB by {current_user.username}.")
    # 204 No Content — return nothing
