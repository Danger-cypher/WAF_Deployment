"""
Shared helper for admin-action audit logging.

The underlying sink (ClickHouse `audit_log` table, 365-day TTL) and its
writer (`clickhouse_service.insert_audit_log`) already existed, fed only by
exclusions (see routes/exclusions.py / db_service.py's exclusion functions).
Every other mutating route (settings, protected apps, users, false
positives) had no persisted audit trail at all. This wraps the existing
writer into a one-line call site so extending coverage doesn't mean
re-deriving the entity_type/username/ip wiring per route.
"""
import logging
from typing import Any, Dict, Optional

from fastapi import Request

from app.services import clickhouse_service
from app.services.auth import TokenData
from app.utils.security import get_client_ip

logger = logging.getLogger(__name__)


def log_admin_action(
    entity_type: str,
    entity_id: str,
    action: str,
    current_user: TokenData,
    details: Optional[Dict[str, Any]] = None,
    request: Optional[Request] = None,
) -> None:
    """
    Best-effort audit write — never raises. The admin action itself has
    already succeeded by the time this is called; a logging hiccup must
    not turn that into a failed request.
    """
    try:
        clickhouse_service.insert_audit_log(
            entity_type=entity_type,
            entity_id=str(entity_id),
            action=action,
            username=current_user.username,
            details=details,
            ip_address=get_client_ip(request) if request is not None else "",
        )
    except Exception as e:
        logger.error(f"log_admin_action failed ({entity_type}/{action}): {e}")
