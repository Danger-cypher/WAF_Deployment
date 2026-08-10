"""
routes/logs.py — CyberSentinel WAF
=====================================
WAF log endpoints. All reads now query ClickHouse directly via
clickhouse_service for paginated, filtered results.

All URL paths and response schemas are unchanged — frontend needs no updates.
"""

import os
import stat
from fastapi import APIRouter, Query, Depends, HTTPException
from typing import Optional

from app.models.response_models import PaginatedLogs
from app.models.log_model import LogEntry
from app.services.auth import require_any_role, require_admin, TokenData
from app.services import clickhouse_service
from app.services.log_reader import list_newest_log_files, _row_to_log_entry
from app.config.settings import settings

router = APIRouter()


@router.get("/logs", response_model=PaginatedLogs)
async def get_logs(
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=3000),
    severity: Optional[str] = None,
    min_severity: Optional[str] = None,
    rule_id: Optional[str] = None,
    ip: Optional[str] = None,
    attack_type: Optional[str] = None,
    status_code: Optional[str] = None,
    search: Optional[str] = None,
    uri_type: Optional[str] = None,
    hours: Optional[int] = None,
    current_user: TokenData = Depends(require_any_role),
):
    """
    Fetch paginated, filtered security events from ClickHouse.
    Only returns blocked threats (4xx/5xx http_code or events with violations).

    Filters:
    - severity: exact match (e.g. 'High')
    - min_severity: threshold — returns this level and above (Critical > High > Medium > Low)
    - rule_id, ip, attack_type, status_code: exact match filters
    - search: full-text search across message, uri, client_ip, rule_id, attack_type
    - uri_type: 'web' (non-/api) or 'api' (/api/*)
    - hours: restrict to last N hours
    """
    rows, total = clickhouse_service.query_waf_events(
        page=page,
        size=size,
        severity=severity,
        min_severity=min_severity,
        rule_id=rule_id,
        ip=ip,
        attack_type=attack_type,
        status_code=status_code,
        search=search,
        uri_type=uri_type,
        hours=hours,
        blocked_only=True,
    )

    # Convert raw dicts to LogEntry models
    data = [_row_to_log_entry(r) for r in rows]

    return PaginatedLogs(data=data, total=total, page=page, size=size)


@router.get("/logs/{log_id}", response_model=LogEntry)
async def get_log_by_id(
    log_id: str,
    current_user: TokenData = Depends(require_any_role),
):
    """Fetch a single WAF log entry by its unique transaction ID from ClickHouse."""
    row = clickhouse_service.get_waf_event_by_id(log_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Log entry not found")
    return _row_to_log_entry(row)


@router.get("/debug/logs")
async def debug_logs(current_user: TokenData = Depends(require_admin)):
    """
    Debug endpoint: audit log directory status + ClickHouse connectivity.
    Requires admin role.
    """
    files = list_newest_log_files(limit=50)

    file_results = []
    for f in files[:50]:
        try:
            file_stat = os.stat(f)
            mode = oct(stat.S_IMODE(file_stat.st_mode))
            readable = os.access(f, os.R_OK)
            file_results.append({
                "path": f,
                "readable": readable,
                "mode": mode,
                "owner_uid": file_stat.st_uid,
                "size_bytes": file_stat.st_size,
                "mtime": file_stat.st_mtime,
            })
        except Exception as e:
            file_results.append({"path": f, "error": str(e)})

    ch_available = clickhouse_service.is_available()
    ch_count = clickhouse_service.get_total_blocked_count() if ch_available else -1

    return {
        "log_dir": settings.LOG_DIR,
        "dir_exists": os.path.isdir(settings.LOG_DIR),
        "dir_readable": os.access(settings.LOG_DIR, os.R_OK),
        "backend_user_uid": os.getuid(),
        "backend_user_gid": os.getgid(),
        "total_files_found": len(files),
        "clickhouse_available": ch_available,
        "clickhouse_total_events": ch_count,
        "files": file_results,
    }
