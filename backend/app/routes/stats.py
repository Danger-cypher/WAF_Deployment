import asyncio
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from typing import List, Dict, Any, Optional
import csv
import io

from app.models.response_models import StatsResponse, TimelineResponse, TimelineEntry
from app.services.auth import require_any_role, TokenData
from app.services.log_reader import get_all_logs
from app.services.stats_calculator import (
    calculate_stats,
    calculate_stats_trend,
    get_top_ips,
    get_top_uris,
    get_attack_types_distribution,
    get_timeline,
    get_top_rules,
    get_severity_distribution,
)

router = APIRouter()


from fastapi import APIRouter, Depends, Query

@router.get("/stats", response_model=StatsResponse)
async def get_general_stats(
    hours: int = Query(None, description="Timeframe in hours"),
    current_user: TokenData = Depends(require_any_role)
):
    """
    Get overall WAF statistics.
    """
    # calculate_stats() does synchronous ClickHouse queries and, on a cache
    # miss with hours=None, a full line-by-line scan of the nginx access log
    # — run directly on this async route it blocks the entire single-process
    # event loop for its full duration, stalling every other concurrent
    # user's request on the dashboard, not just this one.
    stats = await asyncio.to_thread(calculate_stats, hours)
    return StatsResponse(**stats)


@router.get("/stats/trend")
async def get_stats_trend(
    window_hours: int = Query(24, ge=1, le=168, description="Size of the comparison window, in hours"),
    current_user: TokenData = Depends(require_any_role)
):
    """
    Current vs. previous `window_hours` window — powers the Overview KPI
    trend badges (an up/down delta against the prior period, next to each
    metric's all-time total).
    """
    return await asyncio.to_thread(calculate_stats_trend, window_hours)


@router.get("/top-ips", response_model=List[Dict[str, Any]])
async def get_top_attacking_ips(
    hours: int = Query(None, description="Timeframe in hours"),
    current_user: TokenData = Depends(require_any_role)
):
    """
    Get top attacking IPs.
    """
    return await asyncio.to_thread(get_top_ips, hours=hours)


@router.get("/top-uris", response_model=List[Dict[str, Any]])
async def get_top_targeted_uris(
    hours: int = Query(None, description="Timeframe in hours"),
    limit: int = Query(10, ge=1, le=50),
    current_user: TokenData = Depends(require_any_role)
):
    """
    Get most-targeted endpoints (blocked requests grouped by URI).
    """
    return await asyncio.to_thread(get_top_uris, limit=limit, hours=hours)


@router.get("/attack-types", response_model=List[Dict[str, Any]])
async def get_attack_types(
    hours: int = Query(None, description="Timeframe in hours"),
    current_user: TokenData = Depends(require_any_role)
):
    """
    Get attack category distribution.
    """
    return await asyncio.to_thread(get_attack_types_distribution, hours)


@router.get("/timeline", response_model=TimelineResponse)
async def get_attack_timeline(
    hours: int = Query(None, description="Timeframe in hours"),
    current_user: TokenData = Depends(require_any_role)
):
    """
    Get timeline of attacks.
    """
    data = await asyncio.to_thread(get_timeline, hours)
    entries = [TimelineEntry(**item) for item in data]
    return TimelineResponse(data=entries)


@router.get("/top-rules", response_model=List[Dict[str, Any]])
async def get_top_rules_stats(
    hours: int = Query(None, description="Timeframe in hours"),
    current_user: TokenData = Depends(require_any_role)
):
    """
    Get most triggered rules.
    """
    return await asyncio.to_thread(get_top_rules, hours=hours)


@router.get("/severity-distribution", response_model=List[Dict[str, Any]])
async def get_severity_dist(
    hours: int = Query(None, description="Timeframe in hours"),
    current_user: TokenData = Depends(require_any_role)
):
    """
    Get severity level distribution.
    """
    return await asyncio.to_thread(get_severity_distribution, hours)


@router.get("/stats/export/csv")
async def export_logs_csv(
    hours: Optional[int] = None,
    current_user: TokenData = Depends(require_any_role),
):
    """
    Exports the WAF security events/logs as a CSV file, scoped to `hours` if
    given — previously always exported the full log history regardless of
    which timeframe the caller had selected in a report.
    """
    logs = await asyncio.to_thread(get_all_logs, hours=hours)

    def generate():
        output = io.StringIO()
        writer = csv.writer(output)

        # Write CSV header
        writer.writerow([
            "Transaction ID",
            "Timestamp",
            "Client IP",
            "Country",
            "Method",
            "URI",
            "Severity",
            "Attack Type",
            "Rule ID",
            "Message"
        ])

        for log in logs:
            writer.writerow([
                log.id,
                log.timestamp,
                log.client_ip,
                log.country or "Unknown",
                log.method,
                log.uri,
                log.severity,
                log.attack_type,
                log.rule_id or "N/A",
                log.message or ""
            ])
            data = output.getvalue()
            output.seek(0)
            output.truncate(0)
            yield data

    response = StreamingResponse(generate(), media_type="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=waf_security_report.csv"
    return response
