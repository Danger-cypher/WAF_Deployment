from pydantic import BaseModel
from typing import Any, Dict, List, Optional
from app.models.log_model import LogEntry, GroupedLogEntry


class PaginatedLogs(BaseModel):
    data: List[LogEntry]
    total: int
    page: int
    size: int


class PaginatedEndpoints(BaseModel):
    """API Protection's Discovered/Recently-Discovered/Stale endpoint lists
    — was a bare, unpaginated array (every row, every poll); a discovered-
    endpoint row has no fixed schema (calculate_endpoint_score merges in
    whatever fields the ClickHouse aggregation happened to produce), so
    this stays List[Dict] rather than a typed model like LogEntry above."""
    data: List[Dict[str, Any]]
    total: int
    page: int
    size: int


class PaginatedGroupedLogs(BaseModel):
    data: List[GroupedLogEntry]
    total: int
    page: int
    size: int


class StatsResponse(BaseModel):
    total_requests: int
    total_blocked: int
    sqli_count: int
    xss_count: int
    top_attack_type: str
    total_unique_ips: int
    recent_threats: int = 0


class TimelineEntry(BaseModel):
    time: str
    count: int


class TimelineResponse(BaseModel):
    data: List[TimelineEntry]


class HealthResponse(BaseModel):
    status: str
    log_directory_exists: bool
    total_parsed_files: int
    db_initialized: Optional[bool] = None
    redis_connected: Optional[bool] = None
    clickhouse_connected: Optional[bool] = None
    ml_enabled: Optional[bool] = None
