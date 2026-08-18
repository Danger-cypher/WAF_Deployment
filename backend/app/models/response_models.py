from pydantic import BaseModel
from typing import List, Optional
from app.models.log_model import LogEntry, GroupedLogEntry


class PaginatedLogs(BaseModel):
    data: List[LogEntry]
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
