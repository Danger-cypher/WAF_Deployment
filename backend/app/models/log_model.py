from pydantic import BaseModel
from typing import Optional, Dict, Any, List


class ViolationDetail(BaseModel):
    rule_id: str
    message: str
    data: Optional[str] = ""
    pattern: Optional[str] = ""
    file: Optional[str] = ""
    line_number: Optional[str] = ""


class LogEntry(BaseModel):
    id: str  # Unique identifier for the log (e.g. transaction id)
    timestamp: str
    client_ip: str
    uri: str
    method: str
    http_code: str
    rule_id: str
    message: str
    severity: str
    attack_type: str
    hostname: str
    country: Optional[str] = ""
    source_asn_org: Optional[str] = ""
    request_headers: Optional[Dict[str, str]] = {}
    response_headers: Optional[Dict[str, str]] = {}
    violations: Optional[List[ViolationDetail]] = []
    raw_log: Optional[Dict[str, Any]] = None


class GroupedLogEntry(BaseModel):
    """One collapsed (client_ip, rule_id) group for the Events page's
    Grouped view — see clickhouse_service.query_waf_events_grouped()."""
    client_ip: str
    rule_id: str
    event_count: int
    first_seen: str
    last_seen: str
    severity: str
    attack_type: str
    message: str
    sample_uri: str
    country: Optional[str] = ""
