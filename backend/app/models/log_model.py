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


class MlSubScoreDetail(BaseModel):
    """ml_events row matched to a waf_events transaction — see
    clickhouse_service.find_ml_event_near for the fuzzy-join details."""
    unique_id: str
    timestamp: str
    crs_score: float
    matched_vars: str
    xgb_prob: float
    iso_score: float
    threat_score: float
    decision: str
    redis_rep: float
    abuse_score: float


class ExplainBlockResponse(BaseModel):
    """Unified 'why was this blocked' view (P1-13): the ModSecurity
    rule-match record plus whatever ML scoring happened for the same
    request, if any — merged from two ClickHouse tables that don't share
    a request ID (see find_ml_event_near)."""
    waf_event: LogEntry
    ml_event: Optional[MlSubScoreDetail] = None
    ml_match_note: str
    # Plain-language translation of the above (P2 item 7 of the WAAP
    # console teardown roadmap) — see threat_explain.generate_plain_explanation.
    plain_summary: str


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
