from pydantic import BaseModel
from typing import List, Dict, Any, Optional


class RuleEntry(BaseModel):
    id: str
    name: str
    description: str
    severity: str
    category: str
    enabled: bool
    paranoia_level: int
    hit_count: int
    last_triggered: Optional[str] = ""
    file_path: str
    syntax: str
    tags: List[str]
    is_canary: bool = False


class RuleToggleRequest(BaseModel):
    id: str
    enabled: bool = True
    reason: Optional[str] = ""


class RuleCanaryRequest(BaseModel):
    id: str
    canary: bool = True


class RuleCanaryReport(BaseModel):
    rule_id: str
    hours: int
    total_matches: int
    sole_match_count: int  # this rule was the ONLY match — disabling it would let these through unblocked
    co_matched_count: int  # other rule(s) also matched — safe if this one is disabled
    daily_breakdown: List[Dict[str, Any]] = []  # per-day sole/co-matched split, for a trend view


class RuleCanaryStatus(BaseModel):
    rule_id: str
    started_at: Optional[str] = None
    elapsed_hours: Optional[float] = None
    window_hours: int
    needs_review: bool = False


class CanaryRolloutSettings(BaseModel):
    auto_promote_enabled: bool = False
    auto_rollback_enabled: bool = True
    window_hours: int = 72
    min_sample_size: int = 20
    promote_max_sole_match_rate: float = 0.30
    rollback_min_sole_match_rate: float = 0.70


class CanaryRolloutResult(BaseModel):
    promoted: List[str]
    rolled_back: List[str]
    needs_review: List[str]
    still_monitoring: List[str]


class ParanoiaRequest(BaseModel):
    level: int


class AuditLogEntry(BaseModel):
    timestamp: str
    username: str
    action: str  # "enable", "disable", "paranoia_change", "reset"
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    details: str


class RuleStatsResponse(BaseModel):
    total_rules: int
    enabled_rules: int
    disabled_rules: int
    paranoia_level: int
    top_triggered_rules: List[Dict[str, Any]]
    category_distribution: List[Dict[str, Any]]
    tuning_candidates: List[Dict[str, Any]]
