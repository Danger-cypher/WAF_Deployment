"""
CyberSentinel WAF - Alert System Data Models
Pydantic models for alert channels, rules, history, and aggregations
"""
from pydantic import BaseModel, Field, validator, EmailStr
from typing import Optional, List, Dict, Any, Literal
from datetime import datetime
from enum import Enum


# ============================================================================
# Enums
# ============================================================================

class ChannelType(str, Enum):
    EMAIL = "email"
    SLACK = "slack"
    WEBHOOK = "webhook"
    PAGERDUTY = "pagerduty"
    SYSLOG = "syslog"


class EventType(str, Enum):
    ATTACK_DETECTED = "attack_detected"
    HIGH_THREAT_SCORE = "high_threat_score"
    DDOS_DETECTED = "ddos_detected"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    ML_ANOMALY = "ml_anomaly"
    GEO_VIOLATION = "geo_violation"
    SYSTEM_ERROR = "system_error"
    HEALTH_CHECK_FAILED = "health_check_failed"
    CONFIG_CHANGED = "config_changed"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, Enum):
    SENT = "sent"
    FAILED = "failed"
    THROTTLED = "throttled"
    ACKNOWLEDGED = "acknowledged"


# ============================================================================
# Channel Configuration Models
# ============================================================================

class EmailChannelConfig(BaseModel):
    """Email channel configuration"""
    smtp_host: str = Field(..., description="SMTP server hostname")
    smtp_port: int = Field(default=587, ge=1, le=65535)
    username: str = Field(..., description="SMTP username")
    # Was documented as "(encrypted)" — false: alert_db_service.create_channel
    # stores the whole config dict as plain json.dumps() text, and
    # alert_dispatcher.EmailNotificationChannel reads this value straight
    # through with no decrypt step. No encryption-at-rest is implemented
    # for this or any other channel secret (Slack/generic webhook URLs,
    # PagerDuty integration keys) — this field description should say so
    # accurately rather than imply a protection that isn't there.
    password: str = Field(..., description="SMTP password (stored as plain text — not encrypted at rest)")
    from_addr: EmailStr = Field(..., description="Sender email address")
    to_addrs: List[EmailStr] = Field(..., min_items=1, description="Recipient email addresses")
    use_tls: bool = Field(default=True, description="Use TLS encryption")
    use_ssl: bool = Field(default=False, description="Use SSL encryption")


class SlackChannelConfig(BaseModel):
    """Slack webhook configuration"""
    webhook_url: str = Field(..., description="Slack incoming webhook URL")
    channel: Optional[str] = Field(None, description="Override default channel (#channel)")
    username: Optional[str] = Field(default="WAF Alert Bot", description="Bot display name")
    icon_emoji: Optional[str] = Field(default=":shield:", description="Bot icon emoji")
    
    @validator('webhook_url')
    def validate_webhook_url(cls, v):
        if not v.startswith('https://hooks.slack.com/'):
            raise ValueError('Invalid Slack webhook URL')
        return v


class WebhookChannelConfig(BaseModel):
    """Generic webhook configuration"""
    url: str = Field(..., description="Webhook endpoint URL")
    method: Literal["POST", "PUT"] = Field(default="POST", description="HTTP method")
    headers: Optional[Dict[str, str]] = Field(default={}, description="Custom HTTP headers")
    timeout: int = Field(default=10, ge=1, le=60, description="Request timeout in seconds")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")
    
    @validator('url')
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v


class PagerDutyChannelConfig(BaseModel):
    """PagerDuty configuration"""
    integration_key: str = Field(..., description="PagerDuty integration key")
    severity_mapping: Optional[Dict[str, str]] = Field(
        default={"critical": "critical", "high": "error", "medium": "warning", "low": "info"},
        description="Map alert severity to PagerDuty severity"
    )


class SyslogChannelConfig(BaseModel):
    """Outbound SIEM/syslog export configuration. Deliberately NOT
    throttled/deduped like the other channel types — see alert_manager's
    trigger_event, which dispatches syslog channels unconditionally on
    every matching event, since a SIEM wants everything for its own
    correlation rather than a deduped subset meant to avoid human alert
    fatigue."""
    host: str = Field(..., description="Syslog collector hostname or IP")
    port: int = Field(default=514, ge=1, le=65535)
    protocol: Literal["udp", "tcp"] = Field(default="udp")
    facility: str = Field(default="local0", description="Syslog facility (e.g. local0-local7, auth, daemon)")
    format: Literal["rfc5424", "rfc3164"] = Field(default="rfc5424")


# ============================================================================
# Alert Channel Models
# ============================================================================

class AlertChannelBase(BaseModel):
    """Base model for alert channel"""
    name: str = Field(..., min_length=1, max_length=100, description="Unique channel name")
    channel_type: ChannelType = Field(..., description="Type of notification channel")
    enabled: bool = Field(default=True, description="Whether channel is active")


class AlertChannelCreate(AlertChannelBase):
    """Model for creating a new alert channel"""
    config: Dict[str, Any] = Field(..., description="Channel-specific configuration")
    
    @validator('config')
    def validate_config(cls, v, values):
        """Validate config against channel type"""
        if 'channel_type' not in values:
            return v
        
        channel_type = values['channel_type']
        try:
            if channel_type == ChannelType.EMAIL:
                EmailChannelConfig(**v)
            elif channel_type == ChannelType.SLACK:
                SlackChannelConfig(**v)
            elif channel_type == ChannelType.WEBHOOK:
                WebhookChannelConfig(**v)
            elif channel_type == ChannelType.PAGERDUTY:
                PagerDutyChannelConfig(**v)
            elif channel_type == ChannelType.SYSLOG:
                SyslogChannelConfig(**v)
        except Exception as e:
            raise ValueError(f"Invalid configuration for {channel_type}: {str(e)}")
        return v


class AlertChannelUpdate(BaseModel):
    """Model for updating an alert channel"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    config: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None


class AlertChannel(AlertChannelBase):
    """Complete alert channel model with metadata"""
    id: int
    config: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        orm_mode = True


# ============================================================================
# Alert Rule Condition Models
# ============================================================================

class RuleConditions(BaseModel):
    """Generic rule conditions - flexible JSON structure"""
    # Common conditions
    threat_score_gt: Optional[float] = Field(None, ge=0, le=100)
    threat_score_lt: Optional[float] = Field(None, ge=0, le=100)
    crs_score_gt: Optional[float] = None
    rpm_gt: Optional[int] = None
    unique_ips_lt: Optional[int] = None
    duration_seconds_gt: Optional[int] = None
    min_occurrences: Optional[int] = Field(default=1, ge=1)
    time_window_minutes: Optional[int] = Field(default=5, ge=1)
    
    # ML-specific
    xgb_prob_gt: Optional[float] = Field(None, ge=0, le=1)
    isolation_score_gt: Optional[float] = Field(None, ge=0, le=1)
    
    # Geographic
    blocked_countries: Optional[List[str]] = None
    allowed_countries: Optional[List[str]] = None
    
    # Custom field matching
    custom_conditions: Optional[Dict[str, Any]] = Field(default={})


# ============================================================================
# Alert Rule Models
# ============================================================================

class AlertRuleBase(BaseModel):
    """Base model for alert rule"""
    name: str = Field(..., min_length=1, max_length=100, description="Unique rule name")
    description: Optional[str] = Field(None, max_length=500, description="Rule description")
    event_type: EventType = Field(..., description="Type of event to monitor")
    severity: Severity = Field(..., description="Alert severity level")
    enabled: bool = Field(default=True, description="Whether rule is active")


class AlertRuleCreate(AlertRuleBase):
    """Model for creating a new alert rule"""
    conditions: Dict[str, Any] = Field(..., description="Rule evaluation conditions")
    channels: List[int] = Field(..., min_items=1, description="List of channel IDs to notify")
    throttle_minutes: int = Field(default=5, ge=0, le=1440, description="Alert throttle period")


class AlertRuleUpdate(BaseModel):
    """Model for updating an alert rule"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    event_type: Optional[EventType] = None
    severity: Optional[Severity] = None
    conditions: Optional[Dict[str, Any]] = None
    channels: Optional[List[int]] = None
    throttle_minutes: Optional[int] = Field(None, ge=0, le=1440)
    enabled: Optional[bool] = None


class AlertRule(AlertRuleBase):
    """Complete alert rule model with metadata"""
    id: int
    conditions: Dict[str, Any]
    channels: List[int]
    throttle_minutes: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        orm_mode = True


# ============================================================================
# Alert History Models
# ============================================================================

class AlertHistoryCreate(BaseModel):
    """Internal model for creating alert history entry"""
    rule_id: int
    rule_name: str
    event_type: EventType
    severity: Severity
    channels_notified: List[str]
    event_data: Dict[str, Any]
    message: str
    status: AlertStatus
    error_message: Optional[str] = None
    # Per-channel {channel_name, success, error} — the actual dispatch
    # result AlertDispatcher.dispatch() already computes per channel,
    # previously discarded (only the collapsed channels_notified list +
    # one concatenated error string were kept). Backs the per-channel
    # delivery-health rollup below.
    channel_results: List[Dict[str, Any]] = []


class AlertHistoryAcknowledge(BaseModel):
    """Model for acknowledging an alert"""
    acknowledged_by: str = Field(..., min_length=1, description="Username who acknowledged")


class AlertHistory(BaseModel):
    """Complete alert history model"""
    id: int
    rule_id: int
    rule_name: str
    event_type: EventType
    severity: Severity
    channels_notified: List[str]
    event_data: Dict[str, Any]
    message: str
    status: AlertStatus
    error_message: Optional[str] = None
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    created_at: datetime
    channel_results: List[Dict[str, Any]] = []  # absent on rows written before this field existed

    class Config:
        orm_mode = True


# ============================================================================
# Channel Delivery Health Models
# ============================================================================

class ChannelDeliveryHealth(BaseModel):
    """Rolling delivery health for one notification channel, derived from
    its most recent dispatch attempts (see AlertDatabaseService.
    get_channel_delivery_health)."""
    channel_name: str
    attempts: int
    successes: int
    last_attempt_at: Optional[str] = None
    last_success: Optional[bool] = None
    last_error: Optional[str] = None


# ============================================================================
# Alert Statistics Models
# ============================================================================

class AlertStats(BaseModel):
    """Alert statistics and metrics"""
    total_alerts: int
    alerts_by_severity: Dict[str, int]
    alerts_by_status: Dict[str, int]
    alerts_by_event_type: Dict[str, int]
    most_triggered_rules: List[Dict[str, Any]]
    recent_alerts: List[AlertHistory]
    avg_alerts_per_day: float
    alert_rate_trend: str  # "increasing", "decreasing", "stable"


# ============================================================================
# Test Alert Models
# ============================================================================

class TestAlertRequest(BaseModel):
    """Request model for testing an alert channel or rule"""
    test_message: Optional[str] = Field(default="This is a test alert from CyberSentinel WAF")
    test_event_data: Optional[Dict[str, Any]] = Field(default={})


class TestAlertResponse(BaseModel):
    """Response model for test alert"""
    success: bool
    message: str
    details: Optional[Dict[str, Any]] = None
