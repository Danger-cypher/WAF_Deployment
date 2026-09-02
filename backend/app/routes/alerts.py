"""
CyberSentinel WAF - Alerting Routes
"""
import logging
import secrets
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, Header, HTTPException, status, Query

from app.models.alert_models import (
    AlertChannelCreate, AlertChannelUpdate, AlertChannel,
    AlertRuleCreate, AlertRuleUpdate, AlertRule,
    AlertHistory, AlertStats, TestAlertRequest, TestAlertResponse,
    ChannelDeliveryHealth,
)
from app.services.alert_db_service import AlertDatabaseService
from app.services.alert_manager import alert_manager
from app.services.auth import require_admin, require_any_role, TokenData
from app.config.settings import settings

logger = logging.getLogger(__name__)
router = APIRouter()
db = AlertDatabaseService()

# Config keys that hold live credentials (SMTP passwords, Slack/PagerDuty
# webhook URLs and keys act as bearer secrets, arbitrary webhook headers may
# carry an Authorization token). GET /alerts/channels is require_any_role
# (analysts need to see what channels exist), so these are masked unless
# the caller is an admin — otherwise any analyst could read every
# configured integration's credentials straight off this page.
# "url" (not "webhook_url") is the generic Webhook channel's own endpoint
# field (WebhookChannelConfig.url) — omitted here, this leaked exactly the
# same class of secret Slack's webhook_url is masked for, since a webhook
# endpoint's URL commonly carries its own bearer token/signature.
_SECRET_CONFIG_KEYS = {"password", "webhook_url", "integration_key", "url"}
_REDACTED = "••••••••"


def _redact_channel_config(config: dict) -> dict:
    redacted = dict(config)
    for key in redacted:
        if key in _SECRET_CONFIG_KEYS and redacted[key]:
            redacted[key] = _REDACTED
    if isinstance(redacted.get("headers"), dict):
        redacted["headers"] = {k: _REDACTED for k in redacted["headers"]}
    return redacted


# ============================================================================
# Alert Channels API
# ============================================================================

@router.post("/alerts/channels", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_channel(channel: AlertChannelCreate, current_user: TokenData = Depends(require_admin)):
    """Create a new notification channel (Admin only)"""
    try:
        channel_id = db.create_channel(
            name=channel.name,
            channel_type=channel.channel_type.value,
            config=channel.config,
            enabled=channel.enabled
        )
        return {"id": channel_id, "message": "Notification channel created successfully."}
    except Exception as e:
        logger.error(f"Error creating notification channel: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create channel: {str(e)}"
        )


@router.get("/alerts/channels", response_model=List[AlertChannel])
async def get_channels(enabled_only: bool = False, current_user: TokenData = Depends(require_any_role)):
    """List all notification channels (Any role)"""
    try:
        chans = db.get_channels(enabled_only=enabled_only)
        # Parse text/json in SQLite to python dict if necessary
        for c in chans:
            if isinstance(c["config"], str):
                import json
                c["config"] = json.loads(c["config"])
            if current_user.role != "admin":
                c["config"] = _redact_channel_config(c["config"])
        return chans
    except Exception as e:
        logger.error(f"Error getting notification channels: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve channels."
        )


@router.get("/alerts/channels/health", response_model=List[ChannelDeliveryHealth])
async def get_channels_health(current_user: TokenData = Depends(require_any_role)):
    """
    Rolling per-channel delivery health (attempts/successes/last outcome),
    derived from each channel's own dispatch results across recent alert
    history — see AlertDatabaseService.get_channel_delivery_health. Must be
    registered before /alerts/channels/{channel_id} — otherwise "health"
    matches that route's int channel_id and 422s.
    """
    try:
        return db.get_channel_delivery_health()
    except Exception as e:
        logger.error(f"Error computing channel delivery health: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to compute channel delivery health."
        )


@router.get("/alerts/channels/{channel_id}", response_model=AlertChannel)
async def get_channel(channel_id: int, current_user: TokenData = Depends(require_any_role)):
    """Get details of a notification channel (Any role)"""
    chan = db.get_channel(channel_id)
    if not chan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Channel with ID {channel_id} not found."
        )
    if isinstance(chan["config"], str):
        import json
        chan["config"] = json.loads(chan["config"])
    if current_user.role != "admin":
        chan["config"] = _redact_channel_config(chan["config"])
    return chan


@router.put("/alerts/channels/{channel_id}", response_model=Dict[str, Any])
async def update_channel(channel_id: int, channel: AlertChannelUpdate, current_user: TokenData = Depends(require_admin)):
    """Update a notification channel (Admin only)"""
    update_data = {}
    if channel.name is not None:
        update_data["name"] = channel.name
    if channel.config is not None:
        update_data["config"] = channel.config
    if channel.enabled is not None:
        update_data["enabled"] = channel.enabled

    if not update_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No update fields provided."
        )

    success = db.update_channel(channel_id, **update_data)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Channel with ID {channel_id} not found or failed to update."
        )
    return {"message": "Notification channel updated successfully."}


@router.delete("/alerts/channels/{channel_id}", response_model=Dict[str, Any])
async def delete_channel(channel_id: int, current_user: TokenData = Depends(require_admin)):
    """Delete a notification channel (Admin only)"""
    success = db.delete_channel(channel_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Channel with ID {channel_id} not found or failed to delete."
        )
    return {"message": "Notification channel deleted successfully."}


@router.post("/alerts/channels/{channel_id}/test", response_model=TestAlertResponse)
async def test_channel(channel_id: int, req: TestAlertRequest, current_user: TokenData = Depends(require_admin)):
    """Send a test notification through the configured channel (Admin only)"""
    chan = db.get_channel(channel_id)
    if not chan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Channel with ID {channel_id} not found."
        )
    
    # Safely load config
    import json
    c_config = chan["config"]
    if isinstance(c_config, str):
        try:
            c_config = json.loads(c_config)
        except Exception:
            pass

    from app.services.alert_dispatcher import notification_dispatcher
    handler = notification_dispatcher.channels.get(chan["channel_type"])
    if not handler:
        return TestAlertResponse(
            success=False,
            message=f"No notification handler registered for type: {chan['channel_type']}"
        )

    success, err = handler.send(
        config=c_config,
        severity="info",
        event_type="health_check_failed",
        message=req.test_message,
        event_data=req.test_event_data or {"test": "data"}
    )
    
    return TestAlertResponse(
        success=success,
        message="Test alert sent successfully." if success else f"Test alert failed: {err}",
        details={"error": err} if not success else None
    )


# ============================================================================
# Alert Rules API
# ============================================================================

@router.post("/alerts/rules", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_rule(rule: AlertRuleCreate, current_user: TokenData = Depends(require_admin)):
    """Create a new alert rule (Admin only)"""
    try:
        rule_id = db.create_rule(
            name=rule.name,
            event_type=rule.event_type.value,
            severity=rule.severity.value,
            conditions=rule.conditions,
            channels=rule.channels,
            throttle_minutes=rule.throttle_minutes,
            enabled=rule.enabled
        )
        return {"id": rule_id, "message": "Alert rule created successfully."}
    except Exception as e:
        logger.error(f"Error creating alert rule: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create alert rule: {str(e)}"
        )


@router.get("/alerts/rules", response_model=List[AlertRule])
async def get_rules(enabled_only: bool = False, current_user: TokenData = Depends(require_any_role)):
    """List all alert rules (Any role)"""
    try:
        rules = db.get_rules(enabled_only=enabled_only)
        import json
        for r in rules:
            if isinstance(r["conditions"], str):
                r["conditions"] = json.loads(r["conditions"])
            if isinstance(r["channels"], str):
                r["channels"] = json.loads(r["channels"])
        return rules
    except Exception as e:
        logger.error(f"Error getting alert rules: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve rules."
        )


@router.get("/alerts/rules/{rule_id}", response_model=AlertRule)
async def get_rule(rule_id: int, current_user: TokenData = Depends(require_any_role)):
    """Get details of an alert rule (Any role)"""
    rule = db.get_rule(rule_id)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule with ID {rule_id} not found."
        )
    import json
    if isinstance(rule["conditions"], str):
        rule["conditions"] = json.loads(rule["conditions"])
    if isinstance(rule["channels"], str):
        rule["channels"] = json.loads(rule["channels"])
    return rule


@router.put("/alerts/rules/{rule_id}", response_model=Dict[str, Any])
async def update_rule(rule_id: int, rule: AlertRuleUpdate, current_user: TokenData = Depends(require_admin)):
    """Update an alert rule (Admin only)"""
    update_data = {}
    if rule.name is not None:
        update_data["name"] = rule.name
    if rule.description is not None:
        update_data["description"] = rule.description
    if rule.event_type is not None:
        update_data["event_type"] = rule.event_type.value
    if rule.severity is not None:
        update_data["severity"] = rule.severity.value
    if rule.conditions is not None:
        update_data["conditions"] = rule.conditions
    if rule.channels is not None:
        update_data["channels"] = rule.channels
    if rule.throttle_minutes is not None:
        update_data["throttle_minutes"] = rule.throttle_minutes
    if rule.enabled is not None:
        update_data["enabled"] = rule.enabled

    if not update_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No update fields provided."
        )

    success = db.update_rule(rule_id, **update_data)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule with ID {rule_id} not found or failed to update."
        )
    return {"message": "Alert rule updated successfully."}


@router.delete("/alerts/rules/{rule_id}", response_model=Dict[str, Any])
async def delete_rule(rule_id: int, current_user: TokenData = Depends(require_admin)):
    """Delete an alert rule (Admin only)"""
    success = db.delete_rule(rule_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule with ID {rule_id} not found or failed to delete."
        )
    return {"message": "Alert rule deleted successfully."}


# ============================================================================
# Alert History & Operations API
# ============================================================================

@router.get("/alerts/history", response_model=List[AlertHistory])
async def get_history(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    current_user: TokenData = Depends(require_any_role)
):
    """Retrieve filtered and paginated alert history logs (Any role)"""
    try:
        logs = db.get_alert_history(
            limit=limit,
            offset=offset,
            event_type=event_type,
            severity=severity,
            status=status
        )
        import json
        for l in logs:
            if isinstance(l["channels_notified"], str):
                l["channels_notified"] = json.loads(l["channels_notified"])
            if isinstance(l["event_data"], str):
                l["event_data"] = json.loads(l["event_data"])
            if isinstance(l.get("channel_results"), str):
                l["channel_results"] = json.loads(l["channel_results"] or "[]")
        return logs
    except Exception as e:
        logger.error(f"Error fetching alert history: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve alert history."
        )


@router.post("/alerts/history/{alert_id}/acknowledge", response_model=Dict[str, Any])
async def acknowledge_alert(alert_id: int, current_user: TokenData = Depends(require_any_role)):
    """Acknowledge a triggered alert (Any role)"""
    # acknowledged_by comes from the verified session, not client input,
    # so the audit trail can't be spoofed by whatever the frontend sends.
    success = db.acknowledge_alert(alert_id, current_user.username)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert log with ID {alert_id} not found or already acknowledged."
        )
    return {"message": "Alert acknowledged successfully."}


@router.get("/alerts/stats", response_model=AlertStats)
async def get_stats(days: int = Query(30, ge=1, le=365), current_user: TokenData = Depends(require_any_role)):
    """Get alert system statistics and metrics (Any role)"""
    try:
        stats = db.get_alert_stats(days=days)
        # Parse history items in recent_alerts
        import json
        for l in stats.get("recent_alerts", []):
            if isinstance(l["channels_notified"], str):
                l["channels_notified"] = json.loads(l["channels_notified"])
            if isinstance(l["event_data"], str):
                l["event_data"] = json.loads(l["event_data"])
        return stats
    except Exception as e:
        logger.error(f"Error fetching alert stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch alert stats: {str(e)}"
        )


# ============================================================================
# Alert Trigger API (Internal/External trigger Integration endpoint)
# ============================================================================

trigger_router = APIRouter()


def verify_internal_key(x_internal_key: Optional[str] = Header(default=None)) -> None:
    """
    Guards internal service-to-service endpoints (e.g. waf-ml -> backend).
    This is not a user session - callers authenticate with a shared secret
    (INTERNAL_ALERT_TRIGGER_KEY) sent as the X-Internal-Key header, since
    this endpoint is reachable both from other containers on waf-network
    and, via the /api/ reverse-proxy rule, from the public internet.
    """
    if not x_internal_key or not secrets.compare_digest(
        x_internal_key, settings.INTERNAL_ALERT_TRIGGER_KEY
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing internal service credentials."
        )


@trigger_router.post(
    "/alerts/trigger",
    response_model=Dict[str, Any],
    dependencies=[Depends(verify_internal_key)],
)
async def trigger_alert_event(payload: Dict[str, Any]):
    """
    Triggers an alert rule based on external data (like from waf-ml container).
    Expects event_type and event_data fields in json.
    """
    event_type = payload.get("event_type")
    event_data = payload.get("event_data")
    message = payload.get("message")

    if not event_type or not event_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing event_type or event_data in payload."
        )

    # Run Rule engine triggering asynchronously in background
    import asyncio
    asyncio.create_task(alert_manager.trigger_event(event_type, event_data, message))
    
    return {"status": "success", "message": "Event queued for alert evaluation."}

