"""
CyberSentinel WAF - Alerting Rule Evaluation Engine & Manager
"""
import logging
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from app.services.alert_db_service import AlertDatabaseService
from app.services.alert_dispatcher import notification_dispatcher
from app.websocket.connection_manager import manager as ws_manager

logger = logging.getLogger(__name__)


class AlertManager:
    """Manages evaluation of security events against rules and dispatches alerts"""

    def __init__(self):
        self.db = AlertDatabaseService()
        self.dispatcher = notification_dispatcher

    def evaluate_condition(self, conditions: Dict[str, Any], event_data: Dict[str, Any]) -> bool:
        """
        Evaluates whether event_data matches the given conditions.
        Returns True if all conditions are met, False otherwise.
        """
        try:
            # 1. Threat Score
            threat_score_gt = conditions.get("threat_score_gt")
            if threat_score_gt is not None:
                event_score = event_data.get("threat_score")
                if event_score is None or float(event_score) <= float(threat_score_gt):
                    return False

            threat_score_lt = conditions.get("threat_score_lt")
            if threat_score_lt is not None:
                event_score = event_data.get("threat_score")
                if event_score is None or float(event_score) >= float(threat_score_lt):
                    return False

            # 2. CRS Score
            crs_score_gt = conditions.get("crs_score_gt")
            if crs_score_gt is not None:
                # ModSecurity scores can be in crs_score or violations[0].rule_id, or just raw crs_score in ml events
                event_crs = event_data.get("crs_score")
                # Sometimes it might be raw score from ModSecurity parsed log
                if event_crs is None:
                    # Look inside raw log or extracted fields if available
                    event_crs = event_data.get("raw_log", {}).get("extracted_fields", {}).get("score")
                if event_crs is None:
                    return False
                try:
                    if float(event_crs) <= float(crs_score_gt):
                        return False
                except (ValueError, TypeError):
                    return False

            # 3. Request rate limit (RPM)
            rpm_gt = conditions.get("rpm_gt")
            if rpm_gt is not None:
                event_rpm = event_data.get("redis_rpm") or event_data.get("rpm")
                if event_rpm is None or int(event_rpm) <= int(rpm_gt):
                    return False

            # 4. ML Novelty/Isolation Forest score
            isolation_score_gt = conditions.get("isolation_score_gt")
            if isolation_score_gt is not None:
                event_iso = event_data.get("iso_score")
                if event_iso is None or float(event_iso) <= float(isolation_score_gt):
                    return False

            # 5. XGBoost Probability
            xgb_prob_gt = conditions.get("xgb_prob_gt")
            if xgb_prob_gt is not None:
                event_xgb = event_data.get("xgb_prob")
                if event_xgb is None or float(event_xgb) <= float(xgb_prob_gt):
                    return False

            # 6. Geolocation filters
            blocked_countries = conditions.get("blocked_countries")
            if blocked_countries:
                event_country = event_data.get("country")
                if not event_country or event_country not in blocked_countries:
                    return False

            allowed_countries = conditions.get("allowed_countries")
            if allowed_countries:
                event_country = event_data.get("country")
                if not event_country or event_country in allowed_countries:
                    return False

            # 7. Custom conditions (strict equal checks)
            custom_conditions = conditions.get("custom_conditions") or {}
            for key, val in custom_conditions.items():
                if event_data.get(key) != val:
                    return False

            return True
        except Exception as e:
            logger.error(f"Error evaluating alert conditions: {e}")
            return False

    async def trigger_event(self, event_type: str, event_data: Dict[str, Any], custom_message: Optional[str] = None):
        """
        Trigger an alert event. Evaluates rules, throttles, and dispatches.
        """
        logger.info(f"Triggering alert event of type '{event_type}'")
        
        # 1. Fetch enabled rules for event type
        rules = self.db.get_rules(enabled_only=True, event_type=event_type)
        if not rules:
            logger.debug(f"No enabled alert rules found for event type: {event_type}")
            return

        for rule in rules:
            rule_id = rule["id"]
            rule_name = rule["name"]
            severity = rule["severity"]
            throttle_minutes = rule.get("throttle_minutes", 5)

            # Safely parse conditions
            conds_str = rule.get("conditions", "{}")
            try:
                conditions = json.loads(conds_str) if isinstance(conds_str, str) else conds_str
            except Exception:
                conditions = {}

            # 2. Evaluate conditions
            if not self.evaluate_condition(conditions, event_data):
                continue

            logger.info(f"Alert rule '{rule_name}' (ID: {rule_id}) condition matched!")

            # 3. Create default message if not provided
            message = custom_message
            if not message:
                client_ip = event_data.get("client_ip") or event_data.get("remote_addr") or "Unknown IP"
                uri = event_data.get("uri") or "N/A"
                if event_type == "attack_detected":
                    msg_detail = event_data.get("message") or "WAF Rule Triggered"
                    message = f"Attack detected and blocked from IP {client_ip} on URI {uri}. Reason: {msg_detail}"
                elif event_type == "high_threat_score":
                    score = event_data.get("threat_score", 0.0)
                    message = f"ML Engine flagged high threat score ({score}) from IP {client_ip} on URI {uri}."
                elif event_type == "ddos_detected":
                    message = f"DDoS / Traffic anomaly detected from IP {client_ip}."
                elif event_type == "ml_anomaly":
                    message = f"Anomaly detected by Isolation Forest model from IP {client_ip}."
                elif event_type == "system_error":
                    message = f"System error occurred in WAF components: {event_data.get('error', 'Unknown error')}"
                elif event_type == "health_check_failed":
                    message = f"WAF Component health check failed: {event_data.get('component', 'Unknown component')}"
                else:
                    message = f"Security event '{event_type}' triggered on CyberSentinel WAF."

            # 4. Generate signature for deduplication
            # Deduplicate by rule_id + client_ip + URI (if present)
            sig_source = {
                "rule_id": rule_id,
                "client_ip": event_data.get("client_ip") or event_data.get("remote_addr") or "",
                "uri": event_data.get("uri") or ""
            }
            event_signature = AlertDatabaseService.generate_event_signature(sig_source)

            # 5. Check throttling
            is_throttled = self.db.should_throttle_alert(rule_id, event_signature, throttle_minutes)

            # Retrieve rule channels
            channels_str = rule.get("channels", "[]")
            try:
                channel_ids = json.loads(channels_str) if isinstance(channels_str, str) else channels_str
            except Exception:
                channel_ids = []

            channels_data = []
            channels_notified_names = []
            for c_id in channel_ids:
                chan = self.db.get_channel(c_id)
                if chan and chan.get("enabled", True):
                    channels_data.append(chan)
                    channels_notified_names.append(chan["name"])

            if is_throttled:
                logger.info(f"Alert rule '{rule_name}' is currently throttled. Aggregating event.")
                # Update aggregation entry without sending notification
                self.db.update_aggregation(rule_id, event_signature, notified=False)
                # Save to history with status throttled
                self.db.create_alert_history(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    event_type=event_type,
                    severity=severity,
                    channels_notified=channels_notified_names,
                    event_data=event_data,
                    message=message,
                    status="throttled"
                )
                continue

            # Update aggregation entry with notified=True
            self.db.update_aggregation(rule_id, event_signature, notified=True)

            if not channels_data:
                logger.warning(f"No active notification channels configured for rule: {rule_name}")
                new_id = self.db.create_alert_history(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    event_type=event_type,
                    severity=severity,
                    channels_notified=[],
                    event_data=event_data,
                    message=message,
                    status="sent",
                    error_message="No active notification channels configured."
                )
                await self._broadcast_new_alert(
                    new_id, rule_id, rule_name, event_type, severity, [],
                    event_data, message, "sent", "No active notification channels configured."
                )
                continue

            # 6. Dispatch notifications
            logger.info(f"Dispatching alerts for rule '{rule_name}' to channels: {channels_notified_names}")
            dispatch_results = self.dispatcher.dispatch(
                channels_list=channels_data,
                severity=severity,
                event_type=event_type,
                message=message,
                event_data=event_data
            )

            # 7. Log result to Alert History
            failed_channels = [r["channel_name"] for r in dispatch_results if not r["success"]]
            error_msgs = [f"{r['channel_name']}: {r['error']}" for r in dispatch_results if r["error"]]

            status_str = "sent"
            err_msg = None
            if failed_channels:
                if len(failed_channels) == len(channels_data):
                    status_str = "failed"
                err_msg = "; ".join(error_msgs)

            new_id = self.db.create_alert_history(
                rule_id=rule_id,
                rule_name=rule_name,
                event_type=event_type,
                severity=severity,
                channels_notified=channels_notified_names,
                event_data=event_data,
                message=message,
                status=status_str,
                error_message=err_msg
            )
            await self._broadcast_new_alert(
                new_id, rule_id, rule_name, event_type, severity, channels_notified_names,
                event_data, message, status_str, err_msg
            )

    async def _broadcast_new_alert(
        self, alert_id: int, rule_id: int, rule_name: str, event_type: str, severity: str,
        channels_notified: List[str], event_data: Dict[str, Any], message: str,
        status: str, error_message: Optional[str],
    ):
        """Push a freshly-created (non-throttled) alert_history row to connected
        dashboards over the WebSocket, so the notification bell updates live
        instead of polling. Shape mirrors the AlertHistory REST model."""
        if alert_id <= 0:
            return
        try:
            await ws_manager.broadcast_alert({
                "id": alert_id,
                "rule_id": rule_id,
                "rule_name": rule_name,
                "event_type": event_type,
                "severity": severity,
                "channels_notified": channels_notified,
                "event_data": event_data,
                "message": message,
                "status": status,
                "error_message": error_message,
                "acknowledged_by": None,
                "acknowledged_at": None,
                "created_at": datetime.now(timezone.utc).isoformat(),
            })
        except Exception as e:
            logger.error(f"Failed to broadcast alert over websocket: {e}")


# Global alert manager instance
alert_manager = AlertManager()
