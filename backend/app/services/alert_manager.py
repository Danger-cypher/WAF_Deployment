"""
CyberSentinel WAF - Alerting Rule Evaluation Engine & Manager
"""
import logging
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from app.parsers.nginx_errorlog_parser import extract_crs_score
from app.services.alert_db_service import AlertDatabaseService
from app.services.alert_dispatcher import notification_dispatcher
from app.websocket.connection_manager import manager as ws_manager

logger = logging.getLogger(__name__)

# Default ceiling on how many notifications ONE alert rule may dispatch per
# hour, across every event signature. See the "5b" block in trigger_event()
# for why a per-signature throttle alone is not a bound. Overridable per rule
# via its max_alerts_per_hour column; 0 disables the ceiling for that rule.
MAX_ALERTS_PER_RULE_PER_HOUR = 60


def _to_event_scale(threshold: Any) -> float:
    """Maps an alert-rule threshold onto the 0.0-1.0 scale the ML engine
    actually emits, accepting the 0-100 percentage scale the UI presents.

    The product is inconsistent about this scale and always has been: the
    engine stores threat_score/xgb_prob as 0.0-1.0, while MLEngine.jsx
    renders `value * 100` with a "%", the README says "Threat Score (0 to
    100%)", and the alert-rule builder's placeholder is
    {"threat_score_gt": 80}. An admin following the product's own examples
    wrote thresholds that could never be met.

    The conversion is unambiguous rather than a guess: on a 0.0-1.0 scale a
    threshold above 1.0 is unsatisfiable by definition, so a value >1 can
    only ever have been meant as a percentage. Reinterpreting it strictly
    turns dead rules into working ones and changes the meaning of no rule
    that was already capable of firing. Values <= 1.0 pass through
    untouched, so an operator who wrote 0.85 still gets 0.85.

    See audit finding P1-02.
    """
    try:
        value = float(threshold)
    except (TypeError, ValueError):
        return float("inf")  # Unparseable threshold never matches.
    return value / 100.0 if value > 1.0 else value


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
            #
            # Scale reconciliation (audit finding P1-02). The ML engine emits
            # threat_score on a 0.0-1.0 scale, but the whole product presents
            # it as a percentage: MLEngine.jsx renders `threat_score * 100`
            # with a "%" suffix, the README documents "Threat Score (0 to
            # 100%)", the alert-rule builder's own placeholder text is
            # {"threat_score_gt": 80}, and the seeded default rule "Critical
            # ML Threat" ships with threat_score_gt: 80 and the description
            # "Triggers when combined ML threat score exceeds 80".
            #
            # This comparison used the raw value, so every rule written the
            # way the product itself teaches was unsatisfiable — 0.30 <= 80
            # is always true, so it always returned no-match. Measured on the
            # running deployment: 108,014 scored requests, highest
            # threat_score ever recorded 0.30, zero alerts.
            #
            # _to_event_scale() resolves this without breaking anyone: a
            # threshold above 1.0 cannot be satisfied on a 0-1 scale under
            # any circumstances, so reinterpreting it as a percentage only
            # ever turns a dead rule into a working one. A threshold of 0.85
            # keeps meaning 0.85.
            threat_score_gt = conditions.get("threat_score_gt")
            if threat_score_gt is not None:
                event_score = event_data.get("threat_score")
                if event_score is None or float(event_score) <= _to_event_scale(threat_score_gt):
                    return False

            threat_score_lt = conditions.get("threat_score_lt")
            if threat_score_lt is not None:
                event_score = event_data.get("threat_score")
                if event_score is None or float(event_score) >= _to_event_scale(threat_score_lt):
                    return False

            # 2. CRS Score
            crs_score_gt = conditions.get("crs_score_gt")
            if crs_score_gt is not None:
                # Primary source: LogEntry.crs_score, parsed from the 949110
                # "Total Score: N" message at ingestion. That field did not
                # exist until audit finding P1-02 — the default-enabled
                # "High WAF Attack Rule" (crs_score_gt: 4) read it, always
                # got None, and so returned no-match on every one of the
                # 227,317 events ingested over 51 days. Zero alerts were
                # delivered in that window.
                event_crs = event_data.get("crs_score")

                # Fallback for ml_events-shaped payloads and for events
                # ingested before crs_score existed. The previous version of
                # this fallback was itself broken two ways: raw_log arrives
                # as a JSON *string* (it is a String column in ClickHouse),
                # so .get() on it raised AttributeError straight into the
                # broad except below; and even once decoded there is no
                # "score" key under extracted_fields — the anomaly total is
                # only ever present inside the message text.
                if event_crs is None:
                    raw = event_data.get("raw_log")
                    if isinstance(raw, str):
                        try:
                            raw = json.loads(raw)
                        except (ValueError, TypeError):
                            raw = None
                    if isinstance(raw, dict):
                        fields = raw.get("extracted_fields")
                        if isinstance(fields, dict):
                            event_crs = fields.get("score")
                        if event_crs is None:
                            event_crs = extract_crs_score(raw.get("message") or "")

                # Last resort: the message on the event itself, or on any of
                # its violations. In the JSON audit format the anomaly total
                # sits on the 949110 violation rather than the top-level
                # message.
                if event_crs is None:
                    event_crs = extract_crs_score(event_data.get("message") or "")
                if event_crs is None:
                    for v in event_data.get("violations") or []:
                        msg = v.get("message") if isinstance(v, dict) else getattr(v, "message", None)
                        event_crs = extract_crs_score(msg or "")
                        if event_crs is not None:
                            break

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
            #
            # Sign reconciliation (audit finding P1-02). scikit-learn's
            # IsolationForest.score_samples() is inverted relative to
            # intuition: MORE NEGATIVE means more anomalous, and a normal
            # request scores near zero or above. ml_server.py's own anomaly
            # trigger reflects that — it fires on `iso_score < -0.35`.
            #
            # The seeded rule "ML Novelty Anomaly" ships with
            # isolation_score_gt: 0.5, i.e. it demanded a POSITIVE score,
            # which on this scale means "unusually normal". It could never
            # match an anomaly. Measured live: 106,646 of 108,014 events had
            # iso_score < -0.35 (so the engine raised ml_anomaly for them),
            # and not one of them satisfied the rule that exists to catch them.
            #
            # Compared here against normalized anomaly STRENGTH on a 0-1
            # scale, using the exact same formula threat_score.py already
            # uses to fold this into the combined score (-iso/0.5, clamped).
            # A negative threshold is taken as the raw score, so anyone who
            # understood the sklearn convention and wrote isolation_score_gt:
            # -0.35 keeps the behaviour they intended.
            isolation_score_gt = conditions.get("isolation_score_gt")
            if isolation_score_gt is not None:
                event_iso = event_data.get("iso_score")
                if event_iso is None:
                    return False
                threshold = float(isolation_score_gt)
                if threshold < 0:
                    # Raw sklearn scale: more negative = more anomalous.
                    if float(event_iso) >= threshold:
                        return False
                else:
                    anomaly_strength = min(max(-float(event_iso) / 0.5, 0.0), 1.0)
                    if anomaly_strength <= _to_event_scale(threshold):
                        return False

            # 5. XGBoost Probability — a 0.0-1.0 probability the UI also
            # presents as a percentage, so same reconciliation as above.
            xgb_prob_gt = conditions.get("xgb_prob_gt")
            if xgb_prob_gt is not None:
                event_xgb = event_data.get("xgb_prob")
                if event_xgb is None or float(event_xgb) <= _to_event_scale(xgb_prob_gt):
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

            # 5b. Per-rule notification ceiling (audit finding P1-02).
            #
            # The signature throttle above dedupes per (rule_id, client_ip,
            # uri). That stops the same alert repeating, but puts no bound on
            # a rule that matches broadly — every new IP/URI pair opens its
            # own bucket, so on a busy site a mis-thresholded rule dispatches
            # essentially without limit.
            #
            # Concrete risk in this deployment: the seeded "ML Novelty
            # Anomaly" rule matches on Isolation Forest anomaly strength, and
            # the deployed model scores 100% of real traffic above that bar
            # (108,018 events; the highest iso_score ever recorded is
            # -0.3456, so nothing has ever been classified normal). Fixing
            # the evaluator without this ceiling would have converted a
            # product that delivered zero alerts into one that delivers an
            # alert per request — a worse failure, and one that would bury
            # the genuine attack alerts this work exists to restore.
            #
            # Per-rule and configurable, defaulting to MAX_ALERTS_PER_RULE_PER_HOUR.
            # Set max_alerts_per_hour to 0 on a rule to opt out (e.g. a
            # SIEM-only rule that must forward everything).
            ceiling = rule.get("max_alerts_per_hour")
            ceiling = MAX_ALERTS_PER_RULE_PER_HOUR if ceiling is None else int(ceiling)
            over_ceiling = False
            if ceiling > 0 and not is_throttled:
                recent = self.db.count_recent_notifications(rule_id, minutes=60)
                if recent >= ceiling:
                    over_ceiling = True
                    logger.warning(
                        f"Alert rule '{rule_name}' (ID: {rule_id}) hit its notification "
                        f"ceiling of {ceiling}/hour ({recent} already sent). Further "
                        f"matches this hour are aggregated, not dispatched. This usually "
                        f"means the rule's condition matches far more traffic than "
                        f"intended — review its threshold."
                    )
            is_throttled = is_throttled or over_ceiling

            # Retrieve rule channels
            channels_str = rule.get("channels", "[]")
            try:
                channel_ids = json.loads(channels_str) if isinstance(channels_str, str) else channels_str
            except Exception:
                channel_ids = []

            channels_data = []
            for c_id in channel_ids:
                chan = self.db.get_channel(c_id)
                if chan and chan.get("enabled", True):
                    channels_data.append(chan)

            # Syslog channels bypass throttling entirely and get their own,
            # independent dispatch + history entry — handled unconditionally
            # here, BEFORE the throttle logic below, and without ever
            # touching alert_aggregations. A SIEM wants every matching
            # event for its own correlation, not a deduped subset meant to
            # stop a human-facing Slack/email channel from spamming someone
            # — and since alert_aggregations is one row per (rule_id,
            # event_signature) shared by every channel on the rule, letting
            # syslog's own firing update it would incorrectly reset the
            # throttle clock for the OTHER channels on this same rule too.
            always_send_channels = [c for c in channels_data if c.get("channel_type") == "syslog"]
            throttle_gated_channels = [c for c in channels_data if c.get("channel_type") != "syslog"]
            throttle_gated_names = [c["name"] for c in throttle_gated_channels]

            if always_send_channels:
                always_names = [c["name"] for c in always_send_channels]
                always_results = self.dispatcher.dispatch(
                    channels_list=always_send_channels,
                    severity=severity, event_type=event_type,
                    message=message, event_data=event_data,
                )
                always_failed = [r["channel_name"] for r in always_results if not r["success"]]
                always_status = "failed" if always_failed and len(always_failed) == len(always_send_channels) else "sent"
                always_err = "; ".join(
                    f"{r['channel_name']}: {r['error']}" for r in always_results if r["error"]
                ) or None
                always_id = self.db.create_alert_history(
                    rule_id=rule_id, rule_name=rule_name, event_type=event_type, severity=severity,
                    channels_notified=always_names, event_data=event_data, message=message,
                    status=always_status, error_message=always_err,
                    channel_results=always_results,
                )
                await self._broadcast_new_alert(
                    always_id, rule_id, rule_name, event_type, severity, always_names,
                    event_data, message, always_status, always_err,
                )

            if is_throttled:
                if throttle_gated_channels:
                    logger.info(f"Alert rule '{rule_name}' is currently throttled. Aggregating event.")
                    # Update aggregation entry without sending notification
                    self.db.update_aggregation(rule_id, event_signature, notified=False)
                    # Save to history with status throttled (syslog, if
                    # attached, was already handled unconditionally above)
                    self.db.create_alert_history(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        event_type=event_type,
                        severity=severity,
                        channels_notified=throttle_gated_names,
                        event_data=event_data,
                        message=message,
                        status="throttled"
                    )
                continue

            # Update aggregation entry with notified=True
            self.db.update_aggregation(rule_id, event_signature, notified=True)

            if not throttle_gated_channels:
                if not always_send_channels:
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
            logger.info(f"Dispatching alerts for rule '{rule_name}' to channels: {throttle_gated_names}")
            dispatch_results = self.dispatcher.dispatch(
                channels_list=throttle_gated_channels,
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
                if len(failed_channels) == len(throttle_gated_channels):
                    status_str = "failed"
                err_msg = "; ".join(error_msgs)

            new_id = self.db.create_alert_history(
                rule_id=rule_id,
                rule_name=rule_name,
                event_type=event_type,
                severity=severity,
                channels_notified=throttle_gated_names,
                event_data=event_data,
                message=message,
                status=status_str,
                error_message=err_msg,
                channel_results=dispatch_results,
            )
            await self._broadcast_new_alert(
                new_id, rule_id, rule_name, event_type, severity, throttle_gated_names,
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
