import json
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from app.services import db_service, rule_manager
from app.services.settings_manager import settings_manager

logger = logging.getLogger(__name__)

CHECK_INTERVAL_SECONDS = 6 * 3600

_PERIOD_DAYS = {"3 Days": 3, "7 Days": 7, "14 Days": 14, "30 Days": 30}

# rule_manager.suggest_exclusion()'s confidence label mapped to a numeric
# base score, then nudged up per repeat occurrence — a pattern seen many
# times is worth more trust than one seen once, even at the same base label.
_CONFIDENCE_BASE = {"high": 90, "medium": 65, "low": 35}


def _parse_period_days(period: str) -> int:
    return _PERIOD_DAYS.get(period, 7)


def _within_window(timestamp_str: str, cutoff: datetime) -> bool:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(timestamp_str[:19], fmt) >= cutoff
        except ValueError:
            continue
    return True  # unparseable timestamp — don't silently drop real data


def _active_exclusion_key_set() -> set:
    keys = set()
    for exc in db_service.get_all_active_exclusions():
        keys.add((exc.get("rule_id"), exc.get("exclusion_type"), exc.get("uri"), exc.get("parameter_name")))
    return keys


def compute_and_store_suggestions(force: bool = False) -> Dict[str, Any]:
    """
    Scans Resolved false positives observed within the configured Auto-
    Learning window, groups them by the exclusion pattern
    rule_manager.suggest_exclusion() would recommend for each, and upserts
    a Pending suggestion for every pattern whose confidence clears the
    configured threshold.

    Deliberately never writes an exclusion or touches NGINX/ModSecurity
    itself — this only ever populates auto_learning_suggestions for an
    admin to review. See routes/auto_learning.py's approve endpoint for the
    explicit human step that actually applies one.

    `force=True` runs even if Auto-Learning is disabled in Settings (used
    by the manual "Run now" action); the background scheduler always calls
    with force=False so disabling the toggle actually stops new suggestions
    from appearing.
    """
    settings = settings_manager.get_auto_learning()
    if not force and not settings.get("enabled"):
        return {"ran": False, "reason": "Auto-Learning is disabled."}

    period_days = _parse_period_days(settings.get("learning_period", "7 Days"))
    threshold = int(settings.get("confidence_threshold", 90))
    cutoff = datetime.now() - timedelta(days=period_days)

    entries = db_service.get_all_false_positives(status="Resolved")
    active_keys = _active_exclusion_key_set()

    groups: Dict[tuple, Dict[str, Any]] = {}
    for entry in entries:
        ts = entry.get("timestamp") or ""
        if not _within_window(ts, cutoff):
            continue

        raw_log = entry.get("raw_log")
        if isinstance(raw_log, str):
            try:
                raw_log = json.loads(raw_log)
            except Exception:
                raw_log = {}

        suggestion = rule_manager.suggest_exclusion(
            raw_log, entry.get("rule_id", ""), entry.get("uri")
        )
        exclusion_type = suggestion.get("exclusion_type")
        parameter_name = suggestion.get("parameter_name")
        uri = (
            entry.get("uri")
            if exclusion_type in ("uri", "uri_parameter", "endpoint_method", "ip_suppression")
            else None
        )
        rule_id = entry.get("rule_id")

        key = (rule_id, exclusion_type, uri, parameter_name)
        if key in active_keys:
            continue  # already excluded — nothing to suggest

        group = groups.setdefault(
            key,
            {
                "rule_id": rule_id,
                "exclusion_type": exclusion_type,
                "uri": uri,
                "parameter_name": parameter_name,
                "base_confidence": suggestion.get("confidence"),
                "reasoning": suggestion.get("reasoning"),
                "fp_ids": [],
            },
        )
        fp_id = entry.get("id")
        if fp_id is not None:
            group["fp_ids"].append(fp_id)

    stored, skipped_low_confidence = 0, 0
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for group in groups.values():
        occurrence_count = max(len(group["fp_ids"]), 1)
        base = _CONFIDENCE_BASE.get(group["base_confidence"], 35)
        score = min(99, base + min(occurrence_count - 1, 5) * 3)

        if score < threshold:
            skipped_low_confidence += 1
            continue

        result = db_service.upsert_auto_learning_suggestion(
            rule_id=group["rule_id"],
            exclusion_type=group["exclusion_type"],
            uri=group["uri"],
            parameter_name=group["parameter_name"],
            confidence_score=score,
            reasoning=group["reasoning"],
            false_positive_ids=group["fp_ids"],
            timestamp=timestamp,
        )
        if result:
            stored += 1

    logger.info(
        f"Auto-Learning cycle: {len(entries)} resolved FPs scanned, "
        f"{len(groups)} candidate patterns, {stored} suggestions stored/updated, "
        f"{skipped_low_confidence} below confidence threshold ({threshold}%)."
    )
    return {
        "ran": True,
        "scanned_false_positives": len(entries),
        "candidate_patterns": len(groups),
        "suggestions_stored": stored,
        "skipped_low_confidence": skipped_low_confidence,
    }


async def start_auto_learning_scheduler():
    """
    Background loop, same shape as log_retention_service's: an initial
    settle delay, then run-then-sleep every CHECK_INTERVAL_SECONDS. Runs
    unconditionally (compute_and_store_suggestions handles the enabled
    check itself) so toggling Auto-Learning on doesn't require a restart
    to take effect on the next cycle.
    """
    logger.info(
        f"Auto-Learning scheduler started. Runs every "
        f"{CHECK_INTERVAL_SECONDS // 3600}h when enabled in Settings."
    )
    await asyncio.sleep(60)  # Initial delay for app to fully initialize

    from app.services import heartbeat_registry

    while True:
        try:
            result = compute_and_store_suggestions(force=False)
            logger.info(f"Auto-Learning scheduled cycle result: {result}")
            heartbeat_registry.record_heartbeat(
                "auto_learning", CHECK_INTERVAL_SECONDS, status="ok"
            )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"Auto-Learning scheduler encountered an error: {e}")
            heartbeat_registry.record_heartbeat(
                "auto_learning", CHECK_INTERVAL_SECONDS, status="error", detail=str(e)
            )
        await asyncio.sleep(CHECK_INTERVAL_SECONDS)
