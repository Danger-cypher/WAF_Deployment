"""
redis_degraded_monitor.py — CyberSentinel WAF
===============================================
Watches for the WAF's own Redis-degraded-mode marker line in nginx's error
log (emitted by ml-waf/waf_redis.lua on every Redis connect/auth failure,
rate-limited via an nginx shared dict — see that file's comment) and
reports it through the existing heartbeat_registry, so a Redis outage that
used to fail open completely silently — IP/geo/bot/schema checks all
skipped, nobody notified — now surfaces as "WAF running in degraded mode"
through the same health/alerting surface as any other component.

Bridging note: heartbeat_registry's own docstring scopes it to tasks
running inside THIS process; the actual failure this module watches for
originates in Lua, inside the openresty container. The bridge is nginx's
error log itself — already readable from the backend container (see
docker-compose.yml; the same volume log_ingestor already reads
ModSecurity entries from) — not a new mechanism. Redis can't be the
bridge here, since Redis being unreachable is precisely the condition
being reported.
"""
import os
import re
import logging
import asyncio
from datetime import datetime

import pytz

from app.services import heartbeat_registry

logger = logging.getLogger(__name__)

ERROR_LOG_PATH = os.environ.get("NGINX_ERROR_LOG_PATH", "/var/log/nginx/error.log")
CHECK_INTERVAL_SECONDS = 60

# Matches ml-waf/waf_redis.lua's log_degraded() marker exactly.
MARKER = "ML-WAF-REDIS-DEGRADED"

# Bounded tail read instead of reading the whole file — this log can grow
# large over time; 256KB comfortably covers several minutes of real
# traffic volume even under load.
TAIL_BYTES = 262144

# A marker line only counts as "currently degraded" if it's within this
# many seconds of now. Must be longer than waf_redis.lua's own 30s
# log-rate-limit window, or a still-ongoing outage could read as healthy
# in the gap between rate-limited log lines.
FRESHNESS_SECONDS = 120

_TIMESTAMP_RE = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")
# nginx logs in the container's local time (IST here, via the /etc/localtime
# bind mount) — same conversion crs_audit_enrichment.py already does for
# the same reason.
_LOCAL_TZ = pytz.timezone("Asia/Kolkata")


def _tail_lines(path: str, max_bytes: int) -> list:
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
                f.readline()  # discard the partial first line from the seek
            return f.readlines()
    except OSError as e:
        logger.warning(f"Could not read nginx error log for Redis-degraded check: {e}")
        return []


def check_redis_degraded() -> dict:
    """Returns {'degraded': bool, 'last_seen_utc': str|None}."""
    latest_utc = None
    for line in _tail_lines(ERROR_LOG_PATH, TAIL_BYTES):
        if MARKER not in line:
            continue
        m = _TIMESTAMP_RE.match(line)
        if not m:
            continue
        try:
            dt_local = _LOCAL_TZ.localize(datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S"))
            dt_utc = dt_local.astimezone(pytz.UTC)
        except ValueError:
            continue
        if latest_utc is None or dt_utc > latest_utc:
            latest_utc = dt_utc

    if latest_utc is None:
        return {"degraded": False, "last_seen_utc": None}

    age_seconds = (datetime.now(pytz.UTC) - latest_utc).total_seconds()
    return {
        "degraded": age_seconds <= FRESHNESS_SECONDS,
        "last_seen_utc": latest_utc.isoformat(),
    }


async def _alert_degraded(result: dict) -> None:
    try:
        from app.services.alert_manager import alert_manager
        await alert_manager.trigger_event(
            event_type="health_check_failed",
            event_data={"component": "waf_redis_degraded", **result},
            custom_message=(
                "WAF running in degraded mode: openresty cannot reach Redis. "
                "IP/geo blocking, bot-challenge, and schema validation are "
                "failing open until Redis recovers."
            ),
        )
    except Exception as e:
        logger.error(f"Failed to dispatch Redis-degraded-mode alert: {e}")


async def start_redis_degraded_monitor():
    """
    Background loop, same shape as the other schedulers in this codebase.
    Reports through heartbeat_registry every cycle — deliberately using
    status="error" while degraded (not just on the monitor's own
    exceptions, unlike every other task here) because surfacing the
    degraded condition itself IS this task's entire purpose, not a
    side effect of it. Fires a real alert only on the transition into
    degraded mode, same "alert on transition, not on every poll" shape
    heartbeat_registry's own watchdog uses, so an outage generates one
    alert instead of one every cycle.
    """
    logger.info(
        f"Redis-degraded-mode monitor started. Checks every {CHECK_INTERVAL_SECONDS}s."
    )
    await asyncio.sleep(30)  # Initial delay for app to fully initialize

    was_degraded = False
    while True:
        try:
            result = check_redis_degraded()
            if result["degraded"] and not was_degraded:
                logger.warning(
                    "WAF entering Redis-degraded mode — "
                    "IP/geo/bot/schema checks are failing open."
                )
                await _alert_degraded(result)
            elif not result["degraded"] and was_degraded:
                logger.info("WAF has recovered from Redis-degraded mode.")
            was_degraded = result["degraded"]

            heartbeat_registry.record_heartbeat(
                "waf_redis_degraded", CHECK_INTERVAL_SECONDS,
                status="error" if result["degraded"] else "ok",
                detail=(
                    f"Redis unreachable from openresty since {result['last_seen_utc']}"
                    if result["degraded"] else None
                ),
            )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"Redis-degraded-mode monitor encountered an error: {e}")
            heartbeat_registry.record_heartbeat(
                "waf_redis_degraded", CHECK_INTERVAL_SECONDS,
                status="error", detail=str(e),
            )
        await asyncio.sleep(CHECK_INTERVAL_SECONDS)
