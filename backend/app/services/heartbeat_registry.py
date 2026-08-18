"""
heartbeat_registry.py — CyberSentinel WAF
===============================================
Shared in-process registry for background-task health.

Three real bugs found in one session shared the same root shape: a
background loop kept running but silently stopped doing useful work —
log retention's purge failing forever behind a buried logger.warning,
log ingestion silently dropping every event on a ClickHouse auth
failure, and /api/health itself not checking ClickHouse at all. Each
was only found by manually digging through logs after the fact.

Rather than re-inventing ad-hoc detection for the next one of these,
every recurring background task in this process calls record_heartbeat()
at the end of each cycle — success or failure both count, since the
point here is "is the loop still alive and cycling", not judging cycle
outcomes (each task already has its own alerting for that, e.g.
log_retention_service's _alert_if_unhealthy). One read
(get_all_heartbeats) then answers "are all my background services
actually running" without digging through logs.

Scope: this is an in-process, in-memory registry — it covers every
background task that runs inside the `backend` container's single
Python process (log retention, log ingestion flush, API discovery,
anti-defacement monitor, SSL monitor). It does NOT cover ml-waf's drift
monitor, which runs as a separate container/process; unifying that
would need a shared external store (DB/HTTP), out of scope here.
"""
import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Every task expected to heartbeat, and its nominal cycle interval in
# seconds. Used both to flag staleness and to catch a task that has
# NEVER reported a single heartbeat (e.g. crashed on its very first
# cycle, or its coroutine was never scheduled due to an import error at
# startup) — get_all_heartbeats() iterates this fixed list, not just
# whatever happens to already be in _heartbeats, so "never started" is
# visible too, not just "went quiet".
EXPECTED_TASKS: Dict[str, float] = {
    "log_retention": 6 * 3600,
    "log_ingestion_flush": 5.0,
    "api_discovery": 10.0,
    "anti_defacement_monitor": 60.0,  # configurable at runtime; this is a display default
    "ssl_monitor": 60.0,
    "auto_learning": 6 * 3600,
}

# A task is "stale" once it's gone this many multiples of its own
# expected interval without a heartbeat — generous enough to absorb
# normal jitter/backoff (e.g. log_ingestion_flush backs off to
# FLUSH_INTERVAL on a ClickHouse failure) while still catching a
# genuinely stuck or crashed loop.
_STALE_MULTIPLIER = 3

_heartbeats: Dict[str, dict] = {}


def record_heartbeat(
    task_name: str,
    expected_interval_seconds: Optional[float] = None,
    status: str = "ok",
    detail: Optional[str] = None,
) -> None:
    """Call at the end of every cycle of a recurring background task.

    expected_interval_seconds is optional per-call because a couple of
    these tasks (anti-defacement) have a runtime-configurable interval —
    pass the actual current value when known; omit it to keep whatever
    was last reported (falls back to EXPECTED_TASKS's static default on
    the very first call).
    """
    prior = _heartbeats.get(task_name)
    interval = (
        expected_interval_seconds
        if expected_interval_seconds is not None
        else (prior["expected_interval_seconds"] if prior else EXPECTED_TASKS.get(task_name, 60.0))
    )
    _heartbeats[task_name] = {
        "last_success_at": datetime.now(timezone.utc).isoformat(),
        "_monotonic": time.monotonic(),
        "expected_interval_seconds": interval,
        "status": status,
        "detail": detail,
    }


def get_all_heartbeats() -> Dict[str, dict]:
    """Snapshot of every expected task's last cycle, with staleness
    computed relative to now. Tasks that have never reported at all are
    included as `never_reported`/`stale: True` rather than being absent."""
    now = time.monotonic()
    out: Dict[str, dict] = {}
    all_names = set(EXPECTED_TASKS) | set(_heartbeats)
    for name in all_names:
        hb = _heartbeats.get(name)
        if hb is None:
            out[name] = {
                "last_success_at": None,
                "seconds_since_last_cycle": None,
                "expected_interval_seconds": EXPECTED_TASKS.get(name, 60.0),
                "status": "never_reported",
                "detail": None,
                "stale": True,
            }
            continue
        seconds_since = now - hb["_monotonic"]
        stale = seconds_since > (hb["expected_interval_seconds"] * _STALE_MULTIPLIER)
        out[name] = {
            "last_success_at": hb["last_success_at"],
            "seconds_since_last_cycle": round(seconds_since, 1),
            "expected_interval_seconds": hb["expected_interval_seconds"],
            "status": hb["status"],
            "detail": hb["detail"],
            "stale": stale,
        }
    return out


# ---------------------------------------------------------------------------
# Watchdog — fires an alert on the transition into "stale", not on every
# check, so an outage generates one alert (plus periodic re-alerts if it
# stays down) instead of spamming every poll cycle.
# ---------------------------------------------------------------------------
_WATCHDOG_CHECK_INTERVAL_SECONDS = 300  # 5 min
_currently_stale: set = set()


async def start_heartbeat_watchdog():
    """Background loop that checks every registered task's staleness and
    fires a health_check_failed alert (existing alerts pipeline) on each
    task's transition into — and logs its transition out of — a stale
    state. Call with asyncio.create_task() during application startup."""
    logger.info(
        f"[HeartbeatWatchdog] Started. Checks every {_WATCHDOG_CHECK_INTERVAL_SECONDS}s."
    )
    # Give every other background task a chance to report its first
    # heartbeat before the first check, so a normal cold start doesn't
    # immediately look like every task is stale.
    await asyncio.sleep(120)

    while True:
        try:
            snapshot = get_all_heartbeats()
            for name, hb in snapshot.items():
                was_stale = name in _currently_stale
                if hb["stale"] and not was_stale:
                    _currently_stale.add(name)
                    await _alert_stale_task(name, hb)
                elif not hb["stale"] and was_stale:
                    _currently_stale.discard(name)
                    logger.info(f"[HeartbeatWatchdog] '{name}' is reporting again — no longer stale.")
        except Exception as e:
            logger.error(f"[HeartbeatWatchdog] Unexpected error during check: {e}")
        await asyncio.sleep(_WATCHDOG_CHECK_INTERVAL_SECONDS)


async def _alert_stale_task(name: str, hb: dict) -> None:
    try:
        from app.services.alert_manager import alert_manager
        if hb["status"] == "never_reported":
            detail = f"Background task '{name}' has never reported a heartbeat — it may have failed to start."
        else:
            detail = (
                f"Background task '{name}' hasn't completed a cycle in "
                f"{hb['seconds_since_last_cycle']:.0f}s (expected every "
                f"{hb['expected_interval_seconds']:.0f}s) — it may be stuck or crashed."
            )
        await alert_manager.trigger_event(
            event_type="health_check_failed",
            event_data={"component": f"background_task:{name}", **hb},
            custom_message=detail,
        )
    except Exception as e:
        logger.error(f"[HeartbeatWatchdog] Failed to dispatch stale-task alert for '{name}': {e}")
