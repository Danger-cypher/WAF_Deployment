"""
auto_reputation_service.py — CyberSentinel WAF
===============================================
Background service that watches CyberSentinel's own WAF traffic (not a
third-party feed — see threat_intel_service.py for that) for IPs that have
racked up enough blocked requests to count as proven repeat offenders
against this specific deployment, and auto-blocks them — a genuine
self-tuning defense that improves with traffic, on top of (not instead
of) the admin-managed blacklist and the external threat-intel feed.

Kept in its own Redis key namespace (waf:blacklist:auto:<ip>, individual
TTL'd keys — not a CIDR set like the feed tier, since these are individual
IPs with individual expiry, and Redis SET members can't carry per-member
TTLs) so a sync cycle can never clobber the admin-managed blacklist or the
feed tier, and vice versa. Checked LAST in ml_check.lua's check_ip_auth()
— the least-authoritative tier, machine-generated from inference rather
than admin intent or a curated feed, and self-expiring via TTL rather than
a permanent list that only grows. Never overrides the whitelist: an IP is
skipped from auto-blocking entirely if it's already whitelisted (belt and
suspenders — check_ip_auth() would also never reach this tier for a
whitelisted IP anyway, since whitelist is checked first and returns
immediately).

Disabled by default (opt-in, same reasoning as Positive Security / Bot
JS-Challenge / Threat Intel) — this deployment shouldn't start
auto-blocking anyone until an admin explicitly turns it on and tunes the
threshold for their own traffic patterns (over-blocking shared/NAT'd IPs
is the real risk here, not implementation complexity).
"""
import asyncio
import ipaddress
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

AUTO_BLACKLIST_KEY_PREFIX = "waf:blacklist:auto:"

# Disabled-state poll interval — short, so flipping the Settings toggle on
# takes effect quickly instead of waiting up to a full configured sync
# interval for the loop to notice. Same convention as threat_intel_service.
DISABLED_POLL_INTERVAL_SECONDS = 300
MIN_ENABLED_INTERVAL_SECONDS = 300  # never tighter than every 5 minutes


def _is_whitelisted(r, ip: str) -> bool:
    try:
        if r.sismember("waf:whitelist", ip):
            return True
        cidrs = r.smembers("waf:whitelist:cidrs")
        if cidrs:
            ip_obj = ipaddress.ip_address(ip)
            for cidr in cidrs:
                try:
                    if ip_obj in ipaddress.ip_network(cidr, strict=False):
                        return True
                except ValueError:
                    continue
    except Exception as e:
        logger.warning(f"[AutoReputation] Whitelist check failed for {ip}, skipping to be safe: {e}")
        return True  # fail safe toward NOT auto-blocking, not toward blocking
    return False


def run_auto_reputation_sync(force: bool = False) -> dict:
    """
    Executes one sync cycle. Returns a summary dict — never raises (same
    convention as threat_intel_service.run_threat_intel_sync and
    log_retention_service.run_retention_cleanup): callers, including the
    manual "Sync Now" route, get a status back instead of a 500 for a
    transient ClickHouse/Redis hiccup.

    force=True bypasses the enabled check — used by the manual "Sync Now"
    button, which should work even while the background scheduler is off.
    """
    from app.services.settings_manager import settings_manager
    from app.services.nginx_manager import get_redis_client
    from app.services import clickhouse_service

    settings = settings_manager.get_auto_reputation()
    if not force and not settings.get("enabled", False):
        return {"status": "skipped", "count": 0}

    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        threshold = int(settings.get("block_threshold", 50))
        window_hours = int(settings.get("window_hours", 1))
        ttl_seconds = int(settings.get("block_ttl_hours", 24)) * 3600

        offender_ips = clickhouse_service.get_repeat_offender_ips(threshold, window_hours)

        r = get_redis_client()
        if r is None:
            raise RuntimeError("Redis client unavailable")

        blocked_count = 0
        for ip in offender_ips:
            if _is_whitelisted(r, ip):
                continue
            # SETEX on every cycle a still-active offender keeps qualifying
            # refreshes its TTL — a persistent attacker stays blocked
            # continuously; one that stops offending simply expires and
            # isn't re-added, no explicit cleanup needed.
            r.setex(f"{AUTO_BLACKLIST_KEY_PREFIX}{ip}", ttl_seconds, "1")
            blocked_count += 1

        settings_manager.update_auto_reputation({
            **settings, "last_sync_at": now_iso,
            "last_sync_count": blocked_count, "last_sync_status": "success",
            "last_sync_error": None,
        })
        logger.info(
            f"[AutoReputation] {blocked_count} IP(s) auto-blocked "
            f"(>= {threshold} blocked requests in {window_hours}h)."
        )
        return {"status": "success", "count": blocked_count}
    except Exception as e:
        logger.error(f"[AutoReputation] Sync cycle failed: {e}")
        try:
            settings_manager.update_auto_reputation({
                **settings, "last_sync_at": now_iso,
                "last_sync_status": "error", "last_sync_error": str(e),
            })
        except Exception:
            pass
        return {"status": "error", "count": 0, "error": str(e)}


async def start_auto_reputation_service():
    """
    Background async loop. Call with asyncio.create_task() during app
    startup. Re-reads settings every cycle so toggling enabled/threshold/
    window/interval in Settings takes effect without a restart, same
    convention as threat_intel_service.
    """
    logger.info("[AutoReputation] Service started.")
    await asyncio.sleep(75)  # Initial delay for app to fully initialize

    from app.services import heartbeat_registry
    from app.services.settings_manager import settings_manager

    while True:
        settings = settings_manager.get_auto_reputation()
        enabled = settings.get("enabled", False)
        if enabled:
            interval_seconds = max(
                int(settings.get("sync_interval_minutes", 15)) * 60,
                MIN_ENABLED_INTERVAL_SECONDS,
            )
        else:
            interval_seconds = DISABLED_POLL_INTERVAL_SECONDS

        try:
            summary = await asyncio.to_thread(run_auto_reputation_sync)
            heartbeat_registry.record_heartbeat(
                "auto_reputation", interval_seconds,
                status="error" if summary.get("status") == "error" else "ok",
                detail=summary.get("error"),
            )
        except Exception as e:
            logger.error(f"[AutoReputation] Unexpected error during sync cycle: {e}")
            heartbeat_registry.record_heartbeat(
                "auto_reputation", interval_seconds, status="error", detail=str(e)
            )
        await asyncio.sleep(interval_seconds)


def get_auto_blocked_ips() -> list:
    """Currently auto-blocked IPs with their remaining TTL, for the
    Settings panel's read-only list. Uses SCAN (non-blocking, incremental)
    rather than KEYS, which can stall Redis on a large keyspace."""
    from app.services.nginx_manager import get_redis_client

    r = get_redis_client()
    if r is None:
        return []
    results = []
    cursor = 0
    prefix = AUTO_BLACKLIST_KEY_PREFIX
    while True:
        cursor, keys = r.scan(cursor=cursor, match=f"{prefix}*", count=100)
        for key in keys:
            ip = key[len(prefix):]
            ttl = r.ttl(key)
            results.append({"ip": ip, "ttl_seconds": ttl if ttl and ttl > 0 else 0})
        if cursor == 0:
            break
    return results


def release_auto_blocked_ip(ip: str) -> bool:
    """Manual "release" action — deletes one IP's auto-block early rather
    than waiting for its TTL to expire."""
    from app.services.nginx_manager import get_redis_client

    r = get_redis_client()
    if r is None:
        return False
    deleted = r.delete(f"{AUTO_BLACKLIST_KEY_PREFIX}{ip}")
    return bool(deleted)
