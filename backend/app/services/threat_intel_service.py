"""
threat_intel_service.py — CyberSentinel WAF
===============================================
Background service that pulls a free, no-API-key external IP reputation
feed (Spamhaus DROP + EDROP — netblocks hijacked or leased by professional
spammers/cybercriminals, published as plain text for exactly this kind of
automated consumption) and feeds it into the existing Redis-backed IP
blocking mechanism ml_check.lua's check_ip_auth() already reads.

Kept in a SEPARATE Redis key (waf:blacklist:feed:cidrs) from the
admin-managed waf:blacklist:cidrs (Settings > Hardening,
apply_hardening_settings) so a scheduled sync can never silently clobber an
admin's own entries, and vice versa — apply_hardening_settings' flush/
rebuild of its own key never touches this one. Manual whitelist entries
still override either blacklist, same as before.

Disabled by default (opt-in, like Positive Security / Bot JS-Challenge) —
this deployment shouldn't start blocking traffic from a third-party list
nobody asked for.
"""
import asyncio
import logging
from datetime import datetime, timezone

import requests

logger = logging.getLogger(__name__)

SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
SPAMHAUS_EDROP_URL = "https://www.spamhaus.org/drop/edrop.txt"
FETCH_TIMEOUT_SECONDS = 15
FEED_BLACKLIST_CIDRS_KEY = "waf:blacklist:feed:cidrs"

# Disabled-state poll interval — short, so flipping the Settings toggle on
# takes effect quickly instead of waiting up to a full configured sync
# interval for the loop to notice.
DISABLED_POLL_INTERVAL_SECONDS = 300
MIN_ENABLED_INTERVAL_SECONDS = 3600  # never tighter than hourly


def _parse_drop_list(text: str) -> set:
    """
    Spamhaus DROP/EDROP text format: one CIDR per line, optionally followed
    by '; SBLxxxxx' reference comment; full-line comments start with ';';
    blank lines throughout. Returns the set of CIDR strings only.
    """
    cidrs = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        cidr = line.split(";", 1)[0].strip()
        if cidr and "/" in cidr:
            cidrs.add(cidr)
    return cidrs


def _fetch_feed(url: str) -> set:
    resp = requests.get(
        url, timeout=FETCH_TIMEOUT_SECONDS,
        headers={"User-Agent": "CyberSentinel-WAF/1.0 (+threat-intel-sync)"},
    )
    resp.raise_for_status()
    return _parse_drop_list(resp.text)


def run_threat_intel_sync(force: bool = False) -> dict:
    """
    Executes one sync cycle. Returns a summary dict — never raises (matches
    log_retention_service's run_retention_cleanup() convention: callers,
    including the manual "Sync Now" route, get a status back instead of a
    500 for a feed being temporarily unreachable).

    force=True bypasses the enabled check — used by the manual "Sync Now"
    button, which should work even while the background scheduler is off.
    """
    from app.services.settings_manager import settings_manager
    from app.services.nginx_manager import get_redis_client

    settings = settings_manager.get_threat_intel()
    if not force and not settings.get("enabled", False):
        return {"status": "skipped", "count": 0}

    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        cidrs = set()
        fetch_errors = []
        for url in (SPAMHAUS_DROP_URL, SPAMHAUS_EDROP_URL):
            try:
                cidrs |= _fetch_feed(url)
            except Exception as e:
                fetch_errors.append(f"{url}: {e}")
                logger.warning(f"[ThreatIntel] Failed to fetch {url}: {e}")

        if not cidrs:
            error_msg = "; ".join(fetch_errors) or "No CIDRs returned by any configured feed."
            settings_manager.update_threat_intel({
                **settings, "last_sync_at": now_iso,
                "last_sync_status": "error", "last_sync_error": error_msg,
            })
            return {"status": "error", "count": 0, "error": error_msg}

        r = get_redis_client()
        r.delete(FEED_BLACKLIST_CIDRS_KEY)
        for cidr in cidrs:
            r.sadd(FEED_BLACKLIST_CIDRS_KEY, cidr)

        settings_manager.update_threat_intel({
            **settings, "last_sync_at": now_iso,
            "last_sync_count": len(cidrs), "last_sync_status": "success",
            "last_sync_error": None,
        })
        logger.info(f"[ThreatIntel] Synced {len(cidrs)} CIDRs from Spamhaus DROP/EDROP into Redis.")
        return {"status": "success", "count": len(cidrs)}
    except Exception as e:
        logger.error(f"[ThreatIntel] Sync cycle failed: {e}")
        try:
            settings_manager.update_threat_intel({
                **settings, "last_sync_at": now_iso,
                "last_sync_status": "error", "last_sync_error": str(e),
            })
        except Exception:
            pass
        return {"status": "error", "count": 0, "error": str(e)}


async def start_threat_intel_service():
    """
    Background async loop. Call with asyncio.create_task() during app
    startup. Re-reads settings every cycle so toggling enabled/interval in
    Settings takes effect without a restart, same convention as
    log_retention_service.
    """
    logger.info("[ThreatIntel] Service started.")
    await asyncio.sleep(60)  # Initial delay for app to fully initialize

    from app.services import heartbeat_registry
    from app.services.settings_manager import settings_manager

    while True:
        settings = settings_manager.get_threat_intel()
        enabled = settings.get("enabled", False)
        if enabled:
            interval_seconds = max(
                int(settings.get("sync_interval_hours", 24)) * 3600,
                MIN_ENABLED_INTERVAL_SECONDS,
            )
        else:
            interval_seconds = DISABLED_POLL_INTERVAL_SECONDS

        try:
            summary = await asyncio.to_thread(run_threat_intel_sync)
            heartbeat_registry.record_heartbeat(
                "threat_intel", interval_seconds,
                status="error" if summary.get("status") == "error" else "ok",
                detail=summary.get("error"),
            )
        except Exception as e:
            logger.error(f"[ThreatIntel] Unexpected error during sync cycle: {e}")
            heartbeat_registry.record_heartbeat(
                "threat_intel", interval_seconds, status="error", detail=str(e)
            )
        await asyncio.sleep(interval_seconds)
