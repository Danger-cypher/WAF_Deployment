"""
good_bot_service.py — CyberSentinel WAF
===============================================
Background service that pulls the official, self-published IP ranges for
major legitimate search-engine crawlers (Googlebot, Bingbot) and lands
them in Redis as per-crawler CIDR sets — a verified-good-bot allowlist,
the mirror image of threat_intel_service.py's bad-IP feeds.

Why this exists: nginx_manager.py's $is_bad_bot UA map (see its "Bot
Mitigation" section) only ever lists known-BAD tool signatures (sqlmap,
nikto, scrapers) — it has never blocked Googlebot/Bingbot, so this isn't
fixing a block. The actual gap is that nothing in the stack gives a real
crawler special treatment either: its fast, sequential, referrer-less
request pattern is exactly the shape ml_check.lua's adaptive reputation
throttle is designed to flag as suspicious, so a legitimate crawl can get
rate-limited right alongside an attacker.

UA string alone ("Googlebot/2.1") is trivially spoofable by anyone, so
that alone must never grant an exemption. Both major crawlers solve this
by publishing their own authoritative IP ranges (the same mechanism they
tell webmasters to use for verifying a crawler is real via reverse-DNS,
except fetching the published list once and matching CIDRs is far cheaper
than a live rDNS+forward-confirm lookup on every single request). This
service does the verification once, on a schedule, and check_good_bot()
in ml_check.lua just does a CIDR membership test at request time — no
per-request DNS lookup on the hot path, keyed on BOTH matching, not UA
alone: source IP must fall in the claimed crawler's official range AND
the UA must claim that same crawler.

Both feeds happen to share one JSON shape (Google's own "IP ranges" list
format, which Bing's also uses): {"creationTime": "...", "prefixes":
[{"ipv4Prefix": "a.b.c.d/n"} | {"ipv6Prefix": "..."}]} — live-verified
against both URLs before writing this, not assumed from memory.

Kept as per-source Redis sets (waf:goodbot:cidrs:<source>), not merged
into one set like threat_intel_service.py's feeds — the Lua check needs
to know WHICH crawler's range an IP matched, since that has to line up
with what the request's own User-Agent claims.

Disabled by default (opt-in, same convention as threat_intel/
malware_scanning/Positive Security) — an allowlist can only ever loosen
enforcement for the IPs it covers, so it shouldn't turn on by itself
either.
"""
import asyncio
import ipaddress
import logging
from datetime import datetime, timezone

import requests

logger = logging.getLogger(__name__)

GOOGLEBOT_RANGES_URL = "https://developers.google.com/static/search/apis/ipranges/googlebot.json"
BINGBOT_RANGES_URL = "https://www.bing.com/toolbox/bingbot.json"
FETCH_TIMEOUT_SECONDS = 15
GOOD_BOT_CIDRS_KEY_PREFIX = "waf:goodbot:cidrs:"

# Disabled-state poll interval — short, so flipping the Settings toggle on
# takes effect quickly instead of waiting up to a full configured sync
# interval for the loop to notice. Same convention as threat_intel_service.
DISABLED_POLL_INTERVAL_SECONDS = 300
MIN_ENABLED_INTERVAL_SECONDS = 3600  # never tighter than hourly — these ranges change rarely

DEFAULT_SOURCES = {
    "googlebot": True,
    "bingbot": True,
}


def _parse_ip_ranges_json(text: str) -> set:
    """Parses Google's/Bing's shared IP-ranges JSON shape. Silently skips
    any entry that isn't a parseable CIDR — a feed format tweak should
    yield fewer CIDRs, never crash the sync."""
    import json

    cidrs = set()
    try:
        data = json.loads(text)
    except ValueError:
        return cidrs
    for entry in data.get("prefixes", []):
        cidr = entry.get("ipv4Prefix") or entry.get("ipv6Prefix")
        if not cidr:
            continue
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        cidrs.add(cidr)
    return cidrs


def _fetch_feed(url: str) -> set:
    resp = requests.get(
        url, timeout=FETCH_TIMEOUT_SECONDS,
        headers={"User-Agent": "CyberSentinel-WAF/1.0 (+good-bot-sync)"},
    )
    resp.raise_for_status()
    return _parse_ip_ranges_json(resp.text)


# Each source: (settings key in `sources`, human label for logging, feed URL).
SOURCES = [
    ("googlebot", "Googlebot", GOOGLEBOT_RANGES_URL),
    ("bingbot", "Bingbot", BINGBOT_RANGES_URL),
]


def run_good_bot_sync(force: bool = False) -> dict:
    """
    Executes one sync cycle. Returns a summary dict — never raises (same
    convention as threat_intel_service.run_threat_intel_sync / other
    scheduled sync services): a feed being briefly unreachable shouldn't
    ever surface as a 500 to the "Sync Now" button.

    force=True bypasses the enabled check — used by the manual "Sync Now"
    button, which should work even while the background scheduler is off.
    """
    from app.services.settings_manager import settings_manager
    from app.services.nginx_manager import get_redis_client

    settings = settings_manager.get_good_bots()
    if not force and not settings.get("enabled", False):
        return {"status": "skipped", "count": 0}

    now_iso = datetime.now(timezone.utc).isoformat()
    enabled_sources = settings.get("sources", DEFAULT_SOURCES)
    try:
        r = get_redis_client()
        if r is None:
            raise RuntimeError("Redis client unavailable")

        fetch_errors = []
        source_counts = {}
        total = 0
        any_source_enabled = False
        for source_key, label, url in SOURCES:
            if not enabled_sources.get(source_key, DEFAULT_SOURCES.get(source_key, False)):
                continue
            any_source_enabled = True
            try:
                cidrs = _fetch_feed(url)
            except Exception as e:
                fetch_errors.append(f"{url}: {e}")
                logger.warning(f"[GoodBot] Failed to fetch {url}: {e}")
                continue

            source_counts[source_key] = len(cidrs)
            key = f"{GOOD_BOT_CIDRS_KEY_PREFIX}{source_key}"
            if cidrs:
                # Replace atomically-enough for this purpose: write the new
                # set under a temp key, then rename over the old one, so a
                # request mid-sync never sees a briefly-empty set. A stale
                # set for one more cycle (if the fetch fails) is far safer
                # than a window where every crawler IP briefly gets treated
                # as unverified.
                tmp_key = f"{key}:sync"
                r.delete(tmp_key)
                for cidr in cidrs:
                    r.sadd(tmp_key, cidr)
                r.rename(tmp_key, key)
                total += len(cidrs)
                logger.info(f"[GoodBot] {label}: {len(cidrs)} CIDRs.")
            else:
                fetch_errors.append(f"{url}: feed returned zero usable CIDRs")

        if not any_source_enabled:
            error_msg = "No good-bot sources enabled."
            settings_manager.update_good_bots({
                **settings, "last_sync_at": now_iso,
                "last_sync_status": "error", "last_sync_error": error_msg,
            })
            return {"status": "error", "count": 0, "error": error_msg}

        if total == 0:
            error_msg = "; ".join(fetch_errors) or "No CIDRs returned by any enabled source."
            settings_manager.update_good_bots({
                **settings, "last_sync_at": now_iso,
                "last_sync_status": "error", "last_sync_error": error_msg,
            })
            return {"status": "error", "count": 0, "error": error_msg}

        # Partial-failure status: at least one source landed real data —
        # still "success", error surfaced rather than dropped, same
        # spirit as threat_intel_service's partial-failure handling.
        settings_manager.update_good_bots({
            **settings, "last_sync_at": now_iso,
            "last_sync_count": total, "last_sync_status": "success",
            "last_sync_error": "; ".join(fetch_errors) if fetch_errors else None,
            "last_sync_counts": source_counts,
        })
        logger.info(f"[GoodBot] Synced {total} total CIDRs from {len(source_counts)} source(s) into Redis.")
        return {"status": "success", "count": total, "counts": source_counts}
    except Exception as e:
        logger.error(f"[GoodBot] Sync cycle failed: {e}")
        try:
            settings_manager.update_good_bots({
                **settings, "last_sync_at": now_iso,
                "last_sync_status": "error", "last_sync_error": str(e),
            })
        except Exception:
            pass
        return {"status": "error", "count": 0, "error": str(e)}


async def start_good_bot_service():
    """
    Background async loop. Call with asyncio.create_task() during app
    startup. Re-reads settings every cycle so toggling enabled/interval in
    Settings takes effect without a restart, same convention as
    threat_intel_service.
    """
    logger.info("[GoodBot] Service started.")
    await asyncio.sleep(65)  # Initial delay for app to fully initialize

    from app.services import heartbeat_registry
    from app.services.settings_manager import settings_manager

    while True:
        settings = settings_manager.get_good_bots()
        enabled = settings.get("enabled", False)
        if enabled:
            interval_seconds = max(
                int(settings.get("sync_interval_hours", 24)) * 3600,
                MIN_ENABLED_INTERVAL_SECONDS,
            )
        else:
            interval_seconds = DISABLED_POLL_INTERVAL_SECONDS

        try:
            summary = await asyncio.to_thread(run_good_bot_sync)
            heartbeat_registry.record_heartbeat(
                "good_bots", interval_seconds,
                status="error" if summary.get("status") == "error" else "ok",
                detail=summary.get("error"),
            )
        except Exception as e:
            logger.error(f"[GoodBot] Unexpected error during sync cycle: {e}")
            heartbeat_registry.record_heartbeat(
                "good_bots", interval_seconds, status="error", detail=str(e)
            )
        await asyncio.sleep(interval_seconds)
