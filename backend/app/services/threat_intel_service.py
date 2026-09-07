"""
threat_intel_service.py — CyberSentinel WAF
===============================================
Background service that pulls free, no-API-key external IP reputation
feeds and merges them into the existing Redis-backed IP blocking mechanism
ml_check.lua's check_ip_auth() already reads:

  - Spamhaus DROP + EDROP — netblocks hijacked or leased by professional
    spammers/cybercriminals, published as CIDR ranges.
  - Emerging Threats (Proofpoint) "compromised IPs" — hosts with recent
    observed malicious activity (brute-force, scanning, malware C2),
    published as individual IPs.
  - Tor exit nodes — the Tor Project's own official bulk-exit list. Off by
    default (see ThreatIntelModel.sources in routes/settings.py): unlike
    the other two, a Tor exit IP is not inherently malicious traffic, it's
    anonymized traffic — enabling this is a deliberate "block anonymized
    clients" policy choice, not a pure threat-intel signal, so it doesn't
    default on the way the other two do.

All three normalize to CIDR strings (single IPs become /32 or /128) and
land in the SAME Redis key (waf:blacklist:feed:cidrs) — ml_check.lua's
check_ip_auth() already walks that set with match_cidrs(), which handles
/32 exact-match correctly, so adding sources here needed zero Lua changes.

Kept in a SEPARATE Redis key from the admin-managed waf:blacklist:cidrs
(Settings > Hardening, apply_hardening_settings) so a scheduled sync can
never silently clobber an admin's own entries, and vice versa —
apply_hardening_settings' flush/rebuild of its own key never touches this
one. Manual whitelist entries still override either blacklist, same as
before.

Disabled by default (opt-in, like Positive Security / Bot JS-Challenge) —
this deployment shouldn't start blocking traffic from a third-party list
nobody asked for.
"""
import asyncio
import ipaddress
import logging
from datetime import datetime, timezone

import requests

logger = logging.getLogger(__name__)

SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
SPAMHAUS_EDROP_URL = "https://www.spamhaus.org/drop/edrop.txt"
EMERGING_THREATS_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"
FETCH_TIMEOUT_SECONDS = 15
FEED_BLACKLIST_CIDRS_KEY = "waf:blacklist:feed:cidrs"

# Disabled-state poll interval — short, so flipping the Settings toggle on
# takes effect quickly instead of waiting up to a full configured sync
# interval for the loop to notice.
DISABLED_POLL_INTERVAL_SECONDS = 300
MIN_ENABLED_INTERVAL_SECONDS = 3600  # never tighter than hourly

# Per-source defaults for an admin who hasn't saved a `sources` choice yet
# (older saved settings predate this field) — Spamhaus/Emerging Threats
# keep the pre-existing "on once the master toggle is on" behavior; Tor
# stays opt-in even then, per the module docstring above.
DEFAULT_SOURCES = {
    "spamhaus": True,
    "emerging_threats": True,
    "tor_exit_nodes": False,
}


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


def _parse_ip_list(text: str) -> set:
    """
    Generic one-IP-per-line format (Emerging Threats' compromised-ips.txt,
    the Tor Project's torbulkexitlist — live-verified against both: no
    CIDR notation, no inline comments, occasional blank lines). Each valid
    IPv4/IPv6 address is normalized to an exact-match CIDR (/32 or /128)
    so it can share match_cidrs()'s existing CIDR-set path in
    ml_check.lua instead of needing a second, exact-IP-set Lua check.
    Silently skips any line that isn't a parseable address — a feed
    changing its format shouldn't crash the sync, just yield fewer CIDRs.
    """
    cidrs = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        try:
            addr = ipaddress.ip_address(line)
        except ValueError:
            continue
        cidrs.add(f"{addr}/{32 if addr.version == 4 else 128}")
    return cidrs


def _fetch_feed(url: str, parser=_parse_drop_list) -> set:
    resp = requests.get(
        url, timeout=FETCH_TIMEOUT_SECONDS,
        headers={"User-Agent": "CyberSentinel-WAF/1.0 (+threat-intel-sync)"},
    )
    resp.raise_for_status()
    return parser(resp.text)


# Each source: (settings key in `sources`, human label for logging/status,
# list of (url, parser) fetches that make up that source — Spamhaus is
# two URLs merged into one source since DROP/EDROP are always fetched
# together, same as before this change).
SOURCES = [
    ("spamhaus", "Spamhaus DROP/EDROP", [
        (SPAMHAUS_DROP_URL, _parse_drop_list),
        (SPAMHAUS_EDROP_URL, _parse_drop_list),
    ]),
    ("emerging_threats", "Emerging Threats Compromised IPs", [
        (EMERGING_THREATS_URL, _parse_ip_list),
    ]),
    ("tor_exit_nodes", "Tor Exit Nodes", [
        (TOR_EXIT_LIST_URL, _parse_ip_list),
    ]),
]


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
    enabled_sources = settings.get("sources", DEFAULT_SOURCES)
    try:
        cidrs = set()
        fetch_errors = []
        source_counts = {}
        any_source_enabled = False
        for source_key, label, fetches in SOURCES:
            if not enabled_sources.get(source_key, DEFAULT_SOURCES.get(source_key, False)):
                continue
            any_source_enabled = True
            source_cidrs = set()
            for url, parser in fetches:
                try:
                    source_cidrs |= _fetch_feed(url, parser)
                except Exception as e:
                    fetch_errors.append(f"{url}: {e}")
                    logger.warning(f"[ThreatIntel] Failed to fetch {url}: {e}")
            source_counts[source_key] = len(source_cidrs)
            if source_cidrs:
                logger.info(f"[ThreatIntel] {label}: {len(source_cidrs)} CIDRs.")
            cidrs |= source_cidrs

        if not any_source_enabled:
            error_msg = "No feed sources enabled."
            settings_manager.update_threat_intel({
                **settings, "last_sync_at": now_iso,
                "last_sync_status": "error", "last_sync_error": error_msg,
            })
            return {"status": "error", "count": 0, "error": error_msg}

        if not cidrs:
            error_msg = "; ".join(fetch_errors) or "No CIDRs returned by any enabled feed."
            settings_manager.update_threat_intel({
                **settings, "last_sync_at": now_iso,
                "last_sync_status": "error", "last_sync_error": error_msg,
            })
            return {"status": "error", "count": 0, "error": error_msg}

        r = get_redis_client()
        r.delete(FEED_BLACKLIST_CIDRS_KEY)
        for cidr in cidrs:
            r.sadd(FEED_BLACKLIST_CIDRS_KEY, cidr)

        # Partial-failure status: some sources fetched fine, at least one
        # didn't — still a "success" (real data landed in Redis), but the
        # error is surfaced rather than silently dropped, same spirit as
        # the pre-existing Spamhaus DROP+EDROP fetch-both-continue pattern.
        settings_manager.update_threat_intel({
            **settings, "last_sync_at": now_iso,
            "last_sync_count": len(cidrs), "last_sync_status": "success",
            "last_sync_error": "; ".join(fetch_errors) if fetch_errors else None,
            "last_sync_counts": source_counts,
        })
        logger.info(f"[ThreatIntel] Synced {len(cidrs)} total CIDRs from {len(source_counts)} source(s) into Redis.")
        return {"status": "success", "count": len(cidrs), "counts": source_counts}
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
