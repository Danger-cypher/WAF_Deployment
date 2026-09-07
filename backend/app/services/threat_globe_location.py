"""
threat_globe_location.py — CyberSentinel WAF
=============================================
One-shot startup task: resolves this deployment's own public IP to a
lat/lon, so the Threat Globe view has somewhere for attack arcs to land
without an admin having to enter coordinates by hand on a fresh install.

Skips entirely once an admin has set a manual override (Settings) — a
detected IP is frequently WRONG for exactly the deployments most likely to
want a globe in the first place: anything behind a CDN, reverse proxy, or
load balancer, where the address this container happens to egress on
isn't the audience-facing edge.

Best-effort by design: any failure (no outbound internet, the IP-lookup
service being down, the GeoIP City DB missing) just leaves
threat_globe.server_lat/lon as None. The frontend treats a missing
destination as "not configured yet", not an error.
"""
import asyncio
import logging

import requests

from app.services.settings_manager import settings_manager
from app.utils.geoip_manager import geoip_manager

logger = logging.getLogger(__name__)

_IP_LOOKUP_URL = "https://api.ipify.org?format=json"
_TIMEOUT_SECONDS = 5


def _resolve_sync() -> None:
    try:
        resp = requests.get(_IP_LOOKUP_URL, timeout=_TIMEOUT_SECONDS)
        resp.raise_for_status()
        public_ip = resp.json().get("ip", "")
    except Exception as e:
        logger.warning(f"[ThreatGlobeLocation] Could not determine this server's public IP: {e}")
        return

    if not public_ip:
        return

    location = geoip_manager.get_city_location(public_ip)
    if not location:
        logger.warning(
            f"[ThreatGlobeLocation] Public IP {public_ip} resolved, but GeoIP City lookup "
            "returned nothing (City DB missing, or no record for this address) — Threat "
            "Globe destination left unconfigured until an admin sets one manually."
        )
        return

    label = location["city"] or public_ip
    settings_manager.set_threat_globe_auto_location(location["lat"], location["lon"], label)
    logger.info(
        f"[ThreatGlobeLocation] Auto-detected server location: {label} "
        f"({location['lat']}, {location['lon']})"
    )


async def resolve_server_location_once() -> None:
    """Call once during application startup (asyncio.create_task) — not a
    recurring loop, so it isn't registered with heartbeat_registry."""
    try:
        current = settings_manager.get_threat_globe()
        if current.get("override_enabled"):
            logger.info("[ThreatGlobeLocation] Manual override is set — skipping auto-detection.")
            return
        await asyncio.to_thread(_resolve_sync)
    except Exception as e:
        logger.error(f"[ThreatGlobeLocation] Unexpected error during auto-detection: {e}")
