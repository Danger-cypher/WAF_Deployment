import os
import re
import logging
from typing import Dict, Any
from collections import defaultdict
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

ERROR_LOG_PATH = "/var/log/nginx/error.log"

# --- Source 1: nginx's own native limit_req/limit_conn rejection ---
# "limiting requests"/"limiting connections" is nginx's REJECTION log line
# (429 always, as of the P2-07 fix — see GENERAL_RATE_LIMIT_STATUS in
# nginx_manager.py for why this is no longer coupled to
# bot_mitigation_action; that dropdown now only affects reason=bot_ua_limit
# below, which isn't a native nginx rejection at all).
#
# "delaying request"/"delaying connections" is a DIFFERENT, LOWER log
# level nginx emits when a request merely queues behind burst and is then
# still served at the configured rate — it was NOT blocked. Confirmed
# against nginx's own docs (ngx_http_limit_req_module: "delayed requests
# are logged one level lower than rejections") — treating it as a block
# was a real bug found 2026-09-04: on this deployment's own traffic, 100%
# of what this page reported as "blocked" was actually "delaying" lines
# from ordinary browser page-loads, while genuinely blocked traffic
# (adaptive throttle, API-enum detection — both configured on this same
# page) was invisible because they never logged anything nginx-shaped at
# all. See RATE_LIMIT_LUA_REGEX below for how that second half is fixed.
RATE_LIMIT_NATIVE_REGEX = re.compile(
    r"^(?P<date>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?:error|warn)\] .*? "
    r"limiting (?:requests|connections).*? client: (?P<client>[^,]+),"
)

# --- Source 2: this WAF's own Lua-layer mechanisms ---
# WAF-LUA-BLOCK is the one consistent, greppable tag EVERY non-ModSecurity
# blocking decision in this WAF logs before rejecting a request (see
# ml_check.lua's mTLS check for the full explanation — it also feeds
# nginx_errorlog_parser.py, which lands these same events in ClickHouse's
# waf_events so every OTHER dashboard metric sees them too, not just this
# page). This page only cares about the mechanisms ITS OWN settings
# control, so results are filtered to _DDOS_PAGE_REASONS below — a JA4 or
# geo-block, while a real block, isn't something this page's Mitigation
# Configuration form has any control over and would be misleading to
# fold into its counts.
RATE_LIMIT_LUA_REGEX = re.compile(
    r"^(?P<date>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[warn\] .*? "
    r"WAF-LUA-BLOCK reason=(?P<reason>\S+) code=\d+ client=(?P<client>[^\s,]+)"
)

# Reasons this page's own settings actually control — see
# DdosBotMitigationModel in routes/settings.py. Every other WAF-LUA-BLOCK
# reason (mtls, ip_blacklist, ja4, geo_block, api_schema, crs_fallback,
# ml_engine, ml_engine_throttle) is real and lands in waf_events via
# nginx_errorlog_parser.py, just not counted on THIS page.
_DDOS_PAGE_REASONS = {"rate_limit", "adaptive_throttle", "api_enum", "bot_ua_limit"}

# Cheap pre-filter before running either regex — avoids compiling/matching
# every single line in a busy log (this file also carries ModSecurity
# messages, Lua warnings unrelated to blocking, MIME-type notices, etc.).
_KEYWORD_PREFILTER = ("limiting requests", "limiting connections", "WAF-LUA-BLOCK")

DEFAULT_WINDOW_HOURS = 24
# Hard cap on how far back a single call will scan, independent of the
# requested window — this file is read on every poll (the page refreshes
# every 3s), so an admin who passes an unreasonably large `hours` value
# can't turn each poll into an unbounded full-file scan.
MAX_SCAN_BYTES = 25 * 1024 * 1024  # 25MB


def _read_recent_bytes(filepath: str, max_bytes: int) -> list:
    """Reads up to the last `max_bytes` of the file and splits it into
    lines. Unlike a fixed line count, this is a bounded-cost safety net,
    not the actual time-window filter — get_ddos_analytics() below filters
    the resulting lines by their own parsed timestamp against `hours`, so
    the reported window is honest even though the byte read itself is a
    (generous) approximation of "far enough back to cover it"."""
    try:
        with open(filepath, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            raw = f.read()
        return raw.decode("utf-8", errors="ignore").split("\n")
    except Exception as e:
        logger.error(f"Error reading {filepath}: {e}")
        return []


def get_ddos_analytics(hours: int = DEFAULT_WINDOW_HOURS) -> Dict[str, Any]:
    """
    Parses the nginx error log for genuine rejections — nginx's own
    limit_req/limit_conn REJECTIONS (not delays) plus this WAF's own
    Lua-layer blocks (adaptive throttle, API-enumeration detection) — and
    aggregates them into a timeline, top offending IPs, a total count, and
    a per-mechanism breakdown.

    Windowed by real elapsed time (`hours`, default 24), not a raw line
    count — the old "last 2000 lines" approach meant the reported window
    silently varied from seconds to hours depending on how much unrelated
    logging happened to be interleaved, with no way for an admin to know
    which. Bounded by MAX_SCAN_BYTES as a cost safety net, independent of
    the correctness of the time filter itself (see _read_recent_bytes).
    """
    if not os.path.exists(ERROR_LOG_PATH):
        return {
            "timeline": [], "top_ips": [], "total_blocks": 0,
            "total_unique_ips": 0, "by_reason": {}, "window_hours": hours,
        }

    cutoff = datetime.now() - timedelta(hours=hours)
    timeline_data = defaultdict(int)
    ip_counts = defaultdict(int)
    reason_counts = defaultdict(int)
    total_blocks = 0

    try:
        lines = _read_recent_bytes(ERROR_LOG_PATH, MAX_SCAN_BYTES)

        for line in lines:
            if not any(k in line for k in _KEYWORD_PREFILTER):
                continue

            reason = None
            client_ip = None
            date_str = None

            m = RATE_LIMIT_LUA_REGEX.search(line)
            if m:
                reason = m.group("reason")
                if reason not in _DDOS_PAGE_REASONS:
                    continue  # a real block, just not one this page's own settings control
                client_ip = m.group("client").strip()
                date_str = m.group("date")
            else:
                m = RATE_LIMIT_NATIVE_REGEX.search(line)
                if m:
                    reason = "rate_limit"
                    client_ip = m.group("client").strip()
                    date_str = m.group("date")

            if not m or not date_str:
                continue

            try:
                dt = datetime.strptime(date_str, "%Y/%m/%d %H:%M:%S")
            except ValueError:
                continue

            if dt < cutoff:
                continue

            total_blocks += 1
            reason_counts[reason] += 1
            ip_counts[client_ip] += 1

            rounded_minute = (dt.minute // 15) * 15
            time_bucket = f"{dt.strftime('%m/%d')} {dt.hour:02d}:{rounded_minute:02d}"
            timeline_data[time_bucket] += 1

    except Exception as e:
        logger.error(f"Error parsing NGINX error log for DDoS analytics: {e}")

    sorted_times = sorted(timeline_data.keys())[-60:]
    formatted_timeline = [{"time": t, "blocked": timeline_data[t]} for t in sorted_times]

    total_unique_ips = len(ip_counts)
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    formatted_ips = [{"ip": ip, "count": count} for ip, count in sorted_ips]

    return {
        "timeline": formatted_timeline,
        "top_ips": formatted_ips,
        "total_blocks": total_blocks,
        "total_unique_ips": total_unique_ips,
        # Per-mechanism breakdown — e.g. {"rate_limit": 12, "adaptive_throttle": 3,
        # "api_enum": 1} — so an admin can actually see whether a toggle on
        # this page is doing anything, instead of one opaque aggregate.
        "by_reason": dict(reason_counts),
        "window_hours": hours,
    }
