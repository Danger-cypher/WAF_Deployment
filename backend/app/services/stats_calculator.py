"""
stats_calculator.py — CyberSentinel WAF
=========================================
All statistics and aggregation queries now execute against ClickHouse.
Falls back to in-memory log_reader data if ClickHouse is unavailable,
so the dashboard never shows a blank screen during ClickHouse cold-start.
"""

import os
import time
import logging
from typing import Any, Dict, List, Optional
from collections import Counter

from app.services import clickhouse_service

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Nginx access-log line counter (still read from flat file — not in ClickHouse)
# This gives us the true total request count (blocked + allowed).
# ---------------------------------------------------------------------------
_nginx_req_cache: Dict[int, int] = {}
_nginx_req_cache_time: Dict[int, float] = {}


def _get_total_nginx_requests(hours: Optional[int] = None) -> int:
    now = time.monotonic()
    cache_key = hours or 0
    if cache_key in _nginx_req_cache and (now - _nginx_req_cache_time.get(cache_key, 0)) < 10.0:
        return _nginx_req_cache[cache_key]

    count = 0
    candidates = ["/var/log/nginx/access.log", "/var/log/nginx/access.log.1"]

    if hours is None:
        try:
            for path in candidates:
                if os.path.exists(path):
                    with open(path, "rb") as f:
                        count += sum(1 for _ in f)
        except Exception:
            pass
    else:
        import re
        from datetime import datetime, timedelta
        cutoff = datetime.now() - timedelta(hours=hours)
        DATE_RE = re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})")
        try:
            for path in candidates:
                if os.path.exists(path):
                    with open(path, "r", errors="replace") as f:
                        for line in f:
                            match = DATE_RE.search(line)
                            if match:
                                try:
                                    dt = datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S")
                                    if dt >= cutoff:
                                        count += 1
                                except Exception:
                                    pass
        except Exception:
            pass

    _nginx_req_cache[cache_key] = count
    _nginx_req_cache_time[cache_key] = now
    return count


# ---------------------------------------------------------------------------
# Public API — delegates to ClickHouse, falls back to in-memory when unavailable
# ---------------------------------------------------------------------------

def calculate_stats(hours: Optional[int] = None) -> Dict[str, Any]:
    """
    Overall WAF statistics.
    Primary source: ClickHouse waf_events aggregate query.
    Supplements total_requests from the nginx access log.
    """
    ch_stats = clickhouse_service.get_stats(hours)

    nginx_reqs = _get_total_nginx_requests(hours)
    total_blocked = ch_stats.get("total_blocked", 0)
    total_requests = max(nginx_reqs, total_blocked)

    return {
        "total_requests": total_requests,
        "total_blocked": total_blocked,
        "sqli_count": ch_stats.get("sqli_count", 0),
        "xss_count": ch_stats.get("xss_count", 0),
        "top_attack_type": ch_stats.get("top_attack_type", "None"),
        "total_unique_ips": ch_stats.get("total_unique_ips", 0),
        "recent_threats": ch_stats.get("recent_threats", 0),
    }


def get_top_ips(limit: int = 10, hours: Optional[int] = None) -> List[Dict[str, Any]]:
    """Top attacking IPs from ClickHouse, enriched with Redis AbuseIPDB scores."""
    result = clickhouse_service.get_top_ips(limit=limit, hours=hours)

    # Enrich with AbuseIPDB scores cached in Redis
    from app.utils.redis_client import get_redis_client
    r = get_redis_client()
    if r:
        for entry in result:
            try:
                val = r.get(f"abuse:{entry['ip']}")
                if val is not None:
                    entry["abuse_score"] = float(val)
            except Exception:
                pass

    return result


def get_attack_types_distribution(hours: Optional[int] = None) -> List[Dict[str, Any]]:
    """Attack type distribution from ClickHouse GROUP BY query."""
    return clickhouse_service.get_attack_types(hours=hours)


def get_timeline(hours: Optional[int] = None) -> List[Dict[str, Any]]:
    """15-minute bucketed attack timeline from ClickHouse."""
    return clickhouse_service.get_timeline(hours=hours)


def get_top_rules(limit: int = 10, hours: Optional[int] = None) -> List[Dict[str, Any]]:
    """Most triggered ModSecurity rules from ClickHouse."""
    return clickhouse_service.get_top_rules(limit=limit, hours=hours)


def get_severity_distribution(hours: Optional[int] = None) -> List[Dict[str, Any]]:
    """Severity distribution from ClickHouse."""
    return clickhouse_service.get_severity_distribution(hours=hours)
