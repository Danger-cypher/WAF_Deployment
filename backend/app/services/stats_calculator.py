"""
stats_calculator.py — CyberSentinel WAF
=========================================
All statistics and aggregation queries now execute against ClickHouse.
Falls back to in-memory log_reader data if ClickHouse is unavailable,
so the dashboard never shows a blank screen during ClickHouse cold-start.

PERFORMANCE: Redis-backed caching layer added to all dashboard queries.
Cache TTL: 30 seconds for real-time metrics, 60 seconds for nginx log count.
"""

import os
import time
import json
import logging
from typing import Any, Dict, List, Optional
from collections import Counter

from app.services import clickhouse_service

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Redis cache helper — wraps all ClickHouse calls with a 30s TTL
# ---------------------------------------------------------------------------
_CACHE_TTL = 30  # seconds


def _redis():
    """Get global Redis client — returns None if Redis unavailable."""
    try:
        from app.utils.redis_client import get_global_redis_client
        return get_global_redis_client()
    except Exception:
        return None


def _cache_get(key: str):
    """Return deserialized value from Redis cache, or None if missing/expired."""
    try:
        r = _redis()
        if r is None:
            return None
        raw = r.get(f"cache:{key}")
        if raw is None:
            return None
        return json.loads(raw)
    except Exception:
        return None


def _cache_set(key: str, value: Any, ttl: int = _CACHE_TTL) -> None:
    """Serialize and store value in Redis with TTL."""
    try:
        r = _redis()
        if r is None:
            return
        r.setex(f"cache:{key}", ttl, json.dumps(value, default=str))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Nginx access-log line counter (still read from flat file — not in ClickHouse)
# This gives us the true total request count (blocked + allowed).
# ---------------------------------------------------------------------------
_nginx_req_cache: Dict[int, int] = {}
_nginx_req_cache_time: Dict[int, float] = {}


def _get_total_nginx_requests(hours: Optional[int] = None) -> int:
    """
    Counts NGINX allowed requests (status code != 403) from access logs.
    By excluding blocked requests, we prevent double-counting when we combine
    these counts with the ClickHouse blocked database statistics.
    """
    now = time.monotonic()
    cache_key = hours or 0
    # Cache for 60 seconds to avoid hammering disk/CPU
    if cache_key in _nginx_req_cache and (now - _nginx_req_cache_time.get(cache_key, 0)) < 60.0:
        return _nginx_req_cache[cache_key]

    count = 0
    candidates = ["/var/log/nginx/access.log", "/var/log/nginx/access.log.1"]

    if hours is None:
        try:
            for path in candidates:
                if os.path.exists(path):
                    with open(path, "r", errors="replace") as f:
                        for line in f:
                            parts = line.split('"')
                            if len(parts) >= 3:
                                status_part = parts[2].strip().split()
                                if status_part and status_part[0] != "403":
                                    count += 1
        except Exception:
            pass
    else:
        import re
        from datetime import datetime, timedelta
        cutoff = datetime.now() - timedelta(hours=hours)
        DATE_RE = re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})")
        
        for path in candidates:
            if not os.path.exists(path):
                continue
            try:
                with open(path, "rb") as f:
                    f.seek(0, os.SEEK_END)
                    file_size = f.tell()
                    block_size = 1024 * 64  # 64KB blocks
                    data = b""
                    offset = file_size
                    reached_cutoff = False
                    
                    while offset > 0 and not reached_cutoff:
                        if offset - block_size > 0:
                            offset -= block_size
                            f.seek(offset)
                            block_data = f.read(block_size)
                        else:
                            f.seek(0)
                            block_data = f.read(offset)
                            offset = 0
                        
                        data = block_data + data
                        lines = data.split(b"\n")
                        
                        if offset > 0:
                            data = lines[0]
                            lines = lines[1:]
                        else:
                            data = b""
                            
                        for line_bytes in reversed(lines):
                            if not line_bytes:
                                continue
                            line = line_bytes.decode("utf-8", errors="replace")
                            match = DATE_RE.search(line)
                            if match:
                                try:
                                    dt = datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S")
                                    if dt >= cutoff:
                                        parts = line.split('"')
                                        if len(parts) >= 3:
                                            status_part = parts[2].strip().split()
                                            if status_part and status_part[0] != "403":
                                                count += 1
                                    else:
                                        reached_cutoff = True
                                        break
                                except Exception:
                                    pass
            except Exception as e:
                logger.error(f"Error reading {path} backward: {e}")

    _nginx_req_cache[cache_key] = count
    _nginx_req_cache_time[cache_key] = now
    return count



# ---------------------------------------------------------------------------
# Public API — delegates to ClickHouse, falls back to in-memory when unavailable
# ---------------------------------------------------------------------------

def calculate_stats(hours: Optional[int] = None) -> Dict[str, Any]:
    """
    Overall WAF statistics.
    Combined source: ClickHouse blocked count + Nginx allowed log count.
    Redis-cached for 30 seconds — avoids repeated ClickHouse scans per refresh.
    """
    cache_key = f"stats:{hours}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    nginx_allowed = _get_total_nginx_requests(hours)
    try:
        ch_stats = clickhouse_service.get_stats(hours)
    except Exception as e:
        # A transient ClickHouse failure (query timeout, brief connection
        # drop) must not get cached as if it were a real "zero attacks"
        # result — that previously poisoned the 30s cache window and made
        # the dashboard flicker between real numbers and all-zero on every
        # refresh. Degrade gracefully for THIS request only; the next
        # request tries ClickHouse fresh instead of reusing a cached failure.
        logger.error(f"calculate_stats: ClickHouse query failed, not caching: {e}")
        return {
            "total_requests": nginx_allowed, "total_blocked": 0, "sqli_count": 0,
            "xss_count": 0, "top_attack_type": "None", "total_unique_ips": 0,
            "recent_threats": 0,
        }

    total_blocked = ch_stats.get("total_blocked", 0)
    total_requests = total_blocked + nginx_allowed

    result = {
        "total_requests": total_requests,
        "total_blocked": total_blocked,
        "sqli_count": ch_stats.get("sqli_count", 0),
        "xss_count": ch_stats.get("xss_count", 0),
        "top_attack_type": ch_stats.get("top_attack_type", "None"),
        "total_unique_ips": ch_stats.get("total_unique_ips", 0),
        "recent_threats": ch_stats.get("recent_threats", 0),
    }
    _cache_set(cache_key, result)
    return result


def get_top_ips(limit: int = 10, hours: Optional[int] = None) -> List[Dict[str, Any]]:
    """Top attacking IPs from ClickHouse, enriched with Redis AbuseIPDB scores."""
    cache_key = f"top_ips:{limit}:{hours}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        result = clickhouse_service.get_top_ips(limit=limit, hours=hours)
    except Exception as e:
        logger.error(f"get_top_ips: ClickHouse query failed, not caching: {e}")
        return []

    # Enrich with AbuseIPDB scores cached in Redis
    from app.utils.redis_client import get_global_redis_client
    r = get_global_redis_client()
    if r:
        for entry in result:
            try:
                val = r.get(f"abuse:{entry['ip']}")
                if val is not None:
                    entry["abuse_score"] = float(val)
            except Exception:
                pass

    if result:
        _cache_set(cache_key, result)
    return result


def get_attack_types_distribution(hours: Optional[int] = None) -> List[Dict[str, Any]]:
    """Attack type distribution from ClickHouse GROUP BY query."""
    cache_key = f"attack_types:{hours}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached
    try:
        result = clickhouse_service.get_attack_types(hours=hours)
    except Exception as e:
        logger.error(f"get_attack_types_distribution: ClickHouse query failed, not caching: {e}")
        return []
    if result:
        _cache_set(cache_key, result)
    return result


def get_timeline(hours: Optional[int] = None) -> List[Dict[str, Any]]:
    """15-minute bucketed attack timeline from ClickHouse."""
    cache_key = f"timeline:{hours}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached
    try:
        result = clickhouse_service.get_timeline(hours=hours)
    except Exception as e:
        logger.error(f"get_timeline: ClickHouse query failed, not caching: {e}")
        return []
    if result:
        _cache_set(cache_key, result)
    return result


def get_top_rules(limit: int = 10, hours: Optional[int] = None) -> List[Dict[str, Any]]:
    """Most triggered ModSecurity rules from ClickHouse."""
    cache_key = f"top_rules:{limit}:{hours}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached
    try:
        result = clickhouse_service.get_top_rules(limit=limit, hours=hours)
    except Exception as e:
        logger.error(f"get_top_rules: ClickHouse query failed, not caching: {e}")
        return []
    if result:
        _cache_set(cache_key, result)
    return result


def get_severity_distribution(hours: Optional[int] = None) -> List[Dict[str, Any]]:
    """Severity distribution from ClickHouse."""
    cache_key = f"severity:{hours}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached
    try:
        result = clickhouse_service.get_severity_distribution(hours=hours)
    except Exception as e:
        logger.error(f"get_severity_distribution: ClickHouse query failed, not caching: {e}")
        return [{"severity": s, "count": 0} for s in ["Critical", "High", "Medium", "Low"]]

    if any(item.get("count", 0) > 0 for item in result):
        _cache_set(cache_key, result)
    return result
