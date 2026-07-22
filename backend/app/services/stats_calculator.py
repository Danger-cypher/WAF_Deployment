import os
from typing import List, Dict, Any
from app.services.log_reader import get_all_logs, get_total_blocked_count
from collections import Counter


import time

_nginx_req_cache = {}
_nginx_req_cache_time = {}

def _get_total_nginx_requests(hours: int = None) -> int:
    now = time.monotonic()
    cache_key = hours or 0
    if cache_key in _nginx_req_cache and (now - _nginx_req_cache_time.get(cache_key, 0)) < 5.0:
        return _nginx_req_cache[cache_key]

    count = 0
    candidates = [
        '/var/log/nginx/access.log',
        '/var/log/nginx/access.log.1',
    ]
    
    if hours is None:
        try:
            for path in candidates:
                if os.path.exists(path):
                    with open(path, 'rb') as f:
                        count += sum(1 for _ in f)
            _nginx_req_cache[cache_key] = count
            _nginx_req_cache_time[cache_key] = now
            return count
        except Exception:
            return 0
            
    # Time-filtered logic
    import re
    from datetime import datetime, timedelta
    cutoff = datetime.now() - timedelta(hours=hours)
    # Nginx access log timestamp: [17/Jul/2026:10:02:00 +0000]
    DATE_RE = re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})")
    try:
        for path in candidates:
            if os.path.exists(path):
                with open(path, 'r', errors='replace') as f:
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

def calculate_stats(hours: int = None) -> Dict[str, Any]:
    logs = get_all_logs(hours)

    # Total requests is all traffic processed by the proxy (read from NGINX access log)
    nginx_reqs = _get_total_nginx_requests(hours)

    # Blocked count: read ALL "Access denied" lines directly from both error logs
    # (not capped at 5000 like get_all_logs). This is the true cumulative block count.
    total_blocked = get_total_blocked_count(hours)

    # If WAF logs exceed access logs (due to log rotation sync issues), fallback gracefully
    total_requests = max(nginx_reqs, total_blocked)

    sqli_count = sum(1 for log in logs if log.attack_type == "SQL Injection")
    xss_count = sum(1 for log in logs if log.attack_type == "XSS")

    attack_types = [log.attack_type for log in logs if log.attack_type != "Unknown"]
    top_attack_type = "None"
    if attack_types:
        top_attack_type = Counter(attack_types).most_common(1)[0][0]

    unique_ips = len(set(log.client_ip for log in logs if log.client_ip))

    import time
    from datetime import datetime
    current_time = time.time()
    
    recent_threats = 0
    for log in logs:
        if log.timestamp:
            try:
                # ModSecurity time format or ISO
                # log.timestamp is usually YYYY-MM-DD HH:MM:SS from parser
                dt = datetime.strptime(log.timestamp, "%Y-%m-%d %H:%M:%S")
                log_time = dt.timestamp()
                if current_time - log_time < 60:  # within last 60 seconds
                    recent_threats += 1
            except Exception:
                pass

    return {
        "total_requests": total_requests,
        "total_blocked": total_blocked,
        "sqli_count": sqli_count,
        "xss_count": xss_count,
        "top_attack_type": top_attack_type,
        "total_unique_ips": unique_ips,
        "recent_threats": recent_threats,
    }


def get_top_ips(limit: int = 10, hours: int = None) -> List[Dict[str, Any]]:
    logs = get_all_logs(hours)
    ips = [log.client_ip for log in logs if log.client_ip]
    most_common = Counter(ips).most_common(limit)
    
    # Map IPs to country code from logs
    ip_to_country = {}
    for log in logs:
        if log.client_ip and log.country:
            ip_to_country[log.client_ip] = log.country
            
    # Connect to Redis using centralized client to fetch AbuseIPDB scores.
    # Uses REDIS_HOST env var so Docker containers can point to the host Redis
    # instead of hanging on localhost (which doesn't exist inside the container).
    from app.utils.redis_client import get_redis_client
    r = get_redis_client()

    result = []
    for ip, count in most_common:
        country = ip_to_country.get(ip, "Unknown")
        abuse_score = 0.0
        if r:
            try:
                val = r.get(f"abuse:{ip}")
                if val is not None:
                    abuse_score = float(val)
            except Exception:
                pass  # Redis unavailable — skip abuse scores gracefully

        result.append({
            "ip": ip,
            "count": count,
            "country": country,
            "abuse_score": abuse_score
        })
    return result



def get_attack_types_distribution(hours: int = None) -> List[Dict[str, Any]]:
    logs = get_all_logs(hours)
    types = [log.attack_type for log in logs]
    counts = Counter(types)
    return [{"attack_type": t, "count": c} for t, c in counts.items()]


def get_timeline(hours: int = None) -> List[Dict[str, Any]]:
    logs = get_all_logs(hours)
    # Group by 15-minute intervals
    timeline_counter = {}
    
    # logs are sorted newest first, so we reverse to go oldest first (chronological)
    for log in reversed(logs):
        if log.timestamp:
            try:
                parts = log.timestamp.split(':')
                minute = int(parts[1])
                rounded_minute = (minute // 15) * 15
                time_bucket = f"{parts[0]}:{rounded_minute:02d}"
                timeline_counter[time_bucket] = timeline_counter.get(time_bucket, 0) + 1
            except Exception:
                pass

    return [{"time": t, "count": c} for t, c in timeline_counter.items()][-40:]



def get_top_rules(limit: int = 10, hours: int = None) -> List[Dict[str, Any]]:
    logs = get_all_logs(hours)
    rules = [log.rule_id for log in logs if log.rule_id]
    most_common = Counter(rules).most_common(limit)
    return [{"rule_id": r, "count": c} for r, c in most_common]


def get_severity_distribution(hours: int = None) -> List[Dict[str, Any]]:
    logs = get_all_logs(hours)
    # Normalize severities to standardized Title Case
    severities = []
    for log in logs:
        if log.severity:
            sev = log.severity.strip().capitalize()
            # Normalize common names
            if sev == "Crit":
                sev = "Critical"
            elif sev == "Warn":
                sev = "High"
            elif sev == "Info" or sev == "Notice":
                sev = "Low"
            severities.append(sev)

    counts = Counter(severities)
    # Ensure all standard severities are represented, even if 0
    standards = ["Critical", "High", "Medium", "Low"]
    return [{"severity": s, "count": counts.get(s, 0)} for s in standards]
