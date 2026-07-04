import os
from typing import List, Dict, Any
from app.services.log_reader import get_all_logs
from collections import Counter


def calculate_stats() -> Dict[str, Any]:
    logs = get_all_logs()

    total_requests = len(logs)

    # In ModSecurity context, if we have an audit log it usually means it was flagged/blocked depending on SecRuleEngine.
    # We will assume all parsed logs here are 'blocked' or flagged for this MVP.
    total_blocked = total_requests

    sqli_count = sum(1 for log in logs if log.attack_type == "SQL Injection")
    xss_count = sum(1 for log in logs if log.attack_type == "XSS")

    attack_types = [log.attack_type for log in logs if log.attack_type != "Unknown"]
    top_attack_type = "None"
    if attack_types:
        top_attack_type = Counter(attack_types).most_common(1)[0][0]

    unique_ips = len(set(log.client_ip for log in logs if log.client_ip))

    return {
        "total_requests": total_requests,
        "total_blocked": total_blocked,
        "sqli_count": sqli_count,
        "xss_count": xss_count,
        "top_attack_type": top_attack_type,
        "total_unique_ips": unique_ips,
    }


def get_top_ips(limit: int = 10) -> List[Dict[str, Any]]:
    logs = get_all_logs()
    ips = [log.client_ip for log in logs if log.client_ip]
    most_common = Counter(ips).most_common(limit)
    
    # Map IPs to country code from logs
    ip_to_country = {}
    for log in logs:
        if log.client_ip and log.country:
            ip_to_country[log.client_ip] = log.country
            
    # Connect to Redis to fetch AbuseIPDB scores.
    # Uses REDIS_HOST env var so Docker containers can point to the host Redis
    # instead of hanging on localhost (which doesn't exist inside the container).
    import redis
    redis_host     = os.environ.get("REDIS_HOST", "localhost")
    redis_password = os.environ.get("REDIS_PASSWORD", "YourSecureRedisPassword123!")
    r = redis.Redis(
        host=redis_host,
        port=6379,
        password=redis_password if redis_password else None,
        socket_timeout=0.5,          # fail fast — 500 ms max
        socket_connect_timeout=0.5,
    )

    result = []
    for ip, count in most_common:
        country = ip_to_country.get(ip, "Unknown")
        abuse_score = 0.0
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



def get_attack_types_distribution() -> List[Dict[str, Any]]:
    logs = get_all_logs()
    types = [log.attack_type for log in logs]
    counts = Counter(types)
    return [{"attack_type": t, "count": c} for t, c in counts.items()]


def get_timeline() -> List[Dict[str, Any]]:
    logs = get_all_logs()
    # Group by 15-minute intervals
    timeline_counter = {}
    
    # logs are sorted newest first, so we reverse to go oldest first (chronological)
    for log in reversed(logs):
        if log.timestamp:
            try:
                # log.timestamp format: 'Fri Jun 19 15:44:29 2026'
                # log.timestamp[:13] is 'Fri Jun 19 15'
                # log.timestamp[14:16] is the minute '44'
                minute = int(log.timestamp[14:16])
                rounded_minute = (minute // 15) * 15
                time_bucket = f"{log.timestamp[:13]}:{rounded_minute:02d}"
                timeline_counter[time_bucket] = timeline_counter.get(time_bucket, 0) + 1
            except Exception:
                pass

    return [{"time": t, "count": c} for t, c in timeline_counter.items()][-40:]



def get_top_rules(limit: int = 10) -> List[Dict[str, Any]]:
    logs = get_all_logs()
    rules = [log.rule_id for log in logs if log.rule_id]
    most_common = Counter(rules).most_common(limit)
    return [{"rule_id": r, "count": c} for r, c in most_common]


def get_severity_distribution() -> List[Dict[str, Any]]:
    logs = get_all_logs()
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
