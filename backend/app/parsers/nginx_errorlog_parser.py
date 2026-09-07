import re
import os
import logging
from typing import List, Optional
from datetime import datetime
import pytz
from app.models.log_model import LogEntry, ViolationDetail
from app.utils.attack_classifier import classify_attack
from app.utils.geoip_manager import geoip_manager

logger = logging.getLogger(__name__)

# Regex to parse ModSecurity block entries from nginx error log
# Format: 2026/05/20 16:13:46 [error] <pid>: *<conn> [client <ip>] ModSecurity: Access denied with code <code> (phase <N>). <msg> [...] [id "<rule_id>"] [...] [hostname "<host>"] [uri "<uri>"] [unique_id "<uid>"]
MODSEC_LINE_RE = re.compile(
    r"^(?P<date>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[error\] \d+#\d+: \*\d+ "
    r"\[client (?P<client_ip>[\d\.]+)\] ModSecurity: Access denied with code (?P<http_code>\d+)"
    r'.*?\[id "(?P<rule_id>[^"]+)"\]'
    r'.*?\[msg "(?P<message>[^"]+)"\]'
    r'.*?\[hostname "(?P<hostname>[^"]+)"\]'
    r'.*?\[uri "(?P<uri>[^"]+)"\]'
    r'.*?\[unique_id "(?P<unique_id>[^"]+)"\]',
    re.DOTALL,
)

# Alternative pattern for lines where msg comes before id (order can vary)
MODSEC_LINE_RE2 = re.compile(
    r"^(?P<date>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[error\] \d+#\d+: \*\d+ "
    r"\[client (?P<client_ip>[\d\.]+)\] ModSecurity: Access denied with code (?P<http_code>\d+)"
    r'.*?\[hostname "(?P<hostname>[^"]+)"\]'
    r'.*?\[uri "(?P<uri>[^"]+)"\]'
    r'.*?\[unique_id "(?P<unique_id>[^"]+)"\]',
    re.DOTALL,
)

# Simpler pattern to extract individual bracketed fields
FIELD_RE = re.compile(r'\[(?P<key>\w+) "(?P<value>[^"]*)"\]')

# WAF-LUA-BLOCK: every blocking decision this WAF makes OUTSIDE
# ModSecurity's own rule engine (mTLS/IP-blacklist/JA4/geo-block/adaptive-
# throttle/API-enumeration/API-schema/ML-engine/CRS-fallback — see
# ml-waf/ml_check.lua, ml_decide.lua, enum_detect.lua, schema_validate.lua)
# logs this exact tag right before rejecting a request. Before this
# existed, NONE of these decisions ever reached ClickHouse's waf_events —
# every dashboard metric derived from it (Overview totals, severity
# distribution, top attacking IPs, bot traffic composition, the DDoS page)
# only ever reflected ModSecurity/CRS's own blocks, silently missing every
# other layer this WAF actually enforces (real gap, found + fixed
# 2026-09-04). `uri=` is optional in the tag (not every check has one
# cheaply available) so it's captured loosely rather than required.
WAF_LUA_BLOCK_RE = re.compile(
    r"^(?P<date>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[warn\] .*? "
    r"WAF-LUA-BLOCK reason=(?P<reason>\S+) code=(?P<http_code>\d+) client=(?P<client_ip>[^\s,]+)"
    r"(?: uri=(?P<uri>[^\s,]*))?"
)

# (rule_id, attack_type, severity) per WAF-LUA-BLOCK `reason` — mirrors
# attack_classifier.classify_attack()'s taxonomy so these rows read
# consistently alongside real ModSecurity/CRS rule matches everywhere
# severity/attack_type are displayed or grouped.
_LUA_BLOCK_CLASSIFICATION = {
    "mtls":               ("LUA-MTLS",                "Access Control",       "Medium"),
    "ip_blacklist":        ("LUA-IP-BLACKLIST",        "IP Reputation",        "High"),
    "ja4":                 ("LUA-JA4",                 "Bot/Automation",       "Medium"),
    "geo_block":            ("LUA-GEO-BLOCK",           "Access Control",       "Medium"),
    "adaptive_throttle":    ("LUA-ADAPTIVE-THROTTLE",   "IP Reputation",        "High"),
    "api_enum":             ("LUA-API-ENUM",            "Scanner/Recon",        "High"),
    "bot_ua_limit":         ("LUA-BOT-UA-LIMIT",        "Bot/Automation",       "Medium"),
    "api_schema":           ("LUA-API-SCHEMA",          "Positive Security Violation", "Medium"),
    "crs_fallback":         ("LUA-CRS-FALLBACK",        "Anomaly Threshold Exceeded", "High"),
    "ml_engine":            ("LUA-ML-ENGINE",           "ML Threat Detection", "High"),
    "ml_engine_throttle":   ("LUA-ML-ENGINE-THROTTLE",  "ML Threat Detection", "Medium"),
    "rate_limit":           ("NGINX-RATE-LIMIT",        "DoS/DDoS",            "Medium"),
}

# nginx's own native limit_req/limit_conn REJECTION line (not "delaying" —
# that means the request queued and was still served, the opposite of a
# block; see ddos_analytics.py's RATE_LIMIT_NATIVE_REGEX for the fuller
# explanation of that distinction, verified against nginx's own docs).
# Same gap as WAF-LUA-BLOCK above: this is a real, product-configured
# blocking mechanism (the DDoS & Bot Shield page's L7 Rate Limit / Burst
# Tolerance / Advanced Rules) that, before this, only ever showed up on
# that one page and nowhere else in the dashboard.
NGINX_NATIVE_LIMIT_RE = re.compile(
    r"^(?P<date>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?:error|warn)\] .*? "
    r"limiting (?:requests|connections).*? client: (?P<client_ip>[^,]+), server: (?P<hostname>[^,]*),"
    r'(?:.*?request: "(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) (?P<uri>[^ ]+) HTTP)?'
)


def parse_nginx_error_log(log_path: str = "/var/log/nginx/error.log") -> List[LogEntry]:
    """
    Parse ModSecurity attack entries from nginx error log.
    This is a reliable fallback when JSON audit logs aren't accessible.
    The nginx error log is readable by the 'adm' group (soc user is in adm).
    """
    entries: List[LogEntry] = []

    if not os.path.isfile(log_path):
        logger.warning(f"Nginx error log not found: {log_path}")
        return entries

    if not os.access(log_path, os.R_OK):
        logger.error(f"Cannot read nginx error log: {log_path}. Check permissions.")
        return entries

    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                entry = None
                if "ModSecurity: Access denied" in line:
                    entry = _parse_modsec_line(stripped)
                elif "WAF-LUA-BLOCK" in line:
                    entry = _parse_lua_block_line(stripped)
                elif "limiting requests" in line or "limiting connections" in line:
                    entry = _parse_native_rate_limit_line(stripped)

                if entry:
                    entries.append(entry)

        # Sort by timestamp, newest first (ISO 8601 format: "2026-07-09 07:22:53")
        def parse_time(e):
            try:
                return datetime.fromisoformat(e.timestamp)
            except Exception:
                return datetime.min

        entries.sort(key=parse_time, reverse=True)
        logger.info(f"Parsed {len(entries)} ModSecurity entries from nginx error log")
        return entries

    except PermissionError as e:
        logger.error(f"Permission denied reading {log_path}: {e}")
        return entries
    except Exception as e:
        logger.error(f"Error parsing nginx error log: {type(e).__name__}: {e}")
        return entries


def _parse_modsec_line(line: str) -> Optional[LogEntry]:
    """Parse a single ModSecurity error log line into a LogEntry."""
    try:
        # Extract all [key "value"] fields
        fields = {m.group("key"): m.group("value") for m in FIELD_RE.finditer(line)}

        # Extract date from beginning of line
        date_match = re.match(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", line)
        date_str = date_match.group(1) if date_match else ""

        # Extract client IP
        ip_match = re.search(r"\[client ([\d\.]+)\]", line)
        client_ip = ip_match.group(1) if ip_match else ""

        # Extract HTTP code
        code_match = re.search(r"Access denied with code (\d+)", line)
        http_code = code_match.group(1) if code_match else "403"

        # Extract HTTP method from request line — handles HTTP/1.0, HTTP/1.1 and HTTP/2.0
        method_match = re.search(
            r'request: "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) ', line
        )
        # Default to empty string rather than 'GET' to avoid incorrect labelling
        method = method_match.group(1) if method_match else ""

        rule_id = fields.get("id", "")
        message = fields.get("msg", "")
        hostname = fields.get("hostname", "")
        # Prefer URI from the 'request:' line as it contains the full path+query
        request_match = re.search(
            r'request: "(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) ([^ ]+) HTTP', line
        )
        uri_from_request = request_match.group(1) if request_match else ""
        uri = uri_from_request or fields.get("uri", "")
        unique_id = fields.get("unique_id", "")

        if not unique_id:
            # Generate a deterministic ID from the line content if no unique_id
            import hashlib

            unique_id = hashlib.sha256(line.encode()).hexdigest()[:16]

        # For anomaly scoring rule (949110/980130), infer attack from message content
        if rule_id in ("949110", "980130"):
            attack_type, severity = _classify_from_message(message, uri, line)
        else:
            attack_type, severity = classify_attack(rule_id)

        # Parse timestamp — store as ISO 8601 UTC so the frontend can parse/sort it reliably
        timestamp_str = _nginx_ts_to_utc(date_str)

        country_code = geoip_manager.get_country_code(client_ip)
        source_asn_org = geoip_manager.get_asn_org(client_ip)

        request_headers = {"Host": hostname} if hostname else {}
        response_headers = {}

        from app.models.log_model import ViolationDetail

        violations = []
        if rule_id:
            violations.append(
                ViolationDetail(
                    rule_id=rule_id,
                    message=message,
                    data=fields.get("data", ""),
                    pattern="",
                    file=fields.get("file", ""),
                    line_number=fields.get("line", ""),
                )
            )

        return LogEntry(
            id=unique_id,
            timestamp=timestamp_str,
            client_ip=client_ip,
            uri=uri,
            method=method,
            http_code=http_code,
            rule_id=rule_id,
            message=message,
            severity=severity,
            attack_type=attack_type,
            crs_score=extract_crs_score(message),
            hostname=hostname,
            country=country_code,
            source_asn_org=source_asn_org,
            request_headers=request_headers,
            response_headers=response_headers,
            violations=violations,
            raw_log={
                "source": "nginx_error_log",
                "raw_line": line,
                "timestamp": timestamp_str,
                "client_ip": client_ip,
                "country": country_code,
                "source_asn_org": source_asn_org,
                "uri": uri,
                "method": method,
                "http_code": http_code,
                "rule_id": rule_id,
                "message": message,
                "hostname": hostname,
                "severity": severity,
                "attack_type": attack_type,
                "extracted_fields": fields,
            },
        )

    except Exception as e:
        logger.debug(f"Failed to parse line: {e} | Line: {line[:120]}")
        return None


def _nginx_ts_to_utc(date_str: str) -> str:
    """nginx error-log timestamps are server-local time (IST on this
    deployment) with no timezone marker — same conversion _parse_modsec_line
    already does, factored out so the two new parse functions below don't
    duplicate it."""
    try:
        dt = datetime.strptime(date_str, "%Y/%m/%d %H:%M:%S")
        local_tz = pytz.timezone('Asia/Kolkata')
        dt_local = local_tz.localize(dt)
        dt_utc = dt_local.astimezone(pytz.UTC)
        return dt_utc.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, AttributeError):
        return date_str


def _parse_lua_block_line(line: str) -> Optional[LogEntry]:
    """Parses a WAF-LUA-BLOCK line (see the tag's own comment above) into
    a LogEntry — the counterpart to _parse_modsec_line for every blocking
    decision this WAF makes outside ModSecurity's own rule engine."""
    m = WAF_LUA_BLOCK_RE.search(line)
    if not m:
        return None
    try:
        reason = m.group("reason")
        client_ip = m.group("client_ip")
        http_code = m.group("http_code")
        uri = m.group("uri") or ""
        timestamp_str = _nginx_ts_to_utc(m.group("date"))

        rule_id, attack_type, severity = _LUA_BLOCK_CLASSIFICATION.get(
            reason, (f"LUA-{reason.upper()}", "Unknown", "Medium")
        )
        message = f"Blocked by WAF Lua layer ({reason})"

        # No unique_id in these lines (unlike ModSecurity's own audit
        # entries) — a deterministic hash of the full line is the same
        # fallback _parse_modsec_line already uses when unique_id is
        # missing, so a re-parsed line (e.g. after a log-poll overlap)
        # naturally dedupes against what's already in ClickHouse instead
        # of inserting a duplicate row with a fresh random ID each time.
        import hashlib
        entry_id = hashlib.sha256(line.encode()).hexdigest()[:16]

        country_code = geoip_manager.get_country_code(client_ip)
        source_asn_org = geoip_manager.get_asn_org(client_ip)

        return LogEntry(
            id=entry_id,
            timestamp=timestamp_str,
            client_ip=client_ip,
            uri=uri,
            method="",
            http_code=http_code,
            rule_id=rule_id,
            message=message,
            severity=severity,
            attack_type=attack_type,
            crs_score=extract_crs_score(message),
            hostname="",
            country=country_code,
            source_asn_org=source_asn_org,
            request_headers={},
            response_headers={},
            violations=[ViolationDetail(rule_id=rule_id, message=message)],
            raw_log={
                "source": "nginx_error_log_lua_block",
                "raw_line": line,
                "reason": reason,
                "timestamp": timestamp_str,
                "client_ip": client_ip,
                "country": country_code,
                "source_asn_org": source_asn_org,
                "uri": uri,
                "http_code": http_code,
                "rule_id": rule_id,
                "severity": severity,
                "attack_type": attack_type,
            },
        )
    except Exception as e:
        logger.debug(f"Failed to parse WAF-LUA-BLOCK line: {e} | Line: {line[:160]}")
        return None


def _parse_native_rate_limit_line(line: str) -> Optional[LogEntry]:
    """Parses nginx's own native limit_req/limit_conn REJECTION line (not
    a "delaying" line — that means the request was queued and still
    served, not blocked; see ddos_analytics.py's fuller explanation of
    that distinction) into a LogEntry, so this real, product-configured
    blocking mechanism (DDoS & Bot Shield's L7 Rate Limit / Burst
    Tolerance / Advanced Rules) is visible everywhere waf_events is used,
    not just that one page."""
    if "delaying" in line:
        return None
    m = NGINX_NATIVE_LIMIT_RE.search(line)
    if not m:
        return None
    try:
        client_ip = m.group("client_ip").strip()
        hostname = (m.group("hostname") or "").strip()
        uri = m.group("uri") or ""
        timestamp_str = _nginx_ts_to_utc(m.group("date"))

        rule_id, attack_type, severity = _LUA_BLOCK_CLASSIFICATION["rate_limit"]
        message = "Blocked by nginx native rate limiting (limit_req/limit_conn)"

        import hashlib
        entry_id = hashlib.sha256(line.encode()).hexdigest()[:16]

        country_code = geoip_manager.get_country_code(client_ip)
        source_asn_org = geoip_manager.get_asn_org(client_ip)

        # limit_req_status/limit_conn_status is admin-configured (this
        # deployment defaults "Silent Drop"->444, "Block"->429) — not
        # captured in the log line itself, so this reports the WAF's own
        # generic rate-limit code (429) rather than guessing the real one.
        return LogEntry(
            id=entry_id,
            timestamp=timestamp_str,
            client_ip=client_ip,
            uri=uri,
            method="",
            http_code="429",
            rule_id=rule_id,
            message=message,
            severity=severity,
            attack_type=attack_type,
            crs_score=extract_crs_score(message),
            hostname=hostname,
            country=country_code,
            source_asn_org=source_asn_org,
            request_headers={"Host": hostname} if hostname else {},
            response_headers={},
            violations=[ViolationDetail(rule_id=rule_id, message=message)],
            raw_log={
                "source": "nginx_error_log_native_rate_limit",
                "raw_line": line,
                "timestamp": timestamp_str,
                "client_ip": client_ip,
                "country": country_code,
                "source_asn_org": source_asn_org,
                "uri": uri,
                "hostname": hostname,
                "rule_id": rule_id,
                "severity": severity,
                "attack_type": attack_type,
            },
        )
    except Exception as e:
        logger.debug(f"Failed to parse native rate-limit line: {e} | Line: {line[:160]}")
        return None


def extract_crs_score(message: str) -> Optional[float]:
    """Pulls ModSecurity's accumulated CRS anomaly score out of a 949110 /
    980130 message ("Inbound Anomaly Score Exceeded (Total Score: 23)").

    Returns None when the message carries no score, which is the correct
    value for events that genuinely have none — a Lua-originated block
    (WAF-LUA-BLOCK) or a native rate-limit rejection. None, not 0.0:
    alert_manager.evaluate_condition() treats a missing score as no-match
    for a crs_score_gt rule, and a fabricated 0.0 would be indistinguishable
    from a real request that scored zero.

    Broken out of _classify_from_message() (which already parsed this to
    derive severity) so the value can be attached to the LogEntry itself —
    see LogEntry.crs_score and audit finding P1-02.
    """
    if not message:
        return None
    m = re.search(r"Total Score:\s*(\d+)", message)
    return float(m.group(1)) if m else None


def _classify_from_message(message: str, uri: str, full_line: str) -> tuple:
    """
    Infer attack type and severity from anomaly scoring messages and URI/request context.
    Rule 949110 fires when BLOCKING_INBOUND_ANOMALY_SCORE is exceeded.
    We look at the score and the URI/request content to classify.
    """
    # Extract score from message like "Inbound Anomaly Score Exceeded (Total Score: 23)"
    score_match = re.search(r"Total Score:\s*(\d+)", message)
    score = int(score_match.group(1)) if score_match else 0

    # Determine severity based on score
    if score >= 20:
        severity = "Critical"
    elif score >= 10:
        severity = "High"
    elif score >= 5:
        severity = "Medium"
    else:
        severity = "Low"

    # Try to infer attack type from URI and request content
    import urllib.parse
    uri_lower = urllib.parse.unquote(uri).lower()
    line_lower = full_line.lower()

    if any(
        x in line_lower
        for x in [
            "<script",
            "alert(",
            "onerror=",
            "onload=",
            "javascript:",
            "xss",
            "%3cscript",
        ]
    ) or any(x in uri_lower for x in ["<script", "xss", "alert(", "javascript:"]):
        return "XSS", severity
    elif any(
        x in line_lower
        for x in [
            "select ",
            "union ",
            "insert ",
            "drop ",
            "or 1=1",
            "sqlmap",
            "'or'",
            "sql",
        ]
    ) or any(x in uri_lower for x in ["select ", "union ", "or 1=1", "sql"]):
        return "SQL Injection", severity
    elif any(
        x in line_lower
        for x in ["../", "..%2f", "/etc/passwd", "directory traversal", "lfi", "rfi"]
    ) or any(x in uri_lower for x in ["../", "..%2f", "/etc/passwd"]):
        return "LFI/RFI", severity
    elif any(
        x in line_lower
        for x in ["cmd=", "exec(", "system(", "/bin/", "whoami", "passwd", "shell"]
    ):
        return "RCE", severity
    elif any(x in line_lower for x in ["<?php", "eval(", "base64_decode", "phpinfo"]):
        return "PHP Injection", severity
    elif any(
        x in line_lower
        for x in ["scanner", "nikto", "nmap", "sqlmap", "burp", "dirbuster"]
    ):
        return "Scanner/Recon", severity
    else:
        return "Anomaly Detected", severity
