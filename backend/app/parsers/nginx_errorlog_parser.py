import re
import os
import logging
from typing import List, Optional
from datetime import datetime
import pytz
from app.models.log_model import LogEntry
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
                if "ModSecurity: Access denied" not in line:
                    continue

                entry = _parse_modsec_line(line.strip())
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
        timestamp_str = date_str
        try:
            dt = datetime.strptime(date_str, "%Y/%m/%d %H:%M:%S")
            # Convert to UTC since nginx error logs are in server local time (IST)
            local_tz = pytz.timezone('Asia/Kolkata')
            dt_local = local_tz.localize(dt)
            dt_utc = dt_local.astimezone(pytz.UTC)
            timestamp_str = dt_utc.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, AttributeError):
            pass

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
