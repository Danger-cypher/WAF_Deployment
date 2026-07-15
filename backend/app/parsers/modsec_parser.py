import json
import logging
import os
from typing import Optional
from datetime import datetime
import pytz
from app.models.log_model import LogEntry
from app.utils.attack_classifier import classify_attack
from app.utils.geoip_manager import geoip_manager

logger = logging.getLogger(__name__)


def parse_modsec_audit_json(file_path: str, log_dir: str) -> Optional[LogEntry]:
    """
    Safely reads a ModSecurity concurrent JSON audit log file.
    Prevents path traversal by ensuring the file is within the allowed log directory.
    """
    # Security: Prevent path traversal by fully resolving paths and checking boundaries
    abs_file_path = os.path.abspath(file_path)
    abs_log_dir = os.path.abspath(log_dir)

    # Enforce trailing slash to prevent partial matching bypasses
    # e.g., /var/log/modsecurity/audit-malicious bypassing /var/log/modsecurity/audit check
    if not abs_file_path.startswith(os.path.join(abs_log_dir, "")):
        logger.warning(
            f"Path traversal attempt detected or file out of bounds: {abs_file_path}"
        )
        return None

    try:
        if not os.path.isfile(abs_file_path) or os.path.getsize(abs_file_path) == 0:
            return None
    except Exception:
        return None

    try:
        with open(abs_file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

            # Extract relevant fields. We default to "" if missing.
            transaction = data.get("transaction", {})
            request = transaction.get("request", {})
            response = transaction.get("response", {})
            messages = transaction.get("messages", [])

            client_ip = transaction.get("client_ip", "")
            raw_timestamp = transaction.get("time_stamp", transaction.get("time", ""))
            timestamp = raw_timestamp
            if raw_timestamp:
                try:
                    import re
                    # Parse ModSecurity timestamp: "Mon Jul 13 12:38:54 2026" (server local time)
                    clean_ts = re.sub(r"\s+", " ", raw_timestamp.strip())
                    dt = datetime.strptime(clean_ts, "%a %b %d %H:%M:%S %Y")
                    # Convert to UTC since the server runs in IST (UTC+5:30)
                    local_tz = pytz.timezone('Asia/Kolkata')
                    dt_local = local_tz.localize(dt)
                    dt_utc = dt_local.astimezone(pytz.UTC)
                    timestamp = dt_utc.strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    pass
            transaction_id = transaction.get(
                "unique_id", transaction.get("transaction_id", "")
            )
            uri = request.get("uri", "")
            method = request.get("method", "")
            http_code = str(response.get("http_code", ""))

            # Use headers if needed for hostname
            headers = request.get("headers", {})
            hostname = headers.get("Host", "")

            # If there are messages (alerts), extract the primary rule triggered
            rule_id = ""
            message_text = ""
            attack_type = "Unknown"
            severity = "Low"

            severity_weights = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

            if messages:
                for msg in messages:
                    current_r_id = str(msg.get("details", {}).get("ruleId", ""))
                    current_m_txt = msg.get("message", "")
                    current_a_type, current_sev = classify_attack(current_r_id)

                    # If this rule is more severe than the best we've seen, update
                    if severity_weights.get(current_sev, 0) > severity_weights.get(
                        severity, 0
                    ):
                        if current_a_type != "Anomaly Threshold Exceeded":
                            rule_id = current_r_id
                            message_text = current_m_txt
                            attack_type = current_a_type
                            severity = current_sev
                    elif severity_weights.get(current_sev, 0) == severity_weights.get(
                        severity, 0
                    ):
                        # Only overwrite if the existing attack type is generic/unknown
                        if attack_type in [
                            "Protocol Violation",
                            "Anomaly Threshold Exceeded",
                            "Unknown",
                        ] and current_a_type not in [
                            "Protocol Violation",
                            "Anomaly Threshold Exceeded",
                            "Unknown",
                        ]:
                            rule_id = current_r_id
                            message_text = current_m_txt
                            attack_type = current_a_type
                            severity = current_sev

                # Fallback if somehow nothing matched cleanly
                if not rule_id and messages:
                    rule_id = str(messages[0].get("details", {}).get("ruleId", ""))
                    message_text = messages[0].get("message", "")
                    attack_type, severity = classify_attack(rule_id)

            country_code = geoip_manager.get_country_code(client_ip)
            source_asn_org = geoip_manager.get_asn_org(client_ip)
            data["country"] = country_code
            data["source_asn_org"] = source_asn_org

            # Extract Request and Response headers
            request_headers = request.get("headers", {})
            response_headers = response.get("headers", {})

            # Convert header values to string just in case
            request_headers = {k: str(v) for k, v in request_headers.items()}
            response_headers = {k: str(v) for k, v in response_headers.items()}

            # Extract detailed violations list
            violations = []
            import re

            pattern_regex = re.compile(r'Pattern match "(.*?)"')

            seen_violations = set()
            for msg in messages:
                m_rule_id = str(msg.get("details", {}).get("ruleId", ""))
                if not m_rule_id:
                    continue

                m_message = msg.get("message", "")
                m_data = msg.get("details", {}).get("data", "")
                m_file = msg.get("details", {}).get("file", "")
                m_line = str(msg.get("details", {}).get("lineNumber", ""))

                # Regex capture for the matched pattern inside the warning message
                pat_match = pattern_regex.search(m_message)
                m_pattern = pat_match.group(1) if pat_match else ""

                violation_key = (m_rule_id, m_data)
                if violation_key in seen_violations:
                    continue
                seen_violations.add(violation_key)

                from app.models.log_model import ViolationDetail

                violations.append(
                    ViolationDetail(
                        rule_id=m_rule_id,
                        message=m_message,
                        data=m_data,
                        pattern=m_pattern,
                        file=m_file,
                        line_number=m_line,
                    )
                )

            return LogEntry(
                id=transaction_id,
                timestamp=timestamp,
                client_ip=client_ip,
                uri=uri,
                method=method,
                http_code=http_code,
                rule_id=rule_id,
                message=message_text,
                severity=severity,
                attack_type=attack_type,
                hostname=hostname,
                country=country_code,
                source_asn_org=source_asn_org,
                request_headers=request_headers,
                response_headers=response_headers,
                violations=violations,
                raw_log=data,
            )

    except PermissionError as e:
        logger.error(
            f"PERMISSION DENIED reading log file {abs_file_path}: {e}. "
            f"Run: sudo chmod -R o+r /var/log/modsecurity/audit && sudo find /var/log/modsecurity/audit -type d -exec chmod o+x {{}} \\;"
        )
        return None
    except json.JSONDecodeError as e:
        logger.debug(
            f"JSON not fully written or invalid in {abs_file_path} (line {e.lineno}): {e.msg}"
        )
        return None
    except Exception as e:
        logger.error(f"Error parsing log file {abs_file_path}: {type(e).__name__}: {e}")
        return None
