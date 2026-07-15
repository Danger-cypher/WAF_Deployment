import os
import logging
import time
from datetime import datetime
from typing import List, Dict
from app.config.settings import settings
from app.models.log_model import LogEntry
from app.parsers.modsec_parser import parse_modsec_audit_json
from app.parsers.nginx_errorlog_parser import parse_nginx_error_log

logger = logging.getLogger(__name__)

# In-memory storage for MVP
parsed_entries: Dict[str, LogEntry] = {}

# Path to nginx error log (readable by soc user via adm group)
NGINX_ERROR_LOG = "/var/log/nginx/error.log"
# Rotated copy written by logrotate at midnight — always include both
# Note: error.log.1 is the most recent rotated file (current night's logs)
NGINX_ERROR_LOG_ROTATED = "/var/log/nginx/error.log.1"

# Cache state to optimize redundant disk polling and JSON parsing
cached_logs: List[LogEntry] = []
last_scan_time: float = 0.0
SCAN_INTERVAL: float = 2.0


def list_newest_log_files(limit: int = 5000) -> List[str]:
    """
    Chronologically traverses day-level and minute-level subdirectories of settings.LOG_DIR
    to retrieve the newest audit files, bypassing full directory globbing.
    Only returns files with .json extension.
    """
    import re

    if not os.path.isdir(settings.LOG_DIR):
        return []

    day_re = re.compile(r"^\d{8}$")
    min_re = re.compile(r"^\d{8}-\d{4}$")

    try:
        days = [d for d in os.listdir(settings.LOG_DIR) if day_re.match(d)]
    except Exception as e:
        logger.error(f"Error reading LOG_DIR: {e}")
        return []
    days.sort(reverse=True)

    collected_files = []

    for day in days:
        day_path = os.path.join(settings.LOG_DIR, day)
        if not os.path.isdir(day_path):
            continue

        try:
            minutes = [m for m in os.listdir(day_path) if min_re.match(m)]
        except Exception:
            continue
        minutes.sort(reverse=True)

        for minute in minutes:
            minute_path = os.path.join(day_path, minute)
            if not os.path.isdir(minute_path):
                continue

            try:
                sub_files = [
                    os.path.join(minute_path, f) for f in os.listdir(minute_path)
                ]
            except Exception:
                continue

            for f in sub_files:
                if os.path.isfile(f):
                    collected_files.append(f)

            if len(collected_files) >= limit:
                break
        if len(collected_files) >= limit:
            break

    # Fallback to flat directory search if no chronological directories found
    if not collected_files:
        try:
            collected_files = [
                os.path.join(settings.LOG_DIR, f) for f in os.listdir(settings.LOG_DIR)
            ]
            collected_files = [f for f in collected_files if os.path.isfile(f)]
        except Exception as e:
            logger.error(f"Error reading flat LOG_DIR: {e}")
            return []

    # Sort the files by modification time descending and return up to the limit
    collected_files = sorted(collected_files, key=os.path.getmtime, reverse=True)[
        :limit
    ]
    return collected_files


def scan_log_directory():
    """
    Dynamically rescans the ModSecurity log directory for JSON files,
    sorts them by newest first, and parses them.
    """
    files = list_newest_log_files(limit=5000)

    new_count = 0
    for file_path in files:
        # Simple check to avoid symlink traversal outside of root
        if not os.path.abspath(file_path).startswith(
            os.path.join(os.path.abspath(settings.LOG_DIR), "")
        ):
            continue

        if file_path not in parsed_entries:
            entry = parse_modsec_audit_json(file_path, settings.LOG_DIR)
            if entry:
                new_count += 1
                logger.info(f"New attack parsed from JSON log: {file_path}")
                parsed_entries[file_path] = entry

    if new_count > 0:
        logger.info(f"Loaded {new_count} new entries from JSON audit logs")


def get_all_logs() -> List[LogEntry]:
    """
    Get all WAF log entries, merging JSON audit logs with nginx error log entries.
    The nginx error log is always readable and serves as a reliable fallback.
    Entries from both sources are deduplicated by unique_id.
    """
    global last_scan_time, cached_logs
    current_time = time.time()

    # If the cache is still fresh and contains items, return it directly to avoid disk I/O
    if current_time - last_scan_time < SCAN_INTERVAL and cached_logs:
        return cached_logs

    last_scan_time = current_time

    # Rescan JSON audit directory
    scan_log_directory()

    # Read from nginx error log AND its rotated copy to survive nightly logrotate.
    # After midnight logrotate runs: error.log is empty, all entries are in error.log.1.
    # Merging both ensures the blocked count never drops to 0 after rotation.
    nginx_entries: List[LogEntry] = []
    for log_path in (NGINX_ERROR_LOG, NGINX_ERROR_LOG_ROTATED):
        if os.path.isfile(log_path):
            nginx_entries.extend(parse_nginx_error_log(log_path))

    # Build a merged map: unique_id -> LogEntry, preferring JSON audit log data
    # (more detailed) over error log data
    merged: Dict[str, LogEntry] = {}

    # Start with nginx error log entries (lower priority)
    for entry in nginx_entries:
        merged[entry.id] = entry

    # Override with JSON audit log entries (higher priority, more detail)
    for entry in parsed_entries.values():
        merged[entry.id] = entry

    # Return ALL merged logs (no filtering by HTTP code)
    # This is used for stats, timeline, and analytics
    result = list(merged.values())

    # Sort by timestamp (newest first)
    def parse_time(e):
        try:
            return datetime.fromisoformat(e.timestamp)
        except Exception:
            return datetime.min

    result.sort(key=parse_time, reverse=True)

    logger.debug(
        f"Total merged logs: {len(result)} "
        f"(JSON audit: {len(parsed_entries)}, nginx: {len(nginx_entries)})"
    )

    cached_logs = result
    return result


def get_total_blocked_count() -> int:
    """
    Returns an accurate total count of ALL ModSecurity blocks across both the
    current and most recent rotated error log — without the 5000-entry cap
    that get_all_logs() imposes for dashboard display performance.
    This is the authoritative number for the 'Blocked WAF Threats' card.
    """
    import re
    MODSEC_BLOCK_RE = re.compile(r"ModSecurity: Access denied")
    count = 0
    for log_path in (NGINX_ERROR_LOG, NGINX_ERROR_LOG_ROTATED):
        if not os.path.isfile(log_path):
            continue
        try:
            with open(log_path, 'rb') as f:
                for raw_line in f:
                    try:
                        line = raw_line.decode('utf-8', errors='replace')
                        if MODSEC_BLOCK_RE.search(line):
                            count += 1
                    except Exception:
                        pass
        except Exception as e:
            logger.warning(f"Could not read {log_path} for block count: {e}")
    return count


def get_parsed_files_count() -> int:
    return len(parsed_entries)


def get_blocked_logs_only() -> List[LogEntry]:
    """
    Get only BLOCKED logs (HTTP 4xx/5xx status codes).
    Used for the dashboard logs page to show only threats, not all analyzed traffic.
    """
    all_logs = get_all_logs()
    
    blocked_logs = []
    for entry in all_logs:
        # Include entries with error status codes (blocked/denied)
        if entry.http_code and entry.http_code.startswith(('4', '5')):
            blocked_logs.append(entry)
        # Also include entries from error log (always blocks) even if http_code is missing
        elif entry.violations and len(entry.violations) > 0 and not entry.http_code:
            blocked_logs.append(entry)
    
    return blocked_logs
