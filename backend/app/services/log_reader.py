"""
log_reader.py — CyberSentinel WAF
====================================
Public API for reading WAF log entries.

Architecture (post-ClickHouse migration):
- Primary store: ClickHouse waf_events table
- All reads delegate to clickhouse_service
- File-listing utilities (list_newest_log_files, scan_log_directory) are
  KEPT for use by log_ingestor.py during startup backfill
- The in-memory parsed_entries dict is removed — ClickHouse is the single source of truth

Compatibility:
- All function signatures are unchanged so routes/logs.py requires zero edits
- LogEntry objects are reconstructed from ClickHouse row dicts
"""

import os
import logging
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from app.config.settings import settings
from app.models.log_model import LogEntry, ViolationDetail
from app.parsers.modsec_parser import parse_modsec_audit_json
from app.parsers.nginx_errorlog_parser import parse_nginx_error_log
from app.services import clickhouse_service

logger = logging.getLogger(__name__)

NGINX_ERROR_LOG = "/var/log/nginx/error.log"
NGINX_ERROR_LOG_ROTATED = "/var/log/nginx/error.log.1"

# Backward compatibility dictionary
parsed_entries = {}


# ---------------------------------------------------------------------------
# File listing utilities (kept for log_ingestor backfill)
# ---------------------------------------------------------------------------

def list_newest_log_files(limit: int = 5000) -> List[str]:
    """
    Chronologically traverses the audit log directory and returns the newest
    JSON files up to `limit`.  Used by log_ingestor.py during backfill.
    """
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

    collected: List[str] = []

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
                sub_files = [os.path.join(minute_path, f) for f in os.listdir(minute_path)]
            except Exception:
                continue
            collected.extend(f for f in sub_files if os.path.isfile(f))
            if len(collected) >= limit:
                break
        if len(collected) >= limit:
            break

    # Fallback to flat directory listing
    if not collected:
        try:
            collected = [
                os.path.join(settings.LOG_DIR, f)
                for f in os.listdir(settings.LOG_DIR)
                if os.path.isfile(os.path.join(settings.LOG_DIR, f))
            ]
        except Exception as e:
            logger.error(f"Flat LOG_DIR scan failed: {e}")
            return []

    return sorted(collected, key=os.path.getmtime, reverse=True)[:limit]


def scan_log_directory():
    """
    Legacy scan — now a no-op because log_ingestor handles file watching.
    Kept so main.py can still import it without errors during the transition.
    """
    logger.debug("scan_log_directory called — no-op (log_ingestor handles this now)")


# ---------------------------------------------------------------------------
# LogEntry reconstruction helpers
# ---------------------------------------------------------------------------

def _row_to_log_entry(row: Dict) -> LogEntry:
    """Convert a ClickHouse row dict back to a LogEntry Pydantic model."""
    violations_raw = row.get("violations", [])
    violations = []
    if isinstance(violations_raw, list):
        for v in violations_raw:
            if isinstance(v, dict):
                violations.append(ViolationDetail(**{
                    "rule_id": str(v.get("rule_id", "")),
                    "message": str(v.get("message", "")),
                    "data": str(v.get("data", "")),
                    "pattern": str(v.get("pattern", "")),
                    "file": str(v.get("file", "")),
                    "line_number": str(v.get("line_number", "")),
                }))

    return LogEntry(
        id=str(row.get("id", "")),
        timestamp=str(row.get("timestamp", "")),
        client_ip=str(row.get("client_ip", "")),
        uri=str(row.get("uri", "")),
        method=str(row.get("method", "")),
        http_code=str(row.get("http_code", "")),
        rule_id=str(row.get("rule_id", "")),
        message=str(row.get("message", "")),
        severity=str(row.get("severity", "")),
        attack_type=str(row.get("attack_type", "")),
        hostname=str(row.get("hostname", "")),
        country=str(row.get("country", "")),
        source_asn_org=str(row.get("source_asn_org", "")),
        request_headers=row.get("request_headers", {}),
        response_headers=row.get("response_headers", {}),
        violations=violations,
        raw_log=row.get("raw_log"),
    )


# ---------------------------------------------------------------------------
# Public read API (signatures unchanged from original log_reader.py)
# ---------------------------------------------------------------------------

def get_all_logs(hours: Optional[int] = None) -> List[LogEntry]:
    """
    Fetch all WAF log entries from ClickHouse.
    Returns a list of LogEntry objects sorted newest-first.
    Falls back to empty list if ClickHouse is unavailable.
    """
    rows, _ = clickhouse_service.query_waf_events(
        page=1,
        size=5000,
        hours=hours,
        blocked_only=False,
    )
    return [_row_to_log_entry(r) for r in rows]


def get_blocked_logs_only() -> List[LogEntry]:
    """
    Fetch only blocked (4xx/5xx) WAF log entries from ClickHouse.
    Used by routes/logs.py for the Security Events page.
    """
    rows, _ = clickhouse_service.query_waf_events(
        page=1,
        size=5000,
        blocked_only=True,
    )
    return [_row_to_log_entry(r) for r in rows]


def get_total_blocked_count(hours: Optional[int] = None) -> int:
    """Total count of blocked events from ClickHouse."""
    return clickhouse_service.get_total_blocked_count(hours=hours)


def get_parsed_files_count() -> int:
    """Return total event count stored in ClickHouse (replaces in-memory dict count)."""
    return clickhouse_service.get_total_blocked_count()
