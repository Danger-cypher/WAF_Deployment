"""
log_retention_service.py
========================
Background async service that enforces the configured log retention policy.
Runs every 6 hours, purges ModSecurity JSON audit files and SQLite log entries
older than the configured retention window (default: 30 days).

Retention setting format: "7 Days", "14 Days", "30 Days", "90 Days"
"""

import os
import asyncio
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Paths
MODSEC_AUDIT_DIR = "/var/log/modsecurity/audit"
SQLITE_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "waf_logs.db"
)

# How frequently the retention job runs (every 6 hours)
RETENTION_CHECK_INTERVAL_SECONDS = 6 * 3600


def _parse_retention_days(retention_str: str) -> int:
    """Parse '7 Days', '30 Days' etc. into integer days. Default: 30."""
    try:
        parts = retention_str.strip().lower().split()
        if parts and parts[0].isdigit():
            return int(parts[0])
    except Exception:
        pass
    return 30


def _purge_modsec_audit_files(cutoff: datetime) -> int:
    """
    Delete ModSecurity JSON audit log files older than cutoff.
    Handles both flat /var/log/modsecurity/audit/*.json files
    and date-partitioned subdirs /var/log/modsecurity/audit/YYYYMMDD/*.json
    Returns number of files deleted.
    """
    deleted = 0
    audit_dir = Path(MODSEC_AUDIT_DIR)
    if not audit_dir.exists():
        return 0

    for child in audit_dir.iterdir():
        try:
            if child.is_dir():
                try:
                    dir_date = datetime.strptime(child.name, "%Y%m%d").replace(
                        tzinfo=timezone.utc
                    )
                    if dir_date < cutoff:
                        for f in child.glob("*.json"):
                            f.unlink(missing_ok=True)
                            deleted += 1
                        try:
                            child.rmdir()
                        except OSError:
                            pass
                except ValueError:
                    pass
            elif child.is_file() and child.suffix == ".json":
                mtime = datetime.fromtimestamp(child.stat().st_mtime, tz=timezone.utc)
                if mtime < cutoff:
                    child.unlink(missing_ok=True)
                    deleted += 1
        except Exception as e:
            logger.warning(f"Error processing audit path {child}: {e}")

    return deleted


def _purge_sqlite_log_entries(cutoff: datetime) -> int:
    """
    Delete log entries older than cutoff from SQLite waf_logs.db.
    Returns number of rows deleted.
    """
    if not os.path.exists(SQLITE_DB_PATH):
        return 0

    deleted = 0
    cutoff_iso = cutoff.strftime("%Y-%m-%dT%H:%M:%S")

    try:
        conn = sqlite3.connect(SQLITE_DB_PATH, timeout=10.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        cur = conn.cursor()

        for table in ("logs", "waf_events", "ml_events", "attack_events"):
            try:
                cur.execute(
                    f"DELETE FROM {table} WHERE timestamp < ?", (cutoff_iso,)  # nosec B608
                )
                deleted += cur.rowcount
            except sqlite3.OperationalError:
                pass  # Table may not exist

        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error purging SQLite log entries: {e}")

    return deleted


def run_retention_cleanup() -> dict:
    """
    Execute a single retention cleanup cycle. Reads configured retention
    from settings, calculates cutoff, and purges qualifying data.
    Returns a summary dict.
    """
    from app.services.settings_manager import settings_manager

    log_settings = settings_manager.get_log_settings()
    retention_str = log_settings.get("retention", "30 Days")
    retention_days = _parse_retention_days(retention_str)
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    logger.info(
        f"[LogRetention] Running cleanup — retaining last {retention_days} days "
        f"(cutoff: {cutoff.strftime('%Y-%m-%d %H:%M UTC')})"
    )

    audit_deleted = _purge_modsec_audit_files(cutoff)
    db_deleted = _purge_sqlite_log_entries(cutoff)

    summary = {
        "retention_days": retention_days,
        "cutoff": cutoff.isoformat(),
        "audit_files_deleted": audit_deleted,
        "db_rows_deleted": db_deleted,
    }

    logger.info(
        f"[LogRetention] Cleanup complete — "
        f"audit files removed: {audit_deleted}, DB rows removed: {db_deleted}"
    )
    return summary


async def start_log_retention_service():
    """
    Background async loop that runs log retention cleanup every 6 hours.
    Call with asyncio.create_task() during application startup.
    """
    logger.info(
        f"[LogRetention] Service started. "
        f"Runs every {RETENTION_CHECK_INTERVAL_SECONDS // 3600}h."
    )
    # Short initial delay so app fully initializes before first run
    await asyncio.sleep(60)

    while True:
        try:
            run_retention_cleanup()
        except Exception as e:
            logger.error(f"[LogRetention] Unexpected error during cleanup: {e}")
        await asyncio.sleep(RETENTION_CHECK_INTERVAL_SECONDS)
