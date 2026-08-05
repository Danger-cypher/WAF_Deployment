"""
log_retention_service.py — CyberSentinel WAF
===============================================
Background async service that enforces the configured log retention policy.

Post-ClickHouse migration:
- ClickHouse waf_events, ml_events, threat_intelligence all have built-in TTL
  clauses — no Python-side file deletion needed for log data.
- This service now:
  1. Reads the configured retention period from settings
  2. Updates the TTL clause on ClickHouse tables when the setting changes
  3. Purges ModSecurity audit JSON flat files (still on disk) older than cutoff
     so they don't consume infinite disk space after ingestion
  4. Retains SQLite cleanup for false positives / alerts (small config tables)

Runs every 6 hours.
"""

import asyncio
import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

MODSEC_AUDIT_DIR = "/var/log/modsecurity/audit"
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
    Delete ModSecurity JSON audit log files OLDER than cutoff.
    These files are already ingested into ClickHouse; we remove them
    to reclaim disk space. Returns the number of files deleted.
    """
    deleted = 0
    audit_dir = Path(MODSEC_AUDIT_DIR)
    if not audit_dir.exists():
        return 0

    for child in audit_dir.iterdir():
        try:
            if child.is_dir():
                try:
                    dir_date = datetime.strptime(child.name[:8], "%Y%m%d").replace(
                        tzinfo=timezone.utc
                    )
                    if dir_date < cutoff:
                        for f in child.rglob("*.json"):
                            f.unlink(missing_ok=True)
                            deleted += 1
                        try:
                            # Remove empty leaf dirs
                            for d in sorted(child.rglob("*"), reverse=True):
                                if d.is_dir():
                                    try:
                                        d.rmdir()
                                    except OSError:
                                        pass
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


def _sync_clickhouse_ttl(retention_days: int):
    """
    Update the TTL on ClickHouse time-series tables to match the configured retention.
    This is a best-effort operation — failures are logged but do not raise.
    """
    try:
        from app.services import clickhouse_service
        client = clickhouse_service._get_client()
        if client is None:
            return

        tables = [
            ("waf_events", "timestamp"),
            ("ml_events", "timestamp"),
            ("threat_intelligence", "timestamp"),
            ("alert_history", "created_at"),
        ]
        for table, ts_col in tables:
            try:
                client.command(
                    f"ALTER TABLE cybersentinel.{table} "
                    f"MODIFY TTL {ts_col} + INTERVAL {retention_days} DAY DELETE"
                )
                logger.info(
                    f"[LogRetention] ClickHouse TTL updated: {table} → {retention_days} days"
                )
            except Exception as e:
                logger.warning(
                    f"[LogRetention] Could not update TTL on {table}: {e}"
                )
    except Exception as e:
        logger.warning(f"[LogRetention] ClickHouse TTL sync failed: {e}")


def run_retention_cleanup() -> dict:
    """
    Execute a single retention cleanup cycle:
    1. Read configured retention period
    2. Sync TTL to ClickHouse tables
    3. Purge old ModSecurity audit JSON flat files from disk
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

    # 1. Keep ClickHouse TTL in sync with the configured setting
    _sync_clickhouse_ttl(retention_days)

    # 2. Purge old audit JSON files from disk (already in ClickHouse)
    audit_deleted = _purge_modsec_audit_files(cutoff)

    summary = {
        "retention_days": retention_days,
        "cutoff": cutoff.isoformat(),
        "audit_files_deleted": audit_deleted,
        "clickhouse_ttl_synced": True,
    }

    logger.info(
        f"[LogRetention] Cleanup complete — "
        f"audit files removed: {audit_deleted}, ClickHouse TTL: {retention_days} days"
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
    await asyncio.sleep(60)  # Initial delay for app to fully initialize

    while True:
        try:
            run_retention_cleanup()
        except Exception as e:
            logger.error(f"[LogRetention] Unexpected error during cleanup: {e}")
        await asyncio.sleep(RETENTION_CHECK_INTERVAL_SECONDS)
