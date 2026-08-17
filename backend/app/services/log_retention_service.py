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
from typing import Optional

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


def _purge_modsec_audit_files(cutoff: datetime) -> tuple[int, int]:
    """
    Delete ModSecurity JSON audit log files OLDER than cutoff.
    These files are already ingested into ClickHouse; we remove them
    to reclaim disk space. Returns (deleted_count, error_count).

    error_count is tracked separately from a silent `logger.warning` because
    a permission mismatch (audit files written as root, backend running as a
    non-root user) fails every unlink() the same way every cycle, forever,
    with nothing but a debug-level log line to notice it by — the retention
    service looks healthy while doing nothing. Callers use error_count to
    decide whether to page someone.
    """
    deleted = 0
    errors = 0
    audit_dir = Path(MODSEC_AUDIT_DIR)
    if not audit_dir.exists():
        return 0, 0

    for child in audit_dir.iterdir():
        try:
            if child.is_dir():
                try:
                    dir_date = datetime.strptime(child.name[:8], "%Y%m%d").replace(
                        tzinfo=timezone.utc
                    )
                    if dir_date < cutoff:
                        for f in child.rglob("*.json"):
                            try:
                                f.unlink(missing_ok=True)
                                deleted += 1
                            except OSError as e:
                                errors += 1
                                logger.warning(f"Could not delete audit file {f}: {e}")
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
                    try:
                        child.unlink(missing_ok=True)
                        deleted += 1
                    except OSError as e:
                        errors += 1
                        logger.warning(f"Could not delete audit file {child}: {e}")
        except Exception as e:
            errors += 1
            logger.warning(f"Error processing audit path {child}: {e}")

    return deleted, errors


def _count_stale_audit_dirs(cutoff: datetime) -> tuple[int, Optional[str]]:
    """
    Cheap post-purge self-check: count top-level dated audit directories
    that are still older than cutoff after a purge cycle just ran, and
    report the oldest one. A non-zero count here — right after purging —
    means the purge silently failed to keep up (most likely a permissions
    problem), not just that nothing needed deleting.
    """
    audit_dir = Path(MODSEC_AUDIT_DIR)
    if not audit_dir.exists():
        return 0, None

    stale = []
    for child in audit_dir.iterdir():
        if not child.is_dir():
            continue
        try:
            dir_date = datetime.strptime(child.name[:8], "%Y%m%d").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if dir_date < cutoff:
            stale.append((dir_date, child.name))

    if not stale:
        return 0, None
    stale.sort()
    return len(stale), stale[0][1]


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
    audit_deleted, audit_errors = _purge_modsec_audit_files(cutoff)

    # 3. Self-check: anything still older than cutoff right after purging
    #    means the purge isn't keeping up (permissions, disk, etc.) even if
    #    it reported zero errors on this particular cycle's files.
    stale_dirs, oldest_stale_dir = _count_stale_audit_dirs(cutoff)

    summary = {
        "retention_days": retention_days,
        "cutoff": cutoff.isoformat(),
        "audit_files_deleted": audit_deleted,
        "audit_purge_errors": audit_errors,
        "stale_audit_dirs_remaining": stale_dirs,
        "oldest_stale_audit_dir": oldest_stale_dir,
        "clickhouse_ttl_synced": True,
    }

    logger.info(
        f"[LogRetention] Cleanup complete — "
        f"audit files removed: {audit_deleted} (errors: {audit_errors}), "
        f"stale dirs remaining: {stale_dirs}, ClickHouse TTL: {retention_days} days"
    )
    return summary


async def _alert_if_unhealthy(summary: dict) -> None:
    """
    Fire a health_check_failed alert (existing alerts pipeline — dashboard
    bell + any configured notification channels) when the retention cycle
    shows signs of not actually working: delete errors this cycle, or
    audit directories that are still older than the retention cutoff right
    after a purge just ran.
    """
    errors = summary.get("audit_purge_errors", 0)
    stale = summary.get("stale_audit_dirs_remaining", 0)
    if not errors and not stale:
        return
    try:
        from app.services.alert_manager import alert_manager
        detail = (
            f"Log retention purge is not keeping up: {errors} delete error(s) this cycle, "
            f"{stale} audit director{'y' if stale == 1 else 'ies'} still older than the "
            f"{summary.get('retention_days')}-day retention cutoff "
            f"(oldest: {summary.get('oldest_stale_audit_dir') or 'n/a'}). "
            f"Likely cause: the backend process lacks permission to delete files under "
            f"{MODSEC_AUDIT_DIR}."
        )
        await alert_manager.trigger_event(
            event_type="health_check_failed",
            event_data={
                "component": "log_retention_service",
                "audit_purge_errors": errors,
                "stale_audit_dirs_remaining": stale,
                "oldest_stale_audit_dir": summary.get("oldest_stale_audit_dir"),
                "retention_days": summary.get("retention_days"),
            },
            custom_message=detail,
        )
    except Exception as e:
        logger.error(f"[LogRetention] Failed to dispatch health-check alert: {e}")


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

    from app.services import heartbeat_registry

    while True:
        try:
            summary = run_retention_cleanup()
            await _alert_if_unhealthy(summary)
            heartbeat_registry.record_heartbeat(
                "log_retention", RETENTION_CHECK_INTERVAL_SECONDS, status="ok"
            )
        except Exception as e:
            logger.error(f"[LogRetention] Unexpected error during cleanup: {e}")
            heartbeat_registry.record_heartbeat(
                "log_retention", RETENTION_CHECK_INTERVAL_SECONDS, status="error", detail=str(e)
            )
            try:
                from app.services.alert_manager import alert_manager
                await alert_manager.trigger_event(
                    event_type="health_check_failed",
                    event_data={"component": "log_retention_service", "error": str(e)},
                    custom_message=f"Log retention cleanup cycle crashed: {e}",
                )
            except Exception as alert_err:
                logger.error(f"[LogRetention] Failed to dispatch crash alert: {alert_err}")
        await asyncio.sleep(RETENTION_CHECK_INTERVAL_SECONDS)
