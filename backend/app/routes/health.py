import os
import time
import pathlib
import sqlite3
import asyncio
from fastapi import APIRouter, HTTPException, Depends
from app.config.settings import settings
from app.models.response_models import HealthResponse
from app.services.log_reader import get_parsed_files_count, get_all_logs
from app.services.settings_manager import settings_manager
from app.services.anti_defacement import anti_defacement_service
from app.services.auth import require_admin, TokenData
from app.utils.redis_client import validate_redis_connection

router = APIRouter()

# Track if database was initialized successfully
_db_initialized = False
_db_init_error = None

# Cache for health check — avoid ClickHouse and Redis pings on every request
_health_cache: dict = {}
_HEALTH_CACHE_TTL = 60      # seconds for parsed_files count
_REDIS_CHECK_TTL = 15       # seconds for Redis connectivity check
_CLICKHOUSE_CHECK_TTL = 15  # seconds for ClickHouse connectivity check


def check_db_initialized():
    """Check if SQLite database was initialized and is accessible."""
    global _db_initialized, _db_init_error
    if not _db_initialized:
        try:
            db_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)), 
                "config", 
                "false_positives.db"
            )
            conn = sqlite3.connect(db_path, timeout=5.0)
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM false_positives LIMIT 1;")
            conn.close()
            _db_initialized = True
        except Exception as e:
            _db_init_error = str(e)
            return False
    return _db_initialized


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Get API health status and log directory info.
    parsed_files count and Redis check are cached to avoid 1.4s ClickHouse scan
    on every health poll.
    """
    global _db_initialized, _db_init_error
    now = time.monotonic()

    log_dir_exists = os.path.exists(settings.LOG_DIR) and os.path.isdir(
        settings.LOG_DIR
    )

    # Cache the expensive ClickHouse count (SELECT count() FROM waf_events)
    # — on a cache miss this is a ~1.4s synchronous call; run off the event
    # loop so it doesn't stall every other concurrent dashboard request
    # (this endpoint is polled by multiple pages plus the Docker healthcheck).
    if "parsed_files" not in _health_cache or (now - _health_cache.get("parsed_files_ts", 0)) > _HEALTH_CACHE_TTL:
        _health_cache["parsed_files"] = await asyncio.to_thread(get_parsed_files_count)
        _health_cache["parsed_files_ts"] = now
    parsed_files = _health_cache["parsed_files"]

    # Cache ClickHouse connectivity check. This exists because every
    # ClickHouse-backed function in this codebase catches its own exceptions
    # and returns an empty/zero fallback (by design, so one bad query doesn't
    # 500 a dashboard page) — which means total_parsed_files silently reads 0
    # on a ClickHouse outage/auth failure with nothing distinguishing that
    # from "genuinely no traffic yet". This is the exact blind spot that let
    # a real multi-day ClickHouse ingestion outage go undetected: Docker's
    # own healthcheck (`curl -f http://localhost:8000/health`) kept getting
    # a 200 "ok" the entire time. Checking real connectivity here, and
    # folding it into `status`, closes that gap.
    if "clickhouse_ok" not in _health_cache or (now - _health_cache.get("clickhouse_ts", 0)) > _CLICKHOUSE_CHECK_TTL:
        from app.services import clickhouse_service
        _health_cache["clickhouse_ok"] = await asyncio.to_thread(clickhouse_service.is_available)
        _health_cache["clickhouse_ts"] = now
    clickhouse_ok = _health_cache["clickhouse_ok"]

    # Check database initialization (uses in-memory flag after first success)
    db_ok = await asyncio.to_thread(check_db_initialized)
    if not db_ok and not _db_initialized:
        try:
            from app.services.db_service import init_db
            await asyncio.to_thread(init_db)
            db_ok = await asyncio.to_thread(check_db_initialized)
        except Exception as e:
            _db_init_error = str(e)

    # Cache Redis connectivity check
    if "redis_ok" not in _health_cache or (now - _health_cache.get("redis_ts", 0)) > _REDIS_CHECK_TTL:
        _health_cache["redis_ok"] = await asyncio.to_thread(validate_redis_connection)
        _health_cache["redis_ts"] = now
    redis_ok = _health_cache["redis_ok"]

    # ML engine availability (env var check — instant)
    ml_enabled = bool(os.environ.get("ML_HOST", ""))

    return HealthResponse(
        status="ok" if (db_ok and clickhouse_ok) else "warning",
        log_directory_exists=log_dir_exists,
        total_parsed_files=parsed_files,
        db_initialized=db_ok,
        redis_connected=redis_ok,
        clickhouse_connected=clickhouse_ok,
        ml_enabled=ml_enabled,
    )


@router.post("/health/test-defacement")
async def test_defacement(current_user: TokenData = Depends(require_admin)):
    """
    Simulates a defacement attack by creating a test file, modifying it,
    verifying WAF auto-restoration, and asserting that a WAF log alert is generated.
    Requires admin role.
    """
    # Compute path relative to this file so the project is portable across servers.
    # Resolves to: <project_root>/backend/scratch/defacement_test.html
    _backend_root = pathlib.Path(__file__).parent.parent.parent
    test_file = str(_backend_root / "scratch" / "defacement_test.html")

    # 1. Create clean HTML page
    os.makedirs(os.path.dirname(test_file), exist_ok=True)
    clean_html = """<!DOCTYPE html>
<html>
<head><title>Clean Protected Page</title></head>
<body><h1>This is a clean, untouched, protected web page.</h1></body>
</html>
"""
    try:
        with open(test_file, "w") as f:
            f.write(clean_html)

        # 2. Configure WAF settings to monitor our test file
        settings_data = settings_manager.get_anti_defacement()
        original_enabled = settings_data.get("enabled", True)
        original_files = settings_data.get("monitored_files", [])
        original_interval = settings_data.get("check_interval_seconds", 5)

        settings_data["enabled"] = True
        settings_data["monitored_files"] = [test_file]
        settings_data["check_interval_seconds"] = 1
        settings_manager.update_anti_defacement(settings_data)

        # Allow service to prefetch and hash the file
        anti_defacement_service.load_monitored_files()

        # 3. Simulate defacement modification
        defaced_payload = "<html><body><h1>DEFACED BY HACKER!!!</h1></body></html>"
        with open(test_file, "w") as f:
            f.write(defaced_payload)

        # 4. Trigger integrity check manually to restore the file and write logs
        await anti_defacement_service.check_integrity()

        # 5. Read restored file to check integrity
        with open(test_file, "r") as f:
            restored = f.read()

        restored_ok = restored == clean_html

        # 6. Verify WAF Log Alert generation
        logs = get_all_logs()
        defacement_logs = [
            log_entry
            for log_entry in logs
            if log_entry.attack_type == "Web Anti-Defacement" and log_entry.uri == test_file
        ]
        alert_ok = len(defacement_logs) > 0

    finally:
        # Restore original configurations
        settings_data["enabled"] = original_enabled
        settings_data["monitored_files"] = original_files
        settings_data["check_interval_seconds"] = original_interval
        settings_manager.update_anti_defacement(settings_data)

        # Clean up disk
        if os.path.exists(test_file):
            os.remove(test_file)

    if not restored_ok:
        raise HTTPException(
            status_code=500, detail="File restoration failed. Content was not restored."
        )

    if not alert_ok:
        raise HTTPException(
            status_code=500,
            detail="Alert generation failed. No security log entry was found.",
        )

    return {
        "status": "success",
        "message": "Web Anti-Defacement test completed successfully! The defaced file was automatically restored and the Critical log alert was generated.",
    }


@router.get("/health/debug-defacement")
async def debug_defacement(current_user: TokenData = Depends(require_admin)):
    """Returns the current runtime cache state of the Anti-Defacement service. Requires admin role."""
    from app.services.anti_defacement import anti_defacement_service

    _backend_root = pathlib.Path(__file__).parent.parent.parent
    test_file = str(_backend_root / "scratch" / "defacement_test.html")
    return {
        "settings": settings_manager.get_anti_defacement(),
        "cached_hashes": anti_defacement_service.cached_hashes,
        "cached_keys": list(anti_defacement_service.cached_contents.keys()),
        "test_file_exists": os.path.exists(test_file),
        "test_file_path": test_file,
    }


@router.post("/health/log-retention/run")
async def run_log_retention(current_user: TokenData = Depends(require_admin)):
    """
    Manually trigger a log retention cleanup cycle.
    Purges ModSecurity audit files and SQLite log entries older than the
    configured retention window. Requires admin role.
    """
    from app.services.log_retention_service import run_retention_cleanup, _alert_if_unhealthy
    try:
        result = run_retention_cleanup()
        await _alert_if_unhealthy(result)
        return {"status": "success", "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Log retention cleanup failed: {e}")


@router.get("/health/log-retention/status")
async def log_retention_status(current_user: TokenData = Depends(require_admin)):
    """
    Get current log retention policy and storage usage stats.
    """
    import shutil
    from datetime import datetime, timedelta, timezone
    from app.services.log_retention_service import (
        _parse_retention_days, _count_stale_audit_dirs, MODSEC_AUDIT_DIR,
    )

    log_settings = settings_manager.get_log_settings()
    retention_str = log_settings.get("retention", "30 Days")
    retention_days = _parse_retention_days(retention_str)

    # Calculate audit log disk usage
    audit_usage_bytes = 0
    audit_file_count = 0
    if os.path.exists(MODSEC_AUDIT_DIR):
        for dirpath, dirnames, filenames in os.walk(MODSEC_AUDIT_DIR):
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                try:
                    audit_usage_bytes += os.path.getsize(fpath)
                    audit_file_count += 1
                except OSError:
                    pass

    # Signal whether the background purge is actually keeping up — does not
    # trigger a purge itself, just reports current staleness (cheap: only
    # inspects top-level dated directory names, not the file tree).
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    stale_dirs, oldest_stale_dir = _count_stale_audit_dirs(cutoff)

    return {
        "retention_policy": retention_str,
        "retention_days": retention_days,
        "audit_log_directory": MODSEC_AUDIT_DIR,
        "audit_log_files": audit_file_count,
        "audit_log_size_mb": round(audit_usage_bytes / (1024 * 1024), 2),
        "stale_audit_dirs_beyond_retention": stale_dirs,
        "oldest_stale_audit_dir": oldest_stale_dir,
        "purge_appears_healthy": stale_dirs == 0,
    }
