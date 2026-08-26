"""
Covers redis_degraded_monitor.check_redis_degraded() — the tailing/
timestamp-parsing logic that bridges ml-waf/waf_redis.lua's rate-limited
degraded-mode log line (in nginx's error log, written from the openresty
container) into heartbeat_registry (backend-process-only) via the log
volume both containers already have read access to.

Timestamps in these fixtures use the local (Asia/Kolkata) time the real
nginx error log writes, same as nginx_errorlog_parser's own tests would.
"""
import pytz
from datetime import datetime, timedelta

from app.services import redis_degraded_monitor as monitor

MARKER = monitor.MARKER
LOCAL_TZ = pytz.timezone("Asia/Kolkata")


def _local_ts(utc_dt) -> str:
    """Formats a UTC datetime as the local-time string nginx would log."""
    return utc_dt.astimezone(LOCAL_TZ).strftime("%Y/%m/%d %H:%M:%S")


def _write_log(tmp_path, lines):
    path = tmp_path / "error.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def test_no_marker_lines_reports_healthy(tmp_path, monkeypatch):
    log_path = _write_log(tmp_path, [
        "2026/08/26 10:00:00 [warn] 1#1: some unrelated warning",
        "2026/08/26 10:00:01 [error] 1#1: something else entirely",
    ])
    monkeypatch.setattr(monitor, "ERROR_LOG_PATH", log_path)

    result = monitor.check_redis_degraded()
    assert result == {"degraded": False, "last_seen_utc": None}


def test_recent_marker_line_reports_degraded(tmp_path, monkeypatch):
    now_utc = datetime.now(pytz.UTC)
    ts = _local_ts(now_utc - timedelta(seconds=5))
    log_path = _write_log(tmp_path, [
        f"{ts} [error] 1#1: *42 [lua] waf_redis.lua:33: {MARKER}: Redis connect failed: "
        f"connection refused — IP/geo/bot/schema checks are failing open until Redis recovers.",
    ])
    monkeypatch.setattr(monitor, "ERROR_LOG_PATH", log_path)

    result = monitor.check_redis_degraded()
    assert result["degraded"] is True
    assert result["last_seen_utc"] is not None


def test_stale_marker_line_beyond_freshness_window_reports_healthy(tmp_path, monkeypatch):
    now_utc = datetime.now(pytz.UTC)
    stale_ts = _local_ts(now_utc - timedelta(seconds=monitor.FRESHNESS_SECONDS + 60))
    log_path = _write_log(tmp_path, [
        f"{stale_ts} [error] 1#1: {MARKER}: Redis connect failed: timeout — "
        f"IP/geo/bot/schema checks are failing open until Redis recovers.",
    ])
    monkeypatch.setattr(monitor, "ERROR_LOG_PATH", log_path)

    result = monitor.check_redis_degraded()
    # The line exists (so last_seen_utc is populated) but it's too old to
    # count as a CURRENT outage.
    assert result["degraded"] is False
    assert result["last_seen_utc"] is not None


def test_picks_most_recent_of_multiple_marker_lines(tmp_path, monkeypatch):
    now_utc = datetime.now(pytz.UTC)
    old_ts = _local_ts(now_utc - timedelta(seconds=monitor.FRESHNESS_SECONDS + 300))
    recent_ts = _local_ts(now_utc - timedelta(seconds=10))
    log_path = _write_log(tmp_path, [
        f"{old_ts} [error] 1#1: {MARKER}: Redis connect failed: timeout",
        f"{recent_ts} [error] 1#1: {MARKER}: Redis connect failed: timeout",
    ])
    monkeypatch.setattr(monitor, "ERROR_LOG_PATH", log_path)

    result = monitor.check_redis_degraded()
    assert result["degraded"] is True


def test_missing_log_file_reports_healthy_not_error(tmp_path, monkeypatch):
    monkeypatch.setattr(monitor, "ERROR_LOG_PATH", str(tmp_path / "does_not_exist.log"))
    result = monitor.check_redis_degraded()
    assert result == {"degraded": False, "last_seen_utc": None}


def test_tail_read_bounded_ignores_marker_lines_before_the_tail_window(tmp_path, monkeypatch):
    """A marker line far enough back in a large file, beyond TAIL_BYTES from
    the end, must not be found — this is a deliberate bounded-read
    tradeoff (see module docstring), not a correctness bug, but it's worth
    locking in the actual behavior with a test."""
    now_utc = datetime.now(pytz.UTC)
    recent_ts = _local_ts(now_utc - timedelta(seconds=5))
    old_marker_line = (
        f"{_local_ts(now_utc - timedelta(seconds=1))} [error] 1#1: {MARKER}: should be pushed out of the tail window"
    )
    padding_line = "2026/08/26 09:00:00 [info] 1#1: " + ("x" * 200)
    # Enough padding lines after the marker to push it beyond a small
    # simulated tail window.
    lines = [old_marker_line] + [padding_line] * 2000
    log_path = _write_log(tmp_path, lines)
    monkeypatch.setattr(monitor, "ERROR_LOG_PATH", log_path)
    monkeypatch.setattr(monitor, "TAIL_BYTES", 4096)  # small window for this test

    result = monitor.check_redis_degraded()
    assert result == {"degraded": False, "last_seen_utc": None}
