import os
import sqlite3
import importlib

import drift_monitor


def _make_db(tmp_path, monkeypatch, rows):
    """Create an isolated ml_events.db with the given (threat_score, xgb_prob,
    iso_score) rows, and repoint drift_monitor at it."""
    db_path = str(tmp_path / "ml_events.db")
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE ml_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            threat_score REAL, xgb_prob REAL, iso_score REAL, admin_label TEXT
        )
        """
    )
    for threat_score, xgb_prob, iso_score in rows:
        conn.execute(
            "INSERT INTO ml_events (threat_score, xgb_prob, iso_score) VALUES (?, ?, ?)",
            (threat_score, xgb_prob, iso_score),
        )
    conn.commit()
    conn.close()

    monkeypatch.setenv("ML_DB_PATH", db_path)
    importlib.reload(drift_monitor)
    return db_path


def test_no_events_skips_silently(tmp_path, monkeypatch):
    _make_db(tmp_path, monkeypatch, rows=[])
    calls = []
    drift_monitor.monitor_drift(on_drift_detected=lambda reasons: calls.append(reasons))
    assert calls == []
    assert drift_monitor.get_drift_history() == []


def test_healthy_traffic_does_not_trigger_callback(tmp_path, monkeypatch):
    rows = [(0.1, 0.05, 0.5)] * 20
    _make_db(tmp_path, monkeypatch, rows)

    calls = []
    drift_monitor.monitor_drift(on_drift_detected=lambda reasons: calls.append(reasons))

    assert calls == []
    history = drift_monitor.get_drift_history()
    assert len(history) == 1
    assert history[0]["drift_detected"] is False


def test_high_anomaly_rate_triggers_callback_with_reasons(tmp_path, monkeypatch):
    rows = [(0.95, 0.9, -0.5)] * 20
    _make_db(tmp_path, monkeypatch, rows)

    calls = []
    drift_monitor.monitor_drift(on_drift_detected=lambda reasons: calls.append(reasons))

    assert len(calls) == 1
    assert any("iso_anomaly_rate" in r for r in calls[0])

    history = drift_monitor.get_drift_history()
    assert history[0]["drift_detected"] is True
    assert history[0]["reasons"] == calls[0]


def test_false_positive_rate_alone_triggers_drift(tmp_path, monkeypatch):
    # Low threat scores and low anomaly rates, but a high admin-labeled FP rate.
    db_path = str(tmp_path / "ml_events.db")
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE ml_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            threat_score REAL, xgb_prob REAL, iso_score REAL, admin_label TEXT
        )
        """
    )
    for i in range(20):
        label = "false_positive" if i < 5 else None  # 25% FP rate > 15% threshold
        conn.execute(
            "INSERT INTO ml_events (threat_score, xgb_prob, iso_score, admin_label) VALUES (?, ?, ?, ?)",
            (0.1, 0.05, 0.5, label),
        )
    conn.commit()
    conn.close()
    monkeypatch.setenv("ML_DB_PATH", db_path)
    importlib.reload(drift_monitor)

    calls = []
    drift_monitor.monitor_drift(on_drift_detected=lambda reasons: calls.append(reasons))

    assert len(calls) == 1
    assert any("xgb_fp_rate" in r for r in calls[0])


def test_drift_history_is_capped_and_most_recent_first(tmp_path, monkeypatch):
    _make_db(tmp_path, monkeypatch, rows=[(0.1, 0.05, 0.5)] * 5)

    for _ in range(3):
        drift_monitor.monitor_drift(on_drift_detected=lambda reasons: None)

    history = drift_monitor.get_drift_history(limit=2)
    assert len(history) == 2
    # Most recent (highest id) first.
    assert history[0]["id"] > history[1]["id"]


def test_standalone_path_defaults_to_subprocess_trigger(tmp_path, monkeypatch):
    """When called without a callback (e.g. `python3 drift_monitor.py` from a
    host cron job), drift should fall back to the subprocess-based
    _trigger_retrain rather than silently doing nothing."""
    _make_db(tmp_path, monkeypatch, rows=[(0.95, 0.9, -0.5)] * 20)

    called_with = []
    monkeypatch.setattr(
        drift_monitor, "_trigger_retrain", lambda reasons: called_with.append(reasons)
    )

    drift_monitor.monitor_drift()  # no callback passed

    assert len(called_with) == 1
