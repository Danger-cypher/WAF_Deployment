import logging
import subprocess
import sqlite3
import json
import os
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get(
    "ML_DB_PATH",
    os.path.abspath(os.path.join(BASE_DIR, "..", "backend", "app", "data", "ml_events.db")),
)


def _get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.row_factory = sqlite3.Row
    return conn


def _init_drift_table(conn: sqlite3.Connection):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS drift_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            total_requests INTEGER,
            avg_threat_score REAL,
            xgb_anomaly_rate REAL,
            xgb_fp_rate REAL,
            iso_anomaly_rate REAL,
            drift_detected INTEGER NOT NULL,
            reasons TEXT
        )
        """
    )
    conn.commit()


def _save_drift_report(report: dict):
    """Persist a drift check to SQLite so the Admin UI has something to show
    besides a log line. Best-effort — a failure here shouldn't block the
    retrain decision that already happened in monitor_drift()."""
    try:
        conn = _get_connection()
        _init_drift_table(conn)
        conn.execute(
            """
            INSERT INTO drift_reports
                (timestamp, total_requests, avg_threat_score, xgb_anomaly_rate,
                 xgb_fp_rate, iso_anomaly_rate, drift_detected, reasons)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report["timestamp"],
                report["total_requests"],
                report["avg_threat_score"],
                report["xgb_anomaly_rate"],
                report["xgb_fp_rate"],
                report["iso_anomaly_rate"],
                1 if report["drift_detected"] else 0,
                json.dumps(report["reasons"]),
            ),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to persist drift report to SQLite: {e}")


def get_drift_history(limit: int = 50) -> list:
    """Read back recent drift checks for the Admin UI."""
    if not os.path.exists(DB_PATH):
        return []
    try:
        conn = _get_connection()
        _init_drift_table(conn)
        rows = conn.execute(
            "SELECT * FROM drift_reports ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        history = []
        for r in rows:
            d = dict(r)
            d["drift_detected"] = bool(d["drift_detected"])
            try:
                d["reasons"] = json.loads(d["reasons"]) if d["reasons"] else []
            except (TypeError, ValueError):
                d["reasons"] = []
            history.append(d)
        return history
    except Exception as e:
        logger.error(f"Failed to read drift history from SQLite: {e}")
        return []


def monitor_drift(on_drift_detected=None):
    """Check the last 24h of ML telemetry for signs of model drift.

    on_drift_detected(reasons: list[str]), if given, is called instead of
    the standalone `_trigger_retrain` subprocess path — used by ml_server.py
    so an auto-triggered retrain goes through the same retrain_state
    tracking (and "already running" guard) as a manually-triggered one.
    """
    events = []

    if os.path.exists(DB_PATH):
        try:
            conn = _get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ml_events WHERE timestamp >= datetime('now', '-1 day')")
            events = [dict(r) for r in cursor.fetchall()]
            conn.close()

            if events:
                logger.info(f"Retrieved {len(events)} events from SQLite database for drift analysis.")
        except Exception as e:
            logger.warning(f"Failed to query SQLite for drift monitoring: {e}")

    if not events:
        logger.info("No request events logged in the last 24 hours. Drift validation skipped.")
        return

    try:
        total = len(events)

        threat_scores = [float(e.get('threat_score') or 0.0) for e in events]
        avg_threat_score = sum(threat_scores) / total

        xgb_anomalies = sum(1 for e in events if float(e.get('xgb_prob') or 0.0) > 0.75)
        xgb_anomaly_rate = xgb_anomalies / total

        iso_anomalies = sum(1 for e in events if float(e.get('iso_score') or 0.0) < -0.15)
        iso_anomaly_rate = iso_anomalies / total

        fp_count = sum(1 for e in events if e.get('admin_label') == 'false_positive')
        xgb_fp_rate = fp_count / total

        logger.info(
            f"Drift metrics - Requests: {total}, Avg Score: {avg_threat_score:.4f}, "
            f"XGB Anomaly Rate: {xgb_anomaly_rate:.4f}, ISO Anomaly Rate: {iso_anomaly_rate:.4f}, "
            f"XGB FP Rate: {xgb_fp_rate:.4f}"
        )

        trigger_alert = False
        reasons = []

        if avg_threat_score > 0.60:
            trigger_alert = True
            reasons.append(f"avg_threat_score ({avg_threat_score:.3f}) > 0.60")
        if xgb_fp_rate > 0.15:
            trigger_alert = True
            reasons.append(f"xgb_fp_rate ({xgb_fp_rate:.3f}) > 0.15")
        if iso_anomaly_rate > 0.20:
            trigger_alert = True
            reasons.append(f"iso_anomaly_rate ({iso_anomaly_rate:.3f}) > 0.20")

        drift_report = {
            "timestamp": datetime.utcnow().isoformat(),
            "total_requests": total,
            "avg_threat_score": avg_threat_score,
            "xgb_anomaly_rate": xgb_anomaly_rate,
            "xgb_fp_rate": xgb_fp_rate,
            "iso_anomaly_rate": iso_anomaly_rate,
            "drift_detected": trigger_alert,
            "reasons": reasons,
        }
        _save_drift_report(drift_report)

        if trigger_alert:
            logger.warning(f"DRIFT THRESHOLD EXCEEDED: {', '.join(reasons)}")
            if on_drift_detected:
                on_drift_detected(reasons)
            else:
                _trigger_retrain(reasons)
        else:
            logger.info("Drift check passed. Telemetry metrics remain within operational baseline.")

    except Exception as e:
        logger.error(f"Error performing drift validation: {e}")


def _trigger_retrain(reasons: list):
    """
    Standalone fallback: invoke retrain.sh directly as a subprocess. Used
    only when monitor_drift() is run without an on_drift_detected callback
    (e.g. invoked directly via `python3 drift_monitor.py`, such as from a
    host cron job, rather than from ml_server.py's in-process scheduler).
    """
    RETRAIN_SCRIPT = os.path.join(BASE_DIR, "retrain.sh")
    LOG_FILE = os.path.join(BASE_DIR, "logs", "retrain.log")

    if not os.path.exists(RETRAIN_SCRIPT):
        logger.error(f"Retrain script not found: {RETRAIN_SCRIPT}. Cannot auto-retrain.")
        return

    logger.warning(
        f"AUTO-RETRAIN TRIGGERED by drift monitor. Reasons: {', '.join(reasons)}. "
        f"Invoking: {RETRAIN_SCRIPT}"
    )

    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as lf:
            lf.write(
                f"\n[{datetime.utcnow().isoformat()}Z] "
                f"=== AUTO-RETRAIN triggered by drift_monitor.py ===\n"
                f"Reasons: {', '.join(reasons)}\n"
            )

        result = subprocess.run(
            ["bash", RETRAIN_SCRIPT],
            capture_output=True,
            text=True,
            timeout=600,  # Allow up to 10 minutes for full retrain
        )

        if result.returncode == 0:
            logger.info("Auto-retrain completed successfully.")
        else:
            logger.error(
                f"Auto-retrain script exited with code {result.returncode}. "
                f"Check {LOG_FILE} for details."
            )
            logger.error(f"stderr: {result.stderr[-500:] if result.stderr else '(none)'}")

    except subprocess.TimeoutExpired:
        logger.error("Auto-retrain timed out after 10 minutes. Check the retrain log manually.")
    except Exception as e:
        logger.error(f"Failed to trigger auto-retrain: {e}")


if __name__ == "__main__":
    monitor_drift()
