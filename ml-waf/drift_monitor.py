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
            reasons TEXT,
            vector_metrics TEXT
        )
        """
    )
    # Ensure vector_metrics column exists if created previously without it
    try:
        conn.execute("ALTER TABLE drift_reports ADD COLUMN vector_metrics TEXT")
    except sqlite3.OperationalError:
        pass
    conn.commit()


def synthesize_vector_metrics(avg_threat, xgb_anomaly, xgb_fp, iso_anomaly, crs_anomaly=0.0, top_endpoints=None, tuning=None):
    tuning = tuning or {}
    threat_val = float(avg_threat or 0.0)
    xgb_val = float(xgb_anomaly or 0.0)
    fp_val = float(xgb_fp or 0.0)
    iso_val = float(iso_anomaly or 0.0)
    crs_val = float(crs_anomaly or 0.0)

    threat_thresh = float(tuning.get("drift_threat_threshold", 0.60))
    fp_thresh = float(tuning.get("drift_fp_threshold", 0.15))
    iso_thresh = float(tuning.get("drift_iso_threshold", 0.20))
    xgb_thresh = 0.25
    crs_thresh = 0.25

    threat_status = "breached" if threat_val > threat_thresh else "warning" if threat_val > (threat_thresh * 0.82) else "nominal"
    xgb_status = "breached" if xgb_val > xgb_thresh else "warning" if xgb_val > 0.18 else "nominal"
    iso_status = "breached" if iso_val > iso_thresh else "warning" if iso_val > (iso_thresh * 0.75) else "nominal"
    fp_status = "breached" if fp_val > fp_thresh else "warning" if fp_val > (fp_thresh * 0.60) else "nominal"
    crs_status = "breached" if crs_val > crs_thresh else "warning" if crs_val > 0.15 else "nominal"

    is_breached = any(s == "breached" for s in [threat_status, xgb_status, iso_status, fp_status])
    is_warning = any(s == "warning" for s in [threat_status, xgb_status, iso_status, fp_status, crs_status])
    overall_status = "breached" if is_breached else "warning" if is_warning else "nominal"

    return {
        "status": overall_status,
        "vectors": {
            "threat_score": {
                "name": "Average Threat Score",
                "current": round(threat_val, 4),
                "baseline": 0.35,
                "threshold": threat_thresh,
                "status": threat_status,
            },
            "xgb_anomaly": {
                "name": "XGBoost Attack Anomaly",
                "current": round(xgb_val, 4),
                "baseline": 0.10,
                "threshold": xgb_thresh,
                "status": xgb_status,
            },
            "iso_novelty": {
                "name": "Novelty / Outlier Vector (Isolation Forest)",
                "current": round(iso_val, 4),
                "baseline": 0.10,
                "threshold": iso_thresh,
                "status": iso_status,
            },
            "false_positive": {
                "name": "Analyst False-Positive Feedback",
                "current": round(fp_val, 4),
                "baseline": 0.03,
                "threshold": fp_thresh,
                "status": fp_status,
            },
            "crs_anomaly": {
                "name": "Core Rule Set Elevation",
                "current": round(crs_val, 4),
                "baseline": 0.08,
                "threshold": crs_thresh,
                "status": crs_status,
            },
        },
        "top_drifting_endpoints": top_endpoints or [],
    }


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
                 xgb_fp_rate, iso_anomaly_rate, drift_detected, reasons, vector_metrics)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                json.dumps(report.get("vector_metrics", {})),
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
                d["reasons"] = json.loads(d["reasons"]) if d.get("reasons") else []
            except (TypeError, ValueError):
                d["reasons"] = []

            vm = {}
            if d.get("vector_metrics"):
                try:
                    vm = json.loads(d["vector_metrics"])
                except (TypeError, ValueError):
                    vm = {}

            if not vm or not vm.get("vectors"):
                vm = synthesize_vector_metrics(
                    avg_threat=d.get("avg_threat_score", 0.0),
                    xgb_anomaly=d.get("xgb_anomaly_rate", 0.0),
                    xgb_fp=d.get("xgb_fp_rate", 0.0),
                    iso_anomaly=d.get("iso_anomaly_rate", 0.0),
                )
            d["vector_metrics"] = vm
            history.append(d)
        return history
    except Exception as e:
        logger.error(f"Failed to read drift history from SQLite: {e}")
        return []


def monitor_drift(on_drift_detected=None, force_latest: bool = False):
    """Check the last 24h of ML telemetry for signs of model drift.

    on_drift_detected(reasons: list[str]), if given, is called instead of
    the standalone `_trigger_retrain` subprocess path — used by ml_server.py
    so an auto-triggered retrain goes through the same retrain_state
    tracking (and "already running" guard) as a manually-triggered one.

    If force_latest=True and no events are logged in the last 24h, falls
    back to the latest 500 records so drift evaluation can run on demand.
    """
    events = []

    if os.path.exists(DB_PATH):
        try:
            conn = _get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ml_events WHERE timestamp >= datetime('now', '-1 day')")
            events = [dict(r) for r in cursor.fetchall()]

            if not events and force_latest:
                cursor.execute("SELECT * FROM ml_events ORDER BY id DESC LIMIT 500")
                events = [dict(r) for r in cursor.fetchall()]

            conn.close()

            if events:
                logger.info(f"Retrieved {len(events)} events from SQLite database for drift analysis.")
        except Exception as e:
            logger.warning(f"Failed to query SQLite for drift monitoring: {e}")

    if not events:
        logger.info("No request events logged in the last 24 hours. Drift validation skipped.")
        return None

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

        crs_anomalies = sum(1 for e in events if float(e.get('crs_score') or 0.0) >= 5.0)
        crs_anomaly_rate = crs_anomalies / total

        # Load dynamic drift thresholds if available
        tuning = {}
        try:
            from threat_score import get_tuning_config
            tuning = get_tuning_config() or {}
        except Exception:
            pass

        threat_thresh = float(tuning.get("drift_threat_threshold", 0.60))
        fp_thresh = float(tuning.get("drift_fp_threshold", 0.15))
        iso_thresh = float(tuning.get("drift_iso_threshold", 0.20))

        logger.info(
            f"Drift metrics - Requests: {total}, Avg Score: {avg_threat_score:.4f}, "
            f"XGB Anomaly Rate: {xgb_anomaly_rate:.4f}, ISO Anomaly Rate: {iso_anomaly_rate:.4f}, "
            f"XGB FP Rate: {xgb_fp_rate:.4f}, CRS Anomaly Rate: {crs_anomaly_rate:.4f}"
        )

        trigger_alert = False
        reasons = []

        if avg_threat_score > threat_thresh:
            trigger_alert = True
            reasons.append(f"avg_threat_score ({avg_threat_score:.3f}) > {threat_thresh:.2f}")
        if xgb_fp_rate > fp_thresh:
            trigger_alert = True
            reasons.append(f"xgb_fp_rate ({xgb_fp_rate:.3f}) > {fp_thresh:.2f}")
        if iso_anomaly_rate > iso_thresh:
            trigger_alert = True
            reasons.append(f"iso_anomaly_rate ({iso_anomaly_rate:.3f}) > {iso_thresh:.2f}")

        # Endpoint drift analysis
        uri_scores = {}
        for e in events:
            uri = e.get('uri') or ''
            if uri:
                base_uri = uri.split('?')[0][:64]
                if base_uri not in uri_scores:
                    uri_scores[base_uri] = []
                uri_scores[base_uri].append(float(e.get('threat_score') or 0.0))

        top_drifting_endpoints = []
        for u, scores in sorted(
            uri_scores.items(),
            key=lambda item: (sum(item[1]) / len(item[1]), len(item[1])),
            reverse=True,
        )[:5]:
            top_drifting_endpoints.append({
                "uri": u,
                "count": len(scores),
                "avg_threat": round(sum(scores) / len(scores), 3),
            })

        vector_metrics = synthesize_vector_metrics(
            avg_threat=avg_threat_score,
            xgb_anomaly=xgb_anomaly_rate,
            xgb_fp=xgb_fp_rate,
            iso_anomaly=iso_anomaly_rate,
            crs_anomaly=crs_anomaly_rate,
            top_endpoints=top_drifting_endpoints,
            tuning=tuning,
        )

        drift_report = {
            "timestamp": datetime.utcnow().isoformat(),
            "total_requests": total,
            "avg_threat_score": avg_threat_score,
            "xgb_anomaly_rate": xgb_anomaly_rate,
            "xgb_fp_rate": xgb_fp_rate,
            "iso_anomaly_rate": iso_anomaly_rate,
            "drift_detected": trigger_alert,
            "reasons": reasons,
            "vector_metrics": vector_metrics,
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

        return drift_report

    except Exception as e:
        logger.error(f"Error performing drift validation: {e}")
        return None


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
