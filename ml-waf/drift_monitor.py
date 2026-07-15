import logging
import subprocess
import os
from datetime import datetime, timedelta
from opensearchpy import OpenSearch, OpenSearchException

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def connect_opensearch() -> OpenSearch:
    """Initialize connection to local OpenSearch."""
    try:
        return OpenSearch(
            hosts=[{'host': 'localhost', 'port': 9200}],
            http_compress=True,
            timeout=2.0
        )
    except Exception as e:
        logger.error(f"Failed to connect to OpenSearch: {e}")
        return None

def monitor_drift():
    # 0. Try to fetch from SQLite first (primary database)
    import sqlite3
    import os
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DB_PATH = os.environ.get(
        "ML_DB_PATH",
        os.path.abspath(os.path.join(BASE_DIR, "..", "backend", "app", "data", "ml_events.db"))
    )
    events = []
    
    if os.path.exists(DB_PATH):
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Fetch events from last 24 hours
            cursor.execute("SELECT * FROM ml_events WHERE timestamp >= datetime('now', '-1 day')")
            events = [dict(r) for r in cursor.fetchall()]
            conn.close()
            
            if events:
                logger.info(f"Retrieved {len(events)} events from SQLite database for drift analysis.")
        except Exception as e:
            logger.warning(f"Failed to query SQLite for drift monitoring: {e}")

    # 1. Fall back to OpenSearch if SQLite is not available or empty
    if not events:
        client = connect_opensearch()
        if not client:
            logger.info("No data sources available for drift monitoring. Drift analysis skipped.")
            return

        # Check if the events index exists
        if not client.indices.exists(index="ml-waf-events"):
            logger.info("Index 'ml-waf-events' not found. Drift analysis skipped.")
            return

        # Query telemetry data logged in the last 24 hours
        one_day_ago = (datetime.utcnow() - timedelta(days=1)).isoformat()
        query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": one_day_ago
                    }
                }
            },
            "size": 10000  # Cap retrieval size for safety
        }

        try:
            res = client.search(index="ml-waf-events", body=query)
            hits = res['hits']['hits']
            if hits:
                events = [hit['_source'] for hit in hits]
        except Exception as e:
            logger.error(f"OpenSearch query search failed: {e}")

    if not events:
        logger.info("No request events logged in the last 24 hours from any source. Drift validation skipped.")
        return

    try:
        total = len(events)
        
        # Calculate statistics
        threat_scores = [float(e.get('threat_score') or 0.0) for e in events]
        avg_threat_score = sum(threat_scores) / total
        
        # Calculate predicted anomaly rates
        xgb_anomalies = sum(1 for e in events if float(e.get('xgb_prob') or 0.0) > 0.75)
        xgb_anomaly_rate = xgb_anomalies / total
        
        iso_anomalies = sum(1 for e in events if float(e.get('iso_score') or 0.0) < -0.15)
        iso_anomaly_rate = iso_anomalies / total
        
        # Count explicit admin-labeled false positives (FP) if available in database/logs
        fp_count = sum(1 for e in events if e.get('admin_label') == 'false_positive')
        xgb_fp_rate = fp_count / total
        
        logger.info(
            f"Drift metrics - Requests: {total}, Avg Score: {avg_threat_score:.4f}, "
            f"XGB Anomaly Rate: {xgb_anomaly_rate:.4f}, ISO Anomaly Rate: {iso_anomaly_rate:.4f}, "
            f"XGB FP Rate: {xgb_fp_rate:.4f}"
        )
        
        # Check warning thresholds
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
            
        # Log drift analysis report
        drift_report = {
            "timestamp": datetime.utcnow().isoformat(),
            "total_requests": total,
            "avg_threat_score": avg_threat_score,
            "xgb_anomaly_rate": xgb_anomaly_rate,
            "xgb_fp_rate": xgb_fp_rate,
            "iso_anomaly_rate": iso_anomaly_rate,
            "drift_detected": trigger_alert,
            "reasons": reasons
        }
        
        # Send to OpenSearch if client connected
        try:
            client = connect_opensearch()
            if client and client.indices.exists(index="ml-waf-events"):
                client.index(
                    index="ml-waf-drift",
                    body=drift_report
                )
        except Exception:
            pass
            
        if trigger_alert:
            logger.warning(f"DRIFT THRESHOLD EXCEEDED: {', '.join(reasons)}")
            _trigger_retrain(reasons)
        else:
            logger.info("Drift check passed. Telemetry metrics remain within operational baseline.")
            
    except Exception as e:
        logger.error(f"Error performing drift validation: {e}")


def _trigger_retrain(reasons: list):
    """
    Automatically invoke retrain.sh when drift thresholds are exceeded.
    Runs the script as a blocking subprocess so results are fully captured
    in the drift monitor log before this process exits.
    """
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    RETRAIN_SCRIPT = os.path.abspath(os.path.join(BASE_DIR, "retrain.sh"))
    LOG_FILE       = os.path.abspath(os.path.join(BASE_DIR, "logs", "retrain.log"))

    if not os.path.exists(RETRAIN_SCRIPT):
        logger.error(f"Retrain script not found: {RETRAIN_SCRIPT}. Cannot auto-retrain.")
        return

    logger.warning(
        f"AUTO-RETRAIN TRIGGERED by drift monitor. Reasons: {', '.join(reasons)}. "
        f"Invoking: {RETRAIN_SCRIPT}"
    )

    try:
        # Append a drift-triggered header to the retrain log for traceability
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
            timeout=600  # Allow up to 10 minutes for full retrain
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
