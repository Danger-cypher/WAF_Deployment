import os
import pickle
import logging
import re
import sqlite3
import json
import threading
import time
import requests
from datetime import datetime
import pytz
import secrets
from fastapi import FastAPI, BackgroundTasks, Response, status, Header, HTTPException, Depends
from pydantic import BaseModel, Field

import feature_pipeline
import redis_features
import threat_score
import drift_monitor

# ClickHouse client for ML event persistence
try:
    import clickhouse_connect as _ch_connect
    _CH_HOST = os.environ.get("CLICKHOUSE_HOST", "waf-clickhouse")
    _CH_PORT = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
    _CH_USER = os.environ.get("CLICKHOUSE_USER", "wafuser")
    _CH_PASS = os.environ.get("CLICKHOUSE_PASSWORD", "")
    _CH_DB   = os.environ.get("CLICKHOUSE_DB", "cybersentinel")
    # /predict is a sync endpoint, so Starlette dispatches concurrent
    # requests across its threadpool. A single shared client here caused
    # clickhouse-connect's session-id serialization to race across threads,
    # silently failing ~45% of inserts (caught by the broad except below,
    # falling back to SQLite with no visible error) — same failure mode
    # already fixed for the backend in clickhouse_service.py via
    # threading.local(). One client per thread avoids the race entirely.
    _ch_thread_local = threading.local()
    def _get_ch_client():
        try:
            client = getattr(_ch_thread_local, "client", None)
            if client:
                client.ping()
                return client
        except Exception:
            _ch_thread_local.client = None
        try:
            client = _ch_connect.get_client(
                host=_CH_HOST, port=_CH_PORT,
                username=_CH_USER, password=_CH_PASS,
                database=_CH_DB, connect_timeout=5,
            )
            _ch_thread_local.client = client
            return client
        except Exception as exc:
            return None
    _CLICKHOUSE_AVAILABLE = True
except ImportError:
    _CLICKHOUSE_AVAILABLE = False
    def _get_ch_client(): return None

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────
#  Model loading — graceful passive mode
# ──────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
XGB_PATH   = os.path.join(BASE_DIR, "models/xgboost.pkl")
ISO_PATH   = os.path.join(BASE_DIR, "models/isolation_forest.pkl")
META_PATH  = os.path.join(BASE_DIR, "models/model_metadata.json")

# Global model references & state flags
xgb_model   = None
iso_model   = None
PASSIVE_MODE = False          # True  →  models absent, allow all traffic, skip ML scoring


def _try_load_models() -> bool:
    """Attempt to load both model binaries. Returns True on success."""
    global xgb_model, iso_model
    try:
        with open(XGB_PATH, "rb") as f:
            xgb_model = pickle.load(f)
        with open(ISO_PATH, "rb") as f:
            iso_model = pickle.load(f)
        logger.info("Model binaries loaded into memory successfully.")
        return True
    except Exception as e:
        logger.error(f"Failed to load model binaries: {e}")
        xgb_model = None
        iso_model = None
        return False


def _bootstrap_and_load():
    """
    Called in a background thread when models are absent at startup.
    Runs generate_dummy_models.py to create bootstrap placeholders,
    then loads them so the service can switch out of passive mode.
    """
    global PASSIVE_MODE
    bootstrap_script = os.path.join(BASE_DIR, "generate_dummy_models.py")
    venv_python = os.path.join(BASE_DIR, "venv/bin/python3")

    # Prefer the venv Python; fall back to the system interpreter
    python_bin = venv_python if os.path.exists(venv_python) else "python3"

    logger.info("PASSIVE MODE: Bootstrapping placeholder models via generate_dummy_models.py ...")
    ret = os.system(f"{python_bin} {bootstrap_script}")
    if ret == 0 and _try_load_models():
        PASSIVE_MODE = False
        logger.info("Bootstrap complete. Switched from PASSIVE MODE to ACTIVE MODE.")
    else:
        logger.warning("Bootstrap failed. Service will remain in PASSIVE MODE until models are manually provided.")


# ── Try loading existing production models
if not _try_load_models():
    PASSIVE_MODE = True
    logger.warning(
        "[PASSIVE MODE] Model binaries not found. "
        "The ML-WAF service will ALLOW all traffic and skip ML scoring until models are ready. "
        "Bootstrapping placeholder models in background thread..."
    )
    threading.Thread(target=_bootstrap_and_load, daemon=True).start()
else:
    logger.info("ML-WAF service started in ACTIVE MODE — scoring is enabled.")

DB_PATH = os.environ.get(
    "ML_DB_PATH",
    os.path.abspath(
        os.path.join(BASE_DIR, "..", "backend", "app", "data", "ml_events.db")
    )
)

def init_sqlite_db():
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30.0)
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ml_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                unique_id TEXT,
                crs_score REAL,
                matched_vars TEXT,
                uri TEXT,
                args TEXT,
                method TEXT,
                body_len REAL,
                ct TEXT,
                ua TEXT,
                remote_addr TEXT,
                redis_rpm REAL,
                redis_rep REAL,
                xgb_prob REAL,
                iso_score REAL,
                threat_score REAL,
                decision TEXT,
                abuse_score REAL DEFAULT 0.0
            )
        """)
        conn.commit()
        
        # Dynamic schema update for existing tables
        try:
            cursor.execute("SELECT abuse_score FROM ml_events LIMIT 1;")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE ml_events ADD COLUMN abuse_score REAL DEFAULT 0.0;")
            conn.commit()

        try:
            cursor.execute("SELECT unique_id FROM ml_events LIMIT 1;")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE ml_events ADD COLUMN unique_id TEXT;")
            conn.commit()

        try:
            cursor.execute("SELECT admin_label FROM ml_events LIMIT 1;")
        except sqlite3.OperationalError:
            # Analyst feedback ('false_positive' / 'true_positive') fed back
            # via POST /ml/events/{id}/label — drift_monitor's xgb_fp_rate
            # signal depends on this being populated.
            cursor.execute("ALTER TABLE ml_events ADD COLUMN admin_label TEXT;")
            conn.commit()

        conn.close()
        try:
            os.chmod(DB_PATH, 0o666)
        except Exception:
            pass
        logger.info("Successfully initialized ML events SQLite database with abuse_score column.")
    except Exception as e:
        logger.error(f"Failed to initialize SQLite database: {e}")

init_sqlite_db()

# Initialize FastAPI App
app = FastAPI(title="ML-Enhanced WAF Prediction Daemon")

INTERNAL_ALERT_TRIGGER_KEY = os.environ.get("INTERNAL_ALERT_TRIGGER_KEY", "")


def verify_internal_key(x_internal_key: str = Header(default=None)) -> None:
    """
    Guards administrative endpoints (retrain/rollback/reload/model-internals)
    with the same shared secret the backend already uses for its own
    internal endpoint (see app/routes/alerts.py's verify_internal_key).
    Previously these had no auth of their own and relied entirely on Docker
    network topology (waf-ml is `expose`d, not `ports`-published) — any other
    container on waf-network could otherwise trigger a model rollback or
    retrain. /health and /predict are intentionally NOT guarded: /health is
    polled by Docker's own healthcheck with no header, and /predict is the
    per-request hot path called by OpenResty's access_by_lua_file on every
    request, which is out of scope for this fix (see PRODUCTION_GUIDE / audit
    notes — wiring auth into the Lua request path is a separate, higher-risk
    change to the live traffic-blocking path).
    """
    if not INTERNAL_ALERT_TRIGGER_KEY:
        # No key configured (e.g. local dev without .env) — degrade to
        # network-topology-only protection rather than locking out every
        # admin action.
        return
    if not x_internal_key or not secrets.compare_digest(x_internal_key, INTERNAL_ALERT_TRIGGER_KEY):
        raise HTTPException(status_code=403, detail="Invalid or missing internal service credentials.")

class RequestTelemetry(BaseModel):
    unique_id: str = Field(default="", description="Unique request/transaction ID")
    crs_score: float = Field(default=0.0, description="Anomaly score calculated by OWASP CRS")
    matched_vars: str = Field(default="", description="Variables matched by ModSecurity rules")
    uri: str = Field(default="", description="Request URI path")
    args: str = Field(default="", description="Query arguments or POST payload parameters")
    method: str = Field(default="", description="HTTP Request Method")
    body_len: float = Field(default=0.0, description="Content-Length of the request body")
    ct: str = Field(default="", description="Content-Type header value")
    ua: str = Field(default="", description="User-Agent header value")
    remote_addr: str = Field(default="", description="IP address of the client")

def write_to_clickhouse(event: dict):
    """Primary ML event persistence — writes to ClickHouse cybersentinel.ml_events."""
    client = _get_ch_client()
    if client is None:
        logger.warning("ClickHouse unavailable — ML event not persisted to ClickHouse")
        write_to_sqlite(event)   # fallback
        return
    try:
        ts = event.get("timestamp", "")
        if isinstance(ts, str):
            try:
                ts = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            except Exception:
                ts = datetime.utcnow()
        row = [[
            str(event.get("unique_id", "")),
            ts,
            str(event.get("remote_addr", "")),
            str(event.get("method", "")),
            str(event.get("uri", "")),
            str(event.get("args", "")),
            str(event.get("ct", "")),
            str(event.get("ua", "")),
            float(event.get("body_len", 0.0)),
            float(event.get("crs_score", 0.0)),
            str(event.get("matched_vars", "")),
            float(event.get("redis_rpm", 0.0)),
            float(event.get("redis_rep", 0.0)),
            float(event.get("abuse_score", 0.0)),
            float(event.get("xgb_prob", 0.0)),
            float(event.get("iso_score", 0.0)),
            float(event.get("threat_score", 0.0)),
            str(event.get("decision", "")),
        ]]
        client.insert("ml_events", row, column_names=[
            "unique_id", "timestamp", "remote_addr", "method", "uri", "args",
            "ct", "ua", "body_len", "crs_score", "matched_vars",
            "redis_rpm", "redis_rep", "abuse_score",
            "xgb_prob", "iso_score", "threat_score", "decision",
        ])
    except Exception as e:
        logger.error(f"ClickHouse ML event write failed: {e} — falling back to SQLite")
        write_to_sqlite(event)

def write_to_sqlite(event: dict):
    """Fallback ML event persistence to SQLite (used when ClickHouse is unavailable)."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30.0)
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("""
            INSERT INTO ml_events (
                timestamp, unique_id, crs_score, matched_vars, uri, args, method, body_len, ct, ua, remote_addr,
                redis_rpm, redis_rep, xgb_prob, iso_score, threat_score, decision, abuse_score
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.get("timestamp", ""),
            event.get("unique_id", ""),
            event.get("crs_score", 0.0),
            event.get("matched_vars", ""),
            event.get("uri", ""),
            event.get("args", ""),
            event.get("method", ""),
            event.get("body_len", 0.0),
            event.get("ct", ""),
            event.get("ua", ""),
            event.get("remote_addr", ""),
            event.get("redis_rpm", 0.0),
            event.get("redis_rep", 0.0),
            event.get("xgb_prob", 0.0),
            event.get("iso_score", 0.0),
            event.get("threat_score", 0.0),
            event.get("decision", ""),
            event.get("abuse_score", 0.0)
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to insert ML event to SQLite: {e}")

@app.get("/health", status_code=status.HTTP_200_OK)
def health_check():
    """Service health state endpoint — includes model metadata."""
    # Load model_metadata.json if it exists
    model_meta = {}
    try:
        if os.path.exists(META_PATH):
            with open(META_PATH, "r") as f:
                model_meta = json.load(f)
    except Exception:
        model_meta = {}

    return {
        "status":        "healthy",
        "passive_mode":  PASSIVE_MODE,
        "models_loaded": (xgb_model is not None and iso_model is not None),
        "model_metadata": model_meta
    }

@app.post("/reload", dependencies=[Depends(verify_internal_key)])
def reload_models():
    """Dynamically reloads model binaries from disk into memory."""
    global PASSIVE_MODE
    if _try_load_models():
        PASSIVE_MODE = False
        logger.info("Models reloaded dynamically via API call.")
        return {"status": "success", "message": "Models reloaded successfully"}
    else:
        return {"status": "error", "message": "Failed to load model binaries"}

# ──────────────────────────────────────────────────────────────
#  Model Management & Retraining Endpoints
# ──────────────────────────────────────────────────────────────
FEATURE_NAMES = [
    "OWASP CRS Score",
    "OWASP CRS Score (Scaled)",
    "Matched Variables Count",
    "URI Length",
    "URI Slash Count",
    "URI Question Mark Count",
    "URI Equal Sign Count",
    "URI Percent Symbol Count",
    "URI Directory Traversal (..)",
    "Query Args Length",
    "Query Args Entropy",
    "Query Args Uppercase %",
    "Query Args Digits %",
    "Query Args Special Char %",
    "Query Args Signature Keywords",
    "Query Args Quote Count",
    "Query Args Tag Angle Brackets",
    "Query Args SQL Comment (--) Count",
    "Is POST Method",
    "Is PUT Method",
    "Is DELETE Method",
    "Request Content Length",
    "Is JSON Content Type",
    "Is Multipart Content Type",
    "User-Agent Header Length",
    "Empty User-Agent",
    "User-Agent Match Security Scanner",
    "Redis RPM Rate",
    "Redis Reputation Score",
    "URI Entropy"
]

retrain_state = {
    "status": "idle",
    "start_time": None,
    "end_time": None,
    "error": None
}
# Guards the check-then-act on retrain_state["status"] shared between the
# manual /retrain endpoint and the drift-triggered auto-retrain path.
retrain_lock = threading.Lock()
RETRAIN_TIMEOUT_SECONDS = int(os.environ.get("RETRAIN_TIMEOUT_SECONDS", "1800"))


def _try_claim_retrain_slot() -> bool:
    """Atomically claims the retrain slot. Returns False if one is already
    running, so callers on either path never launch retrain.sh twice."""
    with retrain_lock:
        if retrain_state["status"] == "running":
            return False
        retrain_state["status"] = "running"
        retrain_state["error"] = None
        retrain_state["start_time"] = datetime.now().isoformat()
        return True


def run_retrain_subprocess():
    """Runs retrain.sh. The caller must have already claimed the retrain
    slot via _try_claim_retrain_slot()."""
    global retrain_state
    import subprocess
    try:
        process = subprocess.Popen(
            ["bash", "retrain.sh"],
            cwd=BASE_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        try:
            process.wait(timeout=RETRAIN_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            retrain_state["status"] = "failed"
            retrain_state["error"] = (
                f"Retraining timed out after {RETRAIN_TIMEOUT_SECONDS}s and was killed"
            )
            return
        if process.returncode == 0:
            retrain_state["status"] = "success"
        else:
            retrain_state["status"] = "failed"
            retrain_state["error"] = f"Retraining script failed with exit code {process.returncode}"
    except Exception as e:
        logger.error(f"Retraining process execution error: {e}")
        retrain_state["status"] = "failed"
        retrain_state["error"] = str(e)
    finally:
        retrain_state["end_time"] = datetime.now().isoformat()


# ──────────────────────────────────────────────────────────────
#  Drift monitoring — periodic in-process scheduler
# ──────────────────────────────────────────────────────────────
# drift_monitor.py existed in the codebase but nothing ever invoked it: no
# cron entry, no scheduler, and it imported opensearchpy (not installed,
# and no OpenSearch service exists in this stack) so it would have crashed
# even if something had tried. Wired up here as a daemon thread instead of
# a host cron job, since retrain.sh already assumes it's running inside
# this container (writes to ./logs, reloads via localhost:9000/reload).
DRIFT_CHECK_INTERVAL_SECONDS = int(os.environ.get("DRIFT_CHECK_INTERVAL_HOURS", "6")) * 3600


def _on_drift_detected(reasons: list):
    """Routes an auto-detected drift event through the same retrain_state
    tracking as the manual /retrain endpoint, so the Admin UI's retrain
    console reflects auto-triggered runs too and the two paths can't race."""
    if not _try_claim_retrain_slot():
        logger.info(
            f"Drift detected ({', '.join(reasons)}) but a retrain is already "
            f"in progress — skipping this cycle."
        )
        return
    logger.warning(f"Drift-triggered retrain starting. Reasons: {', '.join(reasons)}")
    run_retrain_subprocess()


def _periodic_drift_check_loop():
    logger.info(
        f"Drift monitor started — checking every "
        f"{DRIFT_CHECK_INTERVAL_SECONDS / 3600:.1f}h."
    )
    while True:
        time.sleep(DRIFT_CHECK_INTERVAL_SECONDS)
        try:
            drift_monitor.monitor_drift(on_drift_detected=_on_drift_detected)
        except Exception as e:
            logger.error(f"Periodic drift check failed: {e}")


threading.Thread(target=_periodic_drift_check_loop, daemon=True).start()


@app.get("/drift/history", dependencies=[Depends(verify_internal_key)])
def get_drift_history_endpoint():
    """Recent drift checks (metrics + whether they triggered a retrain)."""
    return {"data": drift_monitor.get_drift_history(limit=50)}


@app.post("/retrain", dependencies=[Depends(verify_internal_key)])
def trigger_retrain(background_tasks: BackgroundTasks):
    """Triggers the model retraining pipeline asynchronously."""
    if not _try_claim_retrain_slot():
        return {"status": "running", "message": "Retraining is already in progress"}

    background_tasks.add_task(run_retrain_subprocess)
    return {"status": "success", "message": "Retraining triggered successfully"}

@app.get("/retrain/status", dependencies=[Depends(verify_internal_key)])
def get_retrain_status():
    """Returns the current retraining pipeline status and tail of training log file."""
    log_path = os.path.join(BASE_DIR, "logs/retrain.log")
    logs = ""
    if os.path.exists(log_path):
        try:
            with open(log_path, "r") as f:
                logs = f.read()
        except Exception as e:
            logs = f"Error reading logs: {e}"
            
    return {
        "status": retrain_state["status"],
        "start_time": retrain_state["start_time"],
        "end_time": retrain_state["end_time"],
        "error": retrain_state["error"],
        "logs": logs[-20000:]
    }

@app.get("/models/backups", dependencies=[Depends(verify_internal_key)])
def get_model_backups():
    """Lists available historical model weight backups on disk."""
    backup_dir = os.path.join(BASE_DIR, "models/backups")
    if not os.path.exists(backup_dir):
        return {"data": []}
        
    try:
        files = os.listdir(backup_dir)
        timestamps = set()
        for f in files:
            parts = f.split(".")
            if len(parts) >= 3 and parts[-1] == "bak":
                timestamps.add(parts[-2])
                
        backups = []
        for ts in sorted(list(timestamps), reverse=True):
            xgb_exists = os.path.exists(os.path.join(backup_dir, f"xgboost.pkl.{ts}.bak"))
            iso_exists = os.path.exists(os.path.join(backup_dir, f"isolation_forest.pkl.{ts}.bak"))
            backups.append({
                "timestamp": ts,
                "xgboost": xgb_exists,
                "isolation_forest": iso_exists,
                "formatted_date": f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[9:11]}:{ts[11:13]}:{ts[13:15]}"
            })
        return {"data": backups}
    except Exception as e:
        logger.error(f"Failed to list backups: {e}")
        return {"error": str(e)}

class RollbackPayload(BaseModel):
    timestamp: str

# retrain.sh names backups via `date '+%Y%m%d-%H%M%S'` — anything not matching
# that exact shape is rejected before it reaches a filename/pickle.load, since
# an unsanitized timestamp here would otherwise be a path-traversal ->
# arbitrary-file-deserialization primitive (behind the internal-key gate).
BACKUP_TIMESTAMP_RE = re.compile(r"^\d{8}-\d{6}$")

@app.post("/models/rollback", dependencies=[Depends(verify_internal_key)])
def rollback_models(payload: RollbackPayload):
    """Restores pickeled models from backup and dynamically updates active references."""
    global PASSIVE_MODE
    ts = payload.timestamp
    if not BACKUP_TIMESTAMP_RE.fullmatch(ts):
        raise HTTPException(status_code=400, detail="Invalid backup timestamp format.")
    backup_dir = os.path.join(BASE_DIR, "models/backups")
    models_dir = os.path.join(BASE_DIR, "models")
    
    xgb_bak = os.path.join(backup_dir, f"xgboost.pkl.{ts}.bak")
    iso_bak = os.path.join(backup_dir, f"isolation_forest.pkl.{ts}.bak")
    
    if not os.path.exists(xgb_bak) or not os.path.exists(iso_bak):
        return {"status": "error", "message": f"Backup binaries for timestamp {ts} not found"}
        
    try:
        import shutil
        shutil.copy(xgb_bak, os.path.join(models_dir, "xgboost.pkl"))
        shutil.copy(iso_bak, os.path.join(models_dir, "isolation_forest.pkl"))
        
        if _try_load_models():
            PASSIVE_MODE = False
            
            meta_path = os.path.join(models_dir, "model_metadata.json")
            if os.path.exists(meta_path):
                try:
                    with open(meta_path, "r") as f:
                        meta = json.load(f)
                    meta["xgboost"]["notes"] = f"Rolled back to backup timestamp {ts}."
                    meta["xgboost"]["training_date"] = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}T{ts[9:11]}:{ts[11:13]}:{ts[13:15]}Z"
                    with open(meta_path, "w") as f:
                        json.dump(meta, f, indent=2)
                except Exception:
                    pass
            return {"status": "success", "message": f"Model rolled back to backup {ts} successfully"}
        else:
            return {"status": "error", "message": "Failed to load backup binaries into memory"}
    except Exception as e:
        logger.error(f"Failed to execute rollback: {e}")
        return {"status": "error", "message": str(e)}

@app.get("/models/feature-importance", dependencies=[Depends(verify_internal_key)])
def get_feature_importance():
    """Extracts features score coefficients from currently loaded XGBoost model."""
    if xgb_model is None:
        return {"error": "XGBoost model is not loaded"}
    try:
        importance_scores = xgb_model.feature_importances_
        data = []
        for name, score in zip(FEATURE_NAMES, importance_scores):
            data.append({"feature": name, "importance": float(score)})
        data = sorted(data, key=lambda x: x["importance"], reverse=True)
        return {"data": data}
    except Exception as e:
        logger.error(f"Failed to load feature importance: {e}")
        return {"error": str(e)}

SETTINGS_PATH = os.environ.get(
    "SETTINGS_FILE",
    os.path.abspath(
        os.path.join(BASE_DIR, "..", "backend", "app", "config", "settings.json")
    )
)

def fetch_abuseipdb_score(ip: str):
    """
    Asynchronous background task to fetch IP reputation from AbuseIPDB API
    and cache the result in Redis. Skipped for internal subnet scopes.
    """
    # Exclude internal / RFC1918 IPs
    if ip in ("127.0.0.1", "localhost", "::1") or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        redis_features.save_abuse_score(ip, 0.0)
        return

    try:
        if not os.path.exists(SETTINGS_PATH):
            logger.warning(f"Settings JSON not found at {SETTINGS_PATH}. Cannot query AbuseIPDB.")
            return

        with open(SETTINGS_PATH, "r") as f:
            settings = json.load(f)
        
        abuse_cfg = settings.get("abuseipdb", {})
        if not abuse_cfg.get("enabled", False):
            return
            
        api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
        if not api_key:
            api_key = abuse_cfg.get("api_key", "")
        if not api_key:
            logger.warning("AbuseIPDB API key missing in environment and settings configuration.")
            return

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": api_key
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": "90"
        }
        
        # Safe timeout to avoid blocking resources
        response = requests.get(url, headers=headers, params=params, timeout=5.0)
        if response.status_code == 200:
            res_json = response.json()
            score = float(res_json.get("data", {}).get("abuseConfidenceScore", 0.0))
            redis_features.save_abuse_score(ip, score)
            logger.info(f"Successfully fetched and cached AbuseIPDB score for IP {ip}: {score}%")
        else:
            logger.warning(f"AbuseIPDB request failed for IP {ip}: HTTP {response.status_code}")
    except Exception as e:
        logger.error(f"Error querying AbuseIPDB for IP {ip}: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Client-side alert throttle
# Prevents firing the same (event_type, ip) pair to the backend more than once
# per _ALERT_COOLDOWN_S seconds.  The backend already has server-side throttling
# but without this guard, every blocked request spawned an HTTP POST.
# _alert_throttle: {signature_str: last_sent_epoch_float}
_ALERT_COOLDOWN_S = 60.0   # seconds
_alert_throttle: dict = {}
_alert_throttle_lock = threading.Lock()


def _should_send_alert(event_type: str, ip: str) -> bool:
    """Returns True only if enough time has passed since the last alert for this key."""
    key = f"{event_type}:{ip}"
    now = time.monotonic()
    with _alert_throttle_lock:
        last = _alert_throttle.get(key, 0.0)
        if now - last < _ALERT_COOLDOWN_S:
            return False
        _alert_throttle[key] = now
        return True


def send_backend_alert(event_type: str, event_data: dict, message: str = None):
    """
    Sends alert to the WAF backend alert trigger API.
    Runs as a background task. Client-side throttle applied before any HTTP call.
    """
    ip = event_data.get("remote_addr") or event_data.get("client_ip") or ""
    if not _should_send_alert(event_type, ip):
        logger.debug(f"Alert throttled (client-side): {event_type} from {ip}")
        return
    try:
        url = "http://waf-backend:8000/alerts/trigger"
        payload = {
            "event_type": event_type,
            "event_data": event_data,
            "message": message
        }
        headers = {"X-Internal-Key": os.environ.get("INTERNAL_ALERT_TRIGGER_KEY", "")}
        res = requests.post(url, json=payload, headers=headers, timeout=5)
        if res.status_code != 200:
            logger.warning(f"Backend alerts trigger failed: HTTP {res.status_code} - {res.text}")
        else:
            logger.info(f"Successfully posted alert of type '{event_type}' to backend")
    except Exception as e:
        logger.error(f"Failed to send alert to backend: {e}")


@app.post("/predict")
def predict(payload: RequestTelemetry, background_tasks: BackgroundTasks, response: Response):
    """
    Main evaluation pipeline endpoint.
    Retrieves Redis behavioral metrics, constructs the feature vector,
    scores the request, updates Redis counters, and schedules logging.
    """
    ip = payload.remote_addr or "unknown"
    
    # ── PASSIVE MODE guard: if models are not yet loaded, allow all traffic
    if PASSIVE_MODE or xgb_model is None or iso_model is None:
        logger.warning(
            f"PASSIVE MODE: Request from {ip} allowed without ML scoring. "
            "Models not yet available."
        )
        response.status_code = status.HTTP_200_OK
        return {"decision": "allow", "threat_score": 0.0, "passive_mode": True, "sub_scores": None}

    # 1. Fetch live Redis behavioral telemetry
    redis_rpm, redis_rep, abuse_score = redis_features.get_redis_metrics(ip)
    
    # Trigger background intelligence check on cache miss
    if abuse_score is None:
        background_tasks.add_task(fetch_abuseipdb_score, ip)
        abuse_score = 0.0 # Default to clean for the current request
    
    # 2. Map payload telemetry to data dictionary for the feature pipeline
    data_map = payload.model_dump()
    data_map['redis_rpm'] = redis_rpm
    data_map['redis_rep'] = redis_rep
    
    # 3. Process numerical feature vector
    try:
        features = feature_pipeline.build_features(data_map)
    except Exception as e:
        logger.error(f"Feature engineering failed: {e}")
        # Default to safe allow, letting ModSecurity's base rules decide
        response.status_code = status.HTTP_200_OK
        return {"decision": "allow", "threat_score": 0.0, "sub_scores": None}

    # 4. Perform machine learning inference
    try:
        # Supervised probability of threat
        xgb_prob = float(xgb_model.predict_proba(features)[0][1])
        # Unsupervised anomaly/novelty score
        iso_score = float(iso_model.score_samples(features)[0])
    except Exception as e:
        logger.error(f"ML Inference failed: {e}")
        response.status_code = status.HTTP_200_OK
        return {"decision": "allow", "threat_score": 0.0, "sub_scores": None}

    # 5. Calculate normalized combined threat score + its named components
    sub_scores = threat_score.calculate_threat_score(payload.crs_score, xgb_prob, iso_score, redis_rep, abuse_score)
    score = sub_scores["total"]
    decision = threat_score.get_routing_outcome(score, payload.crs_score)

    # 6. Update Redis behavioral metrics and IP reputation counters based on outcome
    # Run requests tracker for every evaluation
    background_tasks.add_task(redis_features.increment_request_counters, ip)

    if decision == "block":
        # ML hard block -> increment reputation penalty heavily
        background_tasks.add_task(redis_features.increment_reputation, ip)
        response.status_code = status.HTTP_401_UNAUTHORIZED

    elif decision == "rate_limit":
        # Partial threat (score 0.70-0.85) -> return 429, also penalise reputation
        # so that repeated rate-limited requests escalate toward a hard block.
        background_tasks.add_task(redis_features.increment_reputation, ip)
        response.status_code = status.HTTP_429_TOO_MANY_REQUESTS

    else:
        # "log" or "allow" -> clean or low-risk request, slowly decay reputation
        background_tasks.add_task(redis_features.decay_reputation, ip)
        response.status_code = status.HTTP_200_OK
        if decision == "log":
            # "log" (score 0.40-0.70) is real signal, just not certain
            # enough for the rate_limit/block bands — this header lets
            # ml_check.lua optionally route it through the same JS-reload
            # challenge already used for the bad-bot-UA signal, instead of
            # this band having zero live consequence. Opt-in on the Lua
            # side (waf_risk_challenge_enabled) — this header is set
            # unconditionally so the decision of whether to act on it stays
            # in one place (Lua), not duplicated as a second settings read
            # here.
            response.headers["X-WAF-Risk-Challenge"] = "1"

    # 7. Schedule asynchronous event logging to SQLite
    # Add UTC timestamp to event data
    utc_now = datetime.now(pytz.UTC)
    event_data = {
        "timestamp": utc_now.strftime("%Y-%m-%d %H:%M:%S"),
        **payload.model_dump(),
        "redis_rpm": redis_rpm,
        "redis_rep": redis_rep,
        "xgb_prob": xgb_prob,
        "iso_score": iso_score,
        "threat_score": score,
        "decision": decision,
        "abuse_score": abuse_score
    }
    background_tasks.add_task(write_to_clickhouse, event_data)

    # 8. Trigger WAF Alerting Engine for high threat or anomaly detected
    if decision == "block":
        background_tasks.add_task(send_backend_alert, "high_threat_score", event_data)
    elif decision == "rate_limit":
        background_tasks.add_task(send_backend_alert, "rate_limit_exceeded", event_data)
    
    if iso_score < -0.35:
        background_tasks.add_task(send_backend_alert, "ml_anomaly", event_data)

    return {"decision": decision, "threat_score": score, "sub_scores": sub_scores}
