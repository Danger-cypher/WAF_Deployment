import os
import pickle
import logging
import sqlite3
import json
import threading
import requests
from datetime import datetime
import pytz
from fastapi import FastAPI, BackgroundTasks, Response, status
from pydantic import BaseModel, Field

import feature_pipeline
import redis_features
import threat_score

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

def write_to_sqlite(event: dict):
    """Asynchronous analytics ingestion handler using SQLite."""
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

@app.post("/reload")
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

def run_retrain_subprocess():
    global retrain_state
    import subprocess
    retrain_state["status"] = "running"
    retrain_state["error"] = None
    retrain_state["start_time"] = datetime.now().isoformat()
    try:
        process = subprocess.Popen(
            ["bash", "retrain.sh"],
            cwd=BASE_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        process.wait()
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

@app.post("/retrain")
def trigger_retrain(background_tasks: BackgroundTasks):
    """Triggers the model retraining pipeline asynchronously."""
    if retrain_state["status"] == "running":
        return {"status": "running", "message": "Retraining is already in progress"}
    
    background_tasks.add_task(run_retrain_subprocess)
    return {"status": "success", "message": "Retraining triggered successfully"}

@app.get("/retrain/status")
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

@app.get("/models/backups")
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

@app.post("/models/rollback")
def rollback_models(payload: RollbackPayload):
    """Restores pickeled models from backup and dynamically updates active references."""
    global PASSIVE_MODE
    ts = payload.timestamp
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

@app.get("/models/feature-importance")
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


def send_backend_alert(event_type: str, event_data: dict, message: str = None):
    """
    Sends alert to the WAF backend alert trigger API.
    Runs as a background task.
    """
    try:
        url = "http://waf-backend:8000/alerts/trigger"
        payload = {
            "event_type": event_type,
            "event_data": event_data,
            "message": message
        }
        res = requests.post(url, json=payload, timeout=5)
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
        return {"decision": "allow", "threat_score": 0.0, "passive_mode": True}

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
        return {"decision": "allow", "threat_score": 0.0}

    # 4. Perform machine learning inference
    try:
        # Supervised probability of threat
        xgb_prob = float(xgb_model.predict_proba(features)[0][1])
        # Unsupervised anomaly/novelty score
        iso_score = float(iso_model.score_samples(features)[0])
    except Exception as e:
        logger.error(f"ML Inference failed: {e}")
        response.status_code = status.HTTP_200_OK
        return {"decision": "allow", "threat_score": 0.0}

    # 5. Calculate normalized combined threat score
    score = threat_score.calculate_threat_score(payload.crs_score, xgb_prob, iso_score, redis_rep, abuse_score)
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
    background_tasks.add_task(write_to_sqlite, event_data)

    # 8. Trigger WAF Alerting Engine for high threat or anomaly detected
    if decision == "block":
        background_tasks.add_task(send_backend_alert, "high_threat_score", event_data)
    elif decision == "rate_limit":
        background_tasks.add_task(send_backend_alert, "rate_limit_exceeded", event_data)
    
    if iso_score < -0.35:
        background_tasks.add_task(send_backend_alert, "ml_anomaly", event_data)

    return {"decision": decision, "threat_score": score}
