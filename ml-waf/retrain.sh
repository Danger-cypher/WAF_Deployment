#!/bin/bash
# =============================================================================
# retrain.sh — CyberSentinel ML Model Retraining Automation
# =============================================================================
# Retrains the XGBoost classifier and Isolation Forest anomaly detector
# using the latest traffic telemetry stored in ml_events.db.
#
# After training, it backups the old model binaries, installs the new ones,
# restarts the ml-waf FastAPI service, and verifies the health endpoint.
#
# Schedule: Run monthly via cron (see /etc/cron.monthly/retrain-ml-models)
# Log file: /opt/ml-waf/logs/retrain.log
#
# Usage: sudo /opt/ml-waf/retrain.sh
# =============================================================================

set -euo pipefail

# --- Configuration ---
ML_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
VENV_PYTHON="${ML_DIR}/venv/bin/python3"
MODELS_DIR="${ML_DIR}/models"
BACKUP_DIR="${ML_DIR}/models/backups"
LOG_DIR="${ML_DIR}/logs"
LOG_FILE="${LOG_DIR}/retrain.log"
UDS_SOCKET="${ML_DIR}/run/ml_waf.sock"
SERVICE_NAME="ml-waf"
TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S')"

# Minimum acceptable XGBoost validation accuracy (0.0 – 1.0).
# If the newly trained model scores below this threshold the
# retraining pipeline automatically rolls back to the previous
# model binaries and aborts deployment.
MIN_ACCURACY="0.65"

# --- Colors (only when running interactively) ---
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
fi

log()     { echo -e "${BLUE}[${TIMESTAMP}]${NC} $*" | tee -a "$LOG_FILE"; }
success() { echo -e "${GREEN}[OK]${NC} $*"          | tee -a "$LOG_FILE"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"       | tee -a "$LOG_FILE"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"         | tee -a "$LOG_FILE"; exit 1; }

# --- Check root ---
if [ "$EUID" -ne 0 ]; then
    error "This script must be run as root. Try: sudo $0"
fi

# --- Setup log and backup directories ---
mkdir -p "$LOG_DIR" "$BACKUP_DIR"

log "============================================================"
log "  CyberSentinel ML Model Retraining — ${TIMESTAMP}"
log "============================================================"

# --- Step 1: Verify Python interpreter and training scripts exist ---
if [ ! -f "$VENV_PYTHON" ]; then
    warn "Python venv not found at ${VENV_PYTHON}. Falling back to system python3."
    VENV_PYTHON="python3"
fi
if [ ! -f "${ML_DIR}/train_xgb.py" ] || [ ! -f "${ML_DIR}/train_iso.py" ]; then
    error "Training scripts (train_xgb.py / train_iso.py) not found in ${ML_DIR}."
fi
log "Python venv and training scripts verified."

# --- Step 2: Backup existing model binaries ---
BACKUP_TS="$(date '+%Y%m%d-%H%M%S')"
log "Backing up existing model binaries to ${BACKUP_DIR}/..."

for MODEL_FILE in xgboost.pkl isolation_forest.pkl; do
    SRC="${MODELS_DIR}/${MODEL_FILE}"
    if [ -f "$SRC" ]; then
        DEST="${BACKUP_DIR}/${MODEL_FILE}.${BACKUP_TS}.bak"
        cp "$SRC" "$DEST"
        log "  Backed up: ${MODEL_FILE} → $(basename $DEST)"
    else
        warn "  Model file not found (may be first run): ${SRC}"
    fi
done

# Keep only the last 5 backups per model to avoid disk bloat
for MODEL_FILE in xgboost.pkl isolation_forest.pkl; do
    ls -1t "${BACKUP_DIR}/${MODEL_FILE}".*.bak 2>/dev/null | tail -n +6 | xargs -r rm -f
done
log "Old backups pruned (kept last 5 per model)."

# --- Step 3: Retrain Isolation Forest (unsupervised — benign baseline) ---
log "Training Isolation Forest anomaly detector (train_iso.py)..."
cd "$ML_DIR"
"$VENV_PYTHON" train_iso.py 2>&1 | tee -a "$LOG_FILE"
if [ "${PIPESTATUS[0]}" -ne 0 ]; then
    error "train_iso.py failed. Aborting — old models remain active."
fi
success "Isolation Forest training complete."

# --- Step 4: Retrain XGBoost Classifier (supervised — attack labelling) ---
log "Training XGBoost classifier (train_xgb.py)..."
"$VENV_PYTHON" train_xgb.py 2>&1 | tee -a "$LOG_FILE"
if [ "${PIPESTATUS[0]}" -ne 0 ]; then
    # Restore ISO backup since XGB failed after ISO already ran
    LATEST_ISO_BAK=$(ls -1t "${BACKUP_DIR}/isolation_forest.pkl".*.bak 2>/dev/null | head -n 1)
    [ -n "$LATEST_ISO_BAK" ] && cp "$LATEST_ISO_BAK" "${MODELS_DIR}/isolation_forest.pkl" && warn "Restored ISO Forest backup."
    error "train_xgb.py failed. Aborting — restoring Isolation Forest backup."
fi
success "XGBoost training complete."

# --- Step 5: Accuracy gate — validate new model before deployment ---
# Run a quick validation using the model metadata written by train_xgb.py.
# If validation accuracy is below MIN_ACCURACY, roll back both models.
log "Validating new XGBoost model accuracy against threshold (>= ${MIN_ACCURACY})..."

NEW_ACCURACY=$("$VENV_PYTHON" - <<'PYEOF'
import json, sys, os
meta_path = os.path.join("${MODELS_DIR}", "model_metadata.json")
try:
    with open(meta_path) as f:
        meta = json.load(f)
    acc = meta.get("xgboost", {}).get("accuracy")
    print(acc if acc is not None else "0.0")
except Exception as e:
    print("0.0")
PYEOF
)

log "New model validation accuracy: ${NEW_ACCURACY}"

# Compare accuracy using Python (avoids bash float comparison issues)
PASS_THRESHOLD=$("$VENV_PYTHON" -c "
na = float('${NEW_ACCURACY}' or 0)
mi = float('${MIN_ACCURACY}')
print('yes' if na >= mi else 'no')
")

if [ "$PASS_THRESHOLD" = "no" ]; then
    warn "Accuracy ${NEW_ACCURACY} is below minimum threshold ${MIN_ACCURACY}. Rolling back to previous model binaries."

    # Restore latest XGBoost backup
    LATEST_XGB_BAK=$(ls -1t "${BACKUP_DIR}/xgboost.pkl".*.bak 2>/dev/null | head -n 1)
    if [ -n "$LATEST_XGB_BAK" ]; then
        cp "$LATEST_XGB_BAK" "${MODELS_DIR}/xgboost.pkl"
        warn "  Restored XGBoost from: $(basename $LATEST_XGB_BAK)"
    else
        warn "  No XGBoost backup found — keeping current (potentially bad) model."
    fi

    # Restore latest Isolation Forest backup
    LATEST_ISO_BAK=$(ls -1t "${BACKUP_DIR}/isolation_forest.pkl".*.bak 2>/dev/null | head -n 1)
    if [ -n "$LATEST_ISO_BAK" ]; then
        cp "$LATEST_ISO_BAK" "${MODELS_DIR}/isolation_forest.pkl"
        warn "  Restored Isolation Forest from: $(basename $LATEST_ISO_BAK)"
    else
        warn "  No Isolation Forest backup found — keeping current model."
    fi

    error "Rollback complete. Deployment aborted — investigate training data quality before next retrain."
fi

success "Accuracy gate passed (${NEW_ACCURACY} >= ${MIN_ACCURACY}). Deploying new models."

# --- Step 6: Verify both model files were actually produced ---
log "Verifying new model files..."
for MODEL_FILE in xgboost.pkl isolation_forest.pkl; do
    FULL_PATH="${MODELS_DIR}/${MODEL_FILE}"
    if [ ! -f "$FULL_PATH" ]; then
        error "Expected model not found after training: ${FULL_PATH}"
    fi
    SIZE=$(du -sh "$FULL_PATH" | cut -f1)
    success "  ${MODEL_FILE} — ${SIZE}"
done

# --- Step 7: Restart the ml-waf FastAPI daemon to load new models ---
log "Triggering model reload in running FastAPI instances..."

RELOAD_OK=false
for PORT in 9000 8003; do
    HTTP_STATUS=$(curl -s -o /tmp/reload_response.json -X POST "http://localhost:${PORT}/reload" -w "%{http_code}" --max-time 5 2>/dev/null || echo "000")
    if [ "$HTTP_STATUS" = "200" ]; then
        success "  Successfully triggered dynamic model reload on port ${PORT}."
        RELOAD_OK=true
        break
    fi
done

if [ "$RELOAD_OK" = "false" ]; then
    warn "API reload failed or service not running. Attempting service restarts..."
    # Try systemctl first (if registered as a service)
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl restart "$SERVICE_NAME"
        success "  ${SERVICE_NAME} systemctl service restarted."
    else
        # Fallback: restart via the uvicorn process directly
        log "  systemctl service not found. Restarting via uvicorn process signal..."
        UVICORN_PID=$(pgrep -f "uvicorn ml_server:app" | head -n 1)
        if [ -n "$UVICORN_PID" ]; then
            kill -HUP "$UVICORN_PID" 2>/dev/null && success "  Sent SIGHUP to uvicorn process (PID ${UVICORN_PID})."
        else
            warn "  Could not find a running ml-waf uvicorn process to restart. New models will load on next service start."
        fi
    fi
fi

# --- Step 8: Wait for service to come up then hit health endpoint ---
log "Waiting 5 seconds for service to initialize..."
sleep 5

log "Checking health endpoint..."
HTTP_STATUS="000"

# 1. Try UDS socket first if it exists
if [ -S "$UDS_SOCKET" ]; then
    log "  Checking over UDS socket: ${UDS_SOCKET}"
    HTTP_STATUS=$(curl -s -o /tmp/health_response.json --unix-socket "$UDS_SOCKET" -w "%{http_code}" --max-time 10 "http://localhost/health" 2>/dev/null || echo "000")
fi

# 2. Fallback to TCP ports if UDS check failed
if [ "$HTTP_STATUS" != "200" ]; then
    for PORT in 9000 8003; do
        log "  Checking health on port: ${PORT}"
        HTTP_STATUS=$(curl -s -o /tmp/health_response.json -w "%{http_code}" --max-time 5 "http://localhost:${PORT}/health" 2>/dev/null || echo "000")
        if [ "$HTTP_STATUS" = "200" ]; then
            break
        fi
    done
fi

if [ "$HTTP_STATUS" = "200" ]; then
    HEALTH_BODY=$(cat /tmp/health_response.json 2>/dev/null || echo "{}")
    success "Health check passed (HTTP ${HTTP_STATUS}): ${HEALTH_BODY}"
else
    warn "Health check returned HTTP ${HTTP_STATUS}. Service may still be starting."
fi

# --- Done ---
log ""
success "============================================================"
success "  ML Model Retraining Complete!"
success "  Timestamp : ${TIMESTAMP}"
success "  Models    : ${MODELS_DIR}/"
success "  Backups   : ${BACKUP_DIR}/"
success "============================================================"
log "Full log saved to: ${LOG_FILE}"
