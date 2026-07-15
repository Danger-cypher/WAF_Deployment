"""
generate_dummy_models.py — CyberSentinel Bootstrap Model Generator
====================================================================
Generates placeholder XGBoost and Isolation Forest model binaries
so the ml-waf service can start in passive mode on first deployment
(e.g. Docker / Kubernetes environments with no pre-trained models).

These are intentionally low-accuracy bootstrap models trained on
random synthetic data. They are replaced automatically the first
time retrain.sh runs successfully against real traffic data.

Usage:
    python3 generate_dummy_models.py
"""

import os
import json
import pickle
import datetime
import numpy as np
import xgboost as xgb
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
META_PATH  = os.path.join(MODELS_DIR, "model_metadata.json")
XGB_PATH   = os.path.join(MODELS_DIR, "xgboost.pkl")
ISO_PATH   = os.path.join(MODELS_DIR, "isolation_forest.pkl")

os.makedirs(MODELS_DIR, exist_ok=True)

print("=" * 60)
print("  CyberSentinel — Bootstrap Model Generator")
print("=" * 60)

# ── 1. Synthetic training data (30 features, matching feature_pipeline output)
NUM_SAMPLES = 200
NUM_FEATURES = 30

print(f"\nGenerating {NUM_SAMPLES} synthetic training samples ({NUM_FEATURES} features each)...")
X = np.random.rand(NUM_SAMPLES, NUM_FEATURES).astype(np.float32)
y = np.random.randint(0, 2, NUM_SAMPLES)

# ── 2. Bootstrap XGBoost Classifier
print("Fitting bootstrap XGBoost Classifier...")
model_xgb = xgb.XGBClassifier(
    n_estimators=10,
    max_depth=3,
    eval_metric="logloss",
    random_state=42,
)
model_xgb.fit(X, y)
xgb_acc = float(accuracy_score(y, model_xgb.predict(X)))

with open(XGB_PATH, "wb") as f:
    pickle.dump(model_xgb, f)
print(f"  Saved: {XGB_PATH}  (bootstrap accuracy: {xgb_acc:.2f} — meaningless on synthetic data)")

# ── 3. Bootstrap Isolation Forest Anomaly Detector
print("Fitting bootstrap Isolation Forest Anomaly Detector...")
model_iso = IsolationForest(
    n_estimators=10,
    contamination=0.05,
    random_state=42,
)
model_iso.fit(X)

with open(ISO_PATH, "wb") as f:
    pickle.dump(model_iso, f)
print(f"  Saved: {ISO_PATH}")

# ── 4. Write model_metadata.json alongside model binaries
metadata = {
    "schema_version": 1,
    "xgboost": {
        "version": 1,
        "type": "bootstrap",
        "training_date": datetime.datetime.utcnow().isoformat() + "Z",
        "sample_count": NUM_SAMPLES,
        "accuracy": round(xgb_acc, 4),
        "notes": "Bootstrap placeholder. Replace by running retrain.sh after traffic accumulates."
    },
    "isolation_forest": {
        "version": 1,
        "type": "bootstrap",
        "training_date": datetime.datetime.utcnow().isoformat() + "Z",
        "sample_count": NUM_SAMPLES,
        "accuracy": None,
        "notes": "Bootstrap placeholder. Replace by running retrain.sh after traffic accumulates."
    }
}

with open(META_PATH, "w") as f:
    json.dump(metadata, f, indent=2)
print(f"  Saved: {META_PATH}")

print("\n" + "=" * 60)
print("  Bootstrap models generated successfully.")
print("  The ML service will start in PASSIVE MODE.")
print("  Run retrain.sh once real traffic is captured to")
print("  replace these with production-grade models.")
print("=" * 60 + "\n")
