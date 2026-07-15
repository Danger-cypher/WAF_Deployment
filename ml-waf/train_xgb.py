import os
import json
import pickle
import logging
import datetime
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, balanced_accuracy_score

import collect_data
import feature_pipeline

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Minimum attack samples required for a meaningful supervised model.
# If real data is below this, synthetic samples are injected.
MIN_ATTACK_SAMPLES = 10

# Model serialization paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
XGB_PATH = os.path.join(MODELS_DIR, "xgboost.pkl")


def _synthesize_attack_samples(real_attack_logs: list, target_count: int) -> list:
    """
    Duplicates existing attack samples with minor jitter to reach `target_count`.
    This is a bootstrap technique used when insufficient real attack data exists.
    The model trained on synthetic data is weaker but still functional.
    Operators should collect more real attack data to improve accuracy over time.
    """
    synthetic = []
    base = real_attack_logs.copy()
    while len(synthetic) < target_count:
        for sample in base:
            if len(synthetic) >= target_count:
                break
            # Copy the sample and add small noise to numeric fields to avoid exact duplicates
            s = dict(sample)
            for key in ['crs_score', 'redis_rpm', 'redis_rep', 'xgb_prob', 'iso_score', 'threat_score']:
                if key in s and s[key] is not None:
                    try:
                        s[key] = float(s[key]) + np.random.uniform(-0.01, 0.01)
                    except (TypeError, ValueError):
                        pass
            synthetic.append(s)
    return synthetic


def train():
    # Enforce directory creation
    os.makedirs(MODELS_DIR, exist_ok=True)

    # 1. Fetch raw logs from SQLite / OpenSearch / Local log fallback
    benign_logs, attack_logs = collect_data.get_training_datasets()

    if not benign_logs:
        logger.error("No benign logs available for training. Supervised training aborted.")
        return

    if not attack_logs:
        logger.error("No attack logs available for supervised training. Supervised training aborted.")
        return

    real_attack_count = len(attack_logs)

    # 2. Bootstrap attack samples if insufficient real data exists
    if real_attack_count < MIN_ATTACK_SAMPLES:
        logger.warning(
            f"Only {real_attack_count} real attack sample(s) found. "
            f"Bootstrapping to {MIN_ATTACK_SAMPLES} via synthetic duplication. "
            "Collect more real attack traffic to improve model accuracy."
        )
        attack_logs = attack_logs + _synthesize_attack_samples(attack_logs, MIN_ATTACK_SAMPLES - real_attack_count)
        logger.info(f"Attack samples after bootstrap: {len(attack_logs)} ({real_attack_count} real + {len(attack_logs) - real_attack_count} synthetic)")

    # 3. Extract feature matrices using the single feature pipeline module
    print("Processing feature vectors for training dataset...")
    X_benign = np.vstack([feature_pipeline.build_features(log) for log in benign_logs])
    X_attack = np.vstack([feature_pipeline.build_features(log) for log in attack_logs])

    # Concatenate features and construct labels
    X = np.vstack([X_benign, X_attack])
    y = np.array([0] * len(X_benign) + [1] * len(X_attack))

    # 4. Stratified split — safe because we guaranteed at least MIN_ATTACK_SAMPLES attack samples above.
    #    Fall back to non-stratified if any class still has < 2 members (edge case guard).
    min_class_count = min(np.sum(y == 0), np.sum(y == 1))
    use_stratify = min_class_count >= 2

    if not use_stratify:
        logger.warning("Class size still too small for stratified split. Using non-stratified split.")

    X_train, X_val, y_train, y_val = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y if use_stratify else None
    )

    # 5. Resolve severe class imbalances dynamically using scale_pos_weight
    num_benign = int(np.sum(y_train == 0))
    num_attack = int(np.sum(y_train == 1))
    scale_weight = num_benign / max(num_attack, 1)

    print(f"Training XGBoost classifier on {len(X_train)} samples ({num_benign} Benign, {num_attack} Attack)...")
    print(f"Applying class balancing scale_pos_weight: {scale_weight:.2f}")
    if real_attack_count < MIN_ATTACK_SAMPLES:
        print(f"NOTE: Model bootstrapped with {real_attack_count} real + {len(attack_logs) - real_attack_count} synthetic attack samples.")

    # 6. Initialize XGBoost with specific spec hyperparameters
    model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.05,
        scale_pos_weight=scale_weight,
        eval_metric="logloss",
        random_state=42
    )

    # 7. Fit the classifier model
    model.fit(X_train, y_train)

    # 8. Evaluate classifications against the split validation set
    preds = model.predict(X_val)
    print("\n--- XGBoost Validation Metrics ---")
    print(classification_report(y_val, preds, target_names=["Benign", "Attack"]))

    # 9. Serialize binaries to models directory
    with open(XGB_PATH, "wb") as f:
        pickle.dump(model, f)
    print(f"XGBoost classification binary successfully saved to: {XGB_PATH}\n")

    # 10. Update model_metadata.json with real training metrics
    META_PATH = os.path.join(MODELS_DIR, "model_metadata.json")
    try:
        meta = {}
        if os.path.exists(META_PATH):
            with open(META_PATH, "r") as mf:
                meta = json.load(mf)

        # Bump version if a previous entry exists
        prev_version = meta.get("xgboost", {}).get("version", 0)
        val_accuracy          = float(accuracy_score(y_val, preds))
        val_balanced_accuracy = float(balanced_accuracy_score(y_val, preds))

        meta.setdefault("schema_version", 1)
        meta["xgboost"] = {
            "version":           prev_version + 1,
            "type":              "production",
            "training_date":     datetime.datetime.utcnow().isoformat() + "Z",
            "sample_count":      int(len(X_train)),
            "accuracy":          round(val_accuracy, 4),
            "balanced_accuracy": round(val_balanced_accuracy, 4),
            "notes":             f"{num_benign} benign + {num_attack} attack samples used for training."
        }

        with open(META_PATH, "w") as mf:
            json.dump(meta, mf, indent=2)
        print(f"Model metadata updated: {META_PATH}")
    except Exception as meta_err:
        logger.warning(f"Failed to write model metadata: {meta_err}")


if __name__ == "__main__":
    train()
