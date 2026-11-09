import os
import json
import time

try:
    import redis_features
    _r = getattr(redis_features, "r", None)
except Exception:
    _r = None

_tuning_cache = None
_tuning_cache_time = 0.0
TUNING_CACHE_TTL = 3.0

DEFAULT_TUNING = {
    "block_threshold": 0.85,
    "rate_limit_threshold": 0.70,
    "log_threshold": 0.40,
    "crs_block_threshold": 4.0,
    "crs_weight": 0.50,
    "xgb_weight": 0.30,
    "iso_weight": 0.20,
    "reputation_boost_max": 0.15,
    "abuseipdb_boost_max": 0.15,
    "moderate_risk_action": "log",
}


def get_tuning_config() -> dict:
    """Returns cached ML tuning configuration from Redis or default presets."""
    global _tuning_cache, _tuning_cache_time
    now = time.time()
    if _tuning_cache is not None and (now - _tuning_cache_time) < TUNING_CACHE_TTL:
        return _tuning_cache
    cfg = dict(DEFAULT_TUNING)
    if _r:
        try:
            raw = _r.get("waf:ml:tuning")
            if raw:
                data = json.loads(raw if isinstance(raw, str) else raw.decode("utf-8"))
                if isinstance(data, dict):
                    for k in DEFAULT_TUNING:
                        if k in data:
                            cfg[k] = type(DEFAULT_TUNING[k])(data[k])
        except Exception:
            pass
    _tuning_cache = cfg
    _tuning_cache_time = now
    return cfg


def invalidate_tuning_cache():
    """Immediately invalidates the local tuning cache."""
    global _tuning_cache, _tuning_cache_time
    _tuning_cache = None
    _tuning_cache_time = 0.0


def calculate_threat_score(
    crs_score: float,
    xgb_prob: float,
    iso_score: float,
    redis_rep: float,
    abuse_score: float = 0.0,
    tuning: dict = None,
) -> dict:
    """
    Computes a combined normalized threat score between 0.0 and 1.0, plus
    its named components — dynamically weighted according to ensemble tuning.

    Parameters:
      crs_score: Raw OWASP CRS anomaly score.
      xgb_prob: Probability output of the XGBoost classifier [0.0 - 1.0].
      iso_score: Score output of the Isolation Forest (negative implies anomaly).
      redis_rep: Threat reputation counter of the client IP from Redis.
      abuse_score: Abuse confidence score from AbuseIPDB [0.0 - 100.0].
      tuning: Optional dict overriding active tuning parameters.

    Returns a dict: {total, crs, xgb, iso, reputation} — all in [0.0, 1.0].
    """
    if tuning is None:
        tuning = get_tuning_config()

    # Defensive type conversions
    crs_score = float(crs_score or 0.0)
    xgb_prob = float(xgb_prob or 0.0)
    iso_score = float(iso_score or 0.0)
    redis_rep = float(redis_rep or 0.0)
    abuse_score = float(abuse_score or 0.0)

    # 1. Normalize variables to [0.0 - 1.0] scale
    crs_norm = min(crs_score / 20.0, 1.0)

    # Isolation Forest: normal is close to 0 or positive, outliers are negative down to -0.5
    iso_norm = min(max(-iso_score / 0.5, 0.0), 1.0)

    # Reputation boosts with configurable max caps
    rep_boost_max = float(tuning.get("reputation_boost_max", 0.15))
    abuse_boost_max = float(tuning.get("abuseipdb_boost_max", 0.15))

    rep_boost = min(redis_rep * 0.03, rep_boost_max)
    abuse_boost = min((abuse_score / 100.0) * abuse_boost_max, abuse_boost_max)

    # 2. Dynamic weighted ensemble score calculation
    w_crs = float(tuning.get("crs_weight", 0.50))
    w_xgb = float(tuning.get("xgb_weight", 0.30))
    w_iso = float(tuning.get("iso_weight", 0.20))
    total_w = w_crs + w_xgb + w_iso

    if total_w > 0:
        base_score = (crs_norm * w_crs + xgb_prob * w_xgb + iso_norm * w_iso) / total_w
    else:
        base_score = 0.0

    total = min(base_score + rep_boost + abuse_boost, 1.0)

    return {
        "total": total,
        "crs": crs_norm,
        "xgb": xgb_prob,
        "iso": iso_norm,
        "reputation": min(rep_boost + abuse_boost, 1.0),
    }


def get_routing_outcome(score: float, crs_score: float, tuning: dict = None) -> str:
    """
    Maps threat score to routing actions using dynamic thresholds.
    Enforces immediate blocking on obvious attacks with critically high CRS scores.
    """
    if tuning is None:
        tuning = get_tuning_config()

    crs_score = float(crs_score or 0.0)
    score = float(score or 0.0)

    crs_block = float(tuning.get("crs_block_threshold", 4.0))
    if crs_score >= crs_block:
        return "block"

    block_th = float(tuning.get("block_threshold", 0.85))
    rate_limit_th = float(tuning.get("rate_limit_threshold", 0.70))
    log_th = float(tuning.get("log_threshold", 0.40))
    moderate_risk_action = tuning.get("moderate_risk_action", "log")

    if score >= block_th:
        return "block"
    elif score >= rate_limit_th:
        return "rate_limit"
    elif score >= log_th:
        return moderate_risk_action
    else:
        return "allow"
