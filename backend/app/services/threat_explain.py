"""
threat_explain.py — CyberSentinel WAF
=======================================
Plain-language "why was this blocked" summary (P2 item 7 of the WAAP
console teardown roadmap).

Context: /logs/{id}/explain (P1-13) already surfaces the raw scoring
breakdown — threat_score, xgb_prob, crs_score, iso_score, redis_rep,
matched ModSecurity variables — in the Events drawer. That's real,
already-shipped transparency, not a gap. What's missing is the translation
layer: a security analyst still has to mentally convert "xgb_prob: 0.623,
crs_score: 15.0" into "why did this get blocked" themselves. F5 and Akamai
narrate that translation for the analyst; this module is the same idea,
built from data already computed, not calling out to an LLM or new model.

_score_breakdown() is a deliberate line-for-line port of
ml-waf/threat_score.py's calculate_threat_score() — the two containers
don't share a Python package, so this can't be a real shared import. Keep
the two in sync by hand; test_threat_explain.py pins reference input/output
pairs so a drift shows up as a failing test, not a silently-wrong sentence.
"""
from typing import Optional


def _score_breakdown(crs_score: float, xgb_prob: float, iso_score: float, redis_rep: float, abuse_score: float = 0.0) -> dict:
    """Verbatim port of ml-waf/threat_score.py:calculate_threat_score — see
    that file for the full parameter/return docstring. Recomputes the same
    normalized {total, crs, xgb, iso, reputation} breakdown from the raw
    values already stored on the ml_events row, so the explanation is
    attributed to the actual weights the live score used, not a guess."""
    crs_score = float(crs_score or 0.0)
    xgb_prob = float(xgb_prob or 0.0)
    iso_score = float(iso_score or 0.0)
    redis_rep = float(redis_rep or 0.0)
    abuse_score = float(abuse_score or 0.0)

    crs_norm = min(crs_score / 20.0, 1.0)
    iso_norm = min(max(-iso_score / 0.5, 0.0), 1.0)
    rep_boost = min(redis_rep * 0.03, 0.15)
    abuse_boost = min((abuse_score / 100.0) * 0.15, 0.15)

    base_score = (crs_norm * 0.50 + xgb_prob * 0.30 + iso_norm * 0.20)
    total = min(base_score + rep_boost + abuse_boost, 1.0)

    return {
        "total": total,
        "crs": crs_norm,
        "xgb": xgb_prob,
        "iso": iso_norm,
        "reputation": min(rep_boost + abuse_boost, 1.0),
    }


# Each factor's actual weighted contribution to `total` — crs/xgb/iso are
# weighted inside _score_breakdown already (0.50/0.30/0.20), reputation is
# additive and already capped, so it contributes at face value.
_FACTOR_WEIGHT = {"crs": 0.50, "xgb": 0.30, "iso": 0.20, "reputation": 1.0}

_FACTOR_PHRASING = {
    "crs": lambda v: f"the OWASP Core Rule Set's own anomaly scoring (CRS score contribution: {v:.2f})",
    "xgb": lambda v: f"the ML classifier independently rating this {v * 100:.0f}% likely malicious",
    "iso": lambda v: "this request's shape being statistically unusual compared to normal traffic",
    "reputation": lambda v: "this client IP's history of prior blocks or abuse reports",
}


def generate_plain_explanation(waf_event, ml_event: Optional[object]) -> str:
    """
    Builds a 1-2 sentence plain-language explanation from data already
    computed elsewhere — never invents a reason not backed by an actual
    rule match or score component, since overclaiming certainty is worse
    than no explanation on a security product.

    waf_event: a LogEntry (or anything with .attack_type/.rule_id/.message).
    ml_event: a MlSubScoreDetail, or None (most blocks never reach ML
    scoring — see explain_log_by_id's own docstring for why that's normal).
    """
    attack_type = (waf_event.attack_type or "").strip()
    rule_id = (waf_event.rule_id or "").strip()
    message = (waf_event.message or "").strip()

    if attack_type and attack_type.lower() not in ("unknown", ""):
        what = f"Blocked as a {attack_type} attempt"
    else:
        what = "Blocked by the WAF rule engine"
    if rule_id:
        what += f" (rule {rule_id}"
        what += f": {message})" if message else ")"
    elif message:
        what += f" — {message}"
    what += "."

    if ml_event is None:
        return what

    breakdown = _score_breakdown(
        getattr(ml_event, "crs_score", 0.0), getattr(ml_event, "xgb_prob", 0.0),
        getattr(ml_event, "iso_score", 0.0), getattr(ml_event, "redis_rep", 0.0),
        getattr(ml_event, "abuse_score", 0.0),
    )
    contributions = {
        factor: breakdown[factor] * _FACTOR_WEIGHT[factor]
        for factor in ("crs", "xgb", "iso", "reputation")
    }
    ranked = sorted(contributions.items(), key=lambda kv: kv[1], reverse=True)
    dominant_factor, dominant_value = ranked[0]
    if dominant_value <= 0.01:
        # Every component was ~0 — nothing to attribute a "primary driver"
        # to (e.g. the request only reached ML scoring but scored clean;
        # the rule engine caught it some other way).
        return what

    sentence = f"The ML risk score was primarily driven by {_FACTOR_PHRASING[dominant_factor](breakdown[dominant_factor])}"

    second_factor, second_value = ranked[1] if len(ranked) > 1 else (None, 0)
    if second_factor and second_value >= 0.15:
        sentence += f", amplified by {_FACTOR_PHRASING[second_factor](breakdown[second_factor])}"
    sentence += "."

    return f"{what} {sentence}"
