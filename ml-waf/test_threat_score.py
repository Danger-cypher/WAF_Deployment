"""
Covers threat_score.calculate_threat_score()'s dict return shape (P1-2) —
no test existed for this function directly before this; it was only
exercised indirectly via /predict in test_predict_risk_challenge.py.
"""
import pytest

import threat_score


def test_returns_dict_with_total_and_named_components():
    result = threat_score.calculate_threat_score(
        crs_score=10.0, xgb_prob=0.6, iso_score=0.0, redis_rep=0.0, abuse_score=0.0
    )
    assert set(result.keys()) == {"total", "crs", "xgb", "iso", "reputation"}


def test_total_matches_prior_bare_float_behavior():
    # Same worked example as test_predict_risk_challenge.py's log-band test:
    # crs_norm(10/20=0.5)*0.50 + xgb_prob(0.6)*0.30 = 0.25 + 0.18 = 0.43
    result = threat_score.calculate_threat_score(
        crs_score=10.0, xgb_prob=0.6, iso_score=0.0, redis_rep=0.0, abuse_score=0.0
    )
    assert result["total"] == 0.43


def test_crs_component_normalized_and_capped_at_one():
    result = threat_score.calculate_threat_score(
        crs_score=40.0, xgb_prob=0.0, iso_score=0.0, redis_rep=0.0, abuse_score=0.0
    )
    assert result["crs"] == 1.0  # 40/20 = 2.0, capped


def test_xgb_component_passed_through_unchanged():
    result = threat_score.calculate_threat_score(
        crs_score=0.0, xgb_prob=0.73, iso_score=0.0, redis_rep=0.0, abuse_score=0.0
    )
    assert result["xgb"] == 0.73


def test_iso_component_normalized():
    # iso_score=-0.5 (max anomaly) -> iso_norm = 0.5/0.5 = 1.0
    result = threat_score.calculate_threat_score(
        crs_score=0.0, xgb_prob=0.0, iso_score=-0.5, redis_rep=0.0, abuse_score=0.0
    )
    assert result["iso"] == 1.0

    # Positive iso_score (not anomalous) -> iso_norm floors at 0.0
    result = threat_score.calculate_threat_score(
        crs_score=0.0, xgb_prob=0.0, iso_score=0.3, redis_rep=0.0, abuse_score=0.0
    )
    assert result["iso"] == 0.0


def test_reputation_component_combines_redis_rep_and_abuse_score():
    # redis_rep boost: min(5 * 0.03, 0.15) = 0.15 (capped)
    # abuse_score boost: min((50/100)*0.15, 0.15) = 0.075
    result = threat_score.calculate_threat_score(
        crs_score=0.0, xgb_prob=0.0, iso_score=0.0, redis_rep=5.0, abuse_score=50.0
    )
    assert result["reputation"] == pytest.approx(0.225)


def test_reputation_component_capped_at_one():
    result = threat_score.calculate_threat_score(
        crs_score=0.0, xgb_prob=0.0, iso_score=0.0, redis_rep=999.0, abuse_score=100.0
    )
    assert result["reputation"] <= 1.0


def test_none_inputs_default_to_zero_without_raising():
    result = threat_score.calculate_threat_score(
        crs_score=None, xgb_prob=None, iso_score=None, redis_rep=None, abuse_score=None
    )
    assert result == {"total": 0.0, "crs": 0.0, "xgb": 0.0, "iso": 0.0, "reputation": 0.0}


def test_get_routing_outcome_unaffected_still_takes_bare_float():
    # get_routing_outcome's own signature/behavior is untouched by this
    # change — callers pass result["total"], not the dict itself.
    result = threat_score.calculate_threat_score(
        crs_score=25.0, xgb_prob=0.0, iso_score=0.0, redis_rep=0.0, abuse_score=0.0
    )
    assert threat_score.get_routing_outcome(result["total"], crs_score=25.0) == "block"


# ---------------------------------------------------------------------------
# P2-01 — the CRS high-certainty override must actually be reachable.
#
# ModSecurity's own access-phase blocking rule (949110) denies anything
# scoring >= tx.inbound_anomaly_score_threshold (5, per rules-override.conf)
# before ml_decide.lua's content-phase code — this function's real caller —
# ever runs. A crs_score of 20 could therefore never reach get_routing_
# outcome() in production: dead code presenting as a working safety net.
# ---------------------------------------------------------------------------

def test_high_crs_score_within_reachable_range_forces_block():
    # 4.0 is the highest score realistically reachable here (one point
    # under ModSecurity's own block line) — must force "block" even when
    # every other signal says otherwise.
    assert threat_score.get_routing_outcome(0.0, crs_score=4.0) == "block"


def test_below_the_reachable_threshold_defers_to_the_blended_score():
    # 3.9 must NOT trigger the override — falls through to the normal
    # score-band routing below.
    assert threat_score.get_routing_outcome(0.0, crs_score=3.9) == "allow"
    assert threat_score.get_routing_outcome(0.90, crs_score=3.9) == "block"  # via score band, not the override


def test_old_unreachable_threshold_no_longer_gates_anything():
    # The literal bug: a crs_score that used to fall through silently
    # (anything in [4, 20)) must now correctly force a block.
    assert threat_score.get_routing_outcome(0.0, crs_score=10.0) == "block"


# ---------------------------------------------------------------------------
# Phase 3.1 — Dynamic Ensemble Sensitivity & Threshold Tuning
# ---------------------------------------------------------------------------

def test_dynamic_weights_affect_threat_score():
    # Heavy XGBoost weight: 0.10 CRS, 0.80 XGB, 0.10 ISO
    tuning = {
        "crs_weight": 0.10,
        "xgb_weight": 0.80,
        "iso_weight": 0.10,
        "reputation_boost_max": 0.15,
        "abuseipdb_boost_max": 0.15,
    }
    # With crs=0 and xgb=0.5:
    # base_score = (0*0.10 + 0.5*0.80 + 0*0.10) / 1.0 = 0.40
    res = threat_score.calculate_threat_score(
        crs_score=0.0, xgb_prob=0.5, iso_score=0.0, redis_rep=0.0, abuse_score=0.0, tuning=tuning
    )
    assert res["total"] == pytest.approx(0.40)


def test_custom_routing_thresholds_change_decisions():
    # Aggressive preset: block at 0.70 instead of 0.85
    aggressive_tuning = {
        "crs_block_threshold": 4.0,
        "block_threshold": 0.70,
        "rate_limit_threshold": 0.50,
        "log_threshold": 0.25,
        "moderate_risk_action": "log",
    }
    # Score 0.75 is a block under aggressive tuning, but only rate_limit under default (0.85)
    assert threat_score.get_routing_outcome(0.75, crs_score=0.0, tuning=aggressive_tuning) == "block"
    assert threat_score.get_routing_outcome(0.75, crs_score=0.0) == "rate_limit"


def test_moderate_risk_action_customizable():
    challenge_tuning = {
        "crs_block_threshold": 4.0,
        "block_threshold": 0.85,
        "rate_limit_threshold": 0.70,
        "log_threshold": 0.40,
        "moderate_risk_action": "challenge",
    }
    # Score 0.45 triggers moderate risk -> "challenge" instead of "log"
    assert threat_score.get_routing_outcome(0.45, crs_score=0.0, tuning=challenge_tuning) == "challenge"
