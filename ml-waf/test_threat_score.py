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
