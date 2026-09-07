"""
Tests for /predict's graduated-response signal: the threat_score.py "log"
band (0.40-0.70 — real signal, previously zero live consequence) now sets
X-WAF-Risk-Challenge so ml_check.lua can optionally route it through the
existing JS-reload challenge instead of a silent pass-through. Also locks
in threat_score.get_routing_outcome's score-band boundaries directly, since
nothing exercised them before this change.
"""
from fastapi.testclient import TestClient

import ml_server
import threat_score

client = TestClient(ml_server.app)


class _FixedProbaModel:
    """Minimal stand-in for the real XGBoost/IsolationForest models — only
    the two methods /predict actually calls."""
    def __init__(self, xgb_prob=0.0, iso_score=0.0):
        self._xgb_prob = xgb_prob
        self._iso_score = iso_score

    def predict_proba(self, X):
        return [[1.0 - self._xgb_prob, self._xgb_prob]]

    def score_samples(self, X):
        return [self._iso_score]


def _payload(**overrides):
    base = {
        "unique_id": "test-unique-id",
        "crs_score": 0.0,
        "matched_vars": "",
        "uri": "/test",
        "args": "",
        "method": "GET",
        "body_len": 0,
        "ct": "",
        "ua": "pytest",
        "remote_addr": "10.0.0.1",
    }
    base.update(overrides)
    return base


def _predict_with_models(monkeypatch, xgb_prob, iso_score, crs_score=0.0, redis_rep=0.0, abuse_score=0.0):
    monkeypatch.setattr(ml_server, "PASSIVE_MODE", False)
    monkeypatch.setattr(ml_server, "xgb_model", _FixedProbaModel(xgb_prob, iso_score))
    monkeypatch.setattr(ml_server, "iso_model", _FixedProbaModel(xgb_prob, iso_score))
    # Real Redis isn't available in this test environment — reputation
    # inputs are injected directly via this stub's return value instead.
    monkeypatch.setattr(
        ml_server.redis_features, "get_redis_metrics", lambda ip: (0.0, redis_rep, abuse_score)
    )
    return client.post("/predict", json=_payload(crs_score=crs_score))


# ---------------------------------------------------------------------------
# threat_score.get_routing_outcome — score-band boundaries
# ---------------------------------------------------------------------------

def test_routing_outcome_bands():
    assert threat_score.get_routing_outcome(0.39, crs_score=0.0) == "allow"
    assert threat_score.get_routing_outcome(0.40, crs_score=0.0) == "log"
    assert threat_score.get_routing_outcome(0.69, crs_score=0.0) == "log"
    assert threat_score.get_routing_outcome(0.70, crs_score=0.0) == "rate_limit"
    assert threat_score.get_routing_outcome(0.84, crs_score=0.0) == "rate_limit"
    assert threat_score.get_routing_outcome(0.85, crs_score=0.0) == "block"


def test_routing_outcome_high_crs_forces_block_regardless_of_score():
    assert threat_score.get_routing_outcome(0.0, crs_score=20.0) == "block"


# ---------------------------------------------------------------------------
# /predict — X-WAF-Risk-Challenge header
# ---------------------------------------------------------------------------

def test_predict_log_band_sets_risk_challenge_header(monkeypatch):
    # crs_score deliberately stays under 4.0 (P2-01's high-certainty
    # override threshold — see test_routing_outcome_high_crs_forces_block_
    # regardless_of_score below) so this exercises the score-band path
    # specifically, not the override.
    # score = crs_norm(0/20=0)*0.50 + xgb_prob(1.0)*0.30 + iso_norm(1.0)*0.20 = 0.50
    resp = _predict_with_models(monkeypatch, xgb_prob=1.0, iso_score=-0.5, crs_score=0.0)
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "log"
    assert 0.40 <= body["threat_score"] < 0.70
    assert resp.headers.get("x-waf-risk-challenge") == "1"
    # P1-2: named sub-scores travel alongside the blended total.
    assert body["sub_scores"]["total"] == body["threat_score"]
    assert body["sub_scores"]["crs"] == 0.0
    assert body["sub_scores"]["xgb"] == 1.0


def test_predict_allow_band_does_not_set_risk_challenge_header(monkeypatch):
    resp = _predict_with_models(monkeypatch, xgb_prob=0.0, iso_score=0.0, crs_score=0.0)
    assert resp.status_code == 200
    assert resp.json()["decision"] == "allow"
    assert "x-waf-risk-challenge" not in resp.headers


def test_predict_block_band_does_not_set_risk_challenge_header(monkeypatch):
    # crs_score >= 20 forces "block" regardless of the model outputs.
    resp = _predict_with_models(monkeypatch, xgb_prob=1.0, iso_score=-0.5, crs_score=25.0)
    assert resp.status_code == 401
    assert resp.json()["decision"] == "block"
    assert "x-waf-risk-challenge" not in resp.headers


def test_predict_rate_limit_band_does_not_set_risk_challenge_header(monkeypatch):
    # crs_score stays at 0 (well under P2-01's 4.0 override threshold), so
    # this exercises the score-threshold rate_limit path specifically, not
    # the override. Reputation inputs make up the rest of the band since
    # crs/xgb/iso alone can't reach 0.70 without crs_score crossing 4.0:
    # score = xgb_prob(1.0)*0.30 + iso_norm(1.0)*0.20
    #       + rep_boost(min(5*0.03,0.15)=0.15) + abuse_boost(min(50/100*0.15,0.15)=0.075)
    #       = 0.30 + 0.20 + 0.15 + 0.075 = 0.725
    resp = _predict_with_models(
        monkeypatch, xgb_prob=1.0, iso_score=-0.5, crs_score=0.0,
        redis_rep=5.0, abuse_score=50.0,
    )
    assert resp.status_code == 429
    assert resp.json()["decision"] == "rate_limit"
    assert "x-waf-risk-challenge" not in resp.headers


# ---------------------------------------------------------------------------
# P3-04 — /predict now authenticates like every other internal endpoint.
# Every test above runs with INTERNAL_ALERT_TRIGGER_KEY unset (the default
# test environment), which is verify_internal_key's own degrade-to-no-op
# path — real, but it doesn't prove enforcement actually fires when a key
# IS configured. These do.
# ---------------------------------------------------------------------------

def test_predict_rejects_missing_key_when_one_is_configured(monkeypatch):
    monkeypatch.setattr(ml_server, "INTERNAL_ALERT_TRIGGER_KEY", "the-real-shared-secret")
    resp = client.post("/predict", json=_payload())
    assert resp.status_code == 403


def test_predict_rejects_wrong_key(monkeypatch):
    monkeypatch.setattr(ml_server, "INTERNAL_ALERT_TRIGGER_KEY", "the-real-shared-secret")
    resp = client.post("/predict", json=_payload(), headers={"X-Internal-Key": "wrong-guess"})
    assert resp.status_code == 403


def test_predict_accepts_the_matching_key(monkeypatch):
    monkeypatch.setattr(ml_server, "PASSIVE_MODE", False)
    monkeypatch.setattr(ml_server, "xgb_model", _FixedProbaModel(0.0, 0.0))
    monkeypatch.setattr(ml_server, "iso_model", _FixedProbaModel(0.0, 0.0))
    monkeypatch.setattr(
        ml_server.redis_features, "get_redis_metrics", lambda ip: (0.0, 0.0, 0.0)
    )
    monkeypatch.setattr(ml_server, "INTERNAL_ALERT_TRIGGER_KEY", "the-real-shared-secret")
    resp = client.post(
        "/predict", json=_payload(),
        headers={"X-Internal-Key": "the-real-shared-secret"},
    )
    assert resp.status_code == 200
