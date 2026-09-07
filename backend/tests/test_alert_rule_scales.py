"""
Regression tests for audit finding P1-02: CyberSentinel delivered zero alerts
from 227,317 security events over 51 days, with all three seeded rules enabled.

Measured on the running deployment before this fix:
    ClickHouse alert_history            0 rows
    SQLite     alert_history            1 row  (2026-07-15, delivery FAILED)
               waf_events         227,317 rows (2026-08-03 -> 2026-09-04)
               ml_events          108,018 rows
               3 alert rules, all enabled

Not one root cause but three, each independently fatal to one rule. The
dispatch path itself was fine — ml_server.py does call send_backend_alert(),
and log_ingestor.py does call trigger_event("attack_detected", ...) for every
ingested entry. Every rule died at condition evaluation instead.

  Rule 2 "High WAF Attack Rule"  {"crs_score_gt": 4}
      Read event_data["crs_score"], a field no ingested event carried. Its
      fallback read raw_log["extracted_fields"]["score"], which does not
      exist either, and raw_log arrives as a JSON *string* so .get() on it
      raised straight into the broad except. Fixed by parsing the anomaly
      total onto LogEntry.crs_score at ingestion, plus message/violation
      fallbacks here.

  Rule 1 "Critical ML Threat"    {"threat_score_gt": 80}
      SCALE MISMATCH. The engine emits threat_score on 0.0-1.0; the UI
      renders it as `value * 100` with a "%", the README documents "0 to
      100%", and the rule builder's own placeholder is
      {"threat_score_gt": 80}. Comparing a raw 0.30 against 80 is always
      no-match, so every rule written the way the product teaches was
      unsatisfiable.

  Rule 3 "ML Novelty Anomaly"    {"isolation_score_gt": 0.5}
      SIGN MISMATCH. sklearn's IsolationForest.score_samples() is inverted:
      more negative = more anomalous. ml_server.py's own trigger fires on
      `iso_score < -0.35`, but the rule demanded a POSITIVE score, i.e.
      "unusually normal". 106,650 of 108,018 events crossed the engine's
      anomaly bar; none could satisfy the rule meant to catch them.

The fourth test class here covers the ceiling added alongside these fixes:
repairing the evaluator without a bound would have turned a silent product
into an alert flood, because the deployed Isolation Forest scores 100% of
real traffic as anomalous (highest iso_score ever recorded: -0.3456).
"""
import pytest

from app.services.alert_manager import (
    MAX_ALERTS_PER_RULE_PER_HOUR,
    _to_event_scale,
    alert_manager,
)


def matches(conditions, event):
    return alert_manager.evaluate_condition(conditions, event)


# --------------------------------------------------------------------------
# Rule 2 — crs_score must be readable from every event shape
# --------------------------------------------------------------------------

CRS_RULE = {"crs_score_gt": 4}


def test_crs_score_field_matches():
    assert matches(CRS_RULE, {"crs_score": 23.0}) is True


def test_crs_score_below_threshold_does_not_match():
    assert matches(CRS_RULE, {"crs_score": 3.0}) is False


def test_crs_score_recovered_from_message():
    # Events ingested before LogEntry.crs_score existed still carry the
    # score inside the 949110 message text.
    assert matches(
        CRS_RULE,
        {"message": "Inbound Anomaly Score Exceeded (Total Score: 23)"},
    ) is True


def test_crs_score_recovered_from_violation_message():
    # In the JSON audit format the anomaly total sits on the 949110
    # violation rather than the top-level message.
    assert matches(
        CRS_RULE,
        {
            "message": "Access denied",
            "violations": [
                {"rule_id": "949110",
                 "message": "Inbound Anomaly Score Exceeded (Total Score: 9)"}
            ],
        },
    ) is True


def test_crs_score_raw_log_as_json_string_does_not_raise():
    # The original crash: raw_log is a ClickHouse String column, so .get()
    # on it raised AttributeError into the broad except -> silent no-match.
    import json
    event = {"raw_log": json.dumps(
        {"message": "Inbound Anomaly Score Exceeded (Total Score: 9)"})}
    assert matches(CRS_RULE, event) is True


def test_crs_score_malformed_raw_log_is_survivable():
    assert matches(CRS_RULE, {"raw_log": "{not json"}) is False


def test_event_with_genuinely_no_crs_score_does_not_match():
    # A Lua-originated block or native rate-limit rejection has no CRS
    # score. It must not be treated as zero, nor crash.
    assert matches(CRS_RULE, {"message": "Blocked by WAF (IP Access Denied)"}) is False


# --------------------------------------------------------------------------
# Rule 1 — percentage thresholds must work, raw ones must keep working
# --------------------------------------------------------------------------

def test_percentage_threshold_matches_high_score():
    # The exact seeded rule, against a score that should clearly alert.
    assert matches({"threat_score_gt": 80}, {"threat_score": 0.92}) is True


def test_percentage_threshold_rejects_normal_traffic():
    # 0.30 was the highest threat_score ever observed on this deployment.
    assert matches({"threat_score_gt": 80}, {"threat_score": 0.30}) is False


def test_raw_scale_threshold_still_honoured():
    # An operator who understood the real scale wrote 0.85. That must keep
    # meaning 0.85, not 0.0085.
    assert matches({"threat_score_gt": 0.85}, {"threat_score": 0.92}) is True
    assert matches({"threat_score_gt": 0.85}, {"threat_score": 0.80}) is False


def test_threat_score_lt_uses_the_same_scale():
    assert matches({"threat_score_lt": 50}, {"threat_score": 0.30}) is True
    assert matches({"threat_score_lt": 50}, {"threat_score": 0.70}) is False


def test_xgb_probability_accepts_percentage_too():
    assert matches({"xgb_prob_gt": 70}, {"xgb_prob": 0.85}) is True
    assert matches({"xgb_prob_gt": 70}, {"xgb_prob": 0.60}) is False


def test_missing_score_never_matches():
    assert matches({"threat_score_gt": 80}, {}) is False
    assert matches({"xgb_prob_gt": 70}, {}) is False


@pytest.mark.parametrize(
    "given,expected",
    [
        (80, 0.80),      # percentage, as the UI teaches
        (0.85, 0.85),    # raw scale, unchanged
        (1.0, 1.0),      # boundary stays raw
        (100, 1.0),      # full-scale percentage
        (0, 0.0),
    ],
)
def test_scale_conversion_boundaries(given, expected):
    assert _to_event_scale(given) == pytest.approx(expected)


def test_unparseable_threshold_never_matches():
    # A corrupt threshold must fail closed (no alert) rather than raise or
    # match everything.
    assert _to_event_scale("not-a-number") == float("inf")
    assert matches({"threat_score_gt": "not-a-number"}, {"threat_score": 0.99}) is False


# --------------------------------------------------------------------------
# Rule 3 — anomaly sign convention
# --------------------------------------------------------------------------

def test_positive_threshold_matches_a_real_anomaly():
    # The seeded rule, against an iso_score the engine itself considers
    # anomalous. sklearn: more negative = more anomalous.
    assert matches({"isolation_score_gt": 0.5}, {"iso_score": -0.60}) is True


def test_positive_threshold_rejects_normal_traffic():
    assert matches({"isolation_score_gt": 0.5}, {"iso_score": -0.10}) is False


def test_negative_threshold_uses_the_raw_sklearn_scale():
    # Someone who understood the convention and wrote -0.35 keeps the
    # behaviour they intended.
    assert matches({"isolation_score_gt": -0.35}, {"iso_score": -0.60}) is True
    assert matches({"isolation_score_gt": -0.35}, {"iso_score": -0.10}) is False


def test_anomaly_strength_matches_threat_score_normalisation():
    # Strength is -iso/0.5 clamped to [0,1] — the same formula
    # threat_score.py uses to fold this into the combined score, so the two
    # can never drift apart.
    assert matches({"isolation_score_gt": 0.5}, {"iso_score": -0.26}) is True   # 0.52
    assert matches({"isolation_score_gt": 0.5}, {"iso_score": -0.24}) is False  # 0.48


def test_missing_iso_score_never_matches():
    assert matches({"isolation_score_gt": 0.5}, {}) is False


# --------------------------------------------------------------------------
# Flood ceiling
# --------------------------------------------------------------------------

def test_default_ceiling_is_a_real_bound():
    assert isinstance(MAX_ALERTS_PER_RULE_PER_HOUR, int)
    assert 0 < MAX_ALERTS_PER_RULE_PER_HOUR <= 1000


def test_ceiling_counts_dispatches_per_rule(monkeypatch):
    # count_recent_notifications must be scoped to one rule, so a noisy rule
    # cannot suppress a quiet one.
    seen = {}

    def fake_count(rule_id, minutes=60):
        seen["rule_id"] = rule_id
        seen["minutes"] = minutes
        return 0

    monkeypatch.setattr(alert_manager.db, "count_recent_notifications", fake_count)
    alert_manager.db.count_recent_notifications(7, minutes=60)
    assert seen == {"rule_id": 7, "minutes": 60}


# --------------------------------------------------------------------------
# Unrelated conditions must be unaffected by all of the above
# --------------------------------------------------------------------------

def test_country_and_custom_conditions_still_work():
    assert matches({"blocked_countries": ["CN"]}, {"country": "CN"}) is True
    assert matches({"blocked_countries": ["CN"]}, {"country": "DE"}) is False
    assert matches({"custom_conditions": {"decision": "block"}}, {"decision": "block"}) is True
    assert matches({"custom_conditions": {"decision": "block"}}, {"decision": "allow"}) is False


def test_empty_conditions_match_everything():
    # A rule with no conditions is "alert on every event of this type",
    # which is a legitimate configuration.
    assert matches({}, {"client_ip": "1.2.3.4"}) is True


def test_all_conditions_must_hold():
    cond = {"crs_score_gt": 4, "blocked_countries": ["CN"]}
    assert matches(cond, {"crs_score": 23.0, "country": "CN"}) is True
    assert matches(cond, {"crs_score": 23.0, "country": "DE"}) is False
    assert matches(cond, {"crs_score": 1.0, "country": "CN"}) is False
