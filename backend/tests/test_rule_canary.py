"""
Covers the canary-review feature for existing CRS rules: mark_rule_canary's
pure state bookkeeping (no override-file write / NGINX reload — it never
changes enforcement, see its own docstring for why), and
get_rule_canary_report's ClickHouse query construction against a fake
client (same isolation pattern as test_stats_consistency.py — no real
ClickHouse needed).
"""
import pytest
from fastapi.testclient import TestClient

from app.services import rule_manager, clickhouse_service
from app.main import app as fastapi_app


# A rule ID guaranteed to exist in the real, bundled CRS ruleset (this repo
# ships the actual coreruleset files, not fixtures) — 901001 is CRS's own
# "CRS initialization" rule, present in every CRS version this project has used.
REAL_RULE_ID = "901001"


@pytest.fixture
def isolated_rule_state(tmp_path, monkeypatch):
    monkeypatch.setattr(rule_manager, "STATE_FILE", str(tmp_path / "rule_state.json"))
    return rule_manager


def test_mark_canary_flags_and_unflags(isolated_rule_state):
    ok, msg = rule_manager.mark_rule_canary(REAL_RULE_ID, True, username="tester")
    assert ok, msg

    rule = rule_manager.get_rule_by_id(REAL_RULE_ID)
    assert rule.is_canary is True

    ok, msg = rule_manager.mark_rule_canary(REAL_RULE_ID, False, username="tester")
    assert ok, msg
    rule = rule_manager.get_rule_by_id(REAL_RULE_ID)
    assert rule.is_canary is False


def test_mark_canary_unknown_rule_fails(isolated_rule_state):
    ok, msg = rule_manager.mark_rule_canary("not-a-real-rule-id", True, username="tester")
    assert not ok


def test_mark_canary_records_audit_history_with_real_username(isolated_rule_state):
    rule_manager.mark_rule_canary(REAL_RULE_ID, True, username="alice")
    state = rule_manager._load_state()
    entry = state["audit_history"][0]
    assert entry["username"] == "alice"
    assert entry["action"] == "canary_flag"
    assert entry["rule_id"] == REAL_RULE_ID


def test_get_all_rules_reports_canary_status(isolated_rule_state):
    rule_manager.mark_rule_canary(REAL_RULE_ID, True, username="tester")
    rules, _ = rule_manager.get_all_rules(page=1, size=1000)
    flagged = next(r for r in rules if r.id == REAL_RULE_ID)
    assert flagged.is_canary is True


class _FakeResult:
    def __init__(self, rows):
        self.result_rows = rows


class _FakeClient:
    """
    get_rule_canary_report now issues two queries — the aggregate totals,
    then the per-day breakdown — with different result shapes. `rows`
    answers the first call; `daily_rows` (defaulting to the same `rows`,
    which is fine for tests that don't care about the second call's shape)
    answers the second.
    """
    def __init__(self, rows, daily_rows=None):
        self._rows = rows
        self._daily_rows = rows if daily_rows is None else daily_rows
        self.queries = []
        self.params = []

    def query(self, sql, *args, parameters=None, **kwargs):
        self.queries.append(sql)
        self.params.append(parameters)
        is_first_call = len(self.queries) == 1
        return _FakeResult(self._rows if is_first_call else self._daily_rows)


def test_canary_report_maps_query_result_correctly(monkeypatch):
    # Same fake row shape for both the aggregate and the daily-breakdown
    # query — good enough to prove the mapping/plumbing; the daily query's
    # own column meaning (day, sole, co) is covered by
    # test_canary_report_daily_breakdown_maps_correctly below.
    fake = _FakeClient(rows=[(10, 3, 7)])
    monkeypatch.setattr(clickhouse_service, "_get_client", lambda: fake)

    report = clickhouse_service.get_rule_canary_report("942100", hours=168)

    assert report["total_matches"] == 10
    assert report["sole_match_count"] == 3
    assert report["co_matched_count"] == 7
    # Two queries now: the aggregate totals, then the per-day breakdown.
    assert len(fake.queries) == 2
    # Searches inside the violations JSON itself, not the top-level rule_id
    # column (which only ever holds ONE selected "primary" rule per request)
    assert "JSONExtractArrayRaw(violations)" in fake.queries[0]
    # rule_id travels as a real bound parameter, not interpolated into the
    # SQL text — the query template itself never contains the raw value.
    assert "%(rule_id)s" in fake.queries[0]
    assert "942100" not in fake.queries[0]
    assert fake.params[0] == {"rule_id": "942100"}


def test_canary_report_daily_breakdown_maps_correctly(monkeypatch):
    fake = _FakeClient(
        rows=[(3, 1, 2)],
        daily_rows=[("2026-08-20", 1, 2), ("2026-08-21", 0, 4)],
    )
    monkeypatch.setattr(clickhouse_service, "_get_client", lambda: fake)

    report = clickhouse_service.get_rule_canary_report("942100", hours=168)

    assert report["daily_breakdown"] == [
        {"date": "2026-08-20", "sole_match_count": 1, "co_matched_count": 2},
        {"date": "2026-08-21", "sole_match_count": 0, "co_matched_count": 4},
    ]
    # Same injection-safe binding as the aggregate query, on the second call.
    assert "%(rule_id)s" in fake.queries[1]
    assert "942100" not in fake.queries[1]
    assert fake.params[1] == {"rule_id": "942100"}
    assert "GROUP BY day" in fake.queries[1]


def test_canary_report_empty_result_defaults_to_zero(monkeypatch):
    fake = _FakeClient(rows=[])
    monkeypatch.setattr(clickhouse_service, "_get_client", lambda: fake)

    report = clickhouse_service.get_rule_canary_report("942100", hours=24)
    assert report == {"total_matches": 0, "sole_match_count": 0, "co_matched_count": 0, "daily_breakdown": []}


def test_canary_report_rule_id_survives_injection_attempt(monkeypatch):
    """
    Real end-to-end proof, not just a string-shape assertion: run the exact
    same finalize_query() clickhouse-connect itself calls internally to
    apply `parameters` client-side, and confirm a quote-breakout payload
    comes out properly backslash-escaped rather than breaking out of the
    string literal.
    """
    from clickhouse_connect.driver.binding import finalize_query

    fake = _FakeClient(rows=[(0, 0, 0)])
    monkeypatch.setattr(clickhouse_service, "_get_client", lambda: fake)

    payload = "942100' OR '1'='1"
    clickhouse_service.get_rule_canary_report(payload, hours=24)

    assert fake.params[0] == {"rule_id": payload}
    final_sql = finalize_query(fake.queries[0], fake.params[0])
    # The payload's quotes are backslash-escaped, not left as raw SQL syntax
    assert "OR '1'='1'" not in final_sql
    assert "\\' OR \\'1\\'=\\'1" in final_sql


# --- Route-level wiring (real TestClient, real routes/rules.py) ---

@pytest.fixture
def isolated_rule_state_and_client(tmp_path, monkeypatch, isolated_user_service):
    monkeypatch.setattr(rule_manager, "STATE_FILE", str(tmp_path / "rule_state.json"))
    fake = _FakeClient(rows=[(5, 2, 3)])
    monkeypatch.setattr(clickhouse_service, "_get_client", lambda: fake)
    return TestClient(fastapi_app)


def _login(client, username, password):
    r = client.post("/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    csrf = r.cookies.get("XSRF-TOKEN-V3")
    client.cookies.update(r.cookies)
    return csrf


def test_analyst_can_read_but_not_write_canary_flag(isolated_rule_state_and_client, make_user):
    client = isolated_rule_state_and_client
    analyst = make_user(role="analyst")
    csrf = _login(client, analyst["username"], analyst["password"])

    r = client.get(f"/rules/{REAL_RULE_ID}/canary-report")
    assert r.status_code == 200
    assert r.json()["rule_id"] == REAL_RULE_ID
    assert r.json()["total_matches"] == 5

    r = client.post("/rules/canary", headers={"X-XSRF-TOKEN": csrf}, json={"id": REAL_RULE_ID, "canary": True})
    assert r.status_code == 403


def test_admin_can_flag_and_read_it_back(isolated_rule_state_and_client, make_user):
    client = isolated_rule_state_and_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    r = client.post("/rules/canary", headers={"X-XSRF-TOKEN": csrf}, json={"id": REAL_RULE_ID, "canary": True})
    assert r.status_code == 200, r.text

    r = client.get(f"/rules/{REAL_RULE_ID}")
    assert r.json()["is_canary"] is True


# --- Bounded-window auto-rollout (evaluate_canary_rollout) ---

import datetime as _dt


def _backdate_canary_start(hours_ago: float):
    """Rewrites canary_meta.started_at for REAL_RULE_ID to simulate a
    monitoring window that's partially/fully elapsed, without waiting."""
    state = rule_manager._load_state()
    state["canary_meta"][REAL_RULE_ID]["started_at"] = (
        _dt.datetime.now() - _dt.timedelta(hours=hours_ago)
    ).isoformat()
    rule_manager._save_state(state)


def test_mark_canary_records_started_at(isolated_rule_state):
    rule_manager.mark_rule_canary(REAL_RULE_ID, True, username="tester")
    status = rule_manager.get_canary_status(REAL_RULE_ID)
    assert status is not None
    assert status["started_at"] is not None
    assert status["needs_review"] is False
    assert status["window_hours"] == rule_manager.DEFAULT_CANARY_SETTINGS["window_hours"]


def test_unflag_clears_canary_meta(isolated_rule_state):
    rule_manager.mark_rule_canary(REAL_RULE_ID, True, username="tester")
    rule_manager.mark_rule_canary(REAL_RULE_ID, False, username="tester")
    assert rule_manager.get_canary_status(REAL_RULE_ID) is None


def test_reflagging_preserves_original_window_start(isolated_rule_state, monkeypatch):
    rule_manager.mark_rule_canary(REAL_RULE_ID, True, username="tester")
    _backdate_canary_start(10)
    started_first = rule_manager.get_canary_status(REAL_RULE_ID)["started_at"]

    # Unflag+reflag would normally reset via mark_rule_canary's own path —
    # but re-flagging an ALREADY-flagged rule (no unflag in between) must
    # not reset the clock.
    rule_manager.mark_rule_canary(REAL_RULE_ID, True, username="tester")
    assert rule_manager.get_canary_status(REAL_RULE_ID)["started_at"] == started_first


def test_canary_settings_defaults_and_roundtrip(isolated_rule_state):
    defaults = rule_manager.get_canary_rollout_settings()
    assert defaults == rule_manager.DEFAULT_CANARY_SETTINGS

    ok, msg = rule_manager.save_canary_rollout_settings(
        {"auto_promote_enabled": True, "window_hours": 24}, username="tester"
    )
    assert ok, msg
    updated = rule_manager.get_canary_rollout_settings()
    assert updated["auto_promote_enabled"] is True
    assert updated["window_hours"] == 24
    # Untouched fields keep their defaults
    assert updated["min_sample_size"] == rule_manager.DEFAULT_CANARY_SETTINGS["min_sample_size"]


def _mock_report(monkeypatch, total, sole):
    monkeypatch.setattr(
        clickhouse_service, "get_rule_canary_report",
        lambda rule_id, hours=168: {
            "total_matches": total, "sole_match_count": sole, "co_matched_count": total - sole,
        },
    )


def test_rollout_insufficient_sample_stays_monitoring(isolated_rule_state, monkeypatch):
    rule_manager.mark_rule_canary(REAL_RULE_ID, True, username="tester")
    _mock_report(monkeypatch, total=5, sole=1)  # below default min_sample_size=20

    result = rule_manager.evaluate_canary_rollout()
    assert result["still_monitoring"] == [REAL_RULE_ID]
    assert rule_manager.get_canary_status(REAL_RULE_ID) is not None  # still flagged


def test_rollout_insufficient_sample_after_window_elapses_needs_review(isolated_rule_state, monkeypatch):
    rule_manager.mark_rule_canary(REAL_RULE_ID, True, username="tester")
    _backdate_canary_start(rule_manager.DEFAULT_CANARY_SETTINGS["window_hours"] + 1)
    _mock_report(monkeypatch, total=5, sole=1)

    result = rule_manager.evaluate_canary_rollout()
    assert result["needs_review"] == [REAL_RULE_ID]
    status = rule_manager.get_canary_status(REAL_RULE_ID)
    assert status["needs_review"] is True
    # Rule stays flagged/monitoring — needs_review doesn't touch enforcement
    assert REAL_RULE_ID in rule_manager._load_state()["canary_rule_ids"]


def test_rollout_auto_promote_disabled_by_default_leaves_good_rule_monitoring(isolated_rule_state, monkeypatch):
    rule_manager.mark_rule_canary(REAL_RULE_ID, True, username="tester")
    _mock_report(monkeypatch, total=50, sole=2)  # 4% sole-match rate — well below promote threshold

    result = rule_manager.evaluate_canary_rollout()
    # auto_promote_enabled defaults False — good rate alone isn't enough
    assert result["still_monitoring"] == [REAL_RULE_ID]
    assert rule_manager.get_canary_status(REAL_RULE_ID) is not None


def test_rollout_auto_promotes_when_enabled_and_rate_low(isolated_rule_state, monkeypatch):
    rule_manager.mark_rule_canary(REAL_RULE_ID, True, username="tester")
    rule_manager.save_canary_rollout_settings({"auto_promote_enabled": True})
    _mock_report(monkeypatch, total=50, sole=2)  # 4% sole-match rate

    result = rule_manager.evaluate_canary_rollout()
    assert result["promoted"] == [REAL_RULE_ID]
    assert rule_manager.get_canary_status(REAL_RULE_ID) is None  # flag cleared
    rule = rule_manager.get_rule_by_id(REAL_RULE_ID)
    assert rule.enabled is True  # never touched enforcement — it was always enforcing


def test_rollout_auto_rolls_back_high_sole_match_rate(isolated_rule_state, monkeypatch):
    rule_manager.mark_rule_canary(REAL_RULE_ID, True, username="tester")
    _mock_report(monkeypatch, total=50, sole=40)  # 80% sole-match rate — above rollback threshold

    # Isolate the real config-write/reload side effects toggle_rule would
    # otherwise attempt (docker exec / real modsec override file).
    monkeypatch.setattr(
        rule_manager, "_update_modsecurity_override_file", lambda *a, **k: (True, "ok")
    )
    monkeypatch.setattr(rule_manager, "_run_nginx_reload", lambda: (True, "ok"))

    result = rule_manager.evaluate_canary_rollout()
    assert result["rolled_back"] == [REAL_RULE_ID]
    assert rule_manager.get_canary_status(REAL_RULE_ID) is None  # flag cleared
    rule = rule_manager.get_rule_by_id(REAL_RULE_ID)
    assert rule.enabled is False  # actually disabled this time

    state = rule_manager._load_state()
    actions = [e["action"] for e in state["audit_history"]]
    assert "disable" in actions  # toggle_rule's own audit entry


def test_rollout_auto_rollback_disabled_leaves_bad_rule_monitoring_until_window_elapses(
    isolated_rule_state, monkeypatch
):
    rule_manager.mark_rule_canary(REAL_RULE_ID, True, username="tester")
    rule_manager.save_canary_rollout_settings({"auto_rollback_enabled": False})
    _mock_report(monkeypatch, total=50, sole=40)  # would have rolled back

    result = rule_manager.evaluate_canary_rollout()
    assert result["still_monitoring"] == [REAL_RULE_ID]
    rule = rule_manager.get_rule_by_id(REAL_RULE_ID)
    assert rule.enabled is True  # untouched


def test_rollout_ambiguous_zone_needs_review_after_window_elapses(isolated_rule_state, monkeypatch):
    rule_manager.mark_rule_canary(REAL_RULE_ID, True, username="tester")
    _backdate_canary_start(rule_manager.DEFAULT_CANARY_SETTINGS["window_hours"] + 1)
    _mock_report(monkeypatch, total=50, sole=25)  # 50% — between promote and rollback thresholds

    result = rule_manager.evaluate_canary_rollout()
    assert result["needs_review"] == [REAL_RULE_ID]
    rule = rule_manager.get_rule_by_id(REAL_RULE_ID)
    assert rule.enabled is True  # ambiguous outcome never disables


# --- Route-level wiring for settings + status + run-now ---

def test_analyst_can_read_settings_but_not_write(isolated_rule_state_and_client, make_user):
    client = isolated_rule_state_and_client
    analyst = make_user(role="analyst")
    _login(client, analyst["username"], analyst["password"])

    r = client.get("/rules/canary-settings")
    assert r.status_code == 200
    assert r.json()["auto_rollback_enabled"] is True

    r = client.post("/rules/canary-settings", json={"auto_promote_enabled": True})
    assert r.status_code == 403


def test_admin_can_save_settings_and_run_now(isolated_rule_state_and_client, make_user, monkeypatch):
    client = isolated_rule_state_and_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    r = client.post(
        "/rules/canary-settings", headers={"X-XSRF-TOKEN": csrf},
        json={"auto_promote_enabled": True, "window_hours": 48, "min_sample_size": 20,
              "auto_rollback_enabled": True, "promote_max_sole_match_rate": 0.3,
              "rollback_min_sole_match_rate": 0.7},
    )
    assert r.status_code == 200, r.text
    assert r.json()["window_hours"] == 48

    r = client.post("/rules/canary", headers={"X-XSRF-TOKEN": csrf}, json={"id": REAL_RULE_ID, "canary": True})
    assert r.status_code == 200

    r = client.post("/rules/canary/run-now", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code == 200, r.text
    # isolated_rule_state_and_client's fake ClickHouse client returns (5, 2, 3) —
    # below the default min_sample_size, so it just stays monitoring.
    assert r.json()["still_monitoring"] == [REAL_RULE_ID]


def test_canary_status_route_reflects_flag_state(isolated_rule_state_and_client, make_user):
    client = isolated_rule_state_and_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    r = client.get(f"/rules/{REAL_RULE_ID}/canary-status")
    assert r.status_code == 200
    assert r.json() is None

    client.post("/rules/canary", headers={"X-XSRF-TOKEN": csrf}, json={"id": REAL_RULE_ID, "canary": True})
    r = client.get(f"/rules/{REAL_RULE_ID}/canary-status")
    assert r.json()["rule_id"] == REAL_RULE_ID
    assert r.json()["needs_review"] is False
