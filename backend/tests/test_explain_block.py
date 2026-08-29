"""
Covers P1-13's explain-this-block view: clickhouse_service.find_ml_event_near's
query construction (against a fake ClickHouse client — no real ClickHouse
needed, same isolation pattern as test_rule_canary.py's canary-report
tests) and the GET /logs/{log_id}/explain route's merge/404 behavior.
"""
import pytest
from fastapi.testclient import TestClient

from app.services import clickhouse_service
from app.main import app as fastapi_app


class _FakeResult:
    def __init__(self, rows):
        self.result_rows = rows


class _FakeClient:
    def __init__(self, rows):
        self._rows = rows
        self.queries = []
        self.params = []

    def query(self, sql, *args, parameters=None, **kwargs):
        self.queries.append(sql)
        self.params.append(parameters)
        return _FakeResult(self._rows)


# ---------------------------------------------------------------------------
# clickhouse_service.find_ml_event_near — query construction
# ---------------------------------------------------------------------------

def test_find_ml_event_near_maps_result_correctly(monkeypatch):
    fake = _FakeClient(rows=[(
        "req-abc123", "2026-08-26 12:00:01", 18.0, "942100,942190", 0.6, -0.2, 0.75,
        "rate_limit", 2.0, 0.0,
    )])
    monkeypatch.setattr(clickhouse_service, "_get_client", lambda: fake)

    result = clickhouse_service.find_ml_event_near("10.0.0.1", "/login", "2026-08-26 12:00:00")

    assert result["unique_id"] == "req-abc123"
    assert result["crs_score"] == 18.0
    assert result["decision"] == "rate_limit"
    # remote_addr/uri travel as bound parameters, not interpolated into SQL text
    assert "%(client_ip)s" in fake.queries[0]
    assert "%(uri)s" in fake.queries[0]
    assert "10.0.0.1" not in fake.queries[0]
    assert fake.params[0]["client_ip"] == "10.0.0.1"
    assert fake.params[0]["uri"] == "/login"
    assert fake.params[0]["window"] == clickhouse_service.EXPLAIN_MATCH_WINDOW_SECONDS


def test_find_ml_event_near_no_match_returns_none(monkeypatch):
    fake = _FakeClient(rows=[])
    monkeypatch.setattr(clickhouse_service, "_get_client", lambda: fake)

    result = clickhouse_service.find_ml_event_near("10.0.0.1", "/login", "2026-08-26 12:00:00")
    assert result is None


def test_find_ml_event_near_no_client_returns_none(monkeypatch):
    monkeypatch.setattr(clickhouse_service, "_get_client", lambda: None)
    result = clickhouse_service.find_ml_event_near("10.0.0.1", "/login", "2026-08-26 12:00:00")
    assert result is None


def test_find_ml_event_near_query_error_returns_none_not_raises(monkeypatch):
    class _RaisingClient:
        def query(self, *a, **k):
            raise RuntimeError("connection lost")
    monkeypatch.setattr(clickhouse_service, "_get_client", lambda: _RaisingClient())

    result = clickhouse_service.find_ml_event_near("10.0.0.1", "/login", "2026-08-26 12:00:00")
    assert result is None


# ---------------------------------------------------------------------------
# Route-level: GET /logs/{log_id}/explain
# ---------------------------------------------------------------------------

_WAF_EVENT_ROW = (
    "178765650097.594917", "2026-08-26 12:00:00", "10.0.0.1", "US", "",
    "GET", "/login", "example.com", "403",
    "942100", "SQL Injection Attack Detected", "CRITICAL", "sqli",
    "{}", "{}", "[]", "",
)


@pytest.fixture
def client_with_fake_ch(monkeypatch, isolated_user_service):
    return TestClient(fastapi_app)


def _login(client, username, password):
    r = client.post("/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    client.cookies.update(r.cookies)


def test_explain_returns_404_when_waf_event_not_found(client_with_fake_ch, make_user, monkeypatch):
    monkeypatch.setattr(clickhouse_service, "get_waf_event_by_id", lambda log_id: None)
    analyst = make_user(role="analyst")
    _login(client_with_fake_ch, analyst["username"], analyst["password"])

    r = client_with_fake_ch.get("/logs/nonexistent-id/explain")
    assert r.status_code == 404


def test_explain_returns_merged_view_when_ml_event_found(client_with_fake_ch, make_user, monkeypatch):
    waf_row = dict(zip(
        ["id", "timestamp", "client_ip", "country", "source_asn_org", "method", "uri",
         "hostname", "http_code", "rule_id", "message", "severity", "attack_type",
         "request_headers", "response_headers", "violations", "raw_log"],
        _WAF_EVENT_ROW,
    ))
    waf_row["request_headers"] = {}
    waf_row["response_headers"] = {}
    waf_row["violations"] = []
    waf_row["raw_log"] = None
    monkeypatch.setattr(clickhouse_service, "get_waf_event_by_id", lambda log_id: waf_row)

    ml_match = {
        "unique_id": "req-xyz", "timestamp": "2026-08-26 12:00:01", "crs_score": 20.0,
        "matched_vars": "942100", "xgb_prob": 0.9, "iso_score": -0.4, "threat_score": 0.95,
        "decision": "block", "redis_rep": 1.0, "abuse_score": 0.0,
    }
    monkeypatch.setattr(clickhouse_service, "find_ml_event_near", lambda ip, uri, ts, **k: ml_match)

    analyst = make_user(role="analyst")
    _login(client_with_fake_ch, analyst["username"], analyst["password"])

    r = client_with_fake_ch.get("/logs/178765650097.594917/explain")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["waf_event"]["rule_id"] == "942100"
    assert body["ml_event"]["decision"] == "block"
    assert "3-second window" in body["ml_match_note"]


def test_explain_handles_no_ml_match_gracefully(client_with_fake_ch, make_user, monkeypatch):
    waf_row = dict(zip(
        ["id", "timestamp", "client_ip", "country", "source_asn_org", "method", "uri",
         "hostname", "http_code", "rule_id", "message", "severity", "attack_type",
         "request_headers", "response_headers", "violations", "raw_log"],
        _WAF_EVENT_ROW,
    ))
    waf_row["request_headers"] = {}
    waf_row["response_headers"] = {}
    waf_row["violations"] = []
    waf_row["raw_log"] = None
    monkeypatch.setattr(clickhouse_service, "get_waf_event_by_id", lambda log_id: waf_row)
    monkeypatch.setattr(clickhouse_service, "find_ml_event_near", lambda ip, uri, ts, **k: None)

    analyst = make_user(role="analyst")
    _login(client_with_fake_ch, analyst["username"], analyst["password"])

    r = client_with_fake_ch.get("/logs/178765650097.594917/explain")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ml_event"] is None
    assert "blocked it natively" in body["ml_match_note"]
