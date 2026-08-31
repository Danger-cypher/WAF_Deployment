"""
Coverage for API Protection's endpoint-list pagination — previously every
one of /endpoints, /recently-discovered, /stale-endpoints returned every
matching row unpaginated (up to ~380 of them), which the frontend then
rendered as one giant table, refetched and fully re-rendered every 10s
poll. See ApiProtection.jsx's own comment on the table and this session's
latency investigation for the full story.
"""
import pytest
from fastapi.testclient import TestClient

from app.routes.api_protection import _paginate_scored
from app.services import db_service, clickhouse_service
from app.main import app as fastapi_app


# ---------------------------------------------------------------------------
# _paginate_scored — pure slicing logic
# ---------------------------------------------------------------------------

def _rows(n):
    return [{"uri": f"/r{i}"} for i in range(n)]


def test_first_page():
    result = _paginate_scored(_rows(10), page=1, size=4)
    assert result == {"data": _rows(4), "total": 10, "page": 1, "size": 4}


def test_middle_page():
    result = _paginate_scored(_rows(10), page=2, size=4)
    assert result["data"] == _rows(10)[4:8]
    assert result["total"] == 10


def test_last_partial_page():
    result = _paginate_scored(_rows(10), page=3, size=4)
    assert result["data"] == _rows(10)[8:10]  # only 2 rows, not padded to 4
    assert result["total"] == 10


def test_page_past_the_end_returns_empty_data_but_the_real_total():
    """A stale page number (e.g. the list shrank since the client last
    fetched it) must never look like an error — total tells the frontend
    to clamp back, not a 4xx."""
    result = _paginate_scored(_rows(10), page=99, size=4)
    assert result["data"] == []
    assert result["total"] == 10


def test_empty_list():
    result = _paginate_scored([], page=1, size=25)
    assert result == {"data": [], "total": 0, "page": 1, "size": 25}


# ---------------------------------------------------------------------------
# Route-level: GET /api-protection/endpoints (and siblings) actually apply it
# ---------------------------------------------------------------------------

@pytest.fixture
def client(monkeypatch, isolated_user_service):
    return TestClient(fastapi_app)


def _login(client, username, password):
    r = client.post("/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    client.cookies.update(r.cookies)


def _fake_endpoints(n):
    return [
        {
            "uri": f"/api/resource-{i}", "method": "GET", "hit_count": 100 - i,
            "error_count": 0, "malicious_count": 0, "suspicious_count": 0,
            "external_hit_count": 1, "internal_hit_count": 0, "has_https": 1,
            "has_versioning": 1, "content_encoding": "gzip", "avg_response_time_ms": 10.0,
            "param_names": [],
        }
        for i in range(n)
    ]


def test_endpoints_route_paginates_and_reports_the_true_total(client, make_user, monkeypatch):
    monkeypatch.setattr(db_service, "get_all_discovered_endpoints", lambda: _fake_endpoints(60))
    monkeypatch.setattr(clickhouse_service, "is_available", lambda: False)  # skip the threat-count overlay's CH call

    analyst = make_user(role="analyst")
    _login(client, analyst["username"], analyst["password"])

    r = client.get("/api-protection/endpoints?page=2&size=25")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 60
    assert body["page"] == 2
    assert body["size"] == 25
    assert len(body["data"]) == 25
    # Page 2 starts where page 1 left off — same relative ordering as the
    # unpaginated response used to have (highest hit_count first).
    assert body["data"][0]["uri"] == "/api/resource-25"


def test_endpoints_route_default_page_size(client, make_user, monkeypatch):
    monkeypatch.setattr(db_service, "get_all_discovered_endpoints", lambda: _fake_endpoints(60))
    monkeypatch.setattr(clickhouse_service, "is_available", lambda: False)

    analyst = make_user(role="analyst")
    _login(client, analyst["username"], analyst["password"])

    r = client.get("/api-protection/endpoints")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["page"] == 1
    assert body["size"] == 25
    assert len(body["data"]) == 25
    assert body["total"] == 60


def test_stale_endpoints_route_keeps_its_days_param_alongside_pagination(client, make_user, monkeypatch):
    captured = {}

    def fake_stale(days):
        captured["days"] = days
        return _fake_endpoints(5)

    monkeypatch.setattr(db_service, "get_stale_discovered_endpoints", fake_stale)
    monkeypatch.setattr(clickhouse_service, "is_available", lambda: False)

    analyst = make_user(role="analyst")
    _login(client, analyst["username"], analyst["password"])

    r = client.get("/api-protection/stale-endpoints?days=60&page=1&size=10")
    assert r.status_code == 200, r.text
    assert captured["days"] == 60
    assert r.json()["total"] == 5


def test_analytics_route_is_unaffected_by_pagination_params(client, make_user, monkeypatch):
    """/analytics computes its own top-5 lists from the FULL dataset
    regardless of what page of the inventory table the client happens to
    be looking at — it must never be paginated."""
    monkeypatch.setattr(db_service, "get_all_discovered_endpoints", lambda: _fake_endpoints(60))
    monkeypatch.setattr(clickhouse_service, "is_available", lambda: False)

    analyst = make_user(role="analyst")
    _login(client, analyst["username"], analyst["password"])

    r = client.get("/api-protection/analytics")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_endpoints_count"] == 60
    assert len(body["most_consumed"]) == 5
