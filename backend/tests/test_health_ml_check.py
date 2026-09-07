"""
Regression tests for audit finding P2-02: /health reported ml_enabled=true
based purely on whether the ML_API env var string was non-empty — a static
docker-compose setting, unrelated to whether the waf-ml container was
actually reachable. An ML engine crash/outage was invisible here the same
way a ClickHouse outage used to be (see health.py's own comment on
clickhouse_ok, already fixed once before this).

Also covers the aggregate `status` field, which previously ignored
redis_connected and ml_enabled entirely — `status = "ok" if (db_ok and
clickhouse_ok) else "warning"` — so a genuine Redis or ML outage never
surfaced as anything other than "ok" at the top level, only buried in a
sub-field nothing was reading.
"""
import pytest

import app.routes.health as health_module


@pytest.fixture(autouse=True)
def _reset_health_cache(monkeypatch):
    # Module-level TTL cache — must not leak between tests.
    monkeypatch.setattr(health_module, "_health_cache", {})


def _patch_common(monkeypatch, *, db_ok=True, clickhouse_ok=True, redis_ok=True, ml_status="healthy"):
    monkeypatch.setattr(health_module, "get_parsed_files_count", lambda: 0)
    monkeypatch.setattr(health_module, "check_db_initialized", lambda: db_ok)

    async def fake_ml_api_request(method, path, **kwargs):
        if ml_status == "error":
            return {"status": "error", "message": "connection refused"}
        return {"status": ml_status, "models_loaded": True}

    import app.routes.ml as ml_module
    monkeypatch.setattr(ml_module, "_ml_api_request", fake_ml_api_request)

    import app.services.clickhouse_service as clickhouse_service
    monkeypatch.setattr(clickhouse_service, "is_available", lambda: clickhouse_ok)

    monkeypatch.setattr(health_module, "validate_redis_connection", lambda: redis_ok)


def test_ml_enabled_reflects_a_real_health_check_not_the_env_var(monkeypatch, client):
    _patch_common(monkeypatch, ml_status="error")
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["ml_enabled"] is False


def test_ml_enabled_true_when_engine_actually_reachable(monkeypatch, client):
    _patch_common(monkeypatch, ml_status="healthy")
    r = client.get("/health")
    assert r.json()["ml_enabled"] is True


def test_status_is_warning_when_ml_engine_is_down(monkeypatch, client):
    _patch_common(monkeypatch, db_ok=True, clickhouse_ok=True, redis_ok=True, ml_status="error")
    body = client.get("/health").json()
    assert body["status"] == "warning"


def test_status_is_warning_when_redis_is_down(monkeypatch, client):
    # The other half of the same bug: Redis being down never affected the
    # top-level status either, even though it's a real degraded state.
    _patch_common(monkeypatch, db_ok=True, clickhouse_ok=True, redis_ok=False, ml_status="healthy")
    body = client.get("/health").json()
    assert body["status"] == "warning"
    assert body["redis_connected"] is False


def test_status_is_ok_when_everything_is_actually_up(monkeypatch, client):
    _patch_common(monkeypatch, db_ok=True, clickhouse_ok=True, redis_ok=True, ml_status="healthy")
    body = client.get("/health").json()
    assert body["status"] == "ok"


def test_ml_check_result_is_cached_within_the_ttl(monkeypatch, client):
    calls = {"n": 0}

    async def counting_ml_check(method, path, **kwargs):
        calls["n"] += 1
        return {"status": "healthy"}

    import app.routes.ml as ml_module
    monkeypatch.setattr(ml_module, "_ml_api_request", counting_ml_check)
    monkeypatch.setattr(health_module, "get_parsed_files_count", lambda: 0)
    monkeypatch.setattr(health_module, "check_db_initialized", lambda: True)
    import app.services.clickhouse_service as clickhouse_service
    monkeypatch.setattr(clickhouse_service, "is_available", lambda: True)
    monkeypatch.setattr(health_module, "validate_redis_connection", lambda: True)

    client.get("/health")
    client.get("/health")
    assert calls["n"] == 1
