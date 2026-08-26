"""
End-to-end tests for the per-app positive-security API schema feature
(roadmap item: API schema validation) — real FastAPI TestClient + real
routes, same isolation pattern as test_app_rbac.py (protected_apps lives in
its own SQLite file, nginx_manager.sync_protected_apps_to_nginx is a no-op
for these tests since only apply_api_schema_settings' Redis push matters
here, not full nginx config regen).
"""
import pytest
from fastapi.testclient import TestClient

from app.services import db_service
from app.services import nginx_manager
from app.main import app as fastapi_app


@pytest.fixture
def isolated_db_service(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test_api_schema.db")
    monkeypatch.setattr(db_service, "DB_FILE", db_path)
    db_service.init_db()
    monkeypatch.setattr(nginx_manager, "sync_protected_apps_to_nginx", lambda: (True, ""))

    calls = []

    def fake_apply_api_schema_settings(domain, schema_json, mode):
        calls.append((domain, schema_json, mode))
        return True, ""

    monkeypatch.setattr(nginx_manager, "apply_api_schema_settings", fake_apply_api_schema_settings)
    db_service._test_schema_calls = calls
    return db_service


def _create_app(isolated_db_service, name="testapp", domain="testapp.example.com"):
    app = isolated_db_service.create_protected_app(
        name=name, domain=domain, upstream_host="10.0.0.1", upstream_port=8080,
        protocol="http", is_active=1, rate_limit_rps=50, burst_tolerance=100,
        ssl_option="self-signed", require_auth=0, auth_check_type="header",
        auth_header_name="Authorization",
    )
    return app["id"]


@pytest.fixture
def client(isolated_user_service, isolated_db_service):
    return TestClient(fastapi_app)


def test_get_schema_defaults_to_log_mode_and_empty_endpoints(client, admin_session, isolated_db_service):
    client, csrf, _ = admin_session
    app_id = _create_app(isolated_db_service)

    r = client.get(f"/apps/{app_id}/schema")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["mode"] == "log"
    assert body["endpoints"] == []


def test_put_schema_validates_method_and_path(client, admin_session, isolated_db_service):
    client, csrf, _ = admin_session
    app_id = _create_app(isolated_db_service)

    r = client.put(
        f"/apps/{app_id}/schema",
        headers={"X-XSRF-TOKEN": csrf},
        json={"mode": "enforce", "endpoints": [{"method": "BOGUS", "path": "/api/users"}]},
    )
    assert r.status_code == 400

    r = client.put(
        f"/apps/{app_id}/schema",
        headers={"X-XSRF-TOKEN": csrf},
        json={"mode": "enforce", "endpoints": [{"method": "POST", "path": "no-leading-slash"}]},
    )
    assert r.status_code == 400


def test_put_schema_saves_and_pushes_to_redis(client, admin_session, isolated_db_service):
    client, csrf, _ = admin_session
    app_id = _create_app(isolated_db_service, domain="pushtest.example.com")

    r = client.put(
        f"/apps/{app_id}/schema",
        headers={"X-XSRF-TOKEN": csrf},
        json={
            "mode": "enforce",
            "endpoints": [
                {"method": "POST", "path": "/api/users", "required_fields": ["name", "email"], "allowed_fields": ["name", "email", "role"]},
            ],
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["mode"] == "enforce"
    assert len(r.json()["endpoints"]) == 1

    # Round-trips back out correctly
    r2 = client.get(f"/apps/{app_id}/schema")
    assert r2.json()["mode"] == "enforce"
    assert r2.json()["endpoints"][0]["path"] == "/api/users"

    # And was pushed to the (faked) Redis-application layer, keyed by domain
    calls = isolated_db_service._test_schema_calls
    assert len(calls) == 1
    domain, schema_json, mode = calls[0]
    assert domain == "pushtest.example.com"
    assert mode == "enforce"
    assert "required_fields" in schema_json


def test_clearing_endpoints_clears_stored_schema(client, admin_session, isolated_db_service):
    client, csrf, _ = admin_session
    app_id = _create_app(isolated_db_service)

    client.put(
        f"/apps/{app_id}/schema",
        headers={"X-XSRF-TOKEN": csrf},
        json={"mode": "log", "endpoints": [{"method": "GET", "path": "/api/x"}]},
    )
    r = client.put(
        f"/apps/{app_id}/schema",
        headers={"X-XSRF-TOKEN": csrf},
        json={"mode": "log", "endpoints": []},
    )
    assert r.status_code == 200
    assert r.json()["endpoints"] == []

    calls = isolated_db_service._test_schema_calls
    # Last call cleared the schema (None payload)
    assert calls[-1][1] is None


def test_put_schema_with_field_types_saves_and_round_trips(client, admin_session, isolated_db_service):
    client, csrf, _ = admin_session
    app_id = _create_app(isolated_db_service, domain="fieldtypes.example.com")

    r = client.put(
        f"/apps/{app_id}/schema",
        headers={"X-XSRF-TOKEN": csrf},
        json={
            "mode": "enforce",
            "endpoints": [{
                "method": "POST", "path": "/api/users",
                "required_fields": ["user_id", "role"],
                "allowed_fields": ["user_id", "role", "email"],
                "field_types": {
                    "user_id": {"type": "number"},
                    "role": {"type": "enum", "enum": ["admin", "member"]},
                    "email": {"type": "string", "max_length": 254, "pattern": "^[^@]+@[^@]+$"},
                },
            }],
        },
    )
    assert r.status_code == 200, r.text
    saved = r.json()["endpoints"][0]["field_types"]
    assert saved["user_id"]["type"] == "number"
    assert saved["role"]["enum"] == ["admin", "member"]
    assert saved["email"]["max_length"] == 254

    r2 = client.get(f"/apps/{app_id}/schema")
    assert r2.json()["endpoints"][0]["field_types"]["role"]["type"] == "enum"

    calls = isolated_db_service._test_schema_calls
    assert "field_types" in calls[-1][1]


def test_put_schema_rejects_invalid_field_type(client, admin_session, isolated_db_service):
    client, csrf, _ = admin_session
    app_id = _create_app(isolated_db_service)

    r = client.put(
        f"/apps/{app_id}/schema",
        headers={"X-XSRF-TOKEN": csrf},
        json={
            "mode": "log",
            "endpoints": [{
                "method": "POST", "path": "/api/x",
                "field_types": {"foo": {"type": "not_a_real_type"}},
            }],
        },
    )
    assert r.status_code == 400
    assert "not_a_real_type" in r.text


def test_put_schema_rejects_enum_type_with_no_values(client, admin_session, isolated_db_service):
    client, csrf, _ = admin_session
    app_id = _create_app(isolated_db_service)

    r = client.put(
        f"/apps/{app_id}/schema",
        headers={"X-XSRF-TOKEN": csrf},
        json={
            "mode": "log",
            "endpoints": [{
                "method": "POST", "path": "/api/x",
                "field_types": {"role": {"type": "enum", "enum": []}},
            }],
        },
    )
    assert r.status_code == 400


def test_put_schema_rejects_non_positive_max_length(client, admin_session, isolated_db_service):
    client, csrf, _ = admin_session
    app_id = _create_app(isolated_db_service)

    r = client.put(
        f"/apps/{app_id}/schema",
        headers={"X-XSRF-TOKEN": csrf},
        json={
            "mode": "log",
            "endpoints": [{
                "method": "POST", "path": "/api/x",
                "field_types": {"name": {"type": "string", "max_length": 0}},
            }],
        },
    )
    assert r.status_code == 400


def test_put_schema_rejects_invalid_regex_pattern(client, admin_session, isolated_db_service):
    client, csrf, _ = admin_session
    app_id = _create_app(isolated_db_service)

    r = client.put(
        f"/apps/{app_id}/schema",
        headers={"X-XSRF-TOKEN": csrf},
        json={
            "mode": "log",
            "endpoints": [{
                "method": "POST", "path": "/api/x",
                "field_types": {"name": {"type": "string", "pattern": "("}},
            }],
        },
    )
    assert r.status_code == 400


def test_analyst_cannot_write_schema(client, analyst_session, isolated_db_service):
    client, csrf, _ = analyst_session
    app_id = _create_app(isolated_db_service)

    r = client.put(
        f"/apps/{app_id}/schema",
        headers={"X-XSRF-TOKEN": csrf},
        json={"mode": "log", "endpoints": []},
    )
    assert r.status_code == 403
