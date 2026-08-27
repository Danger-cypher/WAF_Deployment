"""
Covers P1-9: API-key authentication. api_key_service.py's own SQLite file
is isolated to a tmp_path DB per test (same reasoning as
isolated_user_service in conftest.py — never touch the real api_keys.db),
and both the module's own singleton binding and routes/api_keys.py's
separately-imported binding are patched, since a top-level `from ... import
x` creates its own local name that a later monkeypatch of the source
module's attribute won't retroactively update.

auth.py's _resolve_api_key() does its `from app.services.api_key_service
import api_key_service` INSIDE the function body (a deliberate, lazy,
call-time import — see its docstring) specifically so patching the source
module's singleton attribute is picked up automatically there without a
third separate patch target.
"""
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.services.api_key_service import ApiKeyService
import app.services.api_key_service as api_key_service_module
import app.routes.api_keys as api_keys_route
from app.main import app as fastapi_app


@pytest.fixture
def isolated_api_key_service(tmp_path, monkeypatch):
    fresh_service = ApiKeyService(db_path=str(tmp_path / "test_api_keys.db"))
    monkeypatch.setattr(api_key_service_module, "api_key_service", fresh_service)
    monkeypatch.setattr(api_keys_route, "api_key_service", fresh_service)
    return fresh_service


@pytest.fixture
def isolated_client(isolated_user_service, isolated_api_key_service):
    return TestClient(fastapi_app)


def _login(client, username, password):
    r = client.post("/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    csrf = r.cookies.get("XSRF-TOKEN-V3")
    client.cookies.update(r.cookies)
    return csrf


# ---------------------------------------------------------------------------
# ApiKeyService — unit tests
# ---------------------------------------------------------------------------

def test_create_key_returns_raw_key_once_and_never_stores_it(isolated_api_key_service):
    svc = isolated_api_key_service
    record, raw_key = svc.create_key(name="ci-pipeline", role="admin", created_by="admin")

    assert raw_key.startswith("csw_")
    assert "key_hash" not in record
    assert record["name"] == "ci-pipeline"
    assert record["role"] == "admin"
    assert record["enabled"] is True
    assert record["key_prefix"] == raw_key[:12]


def test_list_keys_never_exposes_hash_or_raw_key(isolated_api_key_service):
    svc = isolated_api_key_service
    _, raw_key = svc.create_key(name="k1", role="analyst", created_by="admin")

    keys = svc.list_keys()
    assert len(keys) == 1
    assert "key_hash" not in keys[0]
    assert raw_key not in str(keys[0])


def test_validate_key_succeeds_for_correct_key(isolated_api_key_service):
    svc = isolated_api_key_service
    record, raw_key = svc.create_key(name="k1", role="admin", created_by="admin")

    result = svc.validate_key(raw_key, client_ip="10.0.0.5")
    assert result is not None
    assert result["id"] == record["id"]
    assert result["role"] == "admin"


def test_validate_key_records_last_used(isolated_api_key_service):
    svc = isolated_api_key_service
    _, raw_key = svc.create_key(name="k1", role="admin", created_by="admin")

    svc.validate_key(raw_key, client_ip="10.0.0.5")
    updated = svc.list_keys()[0]
    assert updated["last_used_ip"] == "10.0.0.5"
    assert updated["last_used_at"] is not None


def test_validate_key_rejects_wrong_key(isolated_api_key_service):
    svc = isolated_api_key_service
    svc.create_key(name="k1", role="admin", created_by="admin")

    assert svc.validate_key("csw_totally-wrong-value") is None


def test_validate_key_rejects_garbage_without_prefix(isolated_api_key_service):
    assert isolated_api_key_service.validate_key("not-a-key-at-all") is None
    assert isolated_api_key_service.validate_key("") is None
    assert isolated_api_key_service.validate_key(None) is None


def test_validate_key_rejects_revoked_key(isolated_api_key_service):
    svc = isolated_api_key_service
    record, raw_key = svc.create_key(name="k1", role="admin", created_by="admin")

    assert svc.revoke_key(record["id"]) is True
    assert svc.validate_key(raw_key) is None


def test_revoke_nonexistent_key_returns_false(isolated_api_key_service):
    assert isolated_api_key_service.revoke_key(99999) is False


def test_validate_key_rejects_expired_key(isolated_api_key_service):
    svc = isolated_api_key_service
    record, raw_key = svc.create_key(name="k1", role="admin", created_by="admin", expires_in_days=1)

    # Force it into the past directly — the public create_key API can't
    # produce an already-expired key (expires_in_days must be > 0).
    conn = sqlite3.connect(svc.db_path)
    conn.execute(
        "UPDATE api_keys SET expires_at = datetime('now', '-1 hour') WHERE id = ?",
        (record["id"],),
    )
    conn.commit()
    conn.close()

    assert svc.validate_key(raw_key) is None


def test_validate_key_accepts_unexpired_future_expiry(isolated_api_key_service):
    svc = isolated_api_key_service
    _, raw_key = svc.create_key(name="k1", role="admin", created_by="admin", expires_in_days=30)
    assert svc.validate_key(raw_key) is not None


def test_create_key_rejects_invalid_role(isolated_api_key_service):
    with pytest.raises(ValueError):
        isolated_api_key_service.create_key(name="k1", role="app_admin", created_by="admin")


# ---------------------------------------------------------------------------
# Route-level: management endpoints
# ---------------------------------------------------------------------------

def test_analyst_forbidden_from_api_key_management(isolated_client, make_user):
    client = isolated_client
    analyst = make_user(role="analyst")
    _login(client, analyst["username"], analyst["password"])

    assert client.get("/api-keys").status_code == 403
    assert client.post("/api-keys", json={"name": "x", "role": "analyst"}).status_code == 403


def test_admin_can_create_list_and_the_raw_key_is_shown_once(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    r = client.post(
        "/api-keys", headers={"X-XSRF-TOKEN": csrf},
        json={"name": "grafana-puller", "role": "analyst"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["api_key"].startswith("csw_")
    assert body["role"] == "analyst"

    r = client.get("/api-keys")
    assert r.status_code == 200
    listed = r.json()
    assert len(listed) == 1
    assert "api_key" not in listed[0]
    assert listed[0]["key_prefix"] == body["api_key"][:12]


def test_create_rejects_app_admin_role(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    r = client.post(
        "/api-keys", headers={"X-XSRF-TOKEN": csrf},
        json={"name": "x", "role": "app_admin"},
    )
    assert r.status_code == 422


def test_admin_can_revoke_a_key(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    created = client.post(
        "/api-keys", headers={"X-XSRF-TOKEN": csrf},
        json={"name": "x", "role": "admin"},
    ).json()

    r = client.post(f"/api-keys/{created['id']}/revoke", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code == 200
    assert r.json()["enabled"] is False


def test_revoke_unknown_key_404s(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    r = client.post("/api-keys/99999/revoke", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Route-level: the key actually authenticating subsequent API calls,
# exactly like the research required — via a completely separate,
# cookie-less client simulating a real external script.
# ---------------------------------------------------------------------------

def _create_key_as_admin(isolated_client, make_user, role="admin"):
    admin = make_user(role="admin")
    csrf = _login(isolated_client, admin["username"], admin["password"])
    r = isolated_client.post(
        "/api-keys", headers={"X-XSRF-TOKEN": csrf},
        json={"name": f"key-{role}", "role": role},
    )
    assert r.status_code == 201, r.text
    return r.json()["api_key"]


def test_valid_api_key_authenticates_a_normal_request(isolated_client, make_user):
    raw_key = _create_key_as_admin(isolated_client, make_user, role="admin")

    # A fresh, cookie-less client — nothing here simulates a browser.
    machine_client = TestClient(fastapi_app)
    r = machine_client.get("/auth/me", headers={"X-API-Key": raw_key})
    assert r.status_code == 200
    assert r.json()["username"] == "apikey:key-admin"
    assert r.json()["role"] == "admin"


def test_invalid_api_key_is_rejected(isolated_client, make_user):
    _create_key_as_admin(isolated_client, make_user, role="admin")

    machine_client = TestClient(fastapi_app)
    r = machine_client.get("/auth/me", headers={"X-API-Key": "csw_bogus"})
    assert r.status_code == 401


def test_revoked_api_key_stops_working_immediately(isolated_client, make_user):
    admin = make_user(role="admin")
    csrf = _login(isolated_client, admin["username"], admin["password"])
    created = isolated_client.post(
        "/api-keys", headers={"X-XSRF-TOKEN": csrf},
        json={"name": "temp", "role": "admin"},
    ).json()
    raw_key = created["api_key"]

    machine_client = TestClient(fastapi_app)
    assert machine_client.get("/auth/me", headers={"X-API-Key": raw_key}).status_code == 200

    isolated_client.post(f"/api-keys/{created['id']}/revoke", headers={"X-XSRF-TOKEN": csrf})

    assert machine_client.get("/auth/me", headers={"X-API-Key": raw_key}).status_code == 401


def test_analyst_role_key_gets_403_on_admin_only_route(isolated_client, make_user):
    """RBAC applies identically to key-based callers — an analyst-scoped
    key can't reach an admin-only route just by having a valid key."""
    raw_key = _create_key_as_admin(isolated_client, make_user, role="analyst")

    machine_client = TestClient(fastapi_app)
    r = machine_client.get("/api-keys", headers={"X-API-Key": raw_key})
    assert r.status_code == 403


def test_admin_role_key_can_reach_admin_only_route(isolated_client, make_user):
    raw_key = _create_key_as_admin(isolated_client, make_user, role="admin")

    machine_client = TestClient(fastapi_app)
    r = machine_client.get("/api-keys", headers={"X-API-Key": raw_key})
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# CSRF exemption for cookie-less (API-key / Bearer) requests
# ---------------------------------------------------------------------------

def test_api_key_request_bypasses_csrf_on_a_state_changing_route(isolated_client, make_user):
    """The actual point of the CSRF change: a pure API-key caller (no
    session cookie at all) must be able to POST without ever having an
    X-XSRF-TOKEN header — otherwise API keys would be unusable for
    anything but GETs."""
    raw_key = _create_key_as_admin(isolated_client, make_user, role="admin")

    machine_client = TestClient(fastapi_app)
    # POST /api-keys itself is a state-changing, CSRF-protected-by-default
    # route — calling it with only X-API-Key and no CSRF cookie/header at
    # all must not 403 on CSRF grounds (it should succeed, since this key
    # has the admin role required by the route).
    r = machine_client.post(
        "/api-keys", headers={"X-API-Key": raw_key},
        json={"name": "created-via-api-key", "role": "analyst"},
    )
    assert r.status_code == 201, r.text


def test_session_cookie_requests_still_require_csrf(isolated_client, make_user):
    """Regression guard: the CSRF exemption is scoped to cookie-less
    requests only — a real browser session must still be rejected without
    a matching X-XSRF-TOKEN header."""
    admin = make_user(role="admin")
    _login(isolated_client, admin["username"], admin["password"])

    r = isolated_client.post("/api-keys", json={"name": "x", "role": "admin"})
    assert r.status_code == 403
