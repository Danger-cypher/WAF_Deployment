"""
End-to-end integration tests for per-app RBAC scoping (item 7): a real
FastAPI TestClient, real routes, real auth-dependency resolution — not just
unit tests of db_service's access-check functions in isolation, since the
actual risk is in the FastAPI wiring (does require_app_write_access really
get invoked, does list_apps really filter) more than the SQL itself.

Isolates protected_apps from the real filesystem/nginx the same way
test_mssp_default_server.py does (monkeypatch get_all_protected_apps'
underlying DB + nginx_manager.sync_protected_apps_to_nginx), reusing the
conftest.py isolated_user_service/make_user/admin_session pattern for users.
"""
import pytest
from fastapi.testclient import TestClient

from app.services import db_service
from app.services import nginx_manager
from app.main import app as fastapi_app


@pytest.fixture
def isolated_db_service(tmp_path, monkeypatch):
    """protected_apps + app_user_access live in db_service's own SQLite
    file — routes/apps.py imports db_service as a module (`from
    app.services import db_service`), so patching the DB_FILE attribute on
    the module object is visible everywhere that holds the same reference,
    no per-importer rebinding needed (unlike user_service's singleton
    instance import elsewhere in this test suite)."""
    db_path = str(tmp_path / "test_false_positives.db")
    monkeypatch.setattr(db_service, "DB_FILE", db_path)
    db_service.init_db()
    monkeypatch.setattr(nginx_manager, "sync_protected_apps_to_nginx", lambda: (True, ""))
    return db_service


def _create_app(isolated_db_service, name, domain):
    app = isolated_db_service.create_protected_app(
        name=name, domain=domain, upstream_host="10.0.0.1", upstream_port=8080,
        protocol="http", is_active=1, rate_limit_rps=50, burst_tolerance=100,
        ssl_option="self-signed", require_auth=0, auth_check_type="header",
        auth_header_name="Authorization",
    )
    return app["id"]


def _login(client, username, password):
    r = client.post("/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    csrf = r.cookies.get("XSRF-TOKEN-V3")
    client.cookies.update(r.cookies)
    return csrf


@pytest.fixture
def client(isolated_user_service, isolated_db_service):
    return TestClient(fastapi_app)


def _make_app_admin(isolated_user_service, isolated_db_service, app_ids):
    username = "scoped_admin"
    isolated_user_service.create_user(username, "TestPass123!", "app_admin")
    isolated_db_service.set_app_access_for_user(username, app_ids)
    return {"username": username, "password": "TestPass123!"}


def test_app_admin_sees_only_scoped_apps_in_list(client, isolated_user_service, isolated_db_service):
    app_a = _create_app(isolated_db_service, "App A", "a.example.com")
    app_b = _create_app(isolated_db_service, "App B", "b.example.com")
    user = _make_app_admin(isolated_user_service, isolated_db_service, [app_a])
    _login(client, user["username"], user["password"])

    r = client.get("/apps")
    assert r.status_code == 200
    ids = [a["id"] for a in r.json()]
    assert ids == [app_a]
    assert app_b not in ids


def test_app_admin_can_view_own_app(client, isolated_user_service, isolated_db_service):
    app_a = _create_app(isolated_db_service, "App A", "a.example.com")
    user = _make_app_admin(isolated_user_service, isolated_db_service, [app_a])
    _login(client, user["username"], user["password"])

    r = client.get(f"/apps/{app_a}")
    assert r.status_code == 200
    assert r.json()["id"] == app_a


def test_app_admin_cannot_view_unscoped_app(client, isolated_user_service, isolated_db_service):
    app_a = _create_app(isolated_db_service, "App A", "a.example.com")
    app_b = _create_app(isolated_db_service, "App B", "b.example.com")
    user = _make_app_admin(isolated_user_service, isolated_db_service, [app_a])
    _login(client, user["username"], user["password"])

    r = client.get(f"/apps/{app_b}")
    assert r.status_code == 403


def test_app_admin_can_toggle_own_app_but_not_unscoped(client, isolated_user_service, isolated_db_service):
    app_a = _create_app(isolated_db_service, "App A", "a.example.com")
    app_b = _create_app(isolated_db_service, "App B", "b.example.com")
    user = _make_app_admin(isolated_user_service, isolated_db_service, [app_a])
    csrf = _login(client, user["username"], user["password"])

    r = client.post(f"/apps/{app_a}/toggle", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code == 200

    r = client.post(f"/apps/{app_b}/toggle", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code == 403


def test_app_admin_cannot_delete_unscoped_app(client, isolated_user_service, isolated_db_service):
    app_b = _create_app(isolated_db_service, "App B", "b.example.com")
    user = _make_app_admin(isolated_user_service, isolated_db_service, [])
    csrf = _login(client, user["username"], user["password"])

    r = client.delete(f"/apps/{app_b}", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code == 403
    # Confirm it's actually still there, not just a wrong status code.
    assert db_service.get_protected_app_by_id(app_b) is not None


def test_app_admin_cannot_create_new_apps(client, isolated_user_service, isolated_db_service):
    """Creating brand-new protected apps stays admin-only — an app_admin
    manages apps assigned to them, they don't provision their own."""
    user = _make_app_admin(isolated_user_service, isolated_db_service, [])
    csrf = _login(client, user["username"], user["password"])

    r = client.post(
        "/apps",
        headers={"X-XSRF-TOKEN": csrf},
        json={
            "name": "New App", "domain": "new.example.com", "upstream_host": "10.0.0.2",
            "upstream_port": 8080, "protocol": "http", "is_active": 1,
        },
    )
    assert r.status_code == 403


def test_admin_and_analyst_behavior_completely_unchanged(client, make_user, isolated_db_service):
    app_a = _create_app(isolated_db_service, "App A", "a.example.com")
    app_b = _create_app(isolated_db_service, "App B", "b.example.com")

    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])
    r = client.get("/apps")
    assert sorted(a["id"] for a in r.json()) == sorted([app_a, app_b])
    r = client.get(f"/apps/{app_b}")
    assert r.status_code == 200
    r = client.post(f"/apps/{app_b}/toggle", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code == 200
    client.cookies.clear()

    analyst = make_user(role="analyst")
    _login(client, analyst["username"], analyst["password"])
    r = client.get("/apps")
    assert sorted(a["id"] for a in r.json()) == sorted([app_a, app_b])
    r = client.get(f"/apps/{app_a}")
    assert r.status_code == 200


def test_deleting_user_cleans_up_their_app_access(client, isolated_user_service, isolated_db_service):
    app_a = _create_app(isolated_db_service, "App A", "a.example.com")
    scoped = isolated_user_service.create_user("scoped2", "TestPass123!", "app_admin")
    isolated_db_service.set_app_access_for_user("scoped2", [app_a])
    assert isolated_db_service.get_app_ids_for_user("scoped2") == [app_a]

    admin = isolated_user_service.create_user("admin_del", "TestPass123!", "admin")
    isolated_user_service.get_by_id(admin)
    csrf = _login(client, "admin_del", "TestPass123!")
    r = client.delete(f"/users/{scoped}", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code == 200
    assert isolated_db_service.get_app_ids_for_user("scoped2") == []
