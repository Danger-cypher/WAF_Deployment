"""
Covers P1-14 (simplest version): multiple backend origins per protected
app, load-balanced via nginx's existing upstream{} block (which already
carried passive-failover params — max_fails/fail_timeout — for exactly
ONE server; this just adds more server lines to the SAME block, letting
nginx's default round-robin and the already-wired proxy_next_upstream*
directives do the rest).

Two isolation levels, mirroring existing precedent:
- nginx_manager unit tests: monkeypatch db_service.get_all_protected_apps
  and nginx_manager.write_and_apply_configs, inspect generated config text
  directly (test_mssp_default_server.py's pattern).
- Route-level tests: real FastAPI TestClient + isolated_db_service fixture
  (test_app_rbac.py's pattern) with nginx sync itself stubbed to (True, "").
"""
import json

import pytest
from fastapi.testclient import TestClient

import app.services.db_service as db_service
from app.services import nginx_manager
from app.main import app as fastapi_app


def _make_app(app_id, additional_origins=None, **overrides):
    base = {
        "id": app_id,
        "name": f"App {app_id}",
        "domain": f"app{app_id}.example.com",
        "upstream_host": "10.0.0.1",
        "upstream_port": 8080,
        "protocol": "http",
        "is_active": 1,
        "rate_limit_rps": 50,
        "burst_tolerance": 100,
        "ssl_option": "self-signed",
        "ssl_cert_path": None,
        "ssl_key_path": None,
        "require_auth": 0,
        "auth_check_type": "header",
        "auth_header_name": "Authorization",
        "additional_origins": json.dumps(additional_origins) if additional_origins else None,
    }
    base.update(overrides)
    return base


def _capture_generated_config(monkeypatch, apps):
    monkeypatch.setattr(db_service, "get_all_protected_apps", lambda: apps)
    captured = {}

    def fake_write_and_apply(file_contents):
        captured.update(file_contents)
        return True, ""

    monkeypatch.setattr(nginx_manager, "write_and_apply_configs", fake_write_and_apply)

    ok, msg = nginx_manager.sync_protected_apps_to_nginx()
    assert ok, msg
    return captured["/etc/nginx/sites-enabled/mssp"]


def _upstream_block(config, app_id):
    lines = config.splitlines()
    start = next(i for i, l in enumerate(lines) if l.strip() == f"upstream upstream_app_{app_id} {{")
    end = next(i for i in range(start, len(lines)) if lines[i].strip() == "}")
    return lines[start:end + 1]


# ---------------------------------------------------------------------------
# nginx_manager: upstream{} block generation
# ---------------------------------------------------------------------------

def test_app_with_no_extra_origins_generates_single_server_line(monkeypatch):
    """Backward compatibility: the exact pre-P1-14 behavior for any app
    that never configures additional origins (including the one real live
    app found during research, which has none)."""
    apps = [_make_app(1)]
    config = _capture_generated_config(monkeypatch, apps)
    block = _upstream_block(config, 1)

    server_lines = [l for l in block if l.strip().startswith("server ")]
    assert server_lines == ["    server 10.0.0.1:8080 max_fails=3 fail_timeout=10s;"]


def test_app_with_extra_origins_generates_all_server_lines_in_one_block(monkeypatch):
    apps = [_make_app(1, additional_origins=[
        {"host": "10.0.0.2", "port": 8081},
        {"host": "10.0.0.3", "port": 8082},
    ])]
    config = _capture_generated_config(monkeypatch, apps)
    block = _upstream_block(config, 1)

    server_lines = [l.strip() for l in block if l.strip().startswith("server ")]
    assert server_lines == [
        "server 10.0.0.1:8080 max_fails=3 fail_timeout=10s;",
        "server 10.0.0.2:8081 max_fails=3 fail_timeout=10s;",
        "server 10.0.0.3:8082 max_fails=3 fail_timeout=10s;",
    ]
    # No explicit load-balancing algorithm directive — nginx's implicit
    # default for an upstream{} block with multiple servers is round-robin,
    # which is exactly the "simplest version" scope for this feature.
    assert "least_conn" not in "\n".join(block)
    assert "ip_hash" not in "\n".join(block)


def test_malformed_additional_origins_json_degrades_to_primary_origin_only(monkeypatch):
    """A corrupted additional_origins value must never take down this
    app's whole config generation — degrade to today's single-origin
    behavior instead of raising."""
    apps = [_make_app(1, additional_origins=None)]
    apps[0]["additional_origins"] = "{not valid json"
    config = _capture_generated_config(monkeypatch, apps)
    block = _upstream_block(config, 1)

    server_lines = [l.strip() for l in block if l.strip().startswith("server ")]
    assert server_lines == ["server 10.0.0.1:8080 max_fails=3 fail_timeout=10s;"]


def test_additional_origins_entries_missing_fields_are_skipped(monkeypatch):
    apps = [_make_app(1)]
    apps[0]["additional_origins"] = json.dumps([
        {"host": "10.0.0.2", "port": 8081},
        {"host": "10.0.0.3"},          # missing port — skipped
        {"port": 8083},                # missing host — skipped
        "not-a-dict",                  # wrong type — skipped
    ])
    config = _capture_generated_config(monkeypatch, apps)
    block = _upstream_block(config, 1)

    server_lines = [l.strip() for l in block if l.strip().startswith("server ")]
    assert server_lines == [
        "server 10.0.0.1:8080 max_fails=3 fail_timeout=10s;",
        "server 10.0.0.2:8081 max_fails=3 fail_timeout=10s;",
    ]


def test_multiple_apps_origins_do_not_leak_across_upstream_blocks(monkeypatch):
    apps = [
        _make_app(1, additional_origins=[{"host": "10.0.0.2", "port": 8081}]),
        _make_app(2, additional_origins=[{"host": "10.0.0.9", "port": 9091}]),
    ]
    config = _capture_generated_config(monkeypatch, apps)

    block1 = "\n".join(_upstream_block(config, 1))
    block2 = "\n".join(_upstream_block(config, 2))
    assert "10.0.0.9" not in block1
    assert "10.0.0.2" not in block2


def test_empty_additional_origins_list_same_as_none(monkeypatch):
    apps = [_make_app(1)]
    apps[0]["additional_origins"] = json.dumps([])
    config = _capture_generated_config(monkeypatch, apps)
    block = _upstream_block(config, 1)

    server_lines = [l.strip() for l in block if l.strip().startswith("server ")]
    assert server_lines == ["server 10.0.0.1:8080 max_fails=3 fail_timeout=10s;"]


# ---------------------------------------------------------------------------
# Route-level: persistence through create/update/toggle
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_db_service(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test_multi_server_lb.db")
    monkeypatch.setattr(db_service, "DB_FILE", db_path)
    db_service.init_db()
    monkeypatch.setattr(nginx_manager, "sync_protected_apps_to_nginx", lambda: (True, ""))
    return db_service


@pytest.fixture
def isolated_client(isolated_user_service, isolated_db_service):
    return TestClient(fastapi_app)


def _login(client, username, password):
    r = client.post("/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    csrf = r.cookies.get("XSRF-TOKEN-V3")
    client.cookies.update(r.cookies)
    return csrf


def _app_payload(**overrides):
    payload = {
        "name": "Test App", "domain": "test-app.example.com",
        "upstream_host": "10.0.0.1", "upstream_port": 8080, "protocol": "http",
        "is_active": 1, "rate_limit_rps": 50, "burst_tolerance": 100,
        "ssl_option": "self-signed", "require_auth": 0,
        "auth_check_type": "header", "auth_header_name": "Authorization",
        "additional_origins": [],
    }
    payload.update(overrides)
    return payload


def test_create_app_with_additional_origins_persists_and_returns_them(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    payload = _app_payload(additional_origins=[
        {"host": "10.0.0.2", "port": 8081}, {"host": "10.0.0.3", "port": 8082},
    ])
    r = client.post("/apps", headers={"X-XSRF-TOKEN": csrf}, json=payload)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["additional_origins"] == [
        {"host": "10.0.0.2", "port": 8081}, {"host": "10.0.0.3", "port": 8082},
    ]

    r = client.get(f"/apps/{body['id']}")
    assert r.json()["additional_origins"] == [
        {"host": "10.0.0.2", "port": 8081}, {"host": "10.0.0.3", "port": 8082},
    ]


def test_create_app_without_additional_origins_defaults_to_empty_list(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    r = client.post("/apps", headers={"X-XSRF-TOKEN": csrf}, json=_app_payload())
    assert r.status_code == 201, r.text
    assert r.json()["additional_origins"] == []


def test_invalid_origin_port_rejected(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    payload = _app_payload(additional_origins=[{"host": "10.0.0.2", "port": 99999}])
    r = client.post("/apps", headers={"X-XSRF-TOKEN": csrf}, json=payload)
    assert r.status_code == 422


def test_invalid_origin_host_rejected(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    payload = _app_payload(additional_origins=[{"host": "10.0.0.2; rm -rf", "port": 8081}])
    r = client.post("/apps", headers={"X-XSRF-TOKEN": csrf}, json=payload)
    assert r.status_code == 422


def test_update_app_changes_additional_origins(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    created = client.post("/apps", headers={"X-XSRF-TOKEN": csrf}, json=_app_payload(
        additional_origins=[{"host": "10.0.0.2", "port": 8081}]
    )).json()

    updated_payload = _app_payload(additional_origins=[{"host": "10.0.0.9", "port": 9999}])
    r = client.put(f"/apps/{created['id']}", headers={"X-XSRF-TOKEN": csrf}, json=updated_payload)
    assert r.status_code == 200, r.text
    assert r.json()["additional_origins"] == [{"host": "10.0.0.9", "port": 9999}]


def test_update_app_can_clear_additional_origins(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    created = client.post("/apps", headers={"X-XSRF-TOKEN": csrf}, json=_app_payload(
        additional_origins=[{"host": "10.0.0.2", "port": 8081}]
    )).json()

    r = client.put(f"/apps/{created['id']}", headers={"X-XSRF-TOKEN": csrf}, json=_app_payload(additional_origins=[]))
    assert r.status_code == 200, r.text
    assert r.json()["additional_origins"] == []


def test_toggle_preserves_additional_origins(isolated_client, make_user):
    """The regression this feature was most at risk of: toggle/other
    partial-update endpoints reconstruct their update_protected_app call
    from the existing row and must explicitly pass additional_origins
    through unchanged, or a totally unrelated action (enable/disable)
    would silently wipe out a configured load-balancing setup."""
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    created = client.post("/apps", headers={"X-XSRF-TOKEN": csrf}, json=_app_payload(
        additional_origins=[{"host": "10.0.0.2", "port": 8081}]
    )).json()

    r = client.post(f"/apps/{created['id']}/toggle", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code == 200, r.text
    assert r.json()["additional_origins"] == [{"host": "10.0.0.2", "port": 8081}]
    assert r.json()["is_active"] == 0

    # Toggle back — still preserved.
    r = client.post(f"/apps/{created['id']}/toggle", headers={"X-XSRF-TOKEN": csrf})
    assert r.json()["additional_origins"] == [{"host": "10.0.0.2", "port": 8081}]
    assert r.json()["is_active"] == 1


def test_analyst_can_view_but_not_create_with_additional_origins(isolated_client, make_user):
    client = isolated_client
    analyst = make_user(role="analyst")
    csrf = _login(client, analyst["username"], analyst["password"])

    r = client.post("/apps", headers={"X-XSRF-TOKEN": csrf}, json=_app_payload())
    assert r.status_code == 403
