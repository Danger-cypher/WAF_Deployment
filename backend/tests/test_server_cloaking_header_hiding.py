"""
Regression guard for sync_protected_apps_to_nginx()'s proxy_hide_header
generation — Server Cloaking (Settings > Hardening) previously only set
`server_tokens off`, which strips nginx's OWN version string but does
nothing about headers the PROTECTED APP'S OWN BACKEND sets, since
proxy_pass forwards arbitrary upstream response headers verbatim by
default. Confirmed live against a real deployed app: X-Powered-By: Express
reached the client unchanged even with cloaking on — this closes that gap.

Same isolation pattern as test_mssp_default_server.py: monkeypatch the two
IO dependencies (get_all_protected_apps, write_and_apply_configs) and
inspect the generated config text directly, plus settings_manager.
get_hardening() to control server_cloaking per test.
"""
import app.services.db_service as db_service
from app.services import nginx_manager
from app.services.settings_manager import settings_manager


def _make_app(app_id, domain="app.example.com", is_active=1):
    return {
        "id": app_id,
        "name": f"App {app_id}",
        "domain": domain,
        "upstream_host": "10.0.0.1",
        "upstream_port": 8080,
        "protocol": "http",
        "is_active": is_active,
        "rate_limit_rps": 50,
        "burst_tolerance": 100,
        "ssl_option": "self-signed",
        "ssl_cert_path": None,
        "ssl_key_path": None,
        "require_auth": 0,
        "auth_check_type": "header",
        "auth_header_name": "Authorization",
    }


def _capture_generated_config(monkeypatch, apps, server_cloaking):
    monkeypatch.setattr(db_service, "get_all_protected_apps", lambda: apps)
    monkeypatch.setattr(settings_manager, "get_hardening", lambda: {"server_cloaking": server_cloaking})

    captured = {}

    def fake_write_and_apply(file_contents):
        captured.update(file_contents)
        return True, ""

    monkeypatch.setattr(nginx_manager, "write_and_apply_configs", fake_write_and_apply)

    ok, msg = nginx_manager.sync_protected_apps_to_nginx()
    assert ok, msg
    return captured["/etc/nginx/sites-enabled/mssp"]


def test_server_cloaking_enabled_hides_backend_identifying_headers(monkeypatch):
    config = _capture_generated_config(monkeypatch, [_make_app(1)], server_cloaking=True)
    assert "proxy_hide_header X-Powered-By;" in config
    assert "proxy_hide_header X-AspNet-Version;" in config
    assert "proxy_hide_header X-AspNetMvc-Version;" in config
    assert "proxy_hide_header X-Runtime;" in config
    assert "proxy_hide_header X-Generator;" in config


def test_server_cloaking_disabled_generates_no_hide_header_directives(monkeypatch):
    """An admin who explicitly disables cloaking gets exactly the old
    behavior back — no proxy_hide_header at all, not even a partial set."""
    config = _capture_generated_config(monkeypatch, [_make_app(1)], server_cloaking=False)
    assert "proxy_hide_header" not in config


def test_hide_header_directives_scoped_to_the_proxy_location_only(monkeypatch):
    """proxy_hide_header only makes sense inside the location that actually
    proxy_passes to the backend — confirms it wasn't accidentally emitted
    at server{} scope or inside an unrelated location."""
    config = _capture_generated_config(monkeypatch, [_make_app(1)], server_cloaking=True)
    lines = config.splitlines()
    in_proxy_location = False
    saw_any = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("location @proxy_app_1"):
            in_proxy_location = True
        elif in_proxy_location and stripped == "}":
            in_proxy_location = False
        elif "proxy_hide_header" in stripped:
            saw_any = True
            assert in_proxy_location, f"proxy_hide_header found outside the proxy location: {line}"
    assert saw_any
