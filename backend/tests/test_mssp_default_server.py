"""
Regression guard for the MSSP default-server fix: sync_protected_apps_to_nginx()
used to silently make the first active app the default_server for any
unrecognized Host header on 80/443 whenever no app had explicitly opted in
with domain == "_" — so a request for a completely unrelated hostname could
reach a real customer's backend. Now only an explicit domain == "_" app may
become the catch-all; otherwise a dedicated fallback server block rejects
the connection (return 444) instead.

Isolates sync_protected_apps_to_nginx() from the real filesystem/nginx by
monkeypatching its two IO dependencies (get_all_protected_apps, which it
imports internally, and write_and_apply_configs, which normally writes to
disk and shells out to reload nginx) and inspecting the generated config
text directly.
"""
import app.services.db_service as db_service
from app.services import nginx_manager


def _make_app(app_id, domain, is_active=1):
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


def test_no_wildcard_app_gets_generic_reject_not_first_app_as_default(monkeypatch):
    """Two real apps, neither opted into domain == '_' — previously app #1
    would have silently become default_server. Now neither app's 443 block
    should carry default_server, and the generic-reject fallback must be
    present instead."""
    apps = [_make_app(1, "app-one.example.com"), _make_app(2, "app-two.example.com")]
    config = _capture_generated_config(monkeypatch, apps)

    # Neither real app's server block is the 443 default_server.
    assert "server_name app-one.example.com;" in config
    assert "server_name app-two.example.com;" in config
    # The generic-reject fallback is present and IS the 443 default_server.
    assert "Fallback catch-all: no app is configured as the explicit wildcard" in config
    assert "return 444;" in config

    # None of the real apps' listen lines carry default_server — only the
    # fallback block's do. Count total occurrences of "default_server" on
    # port 443 and confirm they all belong to the fallback block, not an app.
    lines = config.splitlines()
    for i, line in enumerate(lines):
        if "listen 443 ssl default_server;" in line:
            # Walk back to the nearest preceding "server_name" line for
            # this block to confirm it's the wildcard fallback, not a real app.
            for back in lines[i:i + 6]:
                if back.strip().startswith("server_name"):
                    assert back.strip() == "server_name _;", (
                        f"a real app's block unexpectedly carries default_server: {back}"
                    )
                    break


def test_explicit_wildcard_app_still_becomes_deliberate_default(monkeypatch):
    """One app explicitly configured with domain == '_' — it SHOULD become
    the default_server (a deliberate admin choice), and the generic-reject
    fallback must NOT be generated (would conflict: nginx only allows one
    default_server per listen address/port)."""
    apps = [_make_app(1, "app-one.example.com"), _make_app(2, "_")]
    config = _capture_generated_config(monkeypatch, apps)

    assert "Fallback catch-all: no app is configured as the explicit wildcard" not in config

    lines = config.splitlines()
    found_default = False
    for i, line in enumerate(lines):
        if "listen 443 ssl default_server;" in line:
            found_default = True
            for back in lines[i:i + 6]:
                if back.strip().startswith("server_name"):
                    assert back.strip() == "server_name _;"
                    break
    assert found_default, "the explicit wildcard app should still be the default_server"
