"""
Covers two additions made for per-app login/brute-force protection
(ProtectedApps.jsx's "Protect Login" feature):

1. A new "Host+URI" advanced-rule parameter type. Plain "URI" rules match
   $request_uri alone, which is shared across every vhost this gateway
   proxies — a rule for "/login" would rate-limit that path on every
   protected app, not just the one it was meant for. Host+URI scopes the
   match to $host$request_uri instead, so a rule only fires for one
   specific app's domain.
2. An optional rate_limit_unit ("r/s" default, or "r/m") — plain integer
   r/s is too coarse for real brute-force protection (1r/s is already
   60 attempts/minute).

Isolates apply_ddos_settings() from the real filesystem/nginx the same way
test_mssp_default_server.py does for sync_protected_apps_to_nginx().
"""
from app.services import nginx_manager


def _capture_generated_ddos_config(monkeypatch, settings):
    captured = {}

    def fake_write_and_apply(file_contents):
        captured.update(file_contents)
        return True, ""

    monkeypatch.setattr(nginx_manager, "write_and_apply_configs", fake_write_and_apply)

    ok, msg = nginx_manager.apply_ddos_settings(settings)
    assert ok, msg
    return captured[nginx_manager.DDOS_CONF_PATH]


def test_host_uri_rule_scopes_to_host_and_uri(monkeypatch):
    settings = {
        "rate_limit_rps": 50,
        "burst_tolerance": 100,
        "trusted_ips": [],
        "bot_mitigation_action": "Silent Drop",
        "advanced_rules": [
            {
                "id": "rule_login_1",
                "name": "Login Protection — App One",
                "parameter_type": "Host+URI",
                "parameter_value": "app-one.example.com/login",
                "rate_limit_rps": 5,
                "rate_limit_unit": "r/m",
                "burst_tolerance": 2,
                "enabled": True,
            },
        ],
    }
    config = _capture_generated_ddos_config(monkeypatch, settings)

    # Matches on $host$request_uri, not $request_uri alone — so an identical
    # "/login" path on a different app's domain never matches this map.
    assert "map $host$request_uri $limit_key_rule_login_1" in config
    # Anchored exact match, same treatment as Country/IP rules.
    assert '"~*^app-one.example.com/login$"' in config
    # Per-minute rate, not the default per-second.
    assert "rate=5r/m;" in config


def test_uri_only_rule_still_matches_request_uri_alone(monkeypatch):
    """Existing behavior for plain "URI" rules (e.g. API Protection Phase 1's
    per-endpoint rules) must be completely unchanged by this addition."""
    settings = {
        "rate_limit_rps": 50,
        "burst_tolerance": 100,
        "trusted_ips": [],
        "bot_mitigation_action": "Silent Drop",
        "advanced_rules": [
            {
                "id": "rule_api_1",
                "name": "Protect GET /api/data",
                "parameter_type": "URI",
                "parameter_value": "^/api/data$",
                "rate_limit_rps": 10,
                "burst_tolerance": 20,
                "enabled": True,
            },
        ],
    }
    config = _capture_generated_ddos_config(monkeypatch, settings)

    assert "map $request_uri $limit_key_rule_api_1" in config
    assert "$host$request_uri" not in config
    # No rate_limit_unit given — defaults to the original r/s behavior.
    assert "rate=10r/s;" in config


def test_invalid_rate_unit_falls_back_to_rps(monkeypatch):
    """A malformed/unexpected unit value must not corrupt the generated
    nginx directive — falls back to the safe original default."""
    settings = {
        "rate_limit_rps": 50,
        "burst_tolerance": 100,
        "trusted_ips": [],
        "bot_mitigation_action": "Silent Drop",
        "advanced_rules": [
            {
                "id": "rule_bad_unit",
                "name": "Bad unit",
                "parameter_type": "URI",
                "parameter_value": "^/x$",
                "rate_limit_rps": 7,
                "rate_limit_unit": "r/h",
                "burst_tolerance": 5,
                "enabled": True,
            },
        ],
    }
    config = _capture_generated_ddos_config(monkeypatch, settings)
    assert "rate=7r/s;" in config
