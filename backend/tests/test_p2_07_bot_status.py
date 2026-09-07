"""
Regression tests for audit finding P2-07: rate-limit rejections returned
444 (nginx's silent connection-close code) instead of a standard 429 with
Retry-After.

Root cause was broader than the audit description: nginx's
limit_req_status/limit_conn_status directives are single, shared-per-scope
values, not per-zone. apply_ddos_settings() derived ONE status_code purely
from bot_mitigation_action ("Silent Drop" -> 444, else 429) and applied it
globally to waf_ddos.conf. Since login_limit, api_limit, ws_conn_limit
(console) and every generated app's zone_app_<id> all declare their own
limit_req zone but never their own limit_req_status, they all inherited
whatever the *bot* dropdown said — an admin picking "Silent Drop" to keep
scrapers quiet silently turned every legitimate rate-limit rejection in the
entire product into a bare connection close with no Retry-After, for
traffic that has nothing to do with bots.

Fix: general zones (waf_ddos_req/waf_ddos_conn, and everything that
inherits from them) are hardcoded to 429 (GENERAL_RATE_LIMIT_STATUS),
unconditionally. Bad-bot-UA traffic no longer uses a native limit_req zone
at all — that's what forced it to share a scope/status with the general
zones in the first place. It's enforced in ml_check.lua's
check_bad_bot_rate_limit() instead (see test_bad_bot_rate_limit.py for the
Lua-side tests), which reads $waf_bot_mitigation_status (444/429/0) to
decide its own exit status independent of every other zone.
"""
import pytest

from app.services import nginx_manager


BASE_SETTINGS = {
    "rate_limit_rps": 50,
    "burst_tolerance": 100,
    "trusted_ips": [],
    "bot_mitigation_action": "Silent Drop",
    "advanced_rules": [],
}


def _generate(monkeypatch, settings=None):
    captured = {}

    def fake_write_and_apply(file_contents):
        captured.update(file_contents)
        return True, ""

    monkeypatch.setattr(nginx_manager, "write_and_apply_configs", fake_write_and_apply)
    ok, msg = nginx_manager.apply_ddos_settings(settings or dict(BASE_SETTINGS))
    assert ok, msg
    return captured


@pytest.mark.parametrize("bot_action", ["Silent Drop", "Block", "JS Challenge"])
def test_general_zones_always_return_429_regardless_of_bot_action(monkeypatch, bot_action):
    settings = dict(BASE_SETTINGS)
    settings["bot_mitigation_action"] = bot_action
    conf = _generate(monkeypatch, settings)[nginx_manager.DDOS_CONF_PATH]
    assert "limit_req_status 429;" in conf
    assert "limit_conn_status 429;" in conf
    # The literal bug, verbatim: this must never appear as the *general*
    # zones' status, no matter what the bot dropdown is set to.
    assert "limit_req_status 444;" not in conf
    assert "limit_conn_status 444;" not in conf


def test_no_native_bot_zone_survives_in_generated_config(monkeypatch):
    # The bad-bot limit_req_zone (and the map that used to key it) is gone
    # entirely — enforcement moved to Lua specifically so it could stop
    # sharing a status with the zones tested above.
    conf = _generate(monkeypatch)[nginx_manager.DDOS_CONF_PATH]
    assert "waf_bot_req" not in conf
    assert "bot_limit_key" not in conf


@pytest.mark.parametrize(
    "bot_action,expected_status",
    [("Silent Drop", 444), ("Block", 429), ("JS Challenge", 0)],
)
def test_bot_mitigation_status_map_reflects_the_dropdown(monkeypatch, bot_action, expected_status):
    settings = dict(BASE_SETTINGS)
    settings["bot_mitigation_action"] = bot_action
    conf = _generate(monkeypatch, settings)[nginx_manager.DDOS_CONF_PATH]
    assert (
        f"map $host $waf_bot_mitigation_status {{\n    default {expected_status};\n}}"
        in conf
    )


def test_bot_mitigation_status_survives_alongside_general_429(monkeypatch):
    # The core of the fix: Silent Drop mode must produce BOTH a 444 for the
    # bot-specific map AND a 429 for the general zones in the same file —
    # proving the two no longer share one status.
    conf = _generate(monkeypatch)[nginx_manager.DDOS_CONF_PATH]
    assert "limit_req_status 429;" in conf
    assert "map $host $waf_bot_mitigation_status {\n    default 444;\n}" in conf
