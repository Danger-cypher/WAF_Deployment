"""
Covers the new "JS Challenge" bot-mitigation mode: apply_ddos_settings()
must skip applying the existing waf_bot_req rate-limit (1r/m, burst=1 —
which would otherwise reject the JS-challenge page's own self-triggered
reload before ml-waf/bot_challenge.lua ever sees it) and instead expose a
config-time boolean ($waf_bot_challenge_enabled) that Lua reads to decide
whether to serve the interstitial.
"""
from app.services import nginx_manager

BASE_SETTINGS = {
    "rate_limit_rps": 50,
    "burst_tolerance": 100,
    "trusted_ips": [],
    "advanced_rules": [],
}


def _capture_generated_ddos_config(monkeypatch, settings):
    captured = {}

    def fake_write_and_apply(file_contents):
        captured.update(file_contents)
        return True, ""

    monkeypatch.setattr(nginx_manager, "write_and_apply_configs", fake_write_and_apply)

    ok, msg = nginx_manager.apply_ddos_settings(settings)
    assert ok, msg
    return captured[nginx_manager.DDOS_CONF_PATH]


def test_js_challenge_mode_skips_bot_rate_limit_and_sets_flag(monkeypatch):
    settings = {**BASE_SETTINGS, "bot_mitigation_action": "JS Challenge"}
    config = _capture_generated_ddos_config(monkeypatch, settings)

    assert "limit_req zone=waf_bot_req burst=1 nodelay;" not in config
    assert "map $host $waf_bot_challenge_enabled {" in config
    assert "    default 1;" in config


def test_silent_drop_mode_still_applies_bot_rate_limit_and_clears_flag(monkeypatch):
    settings = {**BASE_SETTINGS, "bot_mitigation_action": "Silent Drop"}
    config = _capture_generated_ddos_config(monkeypatch, settings)

    assert "limit_req zone=waf_bot_req burst=1 nodelay;" in config
    assert "map $host $waf_bot_challenge_enabled {" in config
    assert "    default 0;" in config


def test_block_mode_still_applies_bot_rate_limit_and_clears_flag(monkeypatch):
    settings = {**BASE_SETTINGS, "bot_mitigation_action": "Block"}
    config = _capture_generated_ddos_config(monkeypatch, settings)

    assert "limit_req zone=waf_bot_req burst=1 nodelay;" in config
    assert "    default 0;" in config
