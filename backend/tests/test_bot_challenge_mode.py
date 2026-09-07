"""
Covers the new "JS Challenge" bot-mitigation mode: apply_ddos_settings()
must skip applying the bad-bot rate limit (1r/m equivalent — which would
otherwise reject the JS-challenge page's own self-triggered reload before
ml-waf/bot_challenge.lua ever sees it) and instead expose a config-time
boolean ($waf_bot_challenge_enabled) that Lua reads to decide whether to
serve the interstitial.

The bad-bot rate limit itself moved from a native nginx limit_req_zone to
ml_check.lua's check_bad_bot_rate_limit() as part of the P2-07 fix (see
test_p2_07_bot_status.py) — $waf_bot_mitigation_status (444/429/0) is now
how Python tells that Lua check what to do, replacing the
"limit_req zone=waf_bot_req" lines this file used to assert on directly.
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

    assert "waf_bot_req" not in config
    assert "map $host $waf_bot_mitigation_status {\n    default 0;\n}" in config
    assert "map $host $waf_bot_challenge_enabled {" in config
    assert "    default 1;" in config


def test_silent_drop_mode_still_applies_bot_rate_limit_and_clears_flag(monkeypatch):
    settings = {**BASE_SETTINGS, "bot_mitigation_action": "Silent Drop"}
    config = _capture_generated_ddos_config(monkeypatch, settings)

    assert "map $host $waf_bot_mitigation_status {\n    default 444;\n}" in config
    assert "map $host $waf_bot_challenge_enabled {" in config
    assert "    default 0;" in config


def test_block_mode_still_applies_bot_rate_limit_and_clears_flag(monkeypatch):
    settings = {**BASE_SETTINGS, "bot_mitigation_action": "Block"}
    config = _capture_generated_ddos_config(monkeypatch, settings)

    assert "map $host $waf_bot_mitigation_status {\n    default 429;\n}" in config
    assert "    default 0;" in config


# ---------------------------------------------------------------------------
# Risk-triggered challenge ($waf_risk_challenge_enabled) — independent
# toggle from bot_mitigation_action's JS Challenge mode above; off by
# default, no interaction with waf_bot_req either way.
# ---------------------------------------------------------------------------

def test_risk_challenge_enabled_sets_flag(monkeypatch):
    settings = {**BASE_SETTINGS, "bot_mitigation_action": "Silent Drop", "risk_challenge_enabled": True}
    config = _capture_generated_ddos_config(monkeypatch, settings)

    assert "map $host $waf_risk_challenge_enabled {" in config
    risk_map_start = config.index("map $host $waf_risk_challenge_enabled {")
    risk_map_section = config[risk_map_start:risk_map_start + 80]
    assert "default 1;" in risk_map_section


def test_risk_challenge_disabled_by_default(monkeypatch):
    settings = {**BASE_SETTINGS, "bot_mitigation_action": "Silent Drop"}
    config = _capture_generated_ddos_config(monkeypatch, settings)

    risk_map_start = config.index("map $host $waf_risk_challenge_enabled {")
    risk_map_section = config[risk_map_start:risk_map_start + 80]
    assert "default 0;" in risk_map_section


def test_risk_challenge_independent_of_bot_challenge_mode(monkeypatch):
    # JS Challenge mode (bad-bot UA) on, risk challenge off — both flags
    # must reflect their own independent settings, not each other's.
    settings = {**BASE_SETTINGS, "bot_mitigation_action": "JS Challenge", "risk_challenge_enabled": False}
    config = _capture_generated_ddos_config(monkeypatch, settings)

    bot_map_start = config.index("map $host $waf_bot_challenge_enabled {")
    assert "default 1;" in config[bot_map_start:bot_map_start + 60]

    risk_map_start = config.index("map $host $waf_risk_challenge_enabled {")
    assert "default 0;" in config[risk_map_start:risk_map_start + 80]


# ---------------------------------------------------------------------------
# Adaptive per-identity throttle ($waf_adaptive_throttle_enabled) — a third
# independent toggle (P1-3); layered on top of the native limit_req zones
# below it in the generated config, never replacing them.
# ---------------------------------------------------------------------------

def test_adaptive_throttle_enabled_sets_flag(monkeypatch):
    settings = {**BASE_SETTINGS, "bot_mitigation_action": "Silent Drop", "adaptive_throttle_enabled": True}
    config = _capture_generated_ddos_config(monkeypatch, settings)

    assert "map $host $waf_adaptive_throttle_enabled {" in config
    map_start = config.index("map $host $waf_adaptive_throttle_enabled {")
    assert "default 1;" in config[map_start:map_start + 80]


def test_adaptive_throttle_disabled_by_default(monkeypatch):
    settings = {**BASE_SETTINGS, "bot_mitigation_action": "Silent Drop"}
    config = _capture_generated_ddos_config(monkeypatch, settings)

    map_start = config.index("map $host $waf_adaptive_throttle_enabled {")
    assert "default 0;" in config[map_start:map_start + 80]


def test_adaptive_throttle_independent_of_other_two_toggles(monkeypatch):
    settings = {
        **BASE_SETTINGS, "bot_mitigation_action": "JS Challenge",
        "risk_challenge_enabled": True, "adaptive_throttle_enabled": False,
    }
    config = _capture_generated_ddos_config(monkeypatch, settings)

    bot_start = config.index("map $host $waf_bot_challenge_enabled {")
    assert "default 1;" in config[bot_start:bot_start + 60]

    risk_start = config.index("map $host $waf_risk_challenge_enabled {")
    assert "default 1;" in config[risk_start:risk_start + 80]

    throttle_start = config.index("map $host $waf_adaptive_throttle_enabled {")
    assert "default 0;" in config[throttle_start:throttle_start + 80]
