"""
Readiness-review finding, part 2: making ModSecurity's own SecRuleEngine
directive real (see test_sec_rule_engine_toggle.py) turned out not to be
enough — this stack's actual block/allow decision is made by
ml_decide.lua, independent of ModSecurity's own disruptive-action
mechanism. apply_waf_engine_posture() exposes the posture to Lua via the
same map-a-constant trick already used for $waf_risk_challenge_enabled
etc. Covers the generator function in isolation (no real filesystem/nginx
touched) — the Lua-side consumption (ml_decide.lua's early-return when
posture != "On") isn't something pytest can exercise directly; verified
instead via loadfile() syntax check + live regression, same as every
other Lua change in this project.
"""
import pytest

from app.services import nginx_manager


@pytest.fixture
def isolated_nginx_write(monkeypatch):
    written = {}

    def fake_atomic_write(path, content):
        written["path"] = path
        written["content"] = content

    monkeypatch.setattr(nginx_manager, "_atomic_write", fake_atomic_write)
    monkeypatch.setattr(nginx_manager, "test_nginx_config", lambda: (True, ""))
    monkeypatch.setattr(nginx_manager, "reload_nginx", lambda: True)
    return written


def test_writes_the_saved_posture_as_a_map_constant(isolated_nginx_write):
    ok, _msg = nginx_manager.apply_waf_engine_posture("DetectionOnly")
    assert ok
    assert isolated_nginx_write["path"] == nginx_manager.WAF_ENGINE_POSTURE_CONF_PATH
    assert 'default "DetectionOnly";' in isolated_nginx_write["content"]
    assert "map $host $waf_sec_rule_engine_posture" in isolated_nginx_write["content"]


def test_rejects_an_invalid_value_rather_than_disabling_enforcement(isolated_nginx_write):
    ok, _msg = nginx_manager.apply_waf_engine_posture("not-a-real-value")
    assert ok
    assert 'default "On";' in isolated_nginx_write["content"]


def test_off_is_also_a_valid_posture(isolated_nginx_write):
    ok, _msg = nginx_manager.apply_waf_engine_posture("Off")
    assert ok
    assert 'default "Off";' in isolated_nginx_write["content"]


def test_rolls_back_and_reports_failure_when_the_generated_config_is_invalid(monkeypatch):
    monkeypatch.setattr(nginx_manager, "_atomic_write", lambda path, content: None)
    monkeypatch.setattr(nginx_manager, "test_nginx_config", lambda: (False, "syntax error, boom"))
    ok, msg = nginx_manager.apply_waf_engine_posture("DetectionOnly")
    assert not ok
    assert "boom" in msg
