"""
Readiness-review finding: the dashboard's "SecRuleEngine Posture" toggle
(Settings -> WAF Engine Policies) saved to settings.json but was never
applied to ModSecurity's real SecRuleEngine directive, which stayed
hardcoded `On` in modsecurity.conf regardless of what the UI showed.
Fixed in two places: _update_modsecurity_override_file() now writes a
SecRuleEngine line reflecting the saved value, and
SettingsManager.update_waf_settings() triggers a regen+reload when that
value changes (mirroring what already happened for paranoiaLevel).

Also covers a second bug found while fixing the first: the pre-existing
anomaly-threshold-reading code used settings_manager.get(...), a method
that doesn't exist on SettingsManager — every call raised AttributeError,
silently swallowed by its own except-Exception, so those two thresholds
always used their hardcoded fallback regardless of saved settings. Not
reachable from the UI (no route exposes those two fields), so no
behavioral test for it here beyond confirming the accessor itself works.
"""
import pytest

from app.services import rule_manager
from app.services.settings_manager import settings_manager, DEFAULT_SETTINGS


@pytest.fixture
def isolated_override_write(monkeypatch):
    """Captures what would be written/reloaded instead of touching the
    real /etc/nginx/modsec/rules-override.conf or actually reloading nginx."""
    written = {}

    def fake_atomic_write(path, content):
        written["path"] = path
        written["content"] = content

    monkeypatch.setattr(rule_manager, "_atomic_write", fake_atomic_write)
    monkeypatch.setattr(rule_manager, "_ensure_include", lambda *a, **k: None)
    monkeypatch.setattr(
        rule_manager,
        "_update_modsecurity_exclusions_before_crs_file",
        lambda: (True, "ok"),
    )
    monkeypatch.setattr(rule_manager, "_run_nginx_reload", lambda: (True, "ok"))
    return written


@pytest.fixture
def isolated_waf_settings(monkeypatch):
    """SettingsManager.settings is a real dict on the module singleton —
    reset it around each test rather than touching the real settings.json."""
    original = dict(settings_manager.settings.get("waf", DEFAULT_SETTINGS["waf"]))
    settings_manager.settings["waf"] = dict(DEFAULT_SETTINGS["waf"])
    monkeypatch.setattr(settings_manager, "save_settings", lambda data: None)
    yield settings_manager
    settings_manager.settings["waf"] = original


def test_override_file_reflects_the_saved_sec_rule_engine_value(isolated_override_write, isolated_waf_settings):
    isolated_waf_settings.settings["waf"]["secRuleEngine"] = "DetectionOnly"
    ok, _msg = rule_manager._update_modsecurity_override_file([], 1)
    assert ok
    assert "SecRuleEngine DetectionOnly" in isolated_override_write["content"]


def test_override_file_defaults_to_on_when_unset(isolated_override_write, isolated_waf_settings):
    isolated_waf_settings.settings["waf"].pop("secRuleEngine", None)
    ok, _msg = rule_manager._update_modsecurity_override_file([], 1)
    assert ok
    assert "SecRuleEngine On" in isolated_override_write["content"]


def test_override_file_rejects_an_invalid_value_rather_than_disabling_the_engine(isolated_override_write, isolated_waf_settings):
    isolated_waf_settings.settings["waf"]["secRuleEngine"] = "definitely-not-a-real-value"
    ok, _msg = rule_manager._update_modsecurity_override_file([], 1)
    assert ok
    assert "SecRuleEngine On" in isolated_override_write["content"]
    assert "SecRuleEngine definitely-not-a-real-value" not in isolated_override_write["content"]


def test_saving_waf_settings_with_a_new_sec_rule_engine_regenerates_and_reloads(monkeypatch, tmp_path, isolated_override_write, isolated_waf_settings):
    # update_waf_settings() unconditionally calls set_paranoia_level(), which
    # reads its OWN persisted state (rule_manager.STATE_FILE), independent of
    # the settings_manager dict this test otherwise controls — isolate it too
    # so this test doesn't read/write the real on-disk rule state, and reuse
    # isolated_override_write so set_paranoia_level's own writes (if its
    # early-exit doesn't fire) don't touch the real filesystem/nginx either.
    monkeypatch.setattr(rule_manager, "STATE_FILE", str(tmp_path / "rule_state.json"))
    calls = []
    posture_calls = []
    monkeypatch.setattr(
        rule_manager, "sync_rules_and_exclusions", lambda: (calls.append(1), (True, "ok"))[1]
    )
    from app.services import nginx_manager
    monkeypatch.setattr(
        nginx_manager, "apply_waf_engine_posture",
        lambda v: (posture_calls.append(v), (True, "ok"))[1]
    )
    isolated_waf_settings.settings["waf"] = {"secRuleEngine": "On", "detectionMode": "Blocking", "paranoiaLevel": 1}

    isolated_waf_settings.update_waf_settings(
        {"secRuleEngine": "DetectionOnly", "detectionMode": "Blocking", "paranoiaLevel": 1}
    )

    assert len(calls) == 1
    # Both the ModSecurity-level directive (calls) AND the Lua-visible
    # posture (posture_calls) must update — see the readiness-review
    # finding this guards against: fixing only the former looked done but
    # didn't actually stop ml_decide.lua's own independent blocking.
    assert posture_calls == ["DetectionOnly"]


def test_saving_waf_settings_with_no_sec_rule_engine_change_does_not_reload(monkeypatch, tmp_path, isolated_override_write, isolated_waf_settings):
    monkeypatch.setattr(rule_manager, "STATE_FILE", str(tmp_path / "rule_state.json"))
    # Fresh state file defaults to paranoia_level 1 (see rule_manager's own
    # _load_state default) — keep the request's paranoiaLevel matching that,
    # so set_paranoia_level's own early-exit fires and neither path reloads.
    calls = []
    posture_calls = []
    monkeypatch.setattr(
        rule_manager, "sync_rules_and_exclusions", lambda: (calls.append(1), (True, "ok"))[1]
    )
    from app.services import nginx_manager
    monkeypatch.setattr(
        nginx_manager, "apply_waf_engine_posture",
        lambda v: (posture_calls.append(v), (True, "ok"))[1]
    )
    isolated_waf_settings.settings["waf"] = {"secRuleEngine": "On", "detectionMode": "Blocking", "paranoiaLevel": 1}

    isolated_waf_settings.update_waf_settings(
        {"secRuleEngine": "On", "detectionMode": "Detection", "paranoiaLevel": 1}
    )

    assert len(calls) == 0
    assert posture_calls == []


def test_waf_settings_accessor_used_by_rule_manager_actually_exists():
    # The bug this guards against: settings_manager.get(...) doesn't exist
    # on SettingsManager and would raise AttributeError if called directly.
    assert hasattr(settings_manager, "get_waf_settings")
    assert not hasattr(settings_manager, "get")
