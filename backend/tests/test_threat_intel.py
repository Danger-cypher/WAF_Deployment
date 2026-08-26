"""
Covers threat_intel_service.py (Spamhaus DROP/EDROP -> Redis sync) and its
Settings routes. No real network access or Redis — requests.get and
nginx_manager.get_redis_client are both faked.
"""
import pytest
from fastapi.testclient import TestClient

from app.services import threat_intel_service, settings_manager, nginx_manager
from app.main import app as fastapi_app


DROP_SAMPLE = """; Spamhaus DROP List
; Last updated 2026-08-25
; For more info see https://www.spamhaus.org/drop/
1.2.3.0/24 ; SBL12345
5.6.7.0/28 ; SBL54321

; blank/comment lines above must be skipped
"""


def test_parse_drop_list_extracts_cidrs_only():
    cidrs = threat_intel_service._parse_drop_list(DROP_SAMPLE)
    assert cidrs == {"1.2.3.0/24", "5.6.7.0/28"}


def test_parse_drop_list_handles_empty_input():
    assert threat_intel_service._parse_drop_list("") == set()
    assert threat_intel_service._parse_drop_list(";just a comment\n\n") == set()


class _FakeRedis:
    def __init__(self):
        self.sets = {}

    def delete(self, *keys):
        for k in keys:
            self.sets.pop(k, None)

    def sadd(self, key, value):
        self.sets.setdefault(key, set()).add(value)


class _FakeResponse:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")


@pytest.fixture
def isolated_settings(tmp_path, monkeypatch):
    monkeypatch.setattr(settings_manager, "SETTINGS_FILE", str(tmp_path / "settings.json"))
    # `settings` is a lazily-cached @property (self._settings) on the
    # process-wide singleton — repointing SETTINGS_FILE alone wouldn't take
    # effect until the cache is cleared, since a prior test/import may have
    # already populated it from the real path. monkeypatch (not a plain
    # assignment) so this reverts after the test instead of leaking the tmp
    # settings dict into whichever test runs next in the same process.
    monkeypatch.setattr(settings_manager.settings_manager, "_settings", None)
    return settings_manager.settings_manager


def test_sync_skipped_when_disabled(isolated_settings, monkeypatch):
    monkeypatch.setattr(threat_intel_service.requests, "get", lambda *a, **k: pytest.fail("should not fetch when disabled"))
    result = threat_intel_service.run_threat_intel_sync(force=False)
    assert result["status"] == "skipped"


def test_forced_sync_ignores_disabled_flag_and_populates_redis(isolated_settings, monkeypatch):
    fake_redis = _FakeRedis()
    monkeypatch.setattr(nginx_manager, "get_redis_client", lambda: fake_redis)
    monkeypatch.setattr(threat_intel_service.requests, "get", lambda *a, **k: _FakeResponse(DROP_SAMPLE))

    result = threat_intel_service.run_threat_intel_sync(force=True)

    assert result["status"] == "success"
    assert result["count"] == 2
    assert fake_redis.sets["waf:blacklist:feed:cidrs"] == {"1.2.3.0/24", "5.6.7.0/28"}

    status = isolated_settings.get_threat_intel()
    assert status["last_sync_status"] == "success"
    assert status["last_sync_count"] == 2
    assert status["last_sync_at"] is not None


def test_sync_all_feeds_failing_reports_error_without_clearing_redis(isolated_settings, monkeypatch):
    def _raise(*a, **k):
        raise Exception("connection refused")
    monkeypatch.setattr(threat_intel_service.requests, "get", _raise)

    result = threat_intel_service.run_threat_intel_sync(force=True)

    assert result["status"] == "error"
    status = isolated_settings.get_threat_intel()
    assert status["last_sync_status"] == "error"
    assert "connection refused" in status["last_sync_error"]


# --- Route-level wiring ---

@pytest.fixture
def isolated_client(tmp_path, monkeypatch, isolated_user_service, isolated_settings):
    return TestClient(fastapi_app)


def _login(client, username, password):
    r = client.post("/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    csrf = r.cookies.get("XSRF-TOKEN-V3")
    client.cookies.update(r.cookies)
    return csrf


def test_analyst_forbidden_from_threat_intel_settings(isolated_client, make_user):
    client = isolated_client
    analyst = make_user(role="analyst")
    csrf = _login(client, analyst["username"], analyst["password"])

    r = client.get("/settings/threat-intel")
    assert r.status_code == 403


def test_admin_can_enable_and_it_persists(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    r = client.post(
        "/settings/threat-intel",
        headers={"X-XSRF-TOKEN": csrf},
        json={"enabled": True, "sync_interval_hours": 12},
    )
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is True
    assert r.json()["sync_interval_hours"] == 12

    r = client.get("/settings/threat-intel")
    assert r.json()["enabled"] is True


def test_update_rejects_sub_hourly_interval(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    r = client.post(
        "/settings/threat-intel",
        headers={"X-XSRF-TOKEN": csrf},
        json={"enabled": True, "sync_interval_hours": 0},
    )
    assert r.status_code == 400


def test_sync_now_works_while_disabled(isolated_client, make_user, monkeypatch):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    fake_redis = _FakeRedis()
    monkeypatch.setattr(nginx_manager, "get_redis_client", lambda: fake_redis)
    monkeypatch.setattr(threat_intel_service.requests, "get", lambda *a, **k: _FakeResponse(DROP_SAMPLE))

    r = client.post("/settings/threat-intel/sync-now", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "success"
    assert r.json()["count"] == 2
