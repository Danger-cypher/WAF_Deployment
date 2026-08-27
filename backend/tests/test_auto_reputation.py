"""
Covers auto_reputation_service.py (self-learned IP reputation from repeat
WAF-block offenders) and its Settings routes. No real ClickHouse/Redis —
clickhouse_service.get_repeat_offender_ips and nginx_manager.get_redis_client
are both faked, same isolation pattern as test_threat_intel.py.
"""
import fnmatch

import pytest
from fastapi.testclient import TestClient

from app.services import auto_reputation_service, settings_manager, nginx_manager, clickhouse_service
from app.main import app as fastapi_app


class _FakeRedis:
    def __init__(self, whitelist_ips=None, whitelist_cidrs=None):
        self.strings = {}  # key -> (value, ttl)
        self._whitelist_ips = whitelist_ips or set()
        self._whitelist_cidrs = whitelist_cidrs or set()

    def sismember(self, key, value):
        if key == "waf:whitelist":
            return value in self._whitelist_ips
        return False

    def smembers(self, key):
        if key == "waf:whitelist:cidrs":
            return set(self._whitelist_cidrs)
        return set()

    def setex(self, key, ttl, value):
        self.strings[key] = (value, ttl)

    def get(self, key):
        v = self.strings.get(key)
        return v[0] if v else None

    def scan(self, cursor=0, match=None, count=100):
        keys = [k for k in self.strings if not match or fnmatch.fnmatch(k, match)]
        return 0, keys

    def ttl(self, key):
        v = self.strings.get(key)
        return v[1] if v else -2

    def delete(self, key):
        existed = key in self.strings
        self.strings.pop(key, None)
        return 1 if existed else 0


@pytest.fixture
def isolated_settings(tmp_path, monkeypatch):
    monkeypatch.setattr(settings_manager, "SETTINGS_FILE", str(tmp_path / "settings.json"))
    monkeypatch.setattr(settings_manager.settings_manager, "_settings", None)
    return settings_manager.settings_manager


# ---------------------------------------------------------------------------
# run_auto_reputation_sync
# ---------------------------------------------------------------------------

def test_sync_skipped_when_disabled(isolated_settings, monkeypatch):
    monkeypatch.setattr(
        clickhouse_service, "get_repeat_offender_ips",
        lambda *a, **k: pytest.fail("should not query ClickHouse when disabled"),
    )
    result = auto_reputation_service.run_auto_reputation_sync(force=False)
    assert result["status"] == "skipped"


def test_forced_sync_ignores_disabled_flag_and_blocks_offenders(isolated_settings, monkeypatch):
    fake_redis = _FakeRedis()
    monkeypatch.setattr(nginx_manager, "get_redis_client", lambda: fake_redis)
    monkeypatch.setattr(clickhouse_service, "get_repeat_offender_ips", lambda threshold, hours: ["10.0.0.1", "10.0.0.2"])

    result = auto_reputation_service.run_auto_reputation_sync(force=True)

    assert result["status"] == "success"
    assert result["count"] == 2
    assert "waf:blacklist:auto:10.0.0.1" in fake_redis.strings
    assert "waf:blacklist:auto:10.0.0.2" in fake_redis.strings

    status = isolated_settings.get_auto_reputation()
    assert status["last_sync_status"] == "success"
    assert status["last_sync_count"] == 2
    assert status["last_sync_at"] is not None


def test_block_ttl_matches_configured_hours(isolated_settings, monkeypatch):
    isolated_settings.update_auto_reputation({
        **isolated_settings.get_auto_reputation(), "block_ttl_hours": 48,
    })
    fake_redis = _FakeRedis()
    monkeypatch.setattr(nginx_manager, "get_redis_client", lambda: fake_redis)
    monkeypatch.setattr(clickhouse_service, "get_repeat_offender_ips", lambda threshold, hours: ["10.0.0.1"])

    auto_reputation_service.run_auto_reputation_sync(force=True)

    assert fake_redis.strings["waf:blacklist:auto:10.0.0.1"] == ("1", 48 * 3600)


def test_whitelisted_ip_never_auto_blocked(isolated_settings, monkeypatch):
    fake_redis = _FakeRedis(whitelist_ips={"10.0.0.1"})
    monkeypatch.setattr(nginx_manager, "get_redis_client", lambda: fake_redis)
    monkeypatch.setattr(clickhouse_service, "get_repeat_offender_ips", lambda threshold, hours: ["10.0.0.1", "10.0.0.2"])

    result = auto_reputation_service.run_auto_reputation_sync(force=True)

    assert result["count"] == 1  # only 10.0.0.2
    assert "waf:blacklist:auto:10.0.0.1" not in fake_redis.strings
    assert "waf:blacklist:auto:10.0.0.2" in fake_redis.strings


def test_whitelisted_cidr_never_auto_blocked(isolated_settings, monkeypatch):
    fake_redis = _FakeRedis(whitelist_cidrs={"10.0.0.0/24"})
    monkeypatch.setattr(nginx_manager, "get_redis_client", lambda: fake_redis)
    monkeypatch.setattr(clickhouse_service, "get_repeat_offender_ips", lambda threshold, hours: ["10.0.0.99"])

    result = auto_reputation_service.run_auto_reputation_sync(force=True)

    assert result["count"] == 0
    assert "waf:blacklist:auto:10.0.0.99" not in fake_redis.strings


def test_sync_error_reports_status_without_raising(isolated_settings, monkeypatch):
    def _raise(*a, **k):
        raise RuntimeError("ClickHouse unavailable")
    monkeypatch.setattr(clickhouse_service, "get_repeat_offender_ips", _raise)

    result = auto_reputation_service.run_auto_reputation_sync(force=True)

    assert result["status"] == "error"
    status = isolated_settings.get_auto_reputation()
    assert status["last_sync_status"] == "error"
    assert "ClickHouse unavailable" in status["last_sync_error"]


# ---------------------------------------------------------------------------
# get_auto_blocked_ips / release_auto_blocked_ip
# ---------------------------------------------------------------------------

def test_get_auto_blocked_ips_lists_current_entries(monkeypatch):
    fake_redis = _FakeRedis()
    fake_redis.setex("waf:blacklist:auto:10.0.0.1", 3600, "1")
    fake_redis.setex("waf:blacklist:auto:10.0.0.2", 7200, "1")
    monkeypatch.setattr(nginx_manager, "get_redis_client", lambda: fake_redis)

    result = auto_reputation_service.get_auto_blocked_ips()

    ips = {r["ip"] for r in result}
    assert ips == {"10.0.0.1", "10.0.0.2"}


def test_release_auto_blocked_ip_removes_entry(monkeypatch):
    fake_redis = _FakeRedis()
    fake_redis.setex("waf:blacklist:auto:10.0.0.1", 3600, "1")
    monkeypatch.setattr(nginx_manager, "get_redis_client", lambda: fake_redis)

    released = auto_reputation_service.release_auto_blocked_ip("10.0.0.1")
    assert released is True
    assert "waf:blacklist:auto:10.0.0.1" not in fake_redis.strings


def test_release_nonexistent_ip_returns_false(monkeypatch):
    fake_redis = _FakeRedis()
    monkeypatch.setattr(nginx_manager, "get_redis_client", lambda: fake_redis)

    assert auto_reputation_service.release_auto_blocked_ip("10.0.0.99") is False


# ---------------------------------------------------------------------------
# Route-level wiring
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_client(tmp_path, monkeypatch, isolated_user_service, isolated_settings):
    return TestClient(fastapi_app)


def _login(client, username, password):
    r = client.post("/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    csrf = r.cookies.get("XSRF-TOKEN-V3")
    client.cookies.update(r.cookies)
    return csrf


def test_analyst_forbidden_from_auto_reputation_settings(isolated_client, make_user):
    client = isolated_client
    analyst = make_user(role="analyst")
    _login(client, analyst["username"], analyst["password"])

    r = client.get("/settings/auto-reputation")
    assert r.status_code == 403


def test_admin_can_enable_and_it_persists(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    r = client.post(
        "/settings/auto-reputation",
        headers={"X-XSRF-TOKEN": csrf},
        json={
            "enabled": True, "block_threshold": 25, "window_hours": 2,
            "block_ttl_hours": 12, "sync_interval_minutes": 10,
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is True
    assert r.json()["block_threshold"] == 25

    r = client.get("/settings/auto-reputation")
    assert r.json()["block_threshold"] == 25


def test_update_rejects_sub_5min_interval(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    r = client.post(
        "/settings/auto-reputation",
        headers={"X-XSRF-TOKEN": csrf},
        json={
            "enabled": True, "block_threshold": 50, "window_hours": 1,
            "block_ttl_hours": 24, "sync_interval_minutes": 1,
        },
    )
    assert r.status_code == 400


def test_sync_now_works_while_disabled(isolated_client, make_user, monkeypatch):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    fake_redis = _FakeRedis()
    monkeypatch.setattr(nginx_manager, "get_redis_client", lambda: fake_redis)
    monkeypatch.setattr(clickhouse_service, "get_repeat_offender_ips", lambda threshold, hours: ["10.0.0.1"])

    r = client.post("/settings/auto-reputation/sync-now", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "success"
    assert r.json()["count"] == 1


def test_list_and_release_route(isolated_client, make_user, monkeypatch):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    fake_redis = _FakeRedis()
    fake_redis.setex("waf:blacklist:auto:10.0.0.1", 3600, "1")
    monkeypatch.setattr(nginx_manager, "get_redis_client", lambda: fake_redis)

    r = client.get("/settings/auto-reputation/blocked")
    assert r.status_code == 200
    assert r.json()[0]["ip"] == "10.0.0.1"

    r = client.post("/settings/auto-reputation/release/10.0.0.1", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code == 200, r.text

    r = client.post("/settings/auto-reputation/release/10.0.0.1", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code == 404
