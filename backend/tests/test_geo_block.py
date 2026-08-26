"""
Covers apply_geo_block_settings() — the Redis population side of the
Settings > Hardening geo-block feature. Enforcement itself lives in
ml_check.lua (check_geo_block, reading these same Redis keys); this only
verifies the backend writes the right keys for the right settings shape,
mirroring how test_mssp_default_server.py / test_ddos_host_uri_rule.py
isolate nginx_manager functions from real infrastructure.
"""
from app.services import nginx_manager


class _FakeRedis:
    def __init__(self):
        self.strings = {}
        self.sets = {}

    def delete(self, *keys):
        for k in keys:
            self.sets.pop(k, None)
            self.strings.pop(k, None)

    def set(self, key, value):
        self.strings[key] = value

    def sadd(self, key, value):
        self.sets.setdefault(key, set()).add(value)


def test_disabled_sets_mode_to_disabled_and_clears_countries(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(nginx_manager, "get_redis_client", lambda: fake)

    ok, msg = nginx_manager.apply_geo_block_settings(
        {"enabled": False, "mode": "deny", "countries": ["RU", "CN"]}
    )

    assert ok, msg
    assert fake.strings["waf:geo:block_mode"] == "disabled"
    assert fake.sets.get("waf:geo:countries", set()) == set()


def test_deny_mode_populates_normalized_country_set(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(nginx_manager, "get_redis_client", lambda: fake)

    ok, msg = nginx_manager.apply_geo_block_settings(
        {"enabled": True, "mode": "deny", "countries": ["ru", " cn "]}
    )

    assert ok, msg
    assert fake.strings["waf:geo:block_mode"] == "deny"
    assert fake.sets["waf:geo:countries"] == {"RU", "CN"}


def test_allow_mode_stores_mode_correctly(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(nginx_manager, "get_redis_client", lambda: fake)

    ok, msg = nginx_manager.apply_geo_block_settings(
        {"enabled": True, "mode": "allow", "countries": ["US"]}
    )

    assert ok, msg
    assert fake.strings["waf:geo:block_mode"] == "allow"
    assert fake.sets["waf:geo:countries"] == {"US"}
