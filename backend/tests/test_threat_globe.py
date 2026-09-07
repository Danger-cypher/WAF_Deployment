"""
Covers the Threat Globe feature's backend (P1 item 4 of the WAAP console
teardown roadmap): geoip_manager's new City-DB lookup, settings_manager's
threat_globe section (auto-detection vs. manual override), the
/settings/threat-globe route pair, and threat_globe_location.py's
one-shot startup detection — each isolated the same way the rest of this
suite isolates settings_manager/DB state (see test_malware_scanning.py).
"""
import asyncio

import pytest
from fastapi.testclient import TestClient

from app.services import settings_manager as settings_manager_module
from app.services import threat_globe_location
from app.utils.geoip_manager import GeoIPManager
from app.main import app as fastapi_app


# ---------------------------------------------------------------------------
# geoip_manager.get_city_location()
# ---------------------------------------------------------------------------

class _FakeCityResponse:
    def __init__(self, lat, lon, city):
        self.location = type("L", (), {"latitude": lat, "longitude": lon})()
        self.city = type("C", (), {"name": city})()


class _FakeCityReader:
    def __init__(self, result=None, raise_not_found=False):
        self._result = result
        self._raise_not_found = raise_not_found

    def city(self, ip):
        if self._raise_not_found:
            import geoip2.errors
            raise geoip2.errors.AddressNotFoundError("not found")
        return self._result


def _manager_with_city_reader(reader):
    mgr = GeoIPManager.__new__(GeoIPManager)  # skip __init__'s real file loading
    mgr.reader = None
    mgr.asn_reader = None
    mgr.city_reader = reader
    return mgr


def test_get_city_location_returns_none_for_private_ip():
    mgr = _manager_with_city_reader(_FakeCityReader())
    assert mgr.get_city_location("192.168.1.1") is None


def test_get_city_location_returns_none_for_empty_input():
    mgr = _manager_with_city_reader(_FakeCityReader())
    assert mgr.get_city_location("") is None
    assert mgr.get_city_location(None) is None


def test_get_city_location_returns_none_when_city_db_not_loaded():
    mgr = _manager_with_city_reader(None)
    assert mgr.get_city_location("8.8.8.8") is None


def test_get_city_location_returns_none_on_address_not_found():
    mgr = _manager_with_city_reader(_FakeCityReader(raise_not_found=True))
    assert mgr.get_city_location("8.8.8.8") is None


def test_get_city_location_returns_lat_lon_city_on_success():
    mgr = _manager_with_city_reader(_FakeCityReader(_FakeCityResponse(37.75, -97.8, "Wichita")))
    result = mgr.get_city_location("8.8.8.8")
    assert result == {"lat": 37.75, "lon": -97.8, "city": "Wichita"}


def test_get_city_location_returns_none_when_lat_is_none():
    """MaxMind can return a city record with no location fix at all
    (country-level accuracy only) — must not fabricate 0.0/0.0."""
    mgr = _manager_with_city_reader(_FakeCityReader(_FakeCityResponse(None, None, "")))
    assert mgr.get_city_location("8.8.8.8") is None


# ---------------------------------------------------------------------------
# settings_manager.threat_globe section
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_settings(tmp_path, monkeypatch):
    monkeypatch.setattr(settings_manager_module, "SETTINGS_FILE", str(tmp_path / "settings.json"))
    monkeypatch.setattr(settings_manager_module.settings_manager, "_settings", None)
    return settings_manager_module.settings_manager


def test_default_threat_globe_settings_are_empty(isolated_settings):
    result = isolated_settings.get_threat_globe()
    assert result["server_lat"] is None
    assert result["auto_detected"] is False
    assert result["override_enabled"] is False


def test_set_threat_globe_auto_location_updates_server_fields_only(isolated_settings):
    isolated_settings.update_threat_globe({
        "server_lat": None, "server_lon": None, "server_label": "", "auto_detected": False,
        "override_enabled": True, "override_lat": 10.0, "override_lon": 20.0, "override_label": "Manual",
    })

    isolated_settings.set_threat_globe_auto_location(50.11, 8.68, "Frankfurt")

    result = isolated_settings.get_threat_globe()
    assert result["server_lat"] == 50.11
    assert result["server_lon"] == 8.68
    assert result["server_label"] == "Frankfurt"
    assert result["auto_detected"] is True
    # An admin's manual override must survive an auto-detection re-run untouched.
    assert result["override_enabled"] is True
    assert result["override_lat"] == 10.0
    assert result["override_label"] == "Manual"


# ---------------------------------------------------------------------------
# Route: /settings/threat-globe
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_client(isolated_user_service, isolated_settings):
    return TestClient(fastapi_app)


def _login(client, username, password):
    r = client.post("/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    csrf = r.cookies.get("XSRF-TOKEN-V3")
    client.cookies.update(r.cookies)
    return csrf


def test_analyst_can_read_destination_globe_is_a_monitoring_view(isolated_client, make_user):
    """Unlike most /settings/* routes, GET here is intentionally open to
    every role — the globe is a dashboard view an Analyst can see, not a
    settings page."""
    client = isolated_client
    analyst = make_user(role="analyst")
    _login(client, analyst["username"], analyst["password"])

    r = client.get("/settings/threat-globe")
    assert r.status_code == 200


def test_analyst_forbidden_from_setting_override(isolated_client, make_user):
    client = isolated_client
    analyst = make_user(role="analyst")
    _login(client, analyst["username"], analyst["password"])

    r = client.post("/settings/threat-globe", json={
        "override_enabled": True, "override_lat": 10, "override_lon": 20, "override_label": "x",
    })
    assert r.status_code == 403


def test_admin_can_set_override_and_it_persists(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    r = client.post(
        "/settings/threat-globe", headers={"X-XSRF-TOKEN": csrf},
        json={"override_enabled": True, "override_lat": 51.5, "override_lon": -0.12, "override_label": "London"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["override_lat"] == 51.5

    r = client.get("/settings/threat-globe")
    assert r.json()["override_label"] == "London"


def test_override_enabled_without_coordinates_rejected(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    r = client.post(
        "/settings/threat-globe", headers={"X-XSRF-TOKEN": csrf},
        json={"override_enabled": True, "override_label": "no coords"},
    )
    assert r.status_code == 400


@pytest.mark.parametrize("field,value", [("override_lat", 91), ("override_lat", -91), ("override_lon", 181), ("override_lon", -181)])
def test_out_of_range_coordinates_rejected(isolated_client, make_user, field, value):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    payload = {"override_enabled": True, "override_lat": 10, "override_lon": 10, "override_label": "x"}
    payload[field] = value
    r = client.post("/settings/threat-globe", headers={"X-XSRF-TOKEN": csrf}, json=payload)
    assert r.status_code == 422


def test_post_cannot_overwrite_auto_detected_fields_directly(isolated_client, make_user, isolated_settings):
    """server_lat/lon/label/auto_detected are threat_globe_location.py's
    own output — a settings-form round-trip must not let a client
    overwrite them with arbitrary values in the submitted body."""
    isolated_settings.set_threat_globe_auto_location(50.11, 8.68, "Frankfurt")

    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    r = client.post(
        "/settings/threat-globe", headers={"X-XSRF-TOKEN": csrf},
        json={
            "server_lat": 0.0, "server_lon": 0.0, "server_label": "spoofed", "auto_detected": False,
            "override_enabled": False,
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["server_lat"] == 50.11
    assert r.json()["server_label"] == "Frankfurt"
    assert r.json()["auto_detected"] is True


# ---------------------------------------------------------------------------
# threat_globe_location.py — one-shot startup auto-detection
#
# resolve_server_location_once is async but this project has no
# pytest-asyncio configured — run it via a bare asyncio.run() in an
# otherwise-synchronous test function, same convention as
# test_alert_syslog_throttle_bypass.py.
# ---------------------------------------------------------------------------

class _FakeIpResponse:
    def __init__(self, ip):
        self._ip = ip

    def raise_for_status(self):
        pass

    def json(self):
        return {"ip": self._ip}


def test_resolve_skips_when_override_already_enabled(isolated_settings, monkeypatch):
    isolated_settings.update_threat_globe({
        "server_lat": None, "server_lon": None, "server_label": "", "auto_detected": False,
        "override_enabled": True, "override_lat": 1.0, "override_lon": 2.0, "override_label": "manual",
    })

    def _fail_if_called(*a, **k):
        pytest.fail("should not attempt IP lookup when an override is already set")
    monkeypatch.setattr(threat_globe_location.requests, "get", _fail_if_called)

    asyncio.run(threat_globe_location.resolve_server_location_once())

    # untouched
    result = isolated_settings.get_threat_globe()
    assert result["server_lat"] is None


def test_resolve_sets_auto_location_on_success(isolated_settings, monkeypatch):
    monkeypatch.setattr(threat_globe_location.requests, "get", lambda *a, **k: _FakeIpResponse("8.8.8.8"))
    monkeypatch.setattr(
        threat_globe_location.geoip_manager, "get_city_location",
        lambda ip: {"lat": 37.75, "lon": -97.8, "city": "Wichita"} if ip == "8.8.8.8" else None,
    )

    asyncio.run(threat_globe_location.resolve_server_location_once())

    result = isolated_settings.get_threat_globe()
    assert result["server_lat"] == 37.75
    assert result["server_label"] == "Wichita"
    assert result["auto_detected"] is True


def test_resolve_leaves_settings_unchanged_on_network_failure(isolated_settings, monkeypatch):
    def _raise(*a, **k):
        raise ConnectionError("no egress")
    monkeypatch.setattr(threat_globe_location.requests, "get", _raise)

    asyncio.run(threat_globe_location.resolve_server_location_once())  # must not raise

    result = isolated_settings.get_threat_globe()
    assert result["server_lat"] is None
    assert result["auto_detected"] is False


def test_resolve_leaves_settings_unchanged_when_geoip_has_no_fix(isolated_settings, monkeypatch):
    monkeypatch.setattr(threat_globe_location.requests, "get", lambda *a, **k: _FakeIpResponse("8.8.8.8"))
    monkeypatch.setattr(threat_globe_location.geoip_manager, "get_city_location", lambda ip: None)

    asyncio.run(threat_globe_location.resolve_server_location_once())

    result = isolated_settings.get_threat_globe()
    assert result["server_lat"] is None
