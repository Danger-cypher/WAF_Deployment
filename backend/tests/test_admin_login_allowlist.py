"""
Covers P1-8 Part A: the admin-login IP allowlist. Distinct from
/settings/hardening's ip_whitelist/ip_blacklist (which gates all site
traffic through nginx/ml_check.lua) — this gates only the dashboard's own
/auth/login and /auth/login/mfa endpoints, and applies to every account
role uniformly (admin/analyst/app_admin), not just 'admin'.

TestClient requests don't carry a real client IP (request.client.host is
"testclient", not a parseable address), so every test that needs to
control the perceived client IP sets the X-Real-IP header explicitly —
get_client_ip() prefers that header over request.client, same as real
nginx-fronted traffic (see app/utils/security.py's get_client_ip
docstring for why X-Real-IP specifically, not X-Forwarded-For).

Uses the same settings-file isolation pattern as test_auto_reputation.py/
test_threat_intel.py (monkeypatch SETTINGS_FILE to a tmp_path file and
reset the singleton's cached _settings) so these tests never touch the
real settings.json.
"""
import pyotp
import pytest
from fastapi.testclient import TestClient

from app.services import settings_manager
from app.utils.security import is_ip_in_networks
from app.main import app as fastapi_app


# ---------------------------------------------------------------------------
# is_ip_in_networks — pure unit tests
# ---------------------------------------------------------------------------

def test_exact_ip_match():
    assert is_ip_in_networks("203.0.113.5", ["203.0.113.5"]) is True


def test_ip_not_in_list():
    assert is_ip_in_networks("203.0.113.9", ["203.0.113.5"]) is False


def test_cidr_match():
    assert is_ip_in_networks("10.0.0.42", ["10.0.0.0/24"]) is True
    assert is_ip_in_networks("10.0.1.42", ["10.0.0.0/24"]) is False


def test_empty_networks_list_matches_nothing():
    assert is_ip_in_networks("10.0.0.1", []) is False


def test_invalid_entries_are_skipped_not_raised():
    # "not-an-ip" is a garbage saved entry; "10.0.0.0/24" is still valid and
    # should still be checked — one bad entry can't break every other entry.
    assert is_ip_in_networks("10.0.0.5", ["not-an-ip", "10.0.0.0/24"]) is True
    assert is_ip_in_networks("10.0.0.5", ["not-an-ip"]) is False


def test_unparseable_client_ip_never_matches():
    assert is_ip_in_networks("testclient", ["0.0.0.0/0"]) is False


# ---------------------------------------------------------------------------
# Settings routes
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_settings(tmp_path, monkeypatch):
    monkeypatch.setattr(settings_manager, "SETTINGS_FILE", str(tmp_path / "settings.json"))
    monkeypatch.setattr(settings_manager.settings_manager, "_settings", None)
    return settings_manager.settings_manager


@pytest.fixture
def isolated_client(tmp_path, monkeypatch, isolated_user_service, isolated_settings):
    return TestClient(fastapi_app)


def _login(client, username, password, requester_ip="198.51.100.1"):
    r = client.post(
        "/auth/login",
        data={"username": username, "password": password},
        headers={"X-Real-IP": requester_ip},
    )
    assert r.status_code == 200, r.text
    csrf = r.cookies.get("XSRF-TOKEN-V3")
    client.cookies.update(r.cookies)
    return csrf


def test_defaults_are_disabled_and_empty(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"])

    r = client.get("/settings/admin-login-allowlist")
    assert r.status_code == 200
    assert r.json() == {"enabled": False, "allowed_networks": []}


def test_analyst_forbidden_from_allowlist_settings(isolated_client, make_user):
    client = isolated_client
    analyst = make_user(role="analyst")
    _login(client, analyst["username"], analyst["password"])

    r = client.get("/settings/admin-login-allowlist")
    assert r.status_code == 403


def test_admin_can_enable_with_own_ip_included_and_it_persists(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"], requester_ip="198.51.100.1")

    r = client.post(
        "/settings/admin-login-allowlist",
        headers={"X-XSRF-TOKEN": csrf, "X-Real-IP": "198.51.100.1"},
        json={"enabled": True, "allowed_networks": ["198.51.100.1", "10.0.0.0/24"]},
    )
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is True

    r = client.get("/settings/admin-login-allowlist", headers={"X-Real-IP": "198.51.100.1"})
    assert r.json()["allowed_networks"] == ["198.51.100.1", "10.0.0.0/24"]


def test_enabling_without_own_ip_in_list_is_refused(isolated_client, make_user):
    """The self-lockout guard: an admin can't enable a list that excludes
    the IP they're currently connecting from."""
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"], requester_ip="198.51.100.1")

    r = client.post(
        "/settings/admin-login-allowlist",
        headers={"X-XSRF-TOKEN": csrf, "X-Real-IP": "198.51.100.1"},
        json={"enabled": True, "allowed_networks": ["203.0.113.0/24"]},
    )
    assert r.status_code == 400
    assert "lock" in r.json()["detail"].lower()

    # Refused save must not have persisted.
    r = client.get("/settings/admin-login-allowlist", headers={"X-Real-IP": "198.51.100.1"})
    assert r.json()["enabled"] is False


def test_disabling_does_not_require_own_ip_in_list(isolated_client, make_user):
    """The lockout guard only applies when *enabling* — turning it back off
    (e.g. to fix a bad list) must never itself be blocked by the same list."""
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"], requester_ip="198.51.100.1")

    r = client.post(
        "/settings/admin-login-allowlist",
        headers={"X-XSRF-TOKEN": csrf, "X-Real-IP": "198.51.100.1"},
        json={"enabled": False, "allowed_networks": ["203.0.113.0/24"]},
    )
    assert r.status_code == 200, r.text


def test_invalid_cidr_entry_rejected(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"], requester_ip="198.51.100.1")

    r = client.post(
        "/settings/admin-login-allowlist",
        headers={"X-XSRF-TOKEN": csrf, "X-Real-IP": "198.51.100.1"},
        json={"enabled": False, "allowed_networks": ["not-a-valid-entry"]},
    )
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# Login gate — the actual enforcement
# ---------------------------------------------------------------------------

def _enable_allowlist(client, csrf, requester_ip, allowed_networks):
    r = client.post(
        "/settings/admin-login-allowlist",
        headers={"X-XSRF-TOKEN": csrf, "X-Real-IP": requester_ip},
        json={"enabled": True, "allowed_networks": allowed_networks},
    )
    assert r.status_code == 200, r.text


def test_login_unaffected_when_allowlist_disabled(isolated_client, make_user):
    """Default state — no allowlist configured at all. Any client IP works."""
    client = isolated_client
    user = make_user(role="admin")

    r = client.post(
        "/auth/login",
        data={"username": user["username"], "password": user["password"]},
        headers={"X-Real-IP": "1.2.3.4"},
    )
    assert r.status_code == 200


def test_login_blocked_from_disallowed_ip(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"], requester_ip="198.51.100.1")
    _enable_allowlist(client, csrf, "198.51.100.1", ["198.51.100.1"])
    client.post("/auth/logout", headers={"X-XSRF-TOKEN": csrf, "X-Real-IP": "198.51.100.1"})

    r = client.post(
        "/auth/login",
        data={"username": admin["username"], "password": admin["password"]},
        headers={"X-Real-IP": "203.0.113.99"},
    )
    assert r.status_code == 403
    assert "waf_session_v3" not in r.cookies


def test_login_allowed_from_allowed_exact_ip(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"], requester_ip="198.51.100.1")
    _enable_allowlist(client, csrf, "198.51.100.1", ["198.51.100.1"])
    client.post("/auth/logout", headers={"X-XSRF-TOKEN": csrf, "X-Real-IP": "198.51.100.1"})

    r = client.post(
        "/auth/login",
        data={"username": admin["username"], "password": admin["password"]},
        headers={"X-Real-IP": "198.51.100.1"},
    )
    assert r.status_code == 200


def test_login_allowed_from_cidr_range(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"], requester_ip="10.0.0.1")
    _enable_allowlist(client, csrf, "10.0.0.1", ["10.0.0.0/24"])
    client.post("/auth/logout", headers={"X-XSRF-TOKEN": csrf, "X-Real-IP": "10.0.0.1"})

    r = client.post(
        "/auth/login",
        data={"username": admin["username"], "password": admin["password"]},
        headers={"X-Real-IP": "10.0.0.200"},
    )
    assert r.status_code == 200


def test_login_blocked_applies_to_analyst_and_app_admin_too(isolated_client, make_user):
    """The allowlist gates every role uniformly, per the confirmed design —
    not just 'admin' accounts."""
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"], requester_ip="198.51.100.1")
    _enable_allowlist(client, csrf, "198.51.100.1", ["198.51.100.1"])
    client.post("/auth/logout", headers={"X-XSRF-TOKEN": csrf, "X-Real-IP": "198.51.100.1"})

    analyst = make_user(role="analyst")
    r = client.post(
        "/auth/login",
        data={"username": analyst["username"], "password": analyst["password"]},
        headers={"X-Real-IP": "203.0.113.99"},
    )
    assert r.status_code == 403


def test_blocked_login_rejects_before_revealing_username_validity(isolated_client, make_user):
    """A disallowed-IP login must be rejected identically whether or not the
    username exists — the gate runs before any user lookup."""
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"], requester_ip="198.51.100.1")
    _enable_allowlist(client, csrf, "198.51.100.1", ["198.51.100.1"])
    client.post("/auth/logout", headers={"X-XSRF-TOKEN": csrf, "X-Real-IP": "198.51.100.1"})

    r1 = client.post(
        "/auth/login",
        data={"username": admin["username"], "password": "WrongPassword123!"},
        headers={"X-Real-IP": "203.0.113.99"},
    )
    r2 = client.post(
        "/auth/login",
        data={"username": "definitely-does-not-exist", "password": "whatever"},
        headers={"X-Real-IP": "203.0.113.99"},
    )
    assert r1.status_code == r2.status_code == 403
    assert r1.json()["detail"] == r2.json()["detail"]


def test_mfa_step_also_gated_by_allowlist(isolated_client, make_user):
    """Defense in depth: even with a valid MFA-pending cookie, the second
    step (/auth/login/mfa) re-checks the allowlist independently."""
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"], requester_ip="198.51.100.1")

    r = client.post("/users/me/mfa/setup", headers={"X-XSRF-TOKEN": csrf, "X-Real-IP": "198.51.100.1"})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post(
        "/users/me/mfa/confirm",
        headers={"X-XSRF-TOKEN": csrf, "X-Real-IP": "198.51.100.1"},
        json={"code": code},
    )

    _enable_allowlist(client, csrf, "198.51.100.1", ["198.51.100.1"])
    client.post("/auth/logout", headers={"X-XSRF-TOKEN": csrf, "X-Real-IP": "198.51.100.1"})

    # Step 1 from the allowed IP succeeds and issues the MFA-pending cookie.
    r = client.post(
        "/auth/login",
        data={"username": admin["username"], "password": admin["password"]},
        headers={"X-Real-IP": "198.51.100.1"},
    )
    assert r.status_code == 200
    assert r.json()["mfa_required"] is True

    # Step 2 replayed from a disallowed IP must still be blocked, even
    # though the pending cookie and TOTP code are both valid.
    code2 = pyotp.TOTP(secret).now()
    r = client.post(
        "/auth/login/mfa",
        json={"code": code2},
        headers={"X-Real-IP": "203.0.113.99"},
    )
    assert r.status_code == 403


def test_login_still_works_from_allowed_ip_with_mfa(isolated_client, make_user):
    client = isolated_client
    admin = make_user(role="admin")
    csrf = _login(client, admin["username"], admin["password"], requester_ip="198.51.100.1")

    r = client.post("/users/me/mfa/setup", headers={"X-XSRF-TOKEN": csrf, "X-Real-IP": "198.51.100.1"})
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post(
        "/users/me/mfa/confirm",
        headers={"X-XSRF-TOKEN": csrf, "X-Real-IP": "198.51.100.1"},
        json={"code": code},
    )

    _enable_allowlist(client, csrf, "198.51.100.1", ["198.51.100.1"])
    client.post("/auth/logout", headers={"X-XSRF-TOKEN": csrf, "X-Real-IP": "198.51.100.1"})

    client.post(
        "/auth/login",
        data={"username": admin["username"], "password": admin["password"]},
        headers={"X-Real-IP": "198.51.100.1"},
    )
    code2 = pyotp.TOTP(secret).now()
    r = client.post(
        "/auth/login/mfa",
        json={"code": code2},
        headers={"X-Real-IP": "198.51.100.1"},
    )
    assert r.status_code == 200
    assert r.json()["role"] == "admin"
