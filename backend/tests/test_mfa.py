"""Tests for TOTP MFA (Module 6) — setup/confirm/disable and the two-step
login flow (password, then a separate /login/mfa code exchange)."""
import pyotp
from fastapi.testclient import TestClient
from app.main import app as fastapi_app


def _enroll_mfa(client, csrf):
    """Runs setup+confirm for the already-logged-in client and returns the secret."""
    r = client.post("/users/me/mfa/setup", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code == 200
    secret = r.json()["secret"]
    assert r.json()["otpauth_uri"].startswith("otpauth://totp/")
    assert len(r.json()["qr_code_png_base64"]) > 0

    code = pyotp.TOTP(secret).now()
    r = client.post("/users/me/mfa/confirm", headers={"X-XSRF-TOKEN": csrf}, json={"code": code})
    assert r.status_code == 200
    assert r.json() == {"enabled": True}
    return secret


def test_mfa_status_defaults_to_disabled(admin_session):
    client, _csrf, _user = admin_session
    r = client.get("/users/me/mfa/status")
    assert r.status_code == 200
    assert r.json() == {"enabled": False}


def test_setup_and_confirm_enables_mfa(admin_session):
    client, csrf, _user = admin_session
    _enroll_mfa(client, csrf)
    assert client.get("/users/me/mfa/status").json() == {"enabled": True}


def test_confirm_rejects_wrong_code(admin_session):
    client, csrf, _user = admin_session
    client.post("/users/me/mfa/setup", headers={"X-XSRF-TOKEN": csrf})
    r = client.post("/users/me/mfa/confirm", headers={"X-XSRF-TOKEN": csrf}, json={"code": "000000"})
    assert r.status_code == 400
    assert client.get("/users/me/mfa/status").json() == {"enabled": False}


def test_setup_blocked_while_already_enabled(admin_session):
    client, csrf, _user = admin_session
    _enroll_mfa(client, csrf)
    r = client.post("/users/me/mfa/setup", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code == 400


def test_login_with_mfa_enabled_requires_second_step(client, make_user):
    user = make_user(role="admin")
    r = client.post("/auth/login", data={"username": user["username"], "password": user["password"]})
    csrf = r.cookies.get("XSRF-TOKEN-V3")
    client.cookies.update(r.cookies)
    secret = _enroll_mfa(client, csrf)

    # Log out, then log back in — this time MFA should kick in.
    client.post("/auth/logout", headers={"X-XSRF-TOKEN": csrf})

    r = client.post("/auth/login", data={"username": user["username"], "password": user["password"]})
    assert r.status_code == 200
    body = r.json()
    assert body["mfa_required"] is True
    assert body.get("role") is None
    # No full session yet — protected routes must still reject.
    assert client.get("/auth/me").status_code == 401

    code = pyotp.TOTP(secret).now()
    r = client.post("/auth/login/mfa", json={"code": code})
    assert r.status_code == 200
    assert r.json()["mfa_required"] is False
    assert r.json()["role"] == "admin"

    r = client.get("/auth/me")
    assert r.status_code == 200
    assert r.json()["username"] == user["username"]


def test_login_mfa_rejects_wrong_code(client, make_user):
    user = make_user(role="analyst")
    r = client.post("/auth/login", data={"username": user["username"], "password": user["password"]})
    csrf = r.cookies.get("XSRF-TOKEN-V3")
    client.cookies.update(r.cookies)
    _enroll_mfa(client, csrf)
    client.post("/auth/logout", headers={"X-XSRF-TOKEN": csrf})

    client.post("/auth/login", data={"username": user["username"], "password": user["password"]})
    r = client.post("/auth/login/mfa", json={"code": "000000"})
    assert r.status_code == 401
    assert client.get("/auth/me").status_code == 401


def test_login_mfa_without_pending_cookie_rejected(client):
    r = client.post("/auth/login/mfa", json={"code": "123456"})
    assert r.status_code == 401


def test_self_disable_requires_correct_password_and_code(admin_session):
    client, csrf, user = admin_session
    secret = _enroll_mfa(client, csrf)

    r = client.post(
        "/users/me/mfa/disable",
        headers={"X-XSRF-TOKEN": csrf},
        json={"current_password": "WrongPass123!", "code": pyotp.TOTP(secret).now()},
    )
    assert r.status_code == 400
    assert client.get("/users/me/mfa/status").json() == {"enabled": True}

    r = client.post(
        "/users/me/mfa/disable",
        headers={"X-XSRF-TOKEN": csrf},
        json={"current_password": user["password"], "code": "000000"},
    )
    assert r.status_code == 400
    assert client.get("/users/me/mfa/status").json() == {"enabled": True}

    r = client.post(
        "/users/me/mfa/disable",
        headers={"X-XSRF-TOKEN": csrf},
        json={"current_password": user["password"], "code": pyotp.TOTP(secret).now()},
    )
    assert r.status_code == 200
    assert r.json() == {"enabled": False}


def test_admin_can_force_disable_another_users_mfa(admin_session, make_user, isolated_user_service):
    admin_client, admin_csrf, _admin = admin_session
    target = make_user(role="analyst")

    # Separate TestClient = separate "browser" for the target user, so its
    # session cookies never collide with the admin's.
    target_client = TestClient(fastapi_app)
    r = target_client.post(
        "/auth/login", data={"username": target["username"], "password": target["password"]}
    )
    target_csrf = r.cookies.get("XSRF-TOKEN-V3")
    target_client.cookies.update(r.cookies)
    _enroll_mfa(target_client, target_csrf)
    assert user_service_mfa_enabled(isolated_user_service, target["id"]) is True

    r = admin_client.post(f"/users/{target['id']}/mfa/disable", headers={"X-XSRF-TOKEN": admin_csrf})
    assert r.status_code == 200
    assert r.json() == {"enabled": False}
    assert user_service_mfa_enabled(isolated_user_service, target["id"]) is False


def user_service_mfa_enabled(service, user_id):
    return service.get_by_id(user_id)["mfa_enabled"]
