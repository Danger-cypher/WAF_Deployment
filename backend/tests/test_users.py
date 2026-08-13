"""Tests for /users/* — admin CRUD, self-service profile, and the
last-admin guard rails that prevent the system from locking itself out."""
import pytest


def test_analyst_cannot_list_users(analyst_session):
    client, _csrf, _user = analyst_session
    r = client.get("/users")
    assert r.status_code == 403


def test_admin_can_list_users(admin_session):
    client, _csrf, user = admin_session
    r = client.get("/users")
    assert r.status_code == 200
    usernames = [u["username"] for u in r.json()]
    assert user["username"] in usernames


def test_admin_can_create_user(admin_session):
    client, csrf, _user = admin_session
    r = client.post(
        "/users",
        headers={"X-XSRF-TOKEN": csrf},
        json={"username": "newanalyst", "password": "NewPassw123!", "role": "analyst"},
    )
    assert r.status_code == 201
    body = r.json()
    assert body["username"] == "newanalyst"
    assert body["role"] == "analyst"
    assert "password" not in body
    assert "password_hash" not in body


def test_create_user_duplicate_username_conflicts(admin_session):
    client, csrf, user = admin_session
    r = client.post(
        "/users",
        headers={"X-XSRF-TOKEN": csrf},
        json={"username": user["username"], "password": "NewPassw123!", "role": "analyst"},
    )
    assert r.status_code == 409


def test_analyst_cannot_create_user(analyst_session):
    client, csrf, _user = analyst_session
    r = client.post(
        "/users",
        headers={"X-XSRF-TOKEN": csrf},
        json={"username": "sneaky", "password": "NewPassw123!", "role": "admin"},
    )
    assert r.status_code == 403


def test_admin_can_disable_another_user(admin_session, make_user):
    client, csrf, _admin = admin_session
    target = make_user(role="analyst")
    r = client.patch(f"/users/{target['id']}", headers={"X-XSRF-TOKEN": csrf}, json={"enabled": False})
    assert r.status_code == 200
    assert r.json()["enabled"] is False


def test_cannot_delete_own_account(admin_session):
    client, csrf, user = admin_session
    r = client.delete(f"/users/{user['id']}", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code == 400


def test_last_admin_cannot_be_demoted(admin_session, isolated_user_service):
    """Only one enabled admin exists (the session owner) — demoting them
    to analyst would leave the system with no admin at all."""
    client, csrf, user = admin_session
    r = client.patch(f"/users/{user['id']}", headers={"X-XSRF-TOKEN": csrf}, json={"role": "analyst"})
    assert r.status_code == 400


def test_last_admin_cannot_be_disabled(admin_session):
    client, csrf, user = admin_session
    r = client.patch(f"/users/{user['id']}", headers={"X-XSRF-TOKEN": csrf}, json={"enabled": False})
    assert r.status_code == 400


def test_demoting_admin_succeeds_when_another_admin_exists(admin_session, make_user):
    client, csrf, user = admin_session
    make_user(role="admin")  # a second enabled admin
    r = client.patch(f"/users/{user['id']}", headers={"X-XSRF-TOKEN": csrf}, json={"role": "analyst"})
    assert r.status_code == 200
    assert r.json()["role"] == "analyst"


def test_admin_can_reset_another_users_password(admin_session, make_user, client):
    admin_client, csrf, _admin = admin_session
    target = make_user(role="analyst")
    r = admin_client.post(
        f"/users/{target['id']}/reset-password",
        headers={"X-XSRF-TOKEN": csrf},
        json={"new_password": "BrandNewPass123!"},
    )
    assert r.status_code == 200

    # New password logs in; old one no longer does.
    r = admin_client.post("/auth/login", data={"username": target["username"], "password": "BrandNewPass123!"})
    assert r.status_code == 200
    r = admin_client.post("/auth/login", data={"username": target["username"], "password": target["password"]})
    assert r.status_code == 401


def test_self_password_change_requires_correct_current_password(admin_session):
    client, csrf, user = admin_session
    r = client.post(
        "/users/me/password",
        headers={"X-XSRF-TOKEN": csrf},
        json={"current_password": "WrongOne123!", "new_password": "AnotherPass123!"},
    )
    assert r.status_code == 400


def test_self_password_change_succeeds_and_new_password_works(admin_session):
    client, csrf, user = admin_session
    r = client.post(
        "/users/me/password",
        headers={"X-XSRF-TOKEN": csrf},
        json={"current_password": user["password"], "new_password": "AnotherPass123!"},
    )
    assert r.status_code == 200

    r = client.post("/auth/login", data={"username": user["username"], "password": "AnotherPass123!"})
    assert r.status_code == 200


def test_analyst_can_change_own_password(analyst_session):
    """Regression guard: previously only admins could self-service change
    a password because /settings/password required the admin role."""
    client, csrf, user = analyst_session
    r = client.post(
        "/users/me/password",
        headers={"X-XSRF-TOKEN": csrf},
        json={"current_password": user["password"], "new_password": "AnalystNewPass123!"},
    )
    assert r.status_code == 200


def test_profile_update_persists_display_name_and_email(admin_session):
    client, csrf, _user = admin_session
    r = client.patch(
        "/users/me/profile",
        headers={"X-XSRF-TOKEN": csrf},
        json={"display_name": "Jane Doe", "email": "jane@example.com"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["display_name"] == "Jane Doe"
    assert body["email"] == "jane@example.com"

    r = client.get("/users/me/profile")
    assert r.json()["display_name"] == "Jane Doe"


@pytest.mark.parametrize("password", ["short", "1234567"])
def test_create_user_rejects_short_password(admin_session, password):
    client, csrf, _user = admin_session
    r = client.post(
        "/users",
        headers={"X-XSRF-TOKEN": csrf},
        json={"username": "weakpwuser", "password": password, "role": "analyst"},
    )
    assert r.status_code == 422
