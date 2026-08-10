"""Tests for /auth/* — login, logout, /me, and account-state edge cases."""


def test_login_success_sets_session_and_csrf_cookies(client, make_user):
    user = make_user(role="admin")
    r = client.post("/auth/login", data={"username": user["username"], "password": user["password"]})
    assert r.status_code == 200
    assert r.json()["role"] == "admin"
    assert "waf_session_v3" in r.cookies
    assert "XSRF-TOKEN-V3" in r.cookies


def test_login_wrong_password_rejected(client, make_user):
    user = make_user(role="admin")
    r = client.post("/auth/login", data={"username": user["username"], "password": "WrongPassword123!"})
    assert r.status_code == 401


def test_login_unknown_username_rejected(client):
    r = client.post("/auth/login", data={"username": "nobody", "password": "whatever"})
    assert r.status_code == 401


def test_login_disabled_account_rejected(client, make_user):
    user = make_user(role="analyst", enabled=False)
    r = client.post("/auth/login", data={"username": user["username"], "password": user["password"]})
    assert r.status_code == 401


def test_me_requires_authentication(client):
    r = client.get("/auth/me")
    assert r.status_code == 401


def test_me_returns_current_user_after_login(admin_session):
    client, _csrf, user = admin_session
    r = client.get("/auth/me")
    assert r.status_code == 200
    body = r.json()
    assert body["username"] == user["username"]
    assert body["role"] == "admin"


def test_logout_clears_session(admin_session):
    client, csrf, _user = admin_session
    r = client.post("/auth/logout", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code == 200

    r = client.get("/auth/me")
    assert r.status_code == 401


def test_mutating_request_without_csrf_header_rejected(admin_session):
    client, _csrf, _user = admin_session
    # POST /auth/logout is CSRF-protected; omitting the header should 403.
    r = client.post("/auth/logout")
    assert r.status_code == 403


def test_disabling_account_invalidates_existing_session(admin_session, isolated_user_service):
    """A token issued before an account is disabled must stop working —
    get_current_user() re-checks the account's enabled state on every
    request rather than trusting a JWT until it expires."""
    client, _csrf, user = admin_session

    r = client.get("/auth/me")
    assert r.status_code == 200

    isolated_user_service.update_user(user["id"], enabled=False)

    r = client.get("/auth/me")
    assert r.status_code == 401
