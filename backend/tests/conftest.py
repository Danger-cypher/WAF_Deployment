"""
Shared pytest fixtures for the backend test suite.

The app's user/auth modules hold a module-level `user_service` singleton
that's imported directly into app.routes.auth and app.routes.users at
import time (`from app.services.user_service import user_service`).
Monkeypatching the singleton in its home module isn't enough to redirect
those — each importing module needs its own local binding patched too.
This keeps every test running against a throwaway SQLite file instead of
the real users.db.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from fastapi.testclient import TestClient

from app.services.user_service import UserService
import app.services.user_service as user_service_module
import app.routes.auth as auth_route
import app.routes.users as users_route
from app.main import app as fastapi_app


@pytest.fixture
def isolated_user_service(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test_users.db")
    fresh_service = UserService(db_path=db_path)

    # A brand-new UserService auto-seeds the legacy "admin"/"analyst"
    # accounts (upgrade-compatibility behaviour from Module 1). Tests
    # exercise their own users via make_user(), so start from a clean
    # slate rather than have two enabled admins skew last-admin-guard
    # assertions.
    for legacy in ("admin", "analyst"):
        existing = fresh_service.get_by_username(legacy)
        if existing:
            fresh_service.update_user(existing["id"], enabled=False)

    monkeypatch.setattr(user_service_module, "user_service", fresh_service)
    monkeypatch.setattr(auth_route, "user_service", fresh_service)
    monkeypatch.setattr(users_route, "user_service", fresh_service)
    return fresh_service


@pytest.fixture
def client(isolated_user_service):
    return TestClient(fastapi_app)


@pytest.fixture
def make_user(isolated_user_service):
    """Factory fixture: make_user(role="admin") -> {"username", "password"}"""
    counter = {"n": 0}

    def _make(role="admin", enabled=True):
        counter["n"] += 1
        username = f"test_{role}_{counter['n']}"
        password = "TestPass123!"
        user = isolated_user_service.create_user(username, password, role)
        if not enabled:
            isolated_user_service.update_user(user, enabled=False)
        return {"username": username, "password": password, "id": user}

    return _make


def _login(client, username, password):
    r = client.post("/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    csrf = r.cookies.get("XSRF-TOKEN-V3")
    client.cookies.update(r.cookies)
    return csrf


@pytest.fixture
def admin_session(client, make_user):
    """A logged-in admin: returns (client, csrf_token, user_dict)."""
    user = make_user(role="admin")
    csrf = _login(client, user["username"], user["password"])
    return client, csrf, user


@pytest.fixture
def analyst_session(client, make_user):
    """A logged-in analyst: returns (client, csrf_token, user_dict)."""
    user = make_user(role="analyst")
    csrf = _login(client, user["username"], user["password"])
    return client, csrf, user
