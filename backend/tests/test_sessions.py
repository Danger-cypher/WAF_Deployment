"""
Covers P1-8 Part B: per-session revoke. session_service.py is Redis-backed;
conftest.py's autouse `_no_real_redis_for_sessions` fixture defaults every
test to a fast "Redis unavailable" (fail-open) state so the rest of the
suite never touches real Redis — the `fake_session_redis` fixture here
overrides that with an in-memory fake to actually exercise session
lifecycle behavior. Fixture setup order means this one's monkeypatch runs
after the autouse default, so `_client` ends up pointing at the fake.
"""
import fnmatch
import time

import pytest
from fastapi.testclient import TestClient

import app.services.session_service as session_service_module
from app.services import session_service
from app.services.auth import decode_token, create_access_token
from app.main import app as fastapi_app


class _FakeSessionRedis:
    def __init__(self):
        self.hashes = {}
        self.ttls = {}

    def hset(self, key, field=None, value=None, mapping=None):
        h = self.hashes.setdefault(key, {})
        if mapping:
            h.update(mapping)
        if field is not None:
            h[field] = value
        return 1

    def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    def expire(self, key, ttl):
        self.ttls[key] = ttl
        return True

    def ttl(self, key):
        return self.ttls.get(key, -1)

    def exists(self, key):
        return 1 if key in self.hashes else 0

    def delete(self, key):
        existed = key in self.hashes
        self.hashes.pop(key, None)
        self.ttls.pop(key, None)
        return 1 if existed else 0

    def scan(self, cursor=0, match=None, count=100):
        keys = [k for k in self.hashes if not match or fnmatch.fnmatch(k, match)]
        return 0, keys


class _RaisingRedis:
    """Simulates Redis being reachable at connect time but erroring on
    individual commands — must still fail open, not raise into the caller."""
    def hset(self, *a, **k):
        raise ConnectionError("boom")

    def exists(self, *a, **k):
        raise ConnectionError("boom")

    def scan(self, *a, **k):
        raise ConnectionError("boom")

    def delete(self, *a, **k):
        raise ConnectionError("boom")


@pytest.fixture
def fake_session_redis(monkeypatch):
    fake = _FakeSessionRedis()
    monkeypatch.setattr(session_service_module, "_client", fake)
    return fake


@pytest.fixture
def isolated_client(isolated_user_service, fake_session_redis):
    return TestClient(fastapi_app)


def _login(client, username, password):
    r = client.post("/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    csrf = r.cookies.get("XSRF-TOKEN-V3")
    client.cookies.update(r.cookies)
    return csrf


# ---------------------------------------------------------------------------
# session_service.py — unit tests
# ---------------------------------------------------------------------------

def test_create_session_stores_metadata_and_ttl(fake_session_redis):
    sid = session_service.create_session("alice", "10.0.0.5", "curl/8.0", ttl_seconds=3600)
    assert sid is not None
    key = f"session:alice:{sid}"
    assert fake_session_redis.hashes[key]["ip"] == "10.0.0.5"
    assert fake_session_redis.hashes[key]["user_agent"] == "curl/8.0"
    assert fake_session_redis.ttls[key] == 3600


def test_is_session_active_true_for_live_session(fake_session_redis):
    sid = session_service.create_session("alice", "10.0.0.5", "curl", 3600)
    assert session_service.is_session_active("alice", sid) is True


def test_is_session_active_false_for_unknown_session(fake_session_redis):
    assert session_service.is_session_active("alice", "not-a-real-sid") is False


def test_is_session_active_touches_last_seen_at(fake_session_redis):
    sid = session_service.create_session("alice", "10.0.0.5", "curl", 3600)
    original = fake_session_redis.hashes[f"session:alice:{sid}"]["last_seen_at"]
    time.sleep(0.01)
    session_service.is_session_active("alice", sid)
    updated = fake_session_redis.hashes[f"session:alice:{sid}"]["last_seen_at"]
    assert updated >= original


def test_revoke_session_deletes_record(fake_session_redis):
    sid = session_service.create_session("alice", "10.0.0.5", "curl", 3600)
    assert session_service.revoke_session("alice", sid) is True
    assert session_service.is_session_active("alice", sid) is False


def test_revoke_nonexistent_session_returns_false(fake_session_redis):
    assert session_service.revoke_session("alice", "ghost") is False


def test_list_sessions_returns_only_that_users_sessions(fake_session_redis):
    sid_a = session_service.create_session("alice", "10.0.0.5", "curl", 3600)
    session_service.create_session("bob", "10.0.0.6", "curl", 3600)

    sessions = session_service.list_sessions("alice")
    assert len(sessions) == 1
    assert sessions[0]["session_id"] == sid_a
    assert sessions[0]["ip"] == "10.0.0.5"


def test_list_sessions_excludes_revoked(fake_session_redis):
    sid1 = session_service.create_session("alice", "10.0.0.5", "curl", 3600)
    sid2 = session_service.create_session("alice", "10.0.0.6", "curl", 3600)
    session_service.revoke_session("alice", sid1)

    sessions = session_service.list_sessions("alice")
    assert [s["session_id"] for s in sessions] == [sid2]


# ---------------------------------------------------------------------------
# session_service.py — Redis unavailable / erroring (fail-open)
# ---------------------------------------------------------------------------

def test_create_session_returns_none_when_redis_unavailable(monkeypatch):
    monkeypatch.setattr(session_service_module, "_client", None)
    monkeypatch.setattr(session_service_module, "_client_checked_at", time.monotonic())
    assert session_service.create_session("alice", "10.0.0.5", "curl", 3600) is None


def test_is_session_active_fails_open_when_redis_unavailable(monkeypatch):
    monkeypatch.setattr(session_service_module, "_client", None)
    monkeypatch.setattr(session_service_module, "_client_checked_at", time.monotonic())
    assert session_service.is_session_active("alice", "any-sid") is True


def test_list_sessions_empty_when_redis_unavailable(monkeypatch):
    monkeypatch.setattr(session_service_module, "_client", None)
    monkeypatch.setattr(session_service_module, "_client_checked_at", time.monotonic())
    assert session_service.list_sessions("alice") == []


def test_revoke_session_false_when_redis_unavailable(monkeypatch):
    monkeypatch.setattr(session_service_module, "_client", None)
    monkeypatch.setattr(session_service_module, "_client_checked_at", time.monotonic())
    assert session_service.revoke_session("alice", "any-sid") is False


def test_is_session_active_fails_open_on_redis_exception(monkeypatch):
    monkeypatch.setattr(session_service_module, "_client", _RaisingRedis())
    assert session_service.is_session_active("alice", "any-sid") is True


def test_create_session_returns_none_on_redis_exception(monkeypatch):
    monkeypatch.setattr(session_service_module, "_client", _RaisingRedis())
    assert session_service.create_session("alice", "10.0.0.5", "curl", 3600) is None


# ---------------------------------------------------------------------------
# decode_token() — backward compatibility with pre-feature tokens
# ---------------------------------------------------------------------------

def test_decode_token_without_sid_claim_skips_session_check(isolated_user_service, fake_session_redis):
    """A token minted before this feature existed has no 'sid' claim —
    decode_token() must authenticate it exactly as before, never trying to
    look up a session record that was never created."""
    user = isolated_user_service.create_user("legacy_user", "TestPass123!", "admin")
    row = isolated_user_service.get_by_id(user)
    token = create_access_token(data={"sub": "legacy_user", "role": "admin", "tv": row["session_version"]})

    token_data = decode_token(token)
    assert token_data is not None
    assert token_data.session_id is None


# ---------------------------------------------------------------------------
# Route-level: login mints a real session, self-service list/revoke
# ---------------------------------------------------------------------------

def test_login_creates_a_listable_session(isolated_client, make_user):
    client = isolated_client
    user = make_user(role="admin")
    _login(client, user["username"], user["password"])

    r = client.get("/users/me/sessions")
    assert r.status_code == 200
    sessions = r.json()
    assert len(sessions) == 1
    assert sessions[0]["is_current"] is True


def test_two_logins_produce_two_independent_sessions(isolated_client, make_user, fake_session_redis):
    user = make_user(role="admin")

    client_a = isolated_client
    _login(client_a, user["username"], user["password"])

    client_b = TestClient(fastapi_app)
    _login(client_b, user["username"], user["password"])

    sessions = client_a.get("/users/me/sessions").json()
    assert len(sessions) == 2
    # Exactly one of the two listed sessions is "current" from client_a's
    # point of view — the other belongs to client_b's separate login.
    assert sum(1 for s in sessions if s["is_current"]) == 1


def test_revoking_one_session_does_not_affect_the_other(isolated_client, make_user):
    user = make_user(role="admin")

    client_a = isolated_client
    _login(client_a, user["username"], user["password"])

    client_b = TestClient(fastapi_app)
    _login(client_b, user["username"], user["password"])

    sessions = client_a.get("/users/me/sessions").json()
    other_session = next(s for s in sessions if not s["is_current"])

    csrf_a = client_a.cookies.get("XSRF-TOKEN-V3")
    r = client_a.delete(f"/users/me/sessions/{other_session['session_id']}", headers={"X-XSRF-TOKEN": csrf_a})
    assert r.status_code == 200

    # client_b's own session is now dead...
    assert client_b.get("/auth/me").status_code == 401
    # ...but client_a's own session is completely unaffected.
    assert client_a.get("/auth/me").status_code == 200


def test_revoking_own_current_session_logs_you_out(isolated_client, make_user):
    client = isolated_client
    user = make_user(role="admin")
    csrf = _login(client, user["username"], user["password"])

    current = next(s for s in client.get("/users/me/sessions").json() if s["is_current"])
    r = client.delete(f"/users/me/sessions/{current['session_id']}", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code == 200

    assert client.get("/auth/me").status_code == 401


def test_revoke_unknown_session_id_404s(isolated_client, make_user):
    client = isolated_client
    user = make_user(role="admin")
    csrf = _login(client, user["username"], user["password"])

    r = client.delete("/users/me/sessions/does-not-exist", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Route-level: admin managing another user's sessions
# ---------------------------------------------------------------------------

def test_admin_can_list_and_revoke_another_users_session(isolated_client, make_user):
    admin = make_user(role="admin")
    analyst = make_user(role="analyst")

    analyst_client = TestClient(fastapi_app)
    _login(analyst_client, analyst["username"], analyst["password"])

    admin_client = isolated_client
    admin_csrf = _login(admin_client, admin["username"], admin["password"])

    r = admin_client.get(f"/users/{analyst['id']}/sessions")
    assert r.status_code == 200
    sessions = r.json()
    assert len(sessions) == 1
    assert sessions[0]["is_current"] is False  # it's the analyst's session, not the admin's

    r = admin_client.delete(
        f"/users/{analyst['id']}/sessions/{sessions[0]['session_id']}",
        headers={"X-XSRF-TOKEN": admin_csrf},
    )
    assert r.status_code == 200
    assert analyst_client.get("/auth/me").status_code == 401


def test_analyst_forbidden_from_managing_other_users_sessions(isolated_client, make_user):
    admin = make_user(role="admin")
    analyst = make_user(role="analyst")
    analyst_client = isolated_client
    _login(analyst_client, analyst["username"], analyst["password"])

    r = analyst_client.get(f"/users/{admin['id']}/sessions")
    assert r.status_code == 403


def test_admin_session_route_404s_for_unknown_user(isolated_client, make_user):
    admin = make_user(role="admin")
    csrf = _login(isolated_client, admin["username"], admin["password"])

    r = isolated_client.get("/users/99999/sessions")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Logout hardening: server-side revocation, not just cookie deletion
# ---------------------------------------------------------------------------

def test_logout_revokes_the_session_server_side(isolated_client, make_user):
    client = isolated_client
    user = make_user(role="admin")
    csrf = _login(client, user["username"], user["password"])

    # Capture the raw session cookie value before logging out.
    raw_session_cookie = client.cookies.get("waf_session_v3")
    assert raw_session_cookie

    client.post("/auth/logout", headers={"X-XSRF-TOKEN": csrf})

    # Reusing the OLD cookie value directly (bypassing the client's own
    # cookie jar, which already dropped it) must now be rejected — proving
    # server-side revocation actually happened, not just a client-side
    # cookie deletion that a saved/leaked copy of the old value could
    # trivially ignore.
    fresh_client = TestClient(fastapi_app)
    fresh_client.cookies.set("waf_session_v3", raw_session_cookie)
    r = fresh_client.get("/auth/me")
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# WebSocket: a revoked session can't open a NEW connection
# ---------------------------------------------------------------------------

def test_revoked_session_cannot_open_new_websocket_connection(isolated_client, make_user):
    client = isolated_client
    user = make_user(role="admin")
    csrf = _login(client, user["username"], user["password"])
    raw_session_cookie = client.cookies.get("waf_session_v3")

    current = next(s for s in client.get("/users/me/sessions").json() if s["is_current"])
    client.delete(f"/users/me/sessions/{current['session_id']}", headers={"X-XSRF-TOKEN": csrf})

    from starlette.testclient import WebSocketDisconnect

    fresh_client = TestClient(fastapi_app)
    fresh_client.cookies.set("waf_session_v3", raw_session_cookie)
    with pytest.raises(WebSocketDisconnect):
        with fresh_client.websocket_connect("/logs/stream") as ws:
            ws.receive_text()
