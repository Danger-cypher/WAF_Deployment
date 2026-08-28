"""Tests for POST /auth/sso/exchange — the SIEM mint-and-redirect SSO flow."""
import time
import uuid

import jwt
import pytest

from app.config.settings import settings

TEST_SECRET = "unit-test-sso-shared-secret-32-bytes-min"


@pytest.fixture(autouse=True)
def _sso_secret(monkeypatch):
    monkeypatch.setattr(settings, "WAF_SSO_SECRET", TEST_SECRET)


def _mint(
    role="L2-Analyst",
    sub=None,
    email="jane.analyst@example.com",
    name="Jane Analyst",
    iss="cybersentinel-siem",
    aud="cybersentinel-waf",
    purpose="sso_exchange",
    secret=TEST_SECRET,
    ttl=120,
    nbf_skew=-60,
    nonce=None,
    extra=None,
):
    now = int(time.time())
    claims = {
        "iss": iss,
        "aud": aud,
        "sub": sub or f"siem-user-{uuid.uuid4()}",
        "email": email,
        "name": name,
        "role": role,
        "access": "read-write",
        "nonce": nonce or uuid.uuid4().hex,
        "iat": now,
        "nbf": now + nbf_skew,
        "exp": now + ttl,
        "purpose": purpose,
    }
    if extra:
        claims.update(extra)
    return jwt.encode(claims, secret, algorithm="HS256")


def test_new_user_is_jit_provisioned_and_logged_in(client, isolated_user_service):
    token = _mint(role="administrator", email="new.admin@example.com", name="New Admin")
    r = client.post("/auth/sso/exchange", json={"token": token})
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "admin"
    assert "waf_session_v3" in r.cookies

    me = client.get("/auth/me")
    assert me.status_code == 200
    assert me.json()["role"] == "admin"

    user = isolated_user_service.get_by_email_unlinked  # sanity: method exists
    assert callable(user)


def test_role_mapping_least_privilege_for_unknown_role(client):
    token = _mint(role="some-future-siem-role", email="unmapped@example.com")
    r = client.post("/auth/sso/exchange", json={"token": token})
    assert r.status_code == 200
    assert r.json()["role"] == "analyst"


def test_repeat_login_reuses_same_account_via_sub(client, isolated_user_service):
    baseline = len(isolated_user_service.list_users())
    sub = f"siem-user-{uuid.uuid4()}"
    token1 = _mint(sub=sub, role="L1-Analyst")
    r1 = client.post("/auth/sso/exchange", json={"token": token1})
    assert r1.status_code == 200
    username = client.get("/auth/me").json()["username"]

    token2 = _mint(sub=sub, role="L1-Analyst")
    r2 = client.post("/auth/sso/exchange", json={"token": token2})
    assert r2.status_code == 200
    assert client.get("/auth/me").json()["username"] == username

    assert len(isolated_user_service.list_users()) == baseline + 1


def test_role_is_synced_from_siem_on_each_login(client, isolated_user_service):
    sub = f"siem-user-{uuid.uuid4()}"
    r1 = client.post("/auth/sso/exchange", json={"token": _mint(sub=sub, role="L1-Analyst")})
    assert r1.json()["role"] == "analyst"

    r2 = client.post("/auth/sso/exchange", json={"token": _mint(sub=sub, role="administrator")})
    assert r2.status_code == 200
    assert r2.json()["role"] == "admin"

    assert isolated_user_service.get_by_sso_subject(sub)["role"] == "admin"


def test_preexisting_account_adopted_by_email_on_first_sso_login(client, isolated_user_service, make_user):
    baseline = len(isolated_user_service.list_users())
    local_user = make_user(role="analyst")
    isolated_user_service.update_user(local_user["id"], email="shared@example.com")

    token = _mint(email="shared@example.com", role="L2-Analyst")
    r = client.post("/auth/sso/exchange", json={"token": token})
    assert r.status_code == 200
    assert client.get("/auth/me").json()["username"] == local_user["username"]
    assert len(isolated_user_service.list_users()) == baseline + 1


def test_disabled_account_rejected(client, isolated_user_service):
    sub = f"siem-user-{uuid.uuid4()}"
    client.post("/auth/sso/exchange", json={"token": _mint(sub=sub)})
    user = isolated_user_service.get_by_sso_subject(sub)
    isolated_user_service.update_user(user["id"], enabled=False)

    r = client.post("/auth/sso/exchange", json={"token": _mint(sub=sub)})
    assert r.status_code == 403


def test_wrong_audience_rejected(client):
    r = client.post("/auth/sso/exchange", json={"token": _mint(aud="cybersentinel-urlfilter")})
    assert r.status_code == 401


def test_wrong_issuer_rejected(client):
    r = client.post("/auth/sso/exchange", json={"token": _mint(iss="someone-else")})
    assert r.status_code == 401


def test_wrong_signature_rejected(client):
    r = client.post("/auth/sso/exchange", json={"token": _mint(secret="not-the-shared-secret-at-all-32b")})
    assert r.status_code == 401


def test_expired_token_rejected(client):
    # exp is checked with ~60s leeway (matching the SIEM's stated skew
    # tolerance), so must be expired by comfortably more than that.
    r = client.post("/auth/sso/exchange", json={"token": _mint(ttl=-120, nbf_skew=-180)})
    assert r.status_code == 401


def test_not_yet_valid_token_rejected(client):
    r = client.post("/auth/sso/exchange", json={"token": _mint(nbf_skew=300)})
    assert r.status_code == 401


def test_wrong_purpose_rejected(client):
    r = client.post("/auth/sso/exchange", json={"token": _mint(purpose="something-else")})
    assert r.status_code == 401


def test_nonce_replay_rejected(client):
    nonce = uuid.uuid4().hex
    sub = f"siem-user-{uuid.uuid4()}"
    token1 = _mint(sub=sub, nonce=nonce)
    r1 = client.post("/auth/sso/exchange", json={"token": token1})
    assert r1.status_code == 200

    # Same nonce, fresh timestamps otherwise — still a replay of a
    # single-use claim and must be rejected even though the SIEM signed it.
    token2 = _mint(sub=sub, nonce=nonce)
    r2 = client.post("/auth/sso/exchange", json={"token": token2})
    assert r2.status_code == 401


def test_no_shared_secret_configured_rejects_hs256(client, monkeypatch):
    monkeypatch.setattr(settings, "WAF_SSO_SECRET", "")
    r = client.post("/auth/sso/exchange", json={"token": _mint()})
    assert r.status_code == 401
