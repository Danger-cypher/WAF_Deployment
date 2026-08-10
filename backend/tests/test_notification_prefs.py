"""Tests for /users/me/notification-preferences (Module 3)."""


def test_default_preferences_are_empty(admin_session):
    client, _csrf, _user = admin_session
    r = client.get("/users/me/notification-preferences")
    assert r.status_code == 200
    assert r.json() == {"muted_severities": [], "muted_event_types": []}


def test_update_preferences_persists(admin_session):
    client, csrf, _user = admin_session
    r = client.patch(
        "/users/me/notification-preferences",
        headers={"X-XSRF-TOKEN": csrf},
        json={"muted_severities": ["low", "info"], "muted_event_types": ["health_check_failed"]},
    )
    assert r.status_code == 200
    assert r.json() == {
        "muted_severities": ["low", "info"],
        "muted_event_types": ["health_check_failed"],
    }

    r = client.get("/users/me/notification-preferences")
    assert r.json()["muted_severities"] == ["low", "info"]


def test_preferences_are_per_user(admin_session, analyst_session):
    admin_client, admin_csrf, _admin = admin_session
    analyst_client, _analyst_csrf, _analyst = analyst_session

    admin_client.patch(
        "/users/me/notification-preferences",
        headers={"X-XSRF-TOKEN": admin_csrf},
        json={"muted_severities": ["critical"], "muted_event_types": []},
    )

    r = analyst_client.get("/users/me/notification-preferences")
    assert r.json()["muted_severities"] == []


def test_invalid_severity_rejected(admin_session):
    client, csrf, _user = admin_session
    r = client.patch(
        "/users/me/notification-preferences",
        headers={"X-XSRF-TOKEN": csrf},
        json={"muted_severities": ["not_a_real_severity"], "muted_event_types": []},
    )
    assert r.status_code == 422
