"""
Covers GET /alerts/channels' secret redaction (_redact_channel_config in
app/routes/alerts.py) — this page is require_any_role (analysts need to
see what channels exist), so anything in a channel's `config` that
functions as a live credential must be masked for a non-admin caller.

Written after a manual review found a real gap: the generic Webhook
channel's own endpoint field is named `url` (WebhookChannelConfig.url),
distinct from Slack's `webhook_url` — only the latter was in the
redaction set, so a Webhook channel's endpoint (which, like a Slack
webhook, commonly carries its own bearer token/signature in the URL
itself) was sent to every analyst in plain text. Each channel type below
is tested for both the admin (full value) and analyst (redacted) view.
"""
import pytest
from fastapi.testclient import TestClient

from app.routes import alerts as alerts_route
from app.services.alert_db_service import AlertDatabaseService
from app.main import app as fastapi_app


@pytest.fixture
def isolated_alerts_db(tmp_path, monkeypatch):
    db = AlertDatabaseService(db_path=str(tmp_path / "alerts_test.db"))
    monkeypatch.setattr(alerts_route, "db", db)
    return db


@pytest.fixture
def client(isolated_user_service, isolated_alerts_db):
    return TestClient(fastapi_app)


def _login(client, username, password):
    r = client.post("/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    csrf = r.cookies.get("XSRF-TOKEN-V3")
    client.cookies.update(r.cookies)
    return csrf


@pytest.mark.parametrize("channel_type,config,secret_keys,visible_keys", [
    ("slack", {"webhook_url": "https://hooks.slack.com/services/T000/B000/xyz", "channel": "#soc"},
     {"webhook_url": "https://hooks.slack.com/services/T000/B000/xyz"}, {"channel": "#soc"}),
    ("email", {
        "smtp_host": "smtp.example.com", "smtp_port": 587, "username": "alerts@example.com",
        "password": "hunter2", "from_addr": "alerts@example.com", "to_addrs": ["soc@example.com"],
    }, {"password": "hunter2"}, {"smtp_host": "smtp.example.com", "smtp_port": 587}),
    ("pagerduty", {"integration_key": "R0ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"},
     {"integration_key": "R0ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"}, {}),
    ("webhook", {"url": "https://hooks.example.com/t/deadbeef-secret-token", "method": "POST", "headers": {"Authorization": "Bearer abc123"}},
     {"url": "https://hooks.example.com/t/deadbeef-secret-token"}, {"method": "POST"}),
    ("syslog", {"host": "siem.internal", "port": 514, "protocol": "udp"},
     {}, {"host": "siem.internal", "port": 514, "protocol": "udp"}),
])
def test_admin_sees_full_config_analyst_sees_redacted(client, isolated_alerts_db, make_user, channel_type, config, secret_keys, visible_keys):
    # _init_database() auto-seeds an internal "webhook" channel of its own
    # (ML engine -> backend alert trigger loopback) — match by the name we
    # gave our own test channel, not channel_type, so that pre-existing
    # row can't be picked up instead of the one this test actually created.
    chan_name = f"test-{channel_type}"
    isolated_alerts_db.create_channel(name=chan_name, channel_type=channel_type, config=config)

    admin = make_user(role="admin")
    _login(client, admin["username"], admin["password"])
    r = client.get("/alerts/channels")
    assert r.status_code == 200, r.text
    admin_chan = next(c for c in r.json() if c["name"] == chan_name)
    for key, value in {**secret_keys, **visible_keys}.items():
        assert admin_chan["config"][key] == value, f"admin should see the real {key}"

    client.cookies.clear()
    analyst = make_user(role="analyst")
    _login(client, analyst["username"], analyst["password"])
    r = client.get("/alerts/channels")
    assert r.status_code == 200, r.text
    analyst_chan = next(c for c in r.json() if c["name"] == chan_name)
    for key in secret_keys:
        assert analyst_chan["config"][key] == "••••••••", f"analyst must not see the real {key}"
    for key, value in visible_keys.items():
        assert analyst_chan["config"][key] == value, f"non-secret field {key} should stay visible to an analyst"
    if "headers" in config:
        assert all(v == "••••••••" for v in analyst_chan["config"]["headers"].values())
