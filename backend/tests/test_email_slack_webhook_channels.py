"""
Coverage for the Email, Slack, and Webhook notification channels
(alert_dispatcher.py) — previously the only channel with any test coverage
at all was Syslog. Written after a manual review turned up three real
issues, each covered here by a test that fails on the pre-fix code:

1. EmailNotificationChannel leaked its SMTP connection whenever login() or
   sendmail() raised (e.g. a bad password) — the exception path returned
   before server.quit() ever ran.
2. Email's and Slack's json.dumps(event_data, ...) calls had no default=str
   fallback (Syslog's did) — a single non-JSON-native value anywhere in
   event_data (a raw datetime, say) raised TypeError and silently failed
   the ENTIRE send, config and network reachability notwithstanding.
3. Webhook's requests.post(..., json=payload) has the identical gap —
   requests' own json= encoder has no default= hook either.
"""
import pytest
from datetime import datetime

from app.services import alert_dispatcher
from app.services.alert_dispatcher import (
    EmailNotificationChannel, SlackNotificationChannel, WebhookNotificationChannel,
)


# ---------------------------------------------------------------------------
# Email / SMTP
# ---------------------------------------------------------------------------

class _FakeSMTP:
    """Records every call made on it; instances are also collected on the
    class so a test can assert on the exact object dispatch created."""
    instances = []

    def __init__(self, host, port, timeout=None):
        self.host, self.port, self.timeout = host, port, timeout
        self.calls = []
        self.quit_called = False
        _FakeSMTP.instances.append(self)

    def starttls(self):
        self.calls.append("starttls")

    def login(self, username, password):
        self.calls.append(("login", username, password))

    def sendmail(self, from_addr, to_addrs, message):
        self.calls.append(("sendmail", from_addr, to_addrs))

    def quit(self):
        self.quit_called = True


class _FakeSMTPAuthFails(_FakeSMTP):
    def login(self, username, password):
        raise Exception("535 authentication failed")


@pytest.fixture(autouse=True)
def _reset_fake_smtp():
    _FakeSMTP.instances = []
    yield


EMAIL_CONFIG = {
    "smtp_host": "smtp.example.com", "smtp_port": 587, "username": "alerts@example.com",
    "password": "hunter2", "from_addr": "alerts@example.com", "to_addrs": ["soc@example.com"],
    "use_tls": True, "use_ssl": False,
}


def test_email_success_uses_starttls_login_and_sendmail(monkeypatch):
    monkeypatch.setattr(alert_dispatcher.smtplib, "SMTP", _FakeSMTP)
    channel = EmailNotificationChannel()

    ok, err = channel.send(EMAIL_CONFIG, "critical", "attack_detected", "SQLi blocked", {"client_ip": "1.2.3.4"})

    assert ok is True and err is None
    server = _FakeSMTP.instances[0]
    assert server.host == "smtp.example.com" and server.port == 587
    assert "starttls" in server.calls
    assert ("login", "alerts@example.com", "hunter2") in server.calls
    assert any(c[0] == "sendmail" and c[1] == "alerts@example.com" and c[2] == ["soc@example.com"] for c in server.calls)
    assert server.quit_called is True


def test_email_use_ssl_selects_smtp_ssl_and_skips_starttls(monkeypatch):
    monkeypatch.setattr(alert_dispatcher.smtplib, "SMTP_SSL", _FakeSMTP)
    channel = EmailNotificationChannel()

    ok, err = channel.send({**EMAIL_CONFIG, "use_ssl": True, "smtp_port": 465}, "low", "ddos_detected", "msg", {})

    assert ok is True
    server = _FakeSMTP.instances[0]
    assert server.port == 465
    assert "starttls" not in server.calls  # SMTP_SSL is already encrypted end to end


def test_email_missing_required_fields_fails_without_ever_connecting(monkeypatch):
    monkeypatch.setattr(alert_dispatcher.smtplib, "SMTP", _FakeSMTP)
    channel = EmailNotificationChannel()

    ok, err = channel.send({"smtp_host": "smtp.example.com"}, "high", "attack_detected", "msg", {})

    assert ok is False
    assert "Missing" in err
    assert _FakeSMTP.instances == []


def test_email_auth_failure_still_closes_the_connection(monkeypatch):
    """Regression guard for the resource leak: login() raising must not
    skip quit()."""
    monkeypatch.setattr(alert_dispatcher.smtplib, "SMTP", _FakeSMTPAuthFails)
    channel = EmailNotificationChannel()

    ok, err = channel.send(EMAIL_CONFIG, "high", "attack_detected", "msg", {})

    assert ok is False
    assert "authentication failed" in err
    assert _FakeSMTPAuthFails.instances[0].quit_called is True


def test_email_non_json_native_event_data_does_not_fail_the_whole_send(monkeypatch):
    """Regression guard: a raw datetime anywhere in event_data must not
    raise TypeError out of json.dumps and abort a send that was otherwise
    completely fine (valid config, reachable server)."""
    monkeypatch.setattr(alert_dispatcher.smtplib, "SMTP", _FakeSMTP)
    channel = EmailNotificationChannel()

    ok, err = channel.send(EMAIL_CONFIG, "high", "attack_detected", "msg", {"seen_at": datetime(2026, 8, 31, 12, 0, 0)})

    assert ok is True, err
    assert _FakeSMTP.instances[0].quit_called is True


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status_code=200, text="ok"):
        self.status_code = status_code
        self.text = text


def test_slack_success(monkeypatch):
    captured = {}

    def fake_post(url, json=None, timeout=None, **kwargs):
        captured["url"], captured["json"] = url, json
        return _FakeResponse(200)

    monkeypatch.setattr(alert_dispatcher.requests, "post", fake_post)
    channel = SlackNotificationChannel()

    ok, err = channel.send(
        {"webhook_url": "https://hooks.slack.com/services/T000/B000/xyz"},
        "critical", "attack_detected", "SQLi blocked", {"client_ip": "1.2.3.4"},
    )

    assert ok is True and err is None
    assert captured["url"] == "https://hooks.slack.com/services/T000/B000/xyz"
    assert captured["json"]["attachments"][0]["color"] == "#dc2626"  # critical


def test_slack_missing_webhook_url():
    channel = SlackNotificationChannel()
    ok, err = channel.send({}, "high", "attack_detected", "msg", {})
    assert ok is False
    assert "Missing Slack Webhook URL" in err


def test_slack_ssrf_blocked_url_never_calls_requests(monkeypatch):
    called = []
    monkeypatch.setattr(alert_dispatcher.requests, "post", lambda *a, **k: called.append(1))
    channel = SlackNotificationChannel()

    ok, err = channel.send({"webhook_url": "http://169.254.169.254/latest/meta-data/"}, "high", "attack_detected", "msg", {})

    assert ok is False
    assert "non-public address" in err
    assert called == []


def test_slack_non_200_response_reports_status_and_body(monkeypatch):
    monkeypatch.setattr(alert_dispatcher.requests, "post", lambda *a, **k: _FakeResponse(403, "invalid_token"))
    channel = SlackNotificationChannel()

    ok, err = channel.send({"webhook_url": "https://hooks.slack.com/services/x"}, "high", "attack_detected", "msg", {})

    assert ok is False
    assert "403" in err and "invalid_token" in err


def test_slack_non_json_native_event_data_does_not_fail_the_whole_send(monkeypatch):
    monkeypatch.setattr(alert_dispatcher.requests, "post", lambda *a, **k: _FakeResponse(200))
    channel = SlackNotificationChannel()

    ok, err = channel.send(
        {"webhook_url": "https://hooks.slack.com/services/x"}, "high", "attack_detected", "msg",
        {"seen_at": datetime(2026, 8, 31, 12, 0, 0)},
    )

    assert ok is True, err


# ---------------------------------------------------------------------------
# Generic Webhook
# ---------------------------------------------------------------------------

def test_webhook_success_posts_valid_json_body(monkeypatch):
    import json as json_module
    captured = {}

    def fake_post(url, data=None, headers=None, timeout=None, verify=None, **kwargs):
        captured.update(url=url, data=data, headers=headers, verify=verify)
        return _FakeResponse(200)

    monkeypatch.setattr(alert_dispatcher.requests, "post", fake_post)
    channel = WebhookNotificationChannel()

    ok, err = channel.send({"url": "https://example.com/hook"}, "critical", "attack_detected", "SQLi blocked", {"client_ip": "1.2.3.4"})

    assert ok is True and err is None
    assert captured["verify"] is True
    assert captured["headers"]["Content-Type"] == "application/json"
    body = json_module.loads(captured["data"])  # must be a real, parseable JSON string
    assert body["event_type"] == "attack_detected"
    assert body["event_data"]["client_ip"] == "1.2.3.4"


def test_webhook_put_method_dispatches_to_requests_put(monkeypatch):
    called = {"hit": False}

    def fake_put(*a, **k):
        called["hit"] = True
        return _FakeResponse(200)

    monkeypatch.setattr(alert_dispatcher.requests, "put", fake_put)
    monkeypatch.setattr(alert_dispatcher.requests, "post", lambda *a, **k: pytest.fail("should have used PUT"))
    channel = WebhookNotificationChannel()

    ok, _ = channel.send({"url": "https://example.com/hook", "method": "PUT"}, "low", "ddos_detected", "msg", {})

    assert ok is True
    assert called["hit"] is True


def test_webhook_missing_url():
    channel = WebhookNotificationChannel()
    ok, err = channel.send({}, "high", "attack_detected", "msg", {})
    assert ok is False
    assert "Missing Webhook URL" in err


def test_webhook_ssrf_blocked_url_never_calls_requests(monkeypatch):
    called = []
    monkeypatch.setattr(alert_dispatcher.requests, "post", lambda *a, **k: called.append(1))
    channel = WebhookNotificationChannel()

    ok, err = channel.send({"url": "http://127.0.0.1:8000/internal"}, "high", "attack_detected", "msg", {})

    assert ok is False
    assert "non-public address" in err
    assert called == []


def test_webhook_non_2xx_response_reports_status_and_body(monkeypatch):
    monkeypatch.setattr(alert_dispatcher.requests, "post", lambda *a, **k: _FakeResponse(500, "internal error"))
    channel = WebhookNotificationChannel()

    ok, err = channel.send({"url": "https://example.com/hook"}, "high", "attack_detected", "msg", {})

    assert ok is False
    assert "500" in err and "internal error" in err


def test_webhook_non_json_native_event_data_does_not_fail_the_whole_send(monkeypatch):
    monkeypatch.setattr(alert_dispatcher.requests, "post", lambda *a, **k: _FakeResponse(200))
    channel = WebhookNotificationChannel()

    ok, err = channel.send(
        {"url": "https://example.com/hook"}, "high", "attack_detected", "msg",
        {"seen_at": datetime(2026, 8, 31, 12, 0, 0)},
    )

    assert ok is True, err
