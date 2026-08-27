"""
Covers two things not exercised by test_alert_syslog_throttle_bypass.py:

1. alert_db_service's migration of alert_channels.channel_type's CHECK
   constraint to allow 'syslog' — a pre-existing alerts.db (created before
   this feature existed) has the OLD constraint baked in at the SQLite
   level; CREATE TABLE IF NOT EXISTS is a no-op against it, so this needs
   its own rebuild-and-copy migration, exercised here against a simulated
   pre-existing database rather than a fresh one.
2. SyslogNotificationChannel.send()'s packet construction (RFC 5424 /
   RFC 3164, UDP / TCP) — no real network calls, socket is faked.
"""
import sqlite3
import socket as socket_module

import pytest

from app.services.alert_db_service import AlertDatabaseService
from app.services.alert_dispatcher import SyslogNotificationChannel


# ---------------------------------------------------------------------------
# Migration: existing pre-syslog database
# ---------------------------------------------------------------------------

def _create_pre_syslog_db(path: str):
    """Simulates a database created before 'syslog' was a valid
    channel_type — the exact old CHECK constraint, with one real channel
    already in it, so the migration must preserve existing data."""
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE alert_channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            channel_type TEXT NOT NULL CHECK(channel_type IN ('email', 'slack', 'webhook', 'pagerduty')),
            config TEXT NOT NULL,
            enabled BOOLEAN DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute(
        "INSERT INTO alert_channels (name, channel_type, config, enabled) VALUES (?, ?, ?, ?)",
        ("existing-slack", "slack", '{"webhook_url": "https://hooks.slack.com/x"}', 1),
    )
    conn.commit()
    conn.close()


def test_migration_preserves_existing_channel_and_allows_syslog(tmp_path):
    db_path = str(tmp_path / "pre_existing_alerts.db")
    _create_pre_syslog_db(db_path)

    # AlertDatabaseService.__init__ runs _init_database(), which must
    # detect the old constraint and migrate it — this is the real thing
    # under test, not a fixture setup step.
    svc = AlertDatabaseService(db_path=db_path)

    channels = svc.get_channels()
    assert len(channels) == 1
    assert channels[0]["name"] == "existing-slack"
    assert channels[0]["channel_type"] == "slack"

    # The actual assertion: syslog is now insertable where it previously
    # would have hit the CHECK constraint.
    new_id = svc.create_channel(name="new-syslog", channel_type="syslog", config={"host": "10.0.0.5"})
    assert svc.get_channel(new_id)["channel_type"] == "syslog"


def test_migration_is_idempotent_across_repeated_instantiation(tmp_path):
    db_path = str(tmp_path / "pre_existing_alerts.db")
    _create_pre_syslog_db(db_path)

    AlertDatabaseService(db_path=db_path)
    # Second instantiation against the now-migrated file must not error
    # (re-running the rebuild against an already-migrated table would be
    # a real bug — the "syslog" in existing_sql check exists to prevent
    # exactly this).
    svc2 = AlertDatabaseService(db_path=db_path)
    assert len(svc2.get_channels()) == 1


def test_fresh_database_allows_syslog_without_any_migration(tmp_path):
    # A brand-new install never hits the migration path at all — the
    # CREATE TABLE statement itself already has the wide constraint.
    svc = AlertDatabaseService(db_path=str(tmp_path / "fresh_alerts.db"))
    new_id = svc.create_channel(name="siem", channel_type="syslog", config={"host": "10.0.0.5"})
    assert svc.get_channel(new_id)["channel_type"] == "syslog"


# ---------------------------------------------------------------------------
# SyslogNotificationChannel — packet construction
# ---------------------------------------------------------------------------

class _FakeUdpSocket:
    def __init__(self, *a, **k):
        self.sent = []
        self.timeout = None

    def settimeout(self, t):
        self.timeout = t

    def sendto(self, data, addr):
        self.sent.append((data, addr))

    def close(self):
        pass


class _FakeTcpSocket:
    def __init__(self):
        self.sent = b""

    def sendall(self, data):
        self.sent += data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_udp_rfc5424_send_success(monkeypatch):
    fake_sock = _FakeUdpSocket()
    monkeypatch.setattr(socket_module, "socket", lambda *a, **k: fake_sock)

    channel = SyslogNotificationChannel()
    ok, err = channel.send(
        config={"host": "10.0.0.5", "port": 514, "protocol": "udp", "facility": "local0", "format": "rfc5424"},
        severity="critical", event_type="attack_detected", message="SQLi blocked",
        event_data={"client_ip": "1.2.3.4"},
    )

    assert ok is True
    assert err is None
    assert len(fake_sock.sent) == 1
    data, addr = fake_sock.sent[0]
    assert addr == ("10.0.0.5", 514)
    packet = data.decode("utf-8")
    # facility local0 (16) * 8 + critical (2) = 130
    assert packet.startswith("<130>1 ")
    assert "cybersentinel-waf cybersentinel - attack_detected -" in packet
    assert "SQLi blocked" in packet
    assert '"client_ip": "1.2.3.4"' in packet


def test_udp_rfc3164_send_success(monkeypatch):
    fake_sock = _FakeUdpSocket()
    monkeypatch.setattr(socket_module, "socket", lambda *a, **k: fake_sock)

    channel = SyslogNotificationChannel()
    ok, err = channel.send(
        config={"host": "10.0.0.5", "format": "rfc3164", "facility": "auth"},
        severity="low", event_type="ddos_detected", message="rate limited",
        event_data={},
    )

    assert ok is True
    packet = fake_sock.sent[0][0].decode("utf-8")
    # facility auth (4) * 8 + low (5) = 37
    assert packet.startswith("<37>")
    assert "cybersentinel[ddos_detected]:" in packet


def test_tcp_send_uses_octet_counting_framing(monkeypatch):
    fake_sock = _FakeTcpSocket()
    monkeypatch.setattr(socket_module, "create_connection", lambda addr, timeout=None: fake_sock)

    channel = SyslogNotificationChannel()
    ok, err = channel.send(
        config={"host": "siem.internal", "port": 6514, "protocol": "tcp"},
        severity="high", event_type="attack_detected", message="test",
        event_data={},
    )

    assert ok is True
    sent = fake_sock.sent
    # RFC 6587 octet-counting: "<len> <message>"
    prefix, _, rest = sent.partition(b" ")
    assert int(prefix) == len(rest)
    assert rest.decode("utf-8").startswith("<")


def test_missing_host_fails_cleanly():
    channel = SyslogNotificationChannel()
    ok, err = channel.send(
        config={}, severity="high", event_type="attack_detected", message="x", event_data={},
    )
    assert ok is False
    assert "host" in err.lower()


def test_unknown_facility_and_severity_fall_back_to_defaults(monkeypatch):
    fake_sock = _FakeUdpSocket()
    monkeypatch.setattr(socket_module, "socket", lambda *a, **k: fake_sock)

    channel = SyslogNotificationChannel()
    ok, err = channel.send(
        config={"host": "10.0.0.5", "facility": "not-a-real-facility"},
        severity="not-a-real-severity", event_type="attack_detected", message="x", event_data={},
    )
    assert ok is True
    packet = fake_sock.sent[0][0].decode("utf-8")
    # local0 (16) default * 8 + info (6) default = 134
    assert packet.startswith("<134>")


def test_send_failure_returns_error_not_raises(monkeypatch):
    def _raise(*a, **k):
        raise OSError("network unreachable")
    monkeypatch.setattr(socket_module, "socket", _raise)

    channel = SyslogNotificationChannel()
    ok, err = channel.send(
        config={"host": "10.0.0.5"}, severity="high", event_type="attack_detected",
        message="x", event_data={},
    )
    assert ok is False
    assert "network unreachable" in err
