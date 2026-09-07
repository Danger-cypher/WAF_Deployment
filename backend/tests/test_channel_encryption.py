"""
Regression tests for audit finding P2-03: alert_channels.config was stored
as plain JSON — real SMTP passwords and webhook URLs readable by anyone
with filesystem access to alerts.db. alert_db_service.py now Fernet-
encrypts it and refuses to create/read a channel's config unencrypted
rather than ever falling back to plaintext.
"""
import sqlite3

import pytest
from cryptography.fernet import Fernet

from app.config.settings import settings
from app.services.alert_db_service import AlertDatabaseService, ChannelEncryptionError


@pytest.fixture
def svc(tmp_path):
    return AlertDatabaseService(db_path=str(tmp_path / "alerts.db"))


def test_config_is_not_stored_as_readable_json(svc, tmp_path):
    channel_id = svc.create_channel(
        name="smtp", channel_type="email",
        config={"smtp_host": "smtp.example.com", "password": "hunter2-super-secret"},
    )
    # Read the raw column directly, bypassing the service entirely — the
    # literal bug: this used to be plain, grep-able JSON.
    conn = sqlite3.connect(svc.db_path)
    raw = conn.execute("SELECT config FROM alert_channels WHERE id = ?", (channel_id,)).fetchone()[0]
    conn.close()
    assert "hunter2-super-secret" not in raw
    assert "smtp.example.com" not in raw


def test_create_and_read_round_trips_the_real_config(svc):
    channel_id = svc.create_channel(
        name="smtp", channel_type="email",
        config={"smtp_host": "smtp.example.com", "password": "hunter2-super-secret"},
    )
    channel = svc.get_channel(channel_id)
    assert channel["config"] == {"smtp_host": "smtp.example.com", "password": "hunter2-super-secret"}


def test_update_re_encrypts_the_new_config(svc):
    channel_id = svc.create_channel(name="wh", channel_type="webhook", config={"url": "https://a.example/x"})
    svc.update_channel(channel_id, config={"url": "https://b.example/y", "secret": "rotated"})
    channel = svc.get_channel(channel_id)
    assert channel["config"] == {"url": "https://b.example/y", "secret": "rotated"}

    conn = sqlite3.connect(svc.db_path)
    raw = conn.execute("SELECT config FROM alert_channels WHERE id = ?", (channel_id,)).fetchone()[0]
    conn.close()
    assert "rotated" not in raw


def test_create_channel_refuses_without_a_key(svc, monkeypatch):
    # svc's own construction already seeded one default channel (with a
    # real key, via the autouse fixture) — this asserts the *attempted*
    # create adds nothing on top of that, not that the DB is empty.
    before = len(svc.get_channels())
    monkeypatch.setattr(settings, "CHANNEL_ENCRYPTION_KEY", "")
    with pytest.raises(ChannelEncryptionError):
        svc.create_channel(name="wh", channel_type="webhook", config={"url": "https://a.example"})
    assert len(svc.get_channels()) == before


def test_get_channel_degrades_gracefully_without_a_key(svc, monkeypatch):
    channel_id = svc.create_channel(name="wh", channel_type="webhook", config={"url": "https://a.example"})
    monkeypatch.setattr(settings, "CHANNEL_ENCRYPTION_KEY", "")
    # Must not raise and must not crash the whole response — the channel
    # itself (name, type, enabled) stays visible; only its config becomes
    # unreadable, with a clear reason attached.
    channel = svc.get_channel(channel_id)
    assert channel["name"] == "wh"
    assert "_encryption_error" in channel["config"]


def test_get_channels_one_bad_row_does_not_hide_the_others(svc):
    good_id = svc.create_channel(name="good", channel_type="webhook", config={"url": "https://a.example"})
    bad_id = svc.create_channel(name="bad", channel_type="webhook", config={"url": "https://b.example"})

    # Corrupt just one row's stored ciphertext directly.
    conn = sqlite3.connect(svc.db_path)
    conn.execute("UPDATE alert_channels SET config = 'not-a-fernet-token' WHERE id = ?", (bad_id,))
    conn.commit()
    conn.close()

    channels = {c["id"]: c for c in svc.get_channels()}
    assert channels[good_id]["config"] == {"url": "https://a.example"}
    assert "_encryption_error" in channels[bad_id]["config"]


def test_wrong_key_cannot_decrypt_a_channel_created_under_a_different_key(svc, monkeypatch):
    channel_id = svc.create_channel(name="wh", channel_type="webhook", config={"url": "https://a.example"})
    monkeypatch.setattr(settings, "CHANNEL_ENCRYPTION_KEY", Fernet.generate_key().decode())
    channel = svc.get_channel(channel_id)
    assert "_encryption_error" in channel["config"]


def test_default_seed_channel_is_encrypted_when_a_key_is_present(tmp_path):
    # AlertDatabaseService's constructor seeds a default webhook channel on
    # a fresh DB — must go through the same encryption path as any other
    # channel, not a raw plaintext INSERT.
    svc = AlertDatabaseService(db_path=str(tmp_path / "fresh.db"))
    channels = svc.get_channels()
    assert len(channels) == 1
    assert channels[0]["config"] == {"url": "http://localhost:8000/alerts/trigger", "method": "POST"}


def test_default_seed_channel_is_skipped_not_written_plaintext_without_a_key(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "CHANNEL_ENCRYPTION_KEY", "")
    svc = AlertDatabaseService(db_path=str(tmp_path / "fresh_nokey.db"))
    # No channel at all — not a plaintext one — is the correct degraded
    # state; an admin can add one normally once a key is configured.
    assert svc.get_channels() == []


def test_legacy_plaintext_row_reads_through_unchanged(tmp_path):
    # Simulates a database written before this fix — a real plaintext
    # config already on disk. Plain JSON parses successfully as JSON, so
    # it comes back exactly as it always did rather than erroring; it only
    # actually gets encrypted the next time it's saved (create/update).
    db_path = str(tmp_path / "legacy.db")
    svc = AlertDatabaseService(db_path=db_path)
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO alert_channels (name, channel_type, config, enabled) VALUES (?, ?, ?, ?)",
        ("legacy-webhook", "webhook", '{"url": "https://plaintext.example"}', 1),
    )
    conn.commit()
    conn.close()

    channels = svc.get_channels()
    legacy = next(c for c in channels if c["name"] == "legacy-webhook")
    assert legacy["config"] == {"url": "https://plaintext.example"}

    # Saving it again must switch it over to real encryption.
    svc.update_channel(legacy["id"], config={"url": "https://plaintext.example", "now": "encrypted"})
    conn = sqlite3.connect(db_path)
    raw = conn.execute("SELECT config FROM alert_channels WHERE id = ?", (legacy["id"],)).fetchone()[0]
    conn.close()
    assert "plaintext.example" not in raw
