"""
Tests for backup_service.py and its routes (system.py: /system/backups*) —
replaces the old, stale backup_waf_config.sh with something actually
wired into this deployment, tested end-to-end: create, list, download,
restore (including the nginx-validation-failure rollback path), delete.

Also covers audit finding P2-08: these archives bundle users.db/api_keys.db
(password/key hashes), yet were written to disk in plain tar.gz form.
backup_service.py now Fernet-encrypts every archive and refuses to
create/restore one at all without a valid BACKUP_ENCRYPTION_KEY, rather
than ever silently falling back to writing one unencrypted.
"""
import os
import tarfile
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app.config.settings import settings
from app.services import db_service
from app.services import backup_service
from app.services import nginx_manager
from app.main import app as fastapi_app


@pytest.fixture(autouse=True)
def _backup_encryption_key(monkeypatch):
    """Every existing test in this file predates encryption and expects
    create/restore to just work — give them a real key so they keep
    testing what they were written to test. The key-*missing* behavior
    gets its own tests further down, which override this back to "".
    """
    monkeypatch.setattr(settings, "BACKUP_ENCRYPTION_KEY", Fernet.generate_key().decode())


@pytest.fixture
def isolated_db_service(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test_backups.db")
    monkeypatch.setattr(db_service, "DB_FILE", db_path)
    db_service.init_db()
    return db_service


@pytest.fixture
def isolated_backup_paths(tmp_path, monkeypatch):
    """Points backup_service at a throwaway nginx/config/data tree instead
    of the real /etc/nginx and backend/app/{config,data}, with a couple of
    real files in each so a created archive has something to assert on."""
    nginx_dir = tmp_path / "nginx"
    config_dir = tmp_path / "config"
    data_dir = tmp_path / "data"
    backup_dir = data_dir / "backups"
    for d in (nginx_dir, config_dir, data_dir):
        d.mkdir(parents=True, exist_ok=True)
    (nginx_dir / "nginx.conf").write_text("http {}\n")
    (config_dir / "false_positives.db").write_text("fake-db-content")
    (data_dir / "users.db").write_text("fake-users-db")

    monkeypatch.setattr(backup_service, "NGINX_DIR", str(nginx_dir))
    monkeypatch.setattr(backup_service, "CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(backup_service, "DATA_DIR", str(data_dir))
    monkeypatch.setattr(backup_service, "BACKUP_DIR", str(backup_dir))
    return {"nginx": nginx_dir, "config": config_dir, "data": data_dir, "backup_dir": backup_dir}


@pytest.fixture
def client(isolated_user_service, isolated_db_service):
    return TestClient(fastapi_app)


# ---------------------------------------------------------------------------
# backup_service.py — direct unit tests
# ---------------------------------------------------------------------------

def test_create_backup_produces_archive_with_expected_trees(isolated_db_service, isolated_backup_paths):
    result = backup_service.create_backup(triggered_by="tester", trigger_type="manual")

    assert result["filename"].endswith(".tar.gz.enc")
    archive_path = os.path.join(isolated_backup_paths["backup_dir"], result["filename"])
    assert os.path.exists(archive_path)

    with backup_service._open_encrypted_tar(archive_path) as tar:
        names = tar.getnames()
    assert any(n.startswith("nginx/") or n == "nginx/nginx.conf" for n in names)
    assert any("config/false_positives.db" in n for n in names)
    assert any("data/users.db" in n for n in names)
    # The backups directory itself must never be embedded — would recurse.
    assert not any(n.startswith("data/backups") for n in names)

    rows = backup_service.list_backups()
    assert len(rows) == 1
    assert rows[0]["filename"] == result["filename"]
    assert rows[0]["triggered_by"] == "tester"
    assert rows[0]["trigger_type"] == "manual"


def test_get_backup_archive_path_returns_none_for_missing_id(isolated_db_service, isolated_backup_paths):
    assert backup_service.get_backup_archive_path(9999) is None


def test_get_backup_archive_path_returns_none_if_file_deleted_out_of_band(isolated_db_service, isolated_backup_paths):
    result = backup_service.create_backup(triggered_by="tester")
    archive_path = os.path.join(isolated_backup_paths["backup_dir"], result["filename"])
    os.remove(archive_path)
    assert backup_service.get_backup_archive_path(result["id"]) is None


def test_delete_backup_removes_record_and_file(isolated_db_service, isolated_backup_paths):
    result = backup_service.create_backup(triggered_by="tester")
    archive_path = os.path.join(isolated_backup_paths["backup_dir"], result["filename"])
    assert os.path.exists(archive_path)

    ok, _ = backup_service.delete_backup(result["id"])
    assert ok is True
    assert not os.path.exists(archive_path)
    assert backup_service.get_backup_archive_path(result["id"]) is None


def test_delete_backup_missing_id_returns_false(isolated_db_service, isolated_backup_paths):
    ok, msg = backup_service.delete_backup(12345)
    assert ok is False


def test_restore_backup_applies_config_and_data(isolated_db_service, isolated_backup_paths, monkeypatch):
    monkeypatch.setattr(nginx_manager, "test_nginx_config", lambda: (True, ""))
    monkeypatch.setattr(nginx_manager, "reload_nginx", lambda: True)

    result = backup_service.create_backup(triggered_by="tester")

    # Mutate the "live" files after the backup, so restore has something
    # real to overwrite back.
    (isolated_backup_paths["config"] / "false_positives.db").write_text("MUTATED-AFTER-BACKUP")
    (isolated_backup_paths["data"] / "users.db").write_text("MUTATED-AFTER-BACKUP")

    ok, message = backup_service.restore_backup(result["id"], triggered_by="tester")
    assert ok is True
    assert "safety snapshot" in message.lower()

    assert (isolated_backup_paths["config"] / "false_positives.db").read_text() == "fake-db-content"
    assert (isolated_backup_paths["data"] / "users.db").read_text() == "fake-users-db"

    # A pre-restore safety snapshot must exist alongside the original and
    # the one restore_backup's own create_backup call for staging created.
    rows = backup_service.list_backups()
    trigger_types = {r["trigger_type"] for r in rows}
    assert "pre_restore_safety" in trigger_types


def test_restore_backup_rolls_back_nginx_on_validation_failure(isolated_db_service, isolated_backup_paths, monkeypatch):
    monkeypatch.setattr(nginx_manager, "test_nginx_config", lambda: (True, ""))
    monkeypatch.setattr(nginx_manager, "reload_nginx", lambda: True)
    result = backup_service.create_backup(triggered_by="tester")  # good nginx.conf snapshot

    # Simulate the live nginx.conf having drifted to something the restore
    # will bring back, and simulate that restored config being invalid.
    (isolated_backup_paths["nginx"] / "nginx.conf").write_text("CURRENT-LIVE-CONFIG")

    def fail_once():
        return False, "syntax error on line 1"

    monkeypatch.setattr(nginx_manager, "test_nginx_config", fail_once)

    ok, message = backup_service.restore_backup(result["id"], triggered_by="tester")
    assert ok is False
    assert "rolled back" in message.lower()
    # Rolled back to what was live immediately before this restore attempt
    # (captured by restore_backup's own pre-restore safety snapshot), not
    # to the original backup's (different) content.
    assert (isolated_backup_paths["nginx"] / "nginx.conf").read_text() == "CURRENT-LIVE-CONFIG"


def test_restore_backup_missing_id_fails_cleanly(isolated_db_service, isolated_backup_paths):
    ok, message = backup_service.restore_backup(99999, triggered_by="tester")
    assert ok is False
    assert "not found" in message.lower()


# ---------------------------------------------------------------------------
# /system/backups* routes
# ---------------------------------------------------------------------------

def test_create_backup_route_requires_admin(client, analyst_session, isolated_backup_paths):
    client, csrf, _ = analyst_session
    r = client.post("/system/backups", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code == 403


def test_create_and_list_backup_route(client, admin_session, isolated_backup_paths):
    client, csrf, _ = admin_session
    r = client.post("/system/backups", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code == 200, r.text
    filename = r.json()["filename"]

    r2 = client.get("/system/backups")
    assert r2.status_code == 200
    assert any(b["filename"] == filename for b in r2.json())


def test_download_backup_route(client, admin_session, isolated_backup_paths):
    client, csrf, _ = admin_session
    r = client.post("/system/backups", headers={"X-XSRF-TOKEN": csrf})
    backup_id = r.json()["id"]

    r2 = client.get(f"/system/backups/{backup_id}/download")
    assert r2.status_code == 200
    # No longer application/gzip — the bytes are a Fernet token now, not a
    # gzip stream a client could just gunzip.
    assert r2.headers["content-type"] == "application/octet-stream"


def test_download_missing_backup_route_404s(client, admin_session, isolated_backup_paths):
    client, csrf, _ = admin_session
    r = client.get("/system/backups/99999/download")
    assert r.status_code == 404


def test_restore_route_requires_confirm_true(client, admin_session, isolated_backup_paths):
    client, csrf, _ = admin_session
    r = client.post("/system/backups", headers={"X-XSRF-TOKEN": csrf})
    backup_id = r.json()["id"]

    r2 = client.post(
        f"/system/backups/{backup_id}/restore",
        headers={"X-XSRF-TOKEN": csrf},
        json={"confirm": False},
    )
    assert r2.status_code == 400

    r3 = client.post(
        f"/system/backups/{backup_id}/restore",
        headers={"X-XSRF-TOKEN": csrf},
        json={},  # confirm defaults to False
    )
    assert r3.status_code == 400


def test_restore_route_succeeds_with_confirm(client, admin_session, isolated_backup_paths, monkeypatch):
    monkeypatch.setattr(nginx_manager, "test_nginx_config", lambda: (True, ""))
    monkeypatch.setattr(nginx_manager, "reload_nginx", lambda: True)

    client, csrf, _ = admin_session
    r = client.post("/system/backups", headers={"X-XSRF-TOKEN": csrf})
    backup_id = r.json()["id"]

    r2 = client.post(
        f"/system/backups/{backup_id}/restore",
        headers={"X-XSRF-TOKEN": csrf},
        json={"confirm": True},
    )
    assert r2.status_code == 200, r2.text


def test_delete_backup_route(client, admin_session, isolated_backup_paths):
    client, csrf, _ = admin_session
    r = client.post("/system/backups", headers={"X-XSRF-TOKEN": csrf})
    backup_id = r.json()["id"]

    r2 = client.delete(f"/system/backups/{backup_id}", headers={"X-XSRF-TOKEN": csrf})
    assert r2.status_code == 200

    r3 = client.get(f"/system/backups/{backup_id}/download")
    assert r3.status_code == 404


# ---------------------------------------------------------------------------
# P2-08 — archives are encrypted at rest, and refuse to exist without a key
# ---------------------------------------------------------------------------

def test_archive_on_disk_is_not_a_readable_tar_gz(isolated_db_service, isolated_backup_paths):
    # The literal bug: before this fix, the bytes on disk were a plain
    # tar.gz — openable by anyone with filesystem access, no key needed.
    result = backup_service.create_backup(triggered_by="tester")
    archive_path = os.path.join(isolated_backup_paths["backup_dir"], result["filename"])
    with pytest.raises(tarfile.ReadError):
        with tarfile.open(archive_path, "r:gz"):
            pass


def test_create_backup_refuses_without_a_key(isolated_db_service, isolated_backup_paths, monkeypatch):
    monkeypatch.setattr(settings, "BACKUP_ENCRYPTION_KEY", "")
    with pytest.raises(backup_service.BackupEncryptionError):
        backup_service.create_backup(triggered_by="tester")
    # Nothing partially written — no archive, no catalogued record.
    assert backup_service.list_backups() == []
    assert not os.listdir(isolated_backup_paths["backup_dir"]) if os.path.isdir(isolated_backup_paths["backup_dir"]) else True


def test_create_backup_refuses_with_an_invalid_key(isolated_db_service, isolated_backup_paths, monkeypatch):
    monkeypatch.setattr(settings, "BACKUP_ENCRYPTION_KEY", "not-a-real-fernet-key")
    with pytest.raises(backup_service.BackupEncryptionError):
        backup_service.create_backup(triggered_by="tester")


def test_restore_refuses_without_a_key(isolated_db_service, isolated_backup_paths, monkeypatch):
    result = backup_service.create_backup(triggered_by="tester")
    monkeypatch.setattr(settings, "BACKUP_ENCRYPTION_KEY", "")
    with pytest.raises(backup_service.BackupEncryptionError):
        backup_service.restore_backup(result["id"], triggered_by="tester")


def test_restore_refuses_with_the_wrong_key(isolated_db_service, isolated_backup_paths, monkeypatch):
    result = backup_service.create_backup(triggered_by="tester")
    monkeypatch.setattr(settings, "BACKUP_ENCRYPTION_KEY", Fernet.generate_key().decode())
    with pytest.raises(backup_service.BackupEncryptionError):
        backup_service.restore_backup(result["id"], triggered_by="tester")


def test_create_backup_route_fails_cleanly_without_a_key(client, admin_session, isolated_backup_paths, monkeypatch):
    monkeypatch.setattr(settings, "BACKUP_ENCRYPTION_KEY", "")
    client, csrf, _ = admin_session
    r = client.post("/system/backups", headers={"X-XSRF-TOKEN": csrf})
    assert r.status_code >= 500 or r.status_code == 400
    assert backup_service.list_backups() == []
