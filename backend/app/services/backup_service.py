"""
Full-system config/DB backup and restore.

Replaces the old top-level backup_waf_config.sh, which targeted a
pre-Docker bare-metal path layout (/usr/local/openresty/nginx/conf/,
systemd units) that no longer matches this deployment — most of what it
tried to back up simply doesn't exist at those paths anymore, and it was
never scheduled or wired to any API. This module backs up whole directories
this container actually has mounted (see the volume list in
docker-compose.yml's `backend` service) rather than a hardcoded file list,
specifically so it doesn't go stale the same way the moment a new
DB/config file gets added later.

Scope, deliberately: nginx config (/etc/nginx — everything the WAF's own
config-writing paths, e.g. nginx_manager.py, actually write to), the
control-plane SQLite databases (backend/app/config, backend/app/data).
`.env` is intentionally OUT of scope — docker compose only injects its
VALUES as container environment variables; the file itself is never
mounted into any container, so it isn't visible here to back up. Operators
should safeguard .env (and any other host-level secrets) separately.

ClickHouse is also out of scope for now — it's the analytics/telemetry
store (waf_events, ml_events history), not control-plane state; losing it
degrades historical reporting, not enforcement. A dedicated
clickhouse-backup integration is a reasonable future addition if/when
long-term analytics retention becomes a stated requirement, not assumed
here.
"""
import os
import secrets
import shutil
import tarfile
import logging
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.services import db_service

logger = logging.getLogger(__name__)

NGINX_DIR = "/etc/nginx"
CONFIG_DIR = str(Path(__file__).resolve().parent.parent / "config")
DATA_DIR = str(Path(__file__).resolve().parent.parent / "data")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")

# Directories excluded when snapshotting DATA_DIR, so a backup never
# recursively re-embeds every prior backup inside itself.
_DATA_DIR_EXCLUDE = {"backups"}


def _add_tree(tar: tarfile.TarFile, path: str, arcname: str, exclude_top_level: Optional[set] = None) -> None:
    if not os.path.isdir(path):
        return
    if exclude_top_level:
        for entry in sorted(os.listdir(path)):
            if entry in exclude_top_level:
                continue
            tar.add(os.path.join(path, entry), arcname=os.path.join(arcname, entry))
    else:
        tar.add(path, arcname=arcname)


def create_backup(triggered_by: str, trigger_type: str = "manual") -> dict:
    """Creates one timestamped tar.gz under BACKUP_DIR and records it in
    the `backups` table. Blocking (file I/O) — callers on the FastAPI event
    loop must run this via asyncio.to_thread, same convention as every
    other blocking nginx/config operation in this codebase."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    # restore_backup() can create two backups (the target's own pre-restore
    # safety snapshot, plus a rollback re-read of that same snapshot) well
    # within the same second — second-resolution alone collided on
    # `backups.filename`'s UNIQUE constraint in exactly that path.
    unique_suffix = secrets.token_hex(3)
    filename = f"cybersentinel-backup-{timestamp}-{unique_suffix}.tar.gz"
    archive_path = os.path.join(BACKUP_DIR, filename)

    # Write to a .part path and rename on success, so a backup that fails
    # partway through (disk full, killed process) never leaves a
    # corrupt-but-catalogued archive behind for a later restore to trip on.
    tmp_path = archive_path + ".part"
    try:
        with tarfile.open(tmp_path, "w:gz") as tar:
            _add_tree(tar, NGINX_DIR, "nginx")
            _add_tree(tar, CONFIG_DIR, "config")
            _add_tree(tar, DATA_DIR, "data", exclude_top_level=_DATA_DIR_EXCLUDE)
        os.replace(tmp_path, archive_path)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise

    size_bytes = os.path.getsize(archive_path)
    created_at = datetime.now(timezone.utc).isoformat()
    backup_id = db_service.create_backup_record(created_at, filename, size_bytes, triggered_by, trigger_type)
    logger.info(f"Backup created: {filename} ({size_bytes} bytes), triggered_by={triggered_by} ({trigger_type})")
    return {
        "id": backup_id,
        "filename": filename,
        "size_bytes": size_bytes,
        "created_at": created_at,
        "triggered_by": triggered_by,
        "trigger_type": trigger_type,
    }


def list_backups() -> list:
    return db_service.get_all_backups()


def get_backup_archive_path(backup_id: int) -> Optional[dict]:
    """Returns the backup record with an added `path` key if the archive
    file actually still exists on disk, else None (covers both "no such
    backup id" and "record exists but the file was deleted out-of-band")."""
    record = db_service.get_backup_by_id(backup_id)
    if not record:
        return None
    path = os.path.join(BACKUP_DIR, record["filename"])
    if not os.path.exists(path):
        return None
    record = dict(record)
    record["path"] = path
    return record


def delete_backup(backup_id: int) -> tuple[bool, str]:
    record = db_service.get_backup_by_id(backup_id)
    if not record:
        return False, "Backup not found."
    path = os.path.join(BACKUP_DIR, record["filename"])
    if os.path.exists(path):
        os.remove(path)
    db_service.delete_backup_record(backup_id)
    return True, "Backup deleted."


def _overlay_copy(src_dir: str, dst_dir: str) -> None:
    """Copies every file from src_dir into dst_dir, overwriting whatever's
    already there — an overlay/merge, not a wipe-then-replace. Deliberate:
    a full wipe of a live /etc/nginx tree carries real blast radius if
    anything goes wrong mid-copy, and files created after the snapshot
    (e.g. a cert issued since) being left alone is the safer failure mode.
    Preserves file metadata (shutil.copytree's default copy2)."""
    os.makedirs(dst_dir, exist_ok=True)
    shutil.copytree(src_dir, dst_dir, dirs_exist_ok=True)


def restore_backup(backup_id: int, triggered_by: str) -> tuple[bool, str]:
    """
    Restores a backup's config/data trees and, if it included one, its
    nginx tree — validated with `nginx -t` before it's allowed to go live,
    same discipline as every other config-writing path in this codebase
    (nginx_manager.write_and_apply_configs), and rolled back automatically
    if validation fails. A fresh safety snapshot is always taken
    immediately before any of this runs, so both the restore itself and
    the state it's replacing stay recoverable.

    Blocking — callers must run via asyncio.to_thread.
    """
    from app.services.nginx_manager import test_nginx_config, reload_nginx

    record = get_backup_archive_path(backup_id)
    if not record:
        return False, "Backup not found or its archive file is missing on disk."

    safety = create_backup(triggered_by=triggered_by, trigger_type="pre_restore_safety")

    with tempfile.TemporaryDirectory() as stage:
        with tarfile.open(record["path"], "r:gz") as tar:
            tar.extractall(stage)  # nosec B202 -- archive is CyberSentinel's own prior backup, not arbitrary user upload

        staged_config = os.path.join(stage, "config")
        staged_data = os.path.join(stage, "data")
        staged_nginx = os.path.join(stage, "nginx")

        # 1. SQLite control-plane data first — lower live-traffic blast
        #    radius than nginx config, and nothing downstream depends on
        #    it being validated before use the way nginx config does.
        if os.path.isdir(staged_config):
            _overlay_copy(staged_config, CONFIG_DIR)
        if os.path.isdir(staged_data):
            for entry in os.listdir(staged_data):
                if entry in _DATA_DIR_EXCLUDE:
                    continue
                src = os.path.join(staged_data, entry)
                dst = os.path.join(DATA_DIR, entry)
                if os.path.isdir(src):
                    _overlay_copy(src, dst)
                else:
                    shutil.copy2(src, dst)

        # 2. nginx config — highest blast radius, so it's the one thing
        #    here that gets a validate-or-rollback gate.
        if os.path.isdir(staged_nginx):
            _overlay_copy(staged_nginx, NGINX_DIR)
            valid, err_msg = test_nginx_config()
            if not valid:
                with tempfile.TemporaryDirectory() as rollback_stage:
                    with tarfile.open(
                        os.path.join(BACKUP_DIR, safety["filename"]), "r:gz"
                    ) as safety_tar:
                        safety_tar.extractall(rollback_stage)  # nosec B202 -- our own just-created safety snapshot
                    rolled_back_nginx = os.path.join(rollback_stage, "nginx")
                    if os.path.isdir(rolled_back_nginx):
                        _overlay_copy(rolled_back_nginx, NGINX_DIR)
                logger.error(f"Restore {backup_id}: restored nginx config failed validation, rolled back: {err_msg}")
                return False, (
                    f"Restored nginx config failed validation and was rolled back: {err_msg}. "
                    f"SQLite data from the backup WAS applied. A pre-restore safety snapshot "
                    f"(backup id {safety['id']}) was taken if you need to undo that too."
                )
            reload_nginx()

    logger.info(f"Restore complete: backup {backup_id}, triggered_by={triggered_by}, safety snapshot id={safety['id']}")
    return True, (
        f"Restored from backup '{record['filename']}'. "
        f"A pre-restore safety snapshot (backup id {safety['id']}) was also taken."
    )
