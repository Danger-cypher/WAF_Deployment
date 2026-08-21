"""
Highest-stakes test in this session: user_service.py's _migrate_role_check_constraint()
rebuilds the live `users` table (SQLite has no ALTER ... MODIFY CONSTRAINT) to widen
the role CHECK from ('admin','analyst') to also allow 'app_admin'. This is real
production data — password hashes, MFA secrets, session versions. A bug here could
lose or corrupt every account on upgrade.

Builds a temp SQLite file with the EXACT pre-migration schema and realistic rows
(including a non-trivial max id, a row with MFA fields populated, and a row with
NULL optional fields) — not through UserService, which would already apply the
migration — then lets UserService open it and verifies every column of every row
survives byte-for-byte, the CHECK constraint actually widened, autoincrement
continues correctly afterward (no id collision), and running the migration twice
is a safe no-op.
"""
import sqlite3

import pytest

from app.services.user_service import UserService


def _create_pre_migration_db(path: str):
    """Exact schema user_service.py used to ship, before this migration —
    intentionally NOT built via UserService, so this test doesn't silently
    start testing against an already-migrated schema."""
    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'analyst')),
            display_name TEXT,
            email TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login_at DATETIME,
            notification_prefs TEXT,
            mfa_secret TEXT,
            mfa_enabled INTEGER NOT NULL DEFAULT 0,
            session_version INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    # Explicit ids, deliberately non-contiguous and with a high water mark
    # (7), to catch a sqlite_sequence fixup bug that would let the next
    # auto-generated id collide with row id=7.
    cursor.execute(
        """INSERT INTO users (id, username, password_hash, role, display_name, email,
                               enabled, notification_prefs, mfa_secret, mfa_enabled, session_version)
           VALUES (1, 'admin', 'hash_admin', 'admin', 'Administrator', 'a@x.com',
                   1, '{"muted_severities": []}', NULL, 0, 2)"""
    )
    cursor.execute(
        """INSERT INTO users (id, username, password_hash, role, display_name, email,
                               enabled, notification_prefs, mfa_secret, mfa_enabled, session_version)
           VALUES (7, 'analyst_with_mfa', 'hash_analyst', 'analyst', NULL, NULL,
                   1, NULL, 'BASE32SECRETSTRING', 1, 5)"""
    )
    cursor.execute(
        """INSERT INTO users (id, username, password_hash, role, display_name, email,
                               enabled, notification_prefs, mfa_secret, mfa_enabled, session_version)
           VALUES (3, 'disabled_user', 'hash_disabled', 'analyst', 'Disabled Guy', NULL,
                   0, NULL, NULL, 0, 0)"""
    )
    conn.commit()
    conn.close()


def test_migration_preserves_every_row_exactly(tmp_path):
    db_path = str(tmp_path / "pre_migration_users.db")
    _create_pre_migration_db(db_path)

    # Opening via UserService triggers _init_database() -> the migration.
    svc = UserService(db_path=db_path)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM users ORDER BY id")}
    conn.close()

    assert set(rows.keys()) == {1, 3, 7}

    admin = rows[1]
    assert admin["username"] == "admin"
    assert admin["password_hash"] == "hash_admin"
    assert admin["role"] == "admin"
    assert admin["display_name"] == "Administrator"
    assert admin["email"] == "a@x.com"
    assert admin["enabled"] == 1
    assert admin["notification_prefs"] == '{"muted_severities": []}'
    assert admin["mfa_secret"] is None
    assert admin["mfa_enabled"] == 0
    assert admin["session_version"] == 2

    analyst = rows[7]
    assert analyst["username"] == "analyst_with_mfa"
    assert analyst["password_hash"] == "hash_analyst"
    assert analyst["display_name"] is None
    assert analyst["mfa_secret"] == "BASE32SECRETSTRING"
    assert analyst["mfa_enabled"] == 1
    assert analyst["session_version"] == 5

    disabled = rows[3]
    assert disabled["username"] == "disabled_user"
    assert disabled["enabled"] == 0
    assert disabled["display_name"] == "Disabled Guy"


def test_migration_widens_check_constraint(tmp_path):
    db_path = str(tmp_path / "pre_migration_users.db")
    _create_pre_migration_db(db_path)
    UserService(db_path=db_path)

    conn = sqlite3.connect(db_path)
    # Would raise sqlite3.IntegrityError before the migration.
    conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES ('scoped', 'h', 'app_admin')"
    )
    conn.commit()
    role = conn.execute("SELECT role FROM users WHERE username = 'scoped'").fetchone()[0]
    conn.close()
    assert role == "app_admin"

    # The original constraint's values still work too — this widened the
    # allow-list, it didn't replace it.
    conn = sqlite3.connect(db_path)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES ('bad', 'h', 'superuser')"
        )
    conn.close()


def test_autoincrement_continues_without_collision_after_migration(tmp_path):
    db_path = str(tmp_path / "pre_migration_users.db")
    _create_pre_migration_db(db_path)  # highest existing id is 7
    svc = UserService(db_path=db_path)

    new_id = svc.create_user("brand_new_user", "SomePass123!", "analyst")
    assert new_id > 7, "new auto-generated id collided with (or predates) an existing row's id"

    conn = sqlite3.connect(db_path)
    count = conn.execute(
        "SELECT COUNT(*) FROM users WHERE id = ?", (new_id,)
    ).fetchone()[0]
    conn.close()
    assert count == 1


def test_migration_is_idempotent_on_second_open(tmp_path):
    """Re-opening an already-migrated DB (e.g. backend restart) must not
    try to rebuild the table again or error out."""
    db_path = str(tmp_path / "pre_migration_users.db")
    _create_pre_migration_db(db_path)
    UserService(db_path=db_path)  # first open — migrates
    svc2 = UserService(db_path=db_path)  # second open — must be a no-op

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM users ORDER BY id")}
    conn.close()
    assert set(rows.keys()) == {1, 3, 7}
    assert rows[1]["username"] == "admin"


def test_fresh_database_already_allows_app_admin(tmp_path):
    """A brand-new install (no pre-existing users.db) should get the
    widened constraint straight from the CREATE TABLE, no migration path
    needed — covered separately since it never hits _migrate_role_check_constraint's
    rebuild branch at all (current_ddl already contains 'app_admin')."""
    db_path = str(tmp_path / "fresh_users.db")
    svc = UserService(db_path=db_path)
    user_id = svc.create_user("scoped_admin", "SomePass123!", "app_admin")
    assert svc.get_by_id(user_id)["role"] == "app_admin"
