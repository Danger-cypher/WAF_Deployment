"""
CyberSentinel WAF - User Management Service
Handles all database operations for dashboard user accounts (admin/analyst).

Prior to this service, "admin" and "analyst" were the only two accounts,
hardcoded in routes/auth.py with their password hashes living in
settings.json. This service replaces that with a real users table so
additional accounts can be created, disabled, and role-assigned from the
Admin > Users panel, while preserving the legacy accounts on upgrade.
"""
import sqlite3
import json
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

DB_DIR = Path(__file__).parent.parent / "data"
DB_DIR.mkdir(parents=True, exist_ok=True)
USERS_DB_PATH = DB_DIR / "users.db"

# Severities/event types absent from these lists are shown; presence here
# means "don't count this toward my bell". Kept out of the DB schema itself
# (just JSON) since the set of event types is expected to grow over time.
DEFAULT_NOTIFICATION_PREFS = {
    "muted_severities": [],
    "muted_event_types": [],
}


class UserService:
    """Service for managing dashboard user accounts."""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or str(USERS_DB_PATH)
        self._init_database()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_database(self):
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('admin', 'analyst', 'app_admin')),
                    display_name TEXT,
                    email TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_login_at DATETIME
                )
                """
            )
            conn.commit()

            # Lightweight migration: notification_prefs was added after the
            # users table shipped, so existing installs need it bolted on.
            # SQLite has no "ADD COLUMN IF NOT EXISTS", so probe and ignore
            # the error if it's already there.
            try:
                cursor.execute("ALTER TABLE users ADD COLUMN notification_prefs TEXT")
                conn.commit()
            except sqlite3.OperationalError:
                pass

            for column, ddl in (
                ("mfa_secret", "ALTER TABLE users ADD COLUMN mfa_secret TEXT"),
                ("mfa_enabled", "ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0"),
                # Bumped on role/enabled/password changes only (not profile
                # edits) and embedded in issued JWTs, so a stale token from
                # before such a change is rejected instead of trusted until
                # it naturally expires. See decode_token() in services/auth.py.
                ("session_version", "ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0"),
            ):
                try:
                    cursor.execute(ddl)
                    conn.commit()
                except sqlite3.OperationalError:
                    pass

            self._migrate_role_check_constraint(conn, cursor)

            cursor.execute("SELECT COUNT(*) AS c FROM users")
            if cursor.fetchone()["c"] == 0:
                self._seed_legacy_accounts(conn)
        finally:
            conn.close()

    def _migrate_role_check_constraint(self, conn: sqlite3.Connection, cursor: sqlite3.Cursor):
        """
        Widens the 'role' CHECK constraint to allow 'app_admin' (per-app
        scoped admin, RBAC item 7) alongside the existing 'admin'/'analyst'.

        SQLite has no ALTER TABLE ... ADD/DROP/MODIFY CONSTRAINT — the only
        way to change a CHECK constraint on an existing table is the
        documented rebuild procedure: create a new table with the desired
        DDL, copy every row across by explicit column list (never `SELECT
        *` — column order drifting between old/new would silently shuffle
        data into the wrong columns), drop the old table, rename the new
        one into place. This is real production data (password hashes, MFA
        secrets) — everything below runs inside the caller's existing
        connection/transaction so a failure partway through leaves the
        original table completely untouched rather than half-migrated.
        """
        cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'")
        row = cursor.fetchone()
        current_ddl = row["sql"] if row else ""
        if not current_ddl or "app_admin" in current_ddl:
            return  # already migrated (or table doesn't exist yet — CREATE above already ran with it missing, nothing to widen)

        cursor.execute("ALTER TABLE users RENAME TO users_role_migration_old")
        cursor.execute(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'analyst', 'app_admin')),
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
        cursor.execute(
            """
            INSERT INTO users (
                id, username, password_hash, role, display_name, email,
                enabled, created_at, updated_at, last_login_at,
                notification_prefs, mfa_secret, mfa_enabled, session_version
            )
            SELECT
                id, username, password_hash, role, display_name, email,
                enabled, created_at, updated_at, last_login_at,
                notification_prefs, mfa_secret, mfa_enabled, session_version
            FROM users_role_migration_old
            """
        )
        cursor.execute("DROP TABLE users_role_migration_old")

        # Explicit rows were inserted with their original ids, which does
        # NOT advance sqlite_sequence (only inserts that let SQLite
        # auto-generate the id do that) — without this fixup, the next
        # auto-generated id could collide with an existing one.
        cursor.execute("SELECT MAX(id) AS m FROM users")
        max_id = cursor.fetchone()["m"] or 0
        cursor.execute("DELETE FROM sqlite_sequence WHERE name = 'users'")
        cursor.execute("INSERT INTO sqlite_sequence (name, seq) VALUES ('users', ?)", (max_id,))

        conn.commit()
        logger.info("Migrated users.role CHECK constraint to allow 'app_admin'.")

    def _seed_legacy_accounts(self, conn: sqlite3.Connection):
        """First-run migration: carry over the legacy hardcoded admin/analyst
        accounts (and their existing password hashes) from settings.json so
        nobody is locked out when this table is introduced on an upgrade."""
        from app.services.settings_manager import settings_manager

        cursor = conn.cursor()
        seeds = [
            ("admin", settings_manager.get_password_hash(), "admin", "Administrator"),
            ("analyst", settings_manager.get_analyst_password_hash(), "analyst", "Analyst"),
        ]
        for username, password_hash, role, display_name in seeds:
            cursor.execute(
                """INSERT OR IGNORE INTO users
                   (username, password_hash, role, display_name, enabled)
                   VALUES (?, ?, ?, ?, 1)""",
                (username, password_hash, role, display_name),
            )
        conn.commit()
        logger.info("Seeded legacy admin/analyst accounts into users.db")

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["enabled"] = bool(d["enabled"])
        d["mfa_enabled"] = bool(d.get("mfa_enabled", 0))
        return d

    def get_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    def get_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    def list_users(self) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            rows = conn.execute("SELECT * FROM users ORDER BY id ASC").fetchall()
            return [self._row_to_dict(r) for r in rows]
        finally:
            conn.close()

    def count_enabled_admins(self) -> int:
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND enabled = 1"
            ).fetchone()
            return row["c"]
        finally:
            conn.close()

    def create_user(
        self,
        username: str,
        password: str,
        role: str,
        display_name: Optional[str] = None,
        email: Optional[str] = None,
    ) -> int:
        from app.services.auth import get_password_hash

        conn = self._get_connection()
        try:
            cursor = conn.execute(
                """INSERT INTO users (username, password_hash, role, display_name, email, enabled)
                   VALUES (?, ?, ?, ?, ?, 1)""",
                (username, get_password_hash(password), role, display_name, email),
            )
            conn.commit()
            return cursor.lastrowid
        finally:
            conn.close()

    def update_user(
        self,
        user_id: int,
        role: Optional[str] = None,
        enabled: Optional[bool] = None,
        display_name: Optional[str] = None,
        email: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        fields = []
        values = []
        bump_session = False
        if role is not None:
            fields.append("role = ?")
            values.append(role)
            bump_session = True
        if enabled is not None:
            fields.append("enabled = ?")
            values.append(1 if enabled else 0)
            bump_session = True
        if display_name is not None:
            fields.append("display_name = ?")
            values.append(display_name)
        if email is not None:
            fields.append("email = ?")
            values.append(email)

        if not fields:
            return self.get_by_id(user_id)

        if bump_session:
            fields.append("session_version = session_version + 1")
        fields.append("updated_at = CURRENT_TIMESTAMP")
        values.append(user_id)

        conn = self._get_connection()
        try:
            conn.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = ?", values)
            conn.commit()
        finally:
            conn.close()
        return self.get_by_id(user_id)

    def set_password(self, user_id: int, new_password: str) -> None:
        from app.services.auth import get_password_hash

        conn = self._get_connection()
        try:
            conn.execute(
                """UPDATE users SET password_hash = ?, session_version = session_version + 1,
                   updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
                (get_password_hash(new_password), user_id),
            )
            conn.commit()
        finally:
            conn.close()

    def delete_user(self, user_id: int) -> None:
        conn = self._get_connection()
        try:
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
        finally:
            conn.close()

    def update_last_login(self, user_id: int) -> None:
        conn = self._get_connection()
        try:
            conn.execute(
                "UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?",
                (user_id,),
            )
            conn.commit()
        finally:
            conn.close()

    def get_notification_prefs(self, user_id: int) -> Dict[str, Any]:
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT notification_prefs FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        finally:
            conn.close()
        if row is None or not row["notification_prefs"]:
            return dict(DEFAULT_NOTIFICATION_PREFS)
        try:
            parsed = json.loads(row["notification_prefs"])
        except (TypeError, ValueError):
            return dict(DEFAULT_NOTIFICATION_PREFS)
        return {**DEFAULT_NOTIFICATION_PREFS, **parsed}

    def update_notification_prefs(self, user_id: int, prefs: Dict[str, Any]) -> Dict[str, Any]:
        merged = {**DEFAULT_NOTIFICATION_PREFS, **prefs}
        conn = self._get_connection()
        try:
            conn.execute(
                "UPDATE users SET notification_prefs = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (json.dumps(merged), user_id),
            )
            conn.commit()
        finally:
            conn.close()
        return merged

    def set_pending_mfa_secret(self, user_id: int, secret: str) -> None:
        """Stores a freshly-generated TOTP secret without enabling MFA yet —
        it only takes effect once confirm_mfa() verifies the user actually
        scanned it (proves they have a working authenticator, not just that
        the setup request was made)."""
        conn = self._get_connection()
        try:
            conn.execute(
                "UPDATE users SET mfa_secret = ?, mfa_enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (secret, user_id),
            )
            conn.commit()
        finally:
            conn.close()

    def confirm_mfa(self, user_id: int) -> None:
        conn = self._get_connection()
        try:
            conn.execute(
                "UPDATE users SET mfa_enabled = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (user_id,),
            )
            conn.commit()
        finally:
            conn.close()

    def disable_mfa(self, user_id: int) -> None:
        conn = self._get_connection()
        try:
            conn.execute(
                "UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (user_id,),
            )
            conn.commit()
        finally:
            conn.close()


user_service = UserService()
