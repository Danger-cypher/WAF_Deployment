"""
CyberSentinel WAF - API Key Service (P1-9)
============================================
Machine-credential auth for the dashboard's REST API, separate from human
accounts in user_service.py. Exists so CI/CD pipelines, external scripts,
and monitoring tools can call the API without impersonating a real login
(storing an admin password, defeating MFA) and without inheriting a human
account's lifecycle — an API key's own enabled/expiry state is completely
decoupled from any user's password, role changes, or session_version, and
can be revoked individually without affecting that user's own sessions.

Kept in its own SQLite file (api_keys.db) rather than a table on `users`,
deliberately: a key isn't a user (no MFA, no notification prefs, no SSO
linkage), and this keeps its schema/migrations independent of user_service.

Scope: a key is issued with a role ('admin' or 'analyst', the same two
values a human dashboard account can have) and is checked through the
EXACT SAME RBAC dependencies (require_admin/require_any_role) as a human
session — see auth.py's get_current_user(), which resolves a valid
X-API-Key header into a TokenData exactly like it does a session cookie,
so no route needed any change to support key-based callers.
'app_admin' is deliberately not an issuable key role in this version: that
role's per-application scoping is looked up via a live user row
(db_service.user_has_app_access(username, app_id)), and a key has no such
row to scope against.

Secret handling: the raw key is a high-entropy random token
(`secrets.token_urlsafe`), shown to the admin exactly once at creation
time (mirrors how MfaSetupResponse.secret is a one-time reveal) and never
retrievable again — only a SHA-256 hash is stored, plus a short prefix for
display so an admin can recognize a key in a list without ever reading the
secret back. SHA-256 (not bcrypt) is deliberate: this is a lookup index
consulted on every authenticated API request, and preimage resistance
against an already-256-bit-entropy random value doesn't need bcrypt's
deliberate slowness (which exists to blunt guessing of low-entropy human
passwords, not to protect random tokens).
"""
import sqlite3
import secrets
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

logger = logging.getLogger(__name__)

DB_DIR = Path(__file__).parent.parent / "data"
DB_DIR.mkdir(parents=True, exist_ok=True)
API_KEYS_DB_PATH = DB_DIR / "api_keys.db"

KEY_PREFIX = "csw_"
ISSUABLE_ROLES = ("admin", "analyst")

# Columns safe to return to callers — key_hash is never selected outside
# validate_key()'s own lookup, so it can never leak through list/get.
_PUBLIC_COLUMNS = (
    "id, name, key_prefix, role, enabled, created_by, created_at, "
    "expires_at, last_used_at, last_used_ip"
)


class ApiKeyService:
    """Service for managing dashboard API keys."""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or str(API_KEYS_DB_PATH)
        self._init_database()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_database(self):
        conn = self._get_connection()
        try:
            conn.execute(
                f"""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    key_hash TEXT NOT NULL UNIQUE,
                    key_prefix TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN {ISSUABLE_ROLES!r}),
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_by TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    expires_at DATETIME,
                    last_used_at DATETIME,
                    last_used_ip TEXT
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["enabled"] = bool(d["enabled"])
        return d

    @staticmethod
    def _hash(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def create_key(
        self, name: str, role: str, created_by: str, expires_in_days: Optional[int] = None
    ) -> Tuple[Dict[str, Any], str]:
        """Generates and stores a new key. Returns (public record, raw key)
        — the raw key is never recoverable again after this call returns."""
        if role not in ISSUABLE_ROLES:
            raise ValueError(f"role must be one of {ISSUABLE_ROLES}")

        raw_key = KEY_PREFIX + secrets.token_urlsafe(32)
        key_hash = self._hash(raw_key)
        key_prefix = raw_key[:12]
        expires_at = None
        if expires_in_days is not None:
            expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_in_days)).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        conn = self._get_connection()
        try:
            cursor = conn.execute(
                """
                INSERT INTO api_keys (name, key_hash, key_prefix, role, created_by, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (name, key_hash, key_prefix, role, created_by, expires_at),
            )
            conn.commit()
            key_id = cursor.lastrowid
        finally:
            conn.close()

        return self.get_by_id(key_id), raw_key

    def list_keys(self) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            rows = conn.execute(
                f"SELECT {_PUBLIC_COLUMNS} FROM api_keys ORDER BY created_at DESC"
            ).fetchall()
            return [self._row_to_dict(r) for r in rows]
        finally:
            conn.close()

    def get_by_id(self, key_id: int) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            row = conn.execute(
                f"SELECT {_PUBLIC_COLUMNS} FROM api_keys WHERE id = ?", (key_id,)
            ).fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    def revoke_key(self, key_id: int) -> bool:
        """Soft-revoke (enabled=0) rather than delete — keeps the row for
        audit/last-used history, mirrors disabling a user account rather
        than deleting it. Takes effect immediately: validate_key() below
        checks `enabled` live on every request, nothing is cached."""
        conn = self._get_connection()
        try:
            cursor = conn.execute("UPDATE api_keys SET enabled = 0 WHERE id = ?", (key_id,))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

    def validate_key(self, raw_key: str, client_ip: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Looks up a presented raw key by its hash. Returns the public
        record (role/name/id) if it exists, is enabled, and isn't expired
        — None otherwise. On success, records last_used_at/last_used_ip
        (best-effort; a failure to record usage must never block the
        request the key is legitimately authenticating)."""
        if not raw_key or not raw_key.startswith(KEY_PREFIX):
            return None

        key_hash = self._hash(raw_key)
        conn = self._get_connection()
        try:
            row = conn.execute(
                f"""
                SELECT {_PUBLIC_COLUMNS} FROM api_keys
                WHERE key_hash = ? AND enabled = 1
                AND (expires_at IS NULL OR expires_at > datetime('now'))
                """,
                (key_hash,),
            ).fetchone()
            if row is None:
                return None
            record = self._row_to_dict(row)

            try:
                conn.execute(
                    "UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP, last_used_ip = ? WHERE id = ?",
                    (client_ip, record["id"]),
                )
                conn.commit()
            except Exception as e:
                logger.warning(f"Failed to record API key usage for key {record['id']}: {e}")

            return record
        finally:
            conn.close()


api_key_service = ApiKeyService()
