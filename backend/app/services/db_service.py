import os
import sqlite3
import logging
import json
import uuid
from typing import Optional, Any, Union, List

from app.services import clickhouse_service

logger = logging.getLogger(__name__)

# Path to local SQLite DB
DB_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "config", "false_positives.db"
)


def get_connection():
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            # 1. False Positives table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS false_positives (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    log_id TEXT NOT NULL UNIQUE,
                    rule_id TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    uri TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'Pending',
                    analyst_note TEXT DEFAULT '',
                    raw_log TEXT NOT NULL,
                    created_by TEXT NOT NULL DEFAULT 'system'
                )
            """)
            # Add created_by column to existing tables that lack it (migration)
            try:
                cursor.execute("ALTER TABLE false_positives ADD COLUMN created_by TEXT NOT NULL DEFAULT 'system'")
            except Exception:
                pass  # Column already exists — expected on fresh installs

            # 2. Exclusions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS exclusions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    false_positive_id INTEGER NULL,
                    rule_id TEXT NOT NULL,
                    exclusion_type TEXT NOT NULL,
                    uri TEXT NULL,
                    parameter_name TEXT NULL,
                    http_method TEXT NULL,
                    client_ip TEXT NULL,
                    status TEXT NOT NULL DEFAULT 'Active',
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    notes TEXT NOT NULL,
                    modsec_rule TEXT NOT NULL,
                    FOREIGN KEY (false_positive_id) REFERENCES false_positives(id) ON DELETE SET NULL
                )
            """)

            # 3. Exclusion Audit History table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS exclusion_audit_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    exclusion_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    username TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    details TEXT NOT NULL
                )
            """)

            # Ingestion state — small key/value store for cross-restart cursors
            # (e.g. api_discovery.py's nginx access-log read offset). Without
            # this, a backend restart forgets where it left off and either
            # re-scans/double-counts recent lines or, on a slow-growth log,
            # can silently skip lines written between shutdown and the next
            # cold-start's fixed "last 100KB" seek.
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ingestion_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)

            # 4. Discovered Endpoints table for API Protection
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS discovered_endpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    uri TEXT NOT NULL,
                    method TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    avg_response_time_ms REAL DEFAULT 0.0,
                    hit_count INTEGER DEFAULT 0,
                    error_count INTEGER DEFAULT 0,
                    malicious_count INTEGER DEFAULT 0,
                    suspicious_count INTEGER DEFAULT 0,
                    external_hit_count INTEGER DEFAULT 0,
                    internal_hit_count INTEGER DEFAULT 0,
                    has_https INTEGER DEFAULT 1,
                    has_versioning INTEGER DEFAULT 0,
                    content_encoding TEXT DEFAULT '',
                    UNIQUE(uri, method)
                )
            """)
            # Schema migrations: add traffic source columns to existing tables
            for col, default in [
                ("external_hit_count", "0"),
                ("internal_hit_count", "0"),
            ]:
                try:
                    cursor.execute(
                        f"ALTER TABLE discovered_endpoints ADD COLUMN {col} INTEGER DEFAULT {default}"
                    )
                except Exception:
                    pass  # Column already exists — expected on re-init

            # Query-param NAMES observed for this endpoint, as a JSON array
            # string (never values — see api_discovery.extract_param_names).
            # Powers API Protection's sensitive-parameter flagging.
            try:
                cursor.execute(
                    "ALTER TABLE discovered_endpoints ADD COLUMN param_names TEXT DEFAULT '[]'"
                )
            except Exception:
                pass  # Column already exists — expected on re-init

            # One-time migration: has_https used to be hardcoded true and
            # content_encoding was guessed from the status code — neither was
            # ever a real measurement (see api_discovery.py). Reset both to
            # the "unknown" sentinel (2 / "unknown") so that old fabricated
            # data doesn't keep misrepresenting endpoints; fresh log lines
            # (which now carry $scheme/$sent_http_content_encoding) will
            # repopulate real values on the next discovery pass. Guarded by
            # a marker column so this only runs once, ever, per install.
            try:
                cursor.execute(
                    "ALTER TABLE discovered_endpoints ADD COLUMN https_encoding_reset_done INTEGER DEFAULT 0"
                )
                cursor.execute(
                    "UPDATE discovered_endpoints SET has_https = 2, content_encoding = 'unknown'"
                )
                conn.commit()
                logger.info(
                    "One-time reset of discovered_endpoints.has_https/content_encoding "
                    "to 'unknown' — previous values were fabricated, not measured."
                )
            except Exception:
                pass  # Column already exists — reset already ran on a prior startup

            # API Protection: the active OpenAPI/Swagger spec, for shadow/
            # undocumented-endpoint drift detection. Single-row model (id=1)
            # — there's only ever one "current" spec; uploading a new one
            # replaces it. No versioning/history, matching how other single-
            # purpose config blobs in this app work (e.g. positive_security
            # settings) rather than building a spec-history feature nobody
            # asked for.
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS api_spec (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    filename TEXT NOT NULL,
                    version TEXT NOT NULL,
                    raw_content TEXT NOT NULL,
                    endpoint_count INTEGER NOT NULL,
                    uploaded_by TEXT NOT NULL,
                    uploaded_at TEXT NOT NULL
                )
            """)

            # 5. Protected Applications table for dynamic multi-app proxying
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS protected_apps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    domain TEXT NOT NULL UNIQUE,
                    upstream_host TEXT NOT NULL,
                    upstream_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL DEFAULT 'http',
                    is_active INTEGER DEFAULT 1
                )
            """)

            # Run migrations for protected_apps schema changes
            for col, default in [
                ("rate_limit_rps", "50"),
                ("burst_tolerance", "100"),
            ]:
                try:
                    cursor.execute(
                        f"ALTER TABLE protected_apps ADD COLUMN {col} INTEGER DEFAULT {default}"
                    )
                except Exception:
                    pass

            # SSL provisioning columns migration
            for col_def in [
                "ssl_option TEXT NOT NULL DEFAULT 'self-signed'",
                "ssl_cert_path TEXT DEFAULT NULL",
                "ssl_key_path TEXT DEFAULT NULL",
            ]:
                col_name = col_def.split()[0]
                try:
                    cursor.execute(
                        f"ALTER TABLE protected_apps ADD COLUMN {col_def}"
                    )
                except Exception:
                    pass  # Column already exists — expected on re-init

            # Require-auth (Phase 3) columns migration — disabled by default,
            # a presence check only (not full token validation), scoped per
            # app. See nginx_manager.py's app-auth conf generation.
            for col_def in [
                "require_auth INTEGER NOT NULL DEFAULT 0",
                "auth_check_type TEXT NOT NULL DEFAULT 'header'",
                "auth_header_name TEXT NOT NULL DEFAULT 'Authorization'",
            ]:
                col_name = col_def.split()[0]
                try:
                    cursor.execute(
                        f"ALTER TABLE protected_apps ADD COLUMN {col_def}"
                    )
                except Exception:
                    pass  # Column already exists — expected on re-init

            # Per-app positive-security API schema (roadmap item: API schema
            # validation). Declares known-good endpoints (method/path +
            # required/allowed JSON body fields) for a protected app;
            # enforced in ml_check.lua's schema_validate module, which reads
            # this via Redis (nginx_manager.apply_api_schema_settings), not
            # this column directly — this is the source of truth the sync
            # pushes from. NULL/empty = no schema configured = no-op for
            # that app, matching Positive Security's same "absence never
            # means deny-all" convention.
            for col_def in [
                "api_schema TEXT DEFAULT NULL",
                "api_schema_mode TEXT NOT NULL DEFAULT 'log'",
            ]:
                try:
                    cursor.execute(
                        f"ALTER TABLE protected_apps ADD COLUMN {col_def}"
                    )
                except Exception:
                    pass  # Column already exists — expected on re-init

            # Multi-server load balancing (P1-14, simplest version): extra
            # backend origins beyond the primary upstream_host/upstream_port,
            # stored as a JSON array string ('[{"host":..., "port":...}, ...]')
            # — same "pre-serialized JSON in a TEXT column" idiom already used
            # for api_schema above, not a child table, since this is small,
            # single-owner, per-app config with no need for relational
            # queries across apps. NULL/empty = no extra origins = today's
            # exact single-origin behavior; nginx_manager.py's
            # sync_protected_apps_to_nginx() emits one `server host:port ...;`
            # line per origin (primary + these) into the SAME upstream{} block
            # that already existed with passive-failover params wired in.
            try:
                cursor.execute(
                    "ALTER TABLE protected_apps ADD COLUMN additional_origins TEXT DEFAULT NULL"
                )
            except Exception:
                pass  # Column already exists — expected on re-init

            # Per-app RBAC scoping (item 7): which protected app(s) a
            # non-'admin' 'app_admin' user may view/manage. Keyed by
            # username rather than a numeric user_id — users live in a
            # SEPARATE SQLite file (users.db, user_service.py) with no
            # cross-file foreign key, and username is already the identity
            # handle TokenData/JWT carries end-to-end (see auth.py), so this
            # avoids adding a new field to the token just for this. A join
            # table (not a single owner column on protected_apps) so more
            # than one user can be scoped to the same app without a schema
            # change later. 'admin' bypasses this table entirely — it only
            # gates the 'app_admin' role. See auth.require_app_access().
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS app_user_access (
                    username TEXT NOT NULL,
                    app_id INTEGER NOT NULL,
                    PRIMARY KEY (username, app_id)
                )
            """)

            # Auto-Learning suggestions — computed from Resolved false
            # positives observed within Settings > Auto-Learning's rolling
            # window. Never auto-applied: an admin must explicitly Approve
            # (which creates a real exclusion through the normal pipeline)
            # or Reject. One row per distinct (rule_id, exclusion_type, uri,
            # parameter_name) pattern; re-detecting the same pattern updates
            # the existing Pending row's counts instead of duplicating it,
            # and never resurrects a pattern an admin already Rejected.
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS auto_learning_suggestions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT NOT NULL,
                    exclusion_type TEXT NOT NULL,
                    uri TEXT,
                    parameter_name TEXT,
                    occurrence_count INTEGER NOT NULL DEFAULT 1,
                    confidence_score INTEGER NOT NULL,
                    reasoning TEXT NOT NULL,
                    sample_false_positive_ids TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'Pending',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    reviewed_by TEXT,
                    reviewed_at TEXT,
                    UNIQUE(rule_id, exclusion_type, uri, parameter_name)
                )
            """)

            # Full-system config/DB backups — see backup_service.py. One row
            # per archive; the archive itself lives on disk (BACKUP_DIR),
            # this table is just the admin-facing catalog (list/download/
            # restore-by-id) so the UI doesn't have to list a directory.
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS backups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    filename TEXT NOT NULL UNIQUE,
                    size_bytes INTEGER NOT NULL,
                    triggered_by TEXT NOT NULL,
                    trigger_type TEXT NOT NULL DEFAULT 'manual'
                )
            """)

            conn.commit()
            logger.info("Database schemas initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize database schemas: {e}")
        raise e


def get_false_positive_by_log_id(log_id: str):
    if clickhouse_service.is_available():
        res = clickhouse_service.get_false_positive_by_log_id(log_id)
        if res is not None:
            return res
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM false_positives WHERE log_id = ?", (log_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error fetching false positive by log_id {log_id}: {e}")
        return None


def resolve_false_positive_sqlite_id(entry_id: Any) -> Optional[int]:
    """
    Resolves any valid false-positive identifier to its SQLite integer
    primary key — the only ID type exclusions.false_positive_id can
    actually work as a foreign key, since exclusions live in SQLite only.

    Why this is needed: create_false_positive() returns a ClickHouse UUID
    string as `id` whenever ClickHouse is available (the normal case),
    not the SQLite row's real autoincrement integer — every other FP
    operation (status update, delete) works around this by matching
    `id = ? OR log_id = ?`, but exclusions.false_positive_id is a single
    INTEGER column with no such fallback. Passed a UUID string
    unresolved, it gets stored as literal text that can never match
    false_positives.id in a join — the FK link silently does nothing.
    log_id is the one natural key present identically in both stores for
    the same underlying FP, so it's the resolution path here.
    """
    entry = get_false_positive_by_id(entry_id)
    log_id = entry.get("log_id") if entry else None
    if log_id is None:
        return None
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM false_positives WHERE log_id = ?", (log_id,))
            row = cursor.fetchone()
            return row["id"] if row else None
    except Exception as e:
        logger.error(f"Error resolving false_positive sqlite id for {entry_id}: {e}")
        return None


def _get_exclusion_link_map(log_ids: List[str]) -> dict:
    """Bulk log_id -> linked exclusion id, for enriching a list of false
    positives without one query per row."""
    if not log_ids:
        return {}
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            placeholders = ",".join("?" for _ in log_ids)
            cursor.execute(
                f"""
                SELECT fp.log_id, e.id AS exclusion_id
                FROM exclusions e
                JOIN false_positives fp ON fp.id = e.false_positive_id
                WHERE fp.log_id IN ({placeholders})
                """,
                log_ids,
            )
            return {row["log_id"]: row["exclusion_id"] for row in cursor.fetchall()}
    except Exception as e:
        logger.error(f"Error building exclusion link map: {e}")
        return {}


def get_false_positive_by_id(entry_id: Any):
    if clickhouse_service.is_available():
        res = clickhouse_service.get_false_positive_by_id(str(entry_id))
        if res is not None:
            res["linked_exclusion_id"] = _get_exclusion_link_map([res.get("log_id")]).get(res.get("log_id"))
            return res
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM false_positives WHERE id = ?", (entry_id,))
            row = cursor.fetchone()
            if not row:
                return None
            entry = dict(row)
            entry["linked_exclusion_id"] = _get_exclusion_link_map([entry.get("log_id")]).get(entry.get("log_id"))
            return entry
    except Exception as e:
        logger.error(f"Error fetching false positive by id {entry_id}: {e}")
        return None


def create_false_positive(
    log_id: str,
    rule_id: str,
    client_ip: str,
    uri: str,
    timestamp: str,
    severity: str,
    attack_type: str,
    analyst_note: str,
    raw_log: str,
    created_by: str = "system",
):
    import uuid
    ch_ok = False
    new_uuid = str(uuid.uuid4())
    
    if clickhouse_service.is_available():
        try:
            record_raw_log = json.loads(raw_log) if isinstance(raw_log, str) and (raw_log.startswith("{") or raw_log.startswith("[")) else raw_log
        except Exception:
            record_raw_log = raw_log
        
        record = {
            "id": new_uuid,
            "log_id": log_id,
            "rule_id": rule_id,
            "client_ip": client_ip,
            "uri": uri,
            "timestamp": timestamp,
            "severity": severity,
            "attack_type": attack_type,
            "status": "Pending",
            "analyst_note": analyst_note,
            "created_by": created_by,
            "raw_log": record_raw_log,
        }
        ch_ok = clickhouse_service.insert_analyst_feedback(record)
        
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO false_positives (log_id, rule_id, client_ip, uri, timestamp, severity, attack_type, analyst_note, raw_log, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    log_id,
                    rule_id,
                    client_ip,
                    uri,
                    timestamp,
                    severity,
                    attack_type,
                    analyst_note,
                    raw_log,
                    created_by,
                ),
            )
            conn.commit()
            new_id = cursor.lastrowid
            
            if ch_ok:
                return clickhouse_service.get_false_positive_by_id(new_uuid)
            
            cursor.execute("SELECT * FROM false_positives WHERE id = ?", (new_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error creating false positive: {e}")
        if ch_ok:
            return clickhouse_service.get_false_positive_by_id(new_uuid)
        return None


def get_all_false_positives(status=None, severity=None, rule_id=None, search=None):
    if clickhouse_service.is_available():
        entries = clickhouse_service.get_all_false_positives(
            status=status, severity=severity, rule_id=rule_id, search=search
        )
        link_map = _get_exclusion_link_map([e.get("log_id") for e in entries if e.get("log_id")])
        for e in entries:
            e["linked_exclusion_id"] = link_map.get(e.get("log_id"))
        return entries
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM false_positives WHERE 1=1"
            params = []

            if status:
                query += " AND status = ?"
                params.append(status)
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            if rule_id:
                query += " AND rule_id = ?"
                params.append(rule_id)
            if search:
                query += " AND (client_ip LIKE ? OR uri LIKE ? OR analyst_note LIKE ?)"
                search_val = f"%{search}%"
                params.extend([search_val, search_val, search_val])

            query += " ORDER BY id DESC"
            cursor.execute(query, params)
            rows = cursor.fetchall()
            entries = [dict(row) for row in rows]
            link_map = _get_exclusion_link_map([e.get("log_id") for e in entries if e.get("log_id")])
            for e in entries:
                e["linked_exclusion_id"] = link_map.get(e.get("log_id"))
            return entries
    except Exception as e:
        logger.error(f"Error getting all false positives: {e}")
        return []


def update_false_positive_status(entry_id: Any, status: str):
    if clickhouse_service.is_available():
        res = clickhouse_service.update_false_positive_status(str(entry_id), status)
        if res is not None:
            try:
                with get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "UPDATE false_positives SET status = ? WHERE id = ? OR log_id = ?", (status, entry_id, entry_id)
                    )
                    conn.commit()
            except Exception:
                pass
            return res

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE false_positives SET status = ? WHERE id = ? OR log_id = ?", (status, entry_id, entry_id)
            )
            conn.commit()

            cursor.execute("SELECT * FROM false_positives WHERE id = ? OR log_id = ?", (entry_id, entry_id))
            row = cursor.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error updating false positive status for {entry_id}: {e}")
        return None


def update_false_positive_note(entry_id: Any, analyst_note: str):
    if clickhouse_service.is_available():
        res = clickhouse_service.update_false_positive_note(str(entry_id), analyst_note)
        if res is not None:
            try:
                with get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "UPDATE false_positives SET analyst_note = ? WHERE id = ? OR log_id = ?",
                        (analyst_note, entry_id, entry_id),
                    )
                    conn.commit()
            except Exception:
                pass
            return res

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE false_positives SET analyst_note = ? WHERE id = ? OR log_id = ?",
                (analyst_note, entry_id, entry_id),
            )
            conn.commit()

            cursor.execute("SELECT * FROM false_positives WHERE id = ? OR log_id = ?", (entry_id, entry_id))
            row = cursor.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error updating false positive note for {entry_id}: {e}")
        return None


def delete_false_positive(entry_id: Any):
    ch_ok = False
    if clickhouse_service.is_available():
        ch_ok = clickhouse_service.delete_false_positive(str(entry_id))

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM false_positives WHERE id = ? OR log_id = ?", (entry_id, entry_id))
            conn.commit()
            return cursor.rowcount > 0 or ch_ok
    except Exception as e:
        logger.error(f"Error deleting false positive {entry_id}: {e}")
        return ch_ok


# ========================================================
# Phase 2: Exclusions and Exceptions DB operations
# ========================================================


def create_exclusion(
    false_positive_id: Optional[Union[int, str]],
    rule_id: str,
    exclusion_type: str,
    uri: Optional[str],
    parameter_name: Optional[str],
    http_method: Optional[str],
    client_ip: Optional[str],
    created_by: str,
    notes: str,
    modsec_rule: str,
    timestamp: str,
):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO exclusions (false_positive_id, rule_id, exclusion_type, uri, parameter_name, http_method, client_ip, created_by, created_at, notes, modsec_rule)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    false_positive_id,
                    rule_id,
                    exclusion_type,
                    uri,
                    parameter_name,
                    http_method,
                    client_ip,
                    created_by,
                    timestamp,
                    notes,
                    modsec_rule,
                ),
            )
            conn.commit()
            new_id = cursor.lastrowid

            details_text = f"Created exclusion policy of type '{exclusion_type}' for Rule {rule_id}."

            # Log to SQLite audit history
            cursor.execute(
                """
                INSERT INTO exclusion_audit_history (exclusion_id, action, username, timestamp, details)
                VALUES (?, ?, ?, ?, ?)
            """,
                (
                    new_id,
                    "Create",
                    created_by,
                    timestamp,
                    details_text,
                ),
            )
            conn.commit()

            # Log to ClickHouse audit_log
            if clickhouse_service.is_available():
                clickhouse_service.insert_audit_log(
                    entity_type="exclusion",
                    entity_id=str(new_id),
                    action="Create",
                    username=created_by,
                    details={"notes": details_text},
                )

            cursor.execute("SELECT * FROM exclusions WHERE id = ?", (new_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error creating exclusion: {e}")
        return None


def get_next_exclusion_sequence_id() -> int:
    """
    Returns the next safe, monotonically-increasing sequence integer for use
    in generating unique ModSecurity SecRule IDs.

    Uses SQLite's internal sqlite_sequence table which tracks the last
    AUTOINCREMENT value for a table. This value NEVER decreases or reuses
    deleted row IDs — making it safe for generating unique ModSecurity rule IDs
    even when exclusions are created and deleted repeatedly.

    Falls back to a timestamp-based fallback to ensure uniqueness even if
    the exclusions table has never had a row inserted yet.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            # sqlite_sequence only exists after the first AUTOINCREMENT insert
            cursor.execute(
                "SELECT seq FROM sqlite_sequence WHERE name = 'exclusions'"
            )
            row = cursor.fetchone()
            if row:
                return int(row[0]) + 1
            # Table exists but no rows ever inserted — use 1
            return 1
    except Exception as e:
        logger.warning(
            f"Could not read sqlite_sequence for exclusions: {e}. Using timestamp fallback."
        )
        # Fallback: use last 7 digits of unix timestamp for uniqueness
        import time
        return int(time.time()) % 9_000_000 + 1_000_000



def get_all_exclusions(status=None, search=None):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM exclusions WHERE 1=1"
            params = []

            if status:
                query += " AND status = ?"
                params.append(status)
            if search:
                query += " AND (rule_id LIKE ? OR uri LIKE ? OR parameter_name LIKE ? OR notes LIKE ? OR created_by LIKE ?)"
                search_val = f"%{search}%"
                params.extend(
                    [search_val, search_val, search_val, search_val, search_val]
                )

            query += " ORDER BY id DESC"
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Error getting exclusions: {e}")
        return []


def get_exclusion_by_id(entry_id: int):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM exclusions WHERE id = ?", (entry_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error fetching exclusion by id {entry_id}: {e}")
        return None


def update_exclusion_status(entry_id: int, status: str, username: str, timestamp: str):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            # Get old details for audit
            cursor.execute(
                "SELECT status, rule_id FROM exclusions WHERE id = ?", (entry_id,)
            )
            old = cursor.fetchone()
            if not old:
                return None

            cursor.execute(
                "UPDATE exclusions SET status = ? WHERE id = ?", (status, entry_id)
            )

            details_text = f"Status updated from '{old['status']}' to '{status}'."

            # Log audit to SQLite
            cursor.execute(
                """
                INSERT INTO exclusion_audit_history (exclusion_id, action, username, timestamp, details)
                VALUES (?, ?, ?, ?, ?)
            """,
                (
                    entry_id,
                    "Toggle Status",
                    username,
                    timestamp,
                    details_text,
                ),
            )
            conn.commit()

            # Log audit to ClickHouse
            if clickhouse_service.is_available():
                clickhouse_service.insert_audit_log(
                    entity_type="exclusion",
                    entity_id=str(entry_id),
                    action="Toggle Status",
                    username=username,
                    details={"notes": details_text},
                )

            cursor.execute("SELECT * FROM exclusions WHERE id = ?", (entry_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error updating status for exclusion {entry_id}: {e}")
        return None


def update_exclusion_note(entry_id: int, notes: str, username: str, timestamp: str):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE exclusions SET notes = ? WHERE id = ?", (notes, entry_id)
            )

            details_text = "Analyst justification notes updated."

            # Log audit to SQLite
            cursor.execute(
                """
                INSERT INTO exclusion_audit_history (exclusion_id, action, username, timestamp, details)
                VALUES (?, ?, ?, ?, ?)
            """,
                (
                    entry_id,
                    "Update Note",
                    username,
                    timestamp,
                    details_text,
                ),
            )
            conn.commit()

            # Log audit to ClickHouse
            if clickhouse_service.is_available():
                clickhouse_service.insert_audit_log(
                    entity_type="exclusion",
                    entity_id=str(entry_id),
                    action="Update Note",
                    username=username,
                    details={"notes": details_text},
                )

            cursor.execute("SELECT * FROM exclusions WHERE id = ?", (entry_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error updating notes for exclusion {entry_id}: {e}")
        return None


def delete_exclusion(entry_id: int, username: str, timestamp: str):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT rule_id FROM exclusions WHERE id = ?", (entry_id,))
            row = cursor.fetchone()
            if not row:
                return False

            cursor.execute("DELETE FROM exclusions WHERE id = ?", (entry_id,))

            details_text = f"Exclusion policy for Rule {row['rule_id']} deleted from registry."

            # Insert audit record to SQLite (orphaned but kept for historical context)
            cursor.execute(
                """
                INSERT INTO exclusion_audit_history (exclusion_id, action, username, timestamp, details)
                VALUES (?, ?, ?, ?, ?)
            """,
                (
                    entry_id,
                    "Delete",
                    username,
                    timestamp,
                    details_text,
                ),
            )
            conn.commit()

            # Log audit to ClickHouse
            if clickhouse_service.is_available():
                clickhouse_service.insert_audit_log(
                    entity_type="exclusion",
                    entity_id=str(entry_id),
                    action="Delete",
                    username=username,
                    details={"notes": details_text},
                )

            return True
    except Exception as e:
        logger.error(f"Error deleting exclusion {entry_id}: {e}")
        return False


def get_exclusion_audit_history(exclusion_id: Optional[int] = None):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            if exclusion_id:
                cursor.execute(
                    "SELECT * FROM exclusion_audit_history WHERE exclusion_id = ? ORDER BY id DESC",
                    (exclusion_id,),
                )
            else:
                cursor.execute("SELECT * FROM exclusion_audit_history ORDER BY id DESC")
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Error getting audit history: {e}")
        return []


def get_all_active_exclusions():
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM exclusions WHERE status = 'Active'")
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Error getting active exclusions: {e}")
        return []


def get_exclusions_analytics():
    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            # 1. Counts
            cursor.execute("SELECT COUNT(*) FROM exclusions")
            total = cursor.fetchone()[0] or 0

            cursor.execute("SELECT COUNT(*) FROM exclusions WHERE status = 'Active'")
            active = cursor.fetchone()[0] or 0

            cursor.execute("SELECT COUNT(*) FROM exclusions WHERE status = 'Disabled'")
            disabled = cursor.fetchone()[0] or 0

            # 2. Most frequently excluded rules
            cursor.execute("""
                SELECT rule_id, COUNT(*) as count 
                FROM exclusions 
                GROUP BY rule_id 
                ORDER BY count DESC 
                LIMIT 5
            """)
            top_excluded = [dict(row) for row in cursor.fetchall()]

            # 3. Top FP rules
            cursor.execute("""
                SELECT rule_id, COUNT(*) as count 
                FROM false_positives 
                GROUP BY rule_id 
                ORDER BY count DESC 
                LIMIT 5
            """)
            top_fp = [dict(row) for row in cursor.fetchall()]

            # 4. Exclusions created over time (grouped by day)
            cursor.execute("""
                SELECT substr(created_at, 1, 10) as date, COUNT(*) as count 
                FROM exclusions 
                GROUP BY date 
                ORDER BY date ASC
            """)
            over_time = [dict(row) for row in cursor.fetchall()]

            return {
                "total_exclusions": total,
                "active_exclusions": active,
                "disabled_exclusions": disabled,
                "top_excluded_rules": top_excluded,
                "top_fp_rules": top_fp,
                "exclusions_by_date": over_time,
            }
    except Exception as e:
        logger.error(f"Error gathering exclusions analytics: {e}")
        return {
            "total_exclusions": 0,
            "active_exclusions": 0,
            "disabled_exclusions": 0,
            "top_excluded_rules": [],
            "top_fp_rules": [],
            "exclusions_by_date": [],
        }


# ========================================================
# Ingestion state — small cross-restart key/value cursor store
# ========================================================


def get_ingestion_state(key: str, default: Optional[str] = None) -> Optional[str]:
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM ingestion_state WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row["value"] if row else default
    except Exception as e:
        logger.error(f"Error reading ingestion_state[{key}]: {e}")
        return default


def set_ingestion_state(key: str, value: str) -> None:
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO ingestion_state (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Error writing ingestion_state[{key}]: {e}")


# ========================================================
# Phase 3: API Protection database operations
# ========================================================


def _row_to_endpoint_dict(row) -> dict:
    """sqlite3.Row -> dict, with param_names parsed from its stored JSON
    string into an actual list — matches the shape the ClickHouse read path
    returns (Array(String) comes back as a native Python list there)."""
    d = dict(row)
    try:
        d["param_names"] = json.loads(d.get("param_names") or "[]")
    except Exception:
        d["param_names"] = []
    return d


def get_all_discovered_endpoints():
    if clickhouse_service.is_available():
        res = clickhouse_service.get_all_discovered_endpoints()
        if res:
            return res
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM discovered_endpoints ORDER BY hit_count DESC")
            return [_row_to_endpoint_dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Error fetching discovered endpoints: {e}")
        return []


def get_recently_discovered_endpoints(hours: int = 48):
    if clickhouse_service.is_available():
        res = clickhouse_service.get_recently_discovered_endpoints(hours)
        if res:
            return res
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM discovered_endpoints
                WHERE datetime(first_seen) >= datetime('now', ?)
                ORDER BY first_seen DESC
            """,
                (f"-{hours} hours",),
            )
            return [_row_to_endpoint_dict(row) for row in cursor.fetchall()]
    except Exception:
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM discovered_endpoints ORDER BY first_seen DESC LIMIT 10"
                )
                return [_row_to_endpoint_dict(row) for row in cursor.fetchall()]
        except Exception as ex:
            logger.error(f"Error fetching recently discovered endpoints: {ex}")
            return []


def get_stale_discovered_endpoints(days: int = 30):
    """Endpoints whose last_seen is at least `days` days ago — shadow/zombie
    API candidates (deprecated-but-still-reachable, forgotten debug routes,
    etc). A empty result is the normal/healthy case, unlike the other two
    lookups above."""
    if clickhouse_service.is_available():
        res = clickhouse_service.get_stale_discovered_endpoints(days)
        if res:
            return res
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM discovered_endpoints
                WHERE datetime(last_seen) < datetime('now', ?)
                ORDER BY last_seen ASC
            """,
                (f"-{days} days",),
            )
            return [_row_to_endpoint_dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Error fetching stale discovered endpoints: {e}")
        return []


def save_api_spec(filename: str, version: str, raw_content: str, endpoint_count: int, uploaded_by: str, uploaded_at: str) -> None:
    """Replaces the active spec (single-row table, id=1) — an upload
    always supersedes whatever was there before."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO api_spec (id, filename, version, raw_content, endpoint_count, uploaded_by, uploaded_at)
            VALUES (1, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                filename = excluded.filename,
                version = excluded.version,
                raw_content = excluded.raw_content,
                endpoint_count = excluded.endpoint_count,
                uploaded_by = excluded.uploaded_by,
                uploaded_at = excluded.uploaded_at
            """,
            (filename, version, raw_content, endpoint_count, uploaded_by, uploaded_at),
        )
        conn.commit()


def get_api_spec() -> Optional[dict]:
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM api_spec WHERE id = 1")
            row = cursor.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error fetching API spec: {e}")
        return None


def create_backup_record(
    created_at: str, filename: str, size_bytes: int, triggered_by: str, trigger_type: str = "manual"
) -> int:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO backups (created_at, filename, size_bytes, triggered_by, trigger_type)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, filename, size_bytes, triggered_by, trigger_type),
        )
        conn.commit()
        return cursor.lastrowid


def get_all_backups() -> List[dict]:
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM backups ORDER BY created_at DESC")
            return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Error fetching backups: {e}")
        return []


def get_backup_by_id(backup_id: int) -> Optional[dict]:
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM backups WHERE id = ?", (backup_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error fetching backup {backup_id}: {e}")
        return None


def delete_backup_record(backup_id: int) -> None:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM backups WHERE id = ?", (backup_id,))
        conn.commit()


def delete_api_spec() -> None:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM api_spec WHERE id = 1")
        conn.commit()


def reconcile_clickhouse_from_sqlite() -> dict:
    """
    Repairs a ClickHouse/SQLite data-store split for discovered API
    endpoints — e.g. after a ClickHouse outage (auth failure, connection
    drop). SQLite is written unconditionally on every discovery cycle
    (see bulk_upsert_discovered_endpoints) regardless of ClickHouse's
    availability, so it never loses data during an outage — but
    get_all_discovered_endpoints() prefers ClickHouse whenever it has ANY
    rows, so until this runs, an outage leaves the two stores showing
    different totals (ClickHouse only sees traffic since it came back;
    SQLite has the full history).

    Only backfills (uri, method) pairs ClickHouse has never seen at all —
    an endpoint present in both stores is left alone, because SQLite's
    running total for it already includes whatever period ClickHouse's
    own rows also cover (SQLite never stopped accumulating), so copying
    SQLite's total on top would double-count that overlap. Safe to run
    anytime, including when the two stores are already in sync (a no-op).
    """
    if not clickhouse_service.is_available():
        return {"ok": False, "message": "ClickHouse is not available.", "backfilled_count": 0}

    ch_known = clickhouse_service.get_known_endpoint_keys()

    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM discovered_endpoints")
            sqlite_rows = [_row_to_endpoint_dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Reconcile: failed to read SQLite discovered_endpoints: {e}")
        return {"ok": False, "message": f"Failed to read SQLite: {e}", "backfilled_count": 0}

    missing = [r for r in sqlite_rows if (r["uri"], r["method"]) not in ch_known]
    if not missing:
        return {
            "ok": True,
            "message": "Already in sync — no endpoints missing from ClickHouse.",
            "backfilled_count": 0,
            "sqlite_total": len(sqlite_rows),
            "clickhouse_total_before": len(ch_known),
            "clickhouse_total_after": len(ch_known),
        }

    backfilled = clickhouse_service.backfill_api_discovery_rows(missing)
    logger.info(f"Reconcile: backfilled {backfilled} endpoint(s) from SQLite into ClickHouse.")
    return {
        "ok": backfilled == len(missing),
        "message": f"Backfilled {backfilled} endpoint(s) missing from ClickHouse.",
        "backfilled_count": backfilled,
        "sqlite_total": len(sqlite_rows),
        "clickhouse_total_before": len(ch_known),
        "clickhouse_total_after": len(ch_known) + backfilled,
    }


def bulk_upsert_discovered_endpoints(endpoints_data: dict):
    if not endpoints_data:
        return

    # 1. Ingest to ClickHouse
    if clickhouse_service.is_available():
        records = []
        for (uri, method), data in endpoints_data.items():
            records.append({
                "uri": uri,
                "method": method,
                "timestamp": data["timestamp"],
                "hit_count": data["hit_count"],
                "error_count": data["error_count"],
                "malicious_count": data["malicious_count"],
                "suspicious_count": data["suspicious_count"],
                "external_hit_count": data.get("external_hit_count", 0),
                "internal_hit_count": data.get("internal_hit_count", 0),
                "has_https": data["has_https"],
                "has_versioning": data["has_versioning"],
                "content_encoding": data["content_encoding"],
                "avg_response_time_ms": data["response_time_ms_sum"] / data["hit_count"] if data["hit_count"] > 0 else 0.0,
                "param_names": data.get("param_names", []),
            })
        clickhouse_service.insert_api_discovery(records)

    # 2. Sync to SQLite (always as local/redundant fallback store)
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            
            for (uri, method), data in endpoints_data.items():
                cursor.execute(
                    "SELECT * FROM discovered_endpoints WHERE uri = ? AND method = ?",
                    (uri, method),
                )
                row = cursor.fetchone()

                if row:
                    row_dict = dict(row)
                    new_hit_count = row_dict["hit_count"] + data["hit_count"]
                    new_external_hit_count = row_dict.get("external_hit_count", 0) + data.get("external_hit_count", 0)
                    new_internal_hit_count = row_dict.get("internal_hit_count", 0) + data.get("internal_hit_count", 0)

                    total_time_existing = row_dict["avg_response_time_ms"] * row_dict["hit_count"]
                    new_avg = (total_time_existing + data["response_time_ms_sum"]) / new_hit_count

                    new_error_count = row_dict["error_count"] + data["error_count"]
                    new_malicious_count = row_dict["malicious_count"] + data["malicious_count"]
                    new_suspicious_count = row_dict["suspicious_count"] + data["suspicious_count"]

                    # Merge has_https/content_encoding across batches the same way
                    # api_discovery.py merges within a batch: never let the "not
                    # measured" sentinel overwrite a previously known value, and a
                    # confirmed-insecure hit (0) always wins over confirmed-secure
                    # (1) since it's a real finding, not noise to average away.
                    # Sentinels mirrored from api_discovery.py's HTTPS_UNKNOWN (2)
                    # and ENCODING_UNKNOWN ("unknown") — kept local here to avoid
                    # a circular import (api_discovery already imports db_service).
                    existing_https = row_dict.get("has_https", 2)
                    new_https = min(existing_https, data["has_https"])

                    new_encoding = (
                        data["content_encoding"]
                        if data["content_encoding"] != "unknown"
                        else row_dict["content_encoding"]
                    )

                    # Union with whatever param names were already seen —
                    # each batch only carries what it observed, not the
                    # endpoint's full lifetime history, so this must
                    # accumulate rather than overwrite.
                    try:
                        existing_params = set(json.loads(row_dict.get("param_names") or "[]"))
                    except Exception:
                        existing_params = set()
                    new_params = sorted(existing_params | set(data.get("param_names", [])))

                    cursor.execute(
                        """
                        UPDATE discovered_endpoints
                        SET last_seen = ?,
                            avg_response_time_ms = ?,
                            hit_count = ?,
                            external_hit_count = ?,
                            internal_hit_count = ?,
                            error_count = ?,
                            malicious_count = ?,
                            suspicious_count = ?,
                            has_https = ?,
                            content_encoding = ?,
                            param_names = ?
                        WHERE uri = ? AND method = ?
                    """,
                        (
                            data["timestamp"],
                            new_avg,
                            new_hit_count,
                            new_external_hit_count,
                            new_internal_hit_count,
                            new_error_count,
                            new_malicious_count,
                            new_suspicious_count,
                            new_https,
                            new_encoding,
                            json.dumps(new_params),
                            uri,
                            method,
                        ),
                    )
                else:
                    avg_time = data["response_time_ms_sum"] / data["hit_count"] if data["hit_count"] > 0 else 0
                    cursor.execute(
                        """
                        INSERT INTO discovered_endpoints (
                            uri, method, first_seen, last_seen, avg_response_time_ms, hit_count,
                            external_hit_count, internal_hit_count, error_count, malicious_count,
                            suspicious_count, has_https, has_versioning, content_encoding, param_names
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            uri,
                            method,
                            data["timestamp"],
                            data["timestamp"],
                            avg_time,
                            data["hit_count"],
                            data.get("external_hit_count", 0),
                            data.get("internal_hit_count", 0),
                            data["error_count"],
                            data["malicious_count"],
                            data["suspicious_count"],
                            data["has_https"],
                            data["has_versioning"],
                            data["content_encoding"] or "",
                            json.dumps(sorted(data.get("param_names", []))),
                        ),
                    )
            conn.commit()
    except Exception as e:
        logger.error(f"Error in bulk upserting discovered endpoints: {e}")


def get_all_protected_apps():
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM protected_apps ORDER BY id ASC")
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Error fetching all protected apps: {e}")
        return []


def get_protected_app_by_id(app_id: int):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM protected_apps WHERE id = ?", (app_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error fetching protected app by id {app_id}: {e}")
        return None


def create_protected_app(
    name: str,
    domain: str,
    upstream_host: str,
    upstream_port: int,
    protocol: str = "http",
    is_active: int = 1,
    rate_limit_rps: int = 50,
    burst_tolerance: int = 100,
    ssl_option: str = "self-signed",
    ssl_cert_path: str = None,
    ssl_key_path: str = None,
    require_auth: int = 0,
    auth_check_type: str = "header",
    auth_header_name: str = "Authorization",
    additional_origins: str = None,
):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO protected_apps
                    (name, domain, upstream_host, upstream_port, protocol, is_active,
                     rate_limit_rps, burst_tolerance, ssl_option, ssl_cert_path, ssl_key_path,
                     require_auth, auth_check_type, auth_header_name, additional_origins)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                name, domain.strip().lower(), upstream_host.strip(),
                upstream_port, protocol.strip().lower(), is_active,
                rate_limit_rps, burst_tolerance,
                ssl_option, ssl_cert_path, ssl_key_path,
                require_auth, auth_check_type, auth_header_name,
                additional_origins,
            ))
            conn.commit()
            new_id = cursor.lastrowid
            return get_protected_app_by_id(new_id)
    except Exception as e:
        logger.error(f"Error creating protected app: {e}")
        return None


def update_protected_app(
    app_id: int,
    name: str,
    domain: str,
    upstream_host: str,
    upstream_port: int,
    protocol: str = "http",
    is_active: int = 1,
    rate_limit_rps: int = 50,
    burst_tolerance: int = 100,
    ssl_option: str = "self-signed",
    ssl_cert_path: str = None,
    ssl_key_path: str = None,
    require_auth: int = 0,
    auth_check_type: str = "header",
    auth_header_name: str = "Authorization",
    additional_origins: str = None,
):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE protected_apps
                SET name = ?, domain = ?, upstream_host = ?, upstream_port = ?,
                    protocol = ?, is_active = ?, rate_limit_rps = ?, burst_tolerance = ?,
                    ssl_option = ?,
                    ssl_cert_path = COALESCE(?, ssl_cert_path),
                    ssl_key_path  = COALESCE(?, ssl_key_path),
                    require_auth = ?, auth_check_type = ?, auth_header_name = ?,
                    additional_origins = ?
                WHERE id = ?
            """, (
                name, domain.strip().lower(), upstream_host.strip(),
                upstream_port, protocol.strip().lower(), is_active,
                rate_limit_rps, burst_tolerance,
                ssl_option, ssl_cert_path, ssl_key_path,
                require_auth, auth_check_type, auth_header_name,
                additional_origins,
                app_id,
            ))
            conn.commit()
            return get_protected_app_by_id(app_id)
    except Exception as e:
        logger.error(f"Error updating protected app: {e}")
        return None


def update_app_api_schema(app_id: int, api_schema: str, api_schema_mode: str):
    """api_schema is a JSON string (or None to clear) — see nginx_manager.
    apply_api_schema_settings for the expected shape."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE protected_apps SET api_schema = ?, api_schema_mode = ? WHERE id = ?",
                (api_schema, api_schema_mode, app_id),
            )
            conn.commit()
            return get_protected_app_by_id(app_id)
    except Exception as e:
        logger.error(f"Error updating API schema for app {app_id}: {e}")
        return None


def delete_protected_app(app_id: int):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM protected_apps WHERE id = ?", (app_id,))
            # Orphaned scoping rows for a deleted app are meaningless —
            # clean them up so a future app reusing the same id (SQLite
            # reuses rowids once AUTOINCREMENT's high-water mark allows it
            # only in edge cases, but stale rows here are harmless-but-
            # confusing either way) doesn't inherit access grants nobody
            # intended for it.
            cursor.execute("DELETE FROM app_user_access WHERE app_id = ?", (app_id,))
            conn.commit()
            return True
    except Exception as e:
        logger.error(f"Error deleting protected app {app_id}: {e}")
        return False


# ========================================================
# Per-app RBAC scoping (item 7) — which apps an 'app_admin' user may access.
# 'admin' bypasses this entirely (see auth.require_app_access()); these
# functions are meaningless for any other role and callers should not
# invoke them for 'admin'/'analyst' users.
# ========================================================


def get_app_ids_for_user(username: str) -> List[int]:
    """App ids a given app_admin username is scoped to."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT app_id FROM app_user_access WHERE username = ?", (username,))
            return [row["app_id"] for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Error fetching app access for user '{username}': {e}")
        return []


def user_has_app_access(username: str, app_id: int) -> bool:
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT 1 FROM app_user_access WHERE username = ? AND app_id = ?",
                (username, app_id),
            )
            return cursor.fetchone() is not None
    except Exception as e:
        logger.error(f"Error checking app access for user '{username}', app {app_id}: {e}")
        return False


def set_app_access_for_user(username: str, app_ids: List[int]) -> bool:
    """Replaces this username's full set of app grants with exactly
    app_ids (idempotent — safe to call with the same list twice, and an
    empty list simply revokes everything)."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM app_user_access WHERE username = ?", (username,))
            cursor.executemany(
                "INSERT INTO app_user_access (username, app_id) VALUES (?, ?)",
                [(username, app_id) for app_id in app_ids],
            )
            conn.commit()
            return True
    except Exception as e:
        logger.error(f"Error setting app access for user '{username}': {e}")
        return False


# ========================================================
# Auto-Learning suggestions (Settings > Auto-Learning)
# ========================================================


def _find_auto_learning_suggestion(cursor, rule_id: str, exclusion_type: str, uri, parameter_name):
    """
    NULL-safe lookup for the UNIQUE(rule_id, exclusion_type, uri,
    parameter_name) key — SQLite's UNIQUE constraint treats every NULL as
    distinct from every other NULL, so it alone can't prevent duplicate
    rows when uri/parameter_name are both None (e.g. a global 'parameter'
    exclusion_type). This does the real dedup check the constraint can't.
    """
    cursor.execute(
        """
        SELECT * FROM auto_learning_suggestions
        WHERE rule_id = ? AND exclusion_type = ?
          AND (uri IS ? OR uri = ?)
          AND (parameter_name IS ? OR parameter_name = ?)
        """,
        (rule_id, exclusion_type, uri, uri, parameter_name, parameter_name),
    )
    return cursor.fetchone()


def upsert_auto_learning_suggestion(
    rule_id: str,
    exclusion_type: str,
    uri: Optional[str],
    parameter_name: Optional[str],
    confidence_score: int,
    reasoning: str,
    false_positive_ids: List[Any],
    timestamp: str,
):
    """
    Creates a new Pending suggestion, or refreshes an existing Pending
    row's occurrence count/confidence/reasoning/sample IDs. Deliberately
    does NOT touch a row that's already Approved (exclusion already
    applied — recomputing would just be noise) or Rejected (an admin
    already made the call on this exact pattern; don't resurrect it
    silently on the next cycle).
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            existing = _find_auto_learning_suggestion(cursor, rule_id, exclusion_type, uri, parameter_name)

            if existing and existing["status"] != "Pending":
                return dict(existing)

            if existing:
                merged_ids = sorted(set(json.loads(existing["sample_false_positive_ids"])) | set(false_positive_ids))
                cursor.execute(
                    """
                    UPDATE auto_learning_suggestions
                    SET occurrence_count = ?, confidence_score = ?, reasoning = ?,
                        sample_false_positive_ids = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        len(merged_ids), confidence_score, reasoning,
                        json.dumps(merged_ids[:20]), timestamp, existing["id"],
                    ),
                )
                conn.commit()
                new_id = existing["id"]
            else:
                cursor.execute(
                    """
                    INSERT INTO auto_learning_suggestions
                        (rule_id, exclusion_type, uri, parameter_name, occurrence_count,
                         confidence_score, reasoning, sample_false_positive_ids,
                         status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Pending', ?, ?)
                    """,
                    (
                        rule_id, exclusion_type, uri, parameter_name, len(false_positive_ids),
                        confidence_score, reasoning, json.dumps(false_positive_ids[:20]),
                        timestamp, timestamp,
                    ),
                )
                conn.commit()
                new_id = cursor.lastrowid

            cursor.execute("SELECT * FROM auto_learning_suggestions WHERE id = ?", (new_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error upserting auto-learning suggestion for rule {rule_id}: {e}")
        return None


def get_all_auto_learning_suggestions(status: Optional[str] = None):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM auto_learning_suggestions WHERE 1=1"
            params = []
            if status:
                query += " AND status = ?"
                params.append(status)
            query += " ORDER BY confidence_score DESC, occurrence_count DESC"
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Error listing auto-learning suggestions: {e}")
        return []


def get_auto_learning_suggestion_by_id(suggestion_id: int):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM auto_learning_suggestions WHERE id = ?", (suggestion_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error fetching auto-learning suggestion {suggestion_id}: {e}")
        return None


def update_auto_learning_suggestion_status(suggestion_id: int, status: str, reviewed_by: str, timestamp: str):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE auto_learning_suggestions
                SET status = ?, reviewed_by = ?, reviewed_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (status, reviewed_by, timestamp, timestamp, suggestion_id),
            )
            conn.commit()
            cursor.execute("SELECT * FROM auto_learning_suggestions WHERE id = ?", (suggestion_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error updating auto-learning suggestion {suggestion_id}: {e}")
        return None
