import os
import sqlite3
import logging
from typing import Optional

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

            conn.commit()
            logger.info("Database schemas initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize database schemas: {e}")
        raise e


def get_false_positive_by_log_id(log_id: str):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM false_positives WHERE log_id = ?", (log_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error fetching false positive by log_id {log_id}: {e}")
        return None


def get_false_positive_by_id(entry_id: int):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM false_positives WHERE id = ?", (entry_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
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

            cursor.execute("SELECT * FROM false_positives WHERE id = ?", (new_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error creating false positive: {e}")
        return None


def get_all_false_positives(status=None, severity=None, rule_id=None, search=None):
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
            return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"Error getting all false positives: {e}")
        return []


def update_false_positive_status(entry_id: int, status: str):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE false_positives SET status = ? WHERE id = ?", (status, entry_id)
            )
            conn.commit()

            cursor.execute("SELECT * FROM false_positives WHERE id = ?", (entry_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error updating false positive status for {entry_id}: {e}")
        return None


def update_false_positive_note(entry_id: int, analyst_note: str):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE false_positives SET analyst_note = ? WHERE id = ?",
                (analyst_note, entry_id),
            )
            conn.commit()

            cursor.execute("SELECT * FROM false_positives WHERE id = ?", (entry_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error(f"Error updating false positive note for {entry_id}: {e}")
        return None


def delete_false_positive(entry_id: int):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM false_positives WHERE id = ?", (entry_id,))
            conn.commit()
            return cursor.rowcount > 0
    except Exception as e:
        logger.error(f"Error deleting false positive {entry_id}: {e}")
        return False


# ========================================================
# Phase 2: Exclusions and Exceptions DB operations
# ========================================================


def create_exclusion(
    false_positive_id: Optional[int],
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

            # Log to audit history
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
                    f"Created exclusion policy of type '{exclusion_type}' for Rule {rule_id}.",
                ),
            )
            conn.commit()

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

            # Log audit
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
                    f"Status updated from '{old['status']}' to '{status}'.",
                ),
            )
            conn.commit()

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

            # Log audit
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
                    "Analyst justification notes updated.",
                ),
            )
            conn.commit()

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

            # Insert audit record (orphaned but kept for historical context)
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
                    f"Exclusion policy for Rule {row['rule_id']} deleted from registry.",
                ),
            )
            conn.commit()
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
# Phase 3: API Protection database operations
# ========================================================


def get_all_discovered_endpoints():
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM discovered_endpoints ORDER BY hit_count DESC")
            return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Error fetching discovered endpoints: {e}")
        return []


def get_recently_discovered_endpoints(hours: int = 48):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            # SQLite does datetime comparisons.
            # We select endpoints where first_seen is within the last 'hours' hours.
            # first_seen is saved in ISO format: 'YYYY-MM-DD HH:MM:SS' or similar
            cursor.execute(
                """
                SELECT * FROM discovered_endpoints 
                WHERE datetime(first_seen) >= datetime('now', ?) 
                ORDER BY first_seen DESC
            """,
                (f"-{hours} hours",),
            )
            return [dict(row) for row in cursor.fetchall()]
    except Exception:
        # Fallback to simple sorting if datetime parsing fails
        try:
            with get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM discovered_endpoints ORDER BY first_seen DESC LIMIT 10"
                )
                return [dict(row) for row in cursor.fetchall()]
        except Exception as ex:
            logger.error(f"Error fetching recently discovered endpoints: {ex}")
            return []


def bulk_upsert_discovered_endpoints(endpoints_data: dict):
    """
    Upserts multiple endpoints in a single database transaction.
    endpoints_data format:
    {
        (uri, method): {
            "response_time_ms_sum": float,
            "hit_count": int,
            "external_hit_count": int,
            "internal_hit_count": int,
            "error_count": int,
            "malicious_count": int,
            "suspicious_count": int,
            "has_https": int,
            "has_versioning": int,
            "content_encoding": str,
            "timestamp": str,
        },
        ...
    }
    """
    if not endpoints_data:
        return

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
                    
                    # Calculate new average
                    total_time_existing = row_dict["avg_response_time_ms"] * row_dict["hit_count"]
                    new_avg = (total_time_existing + data["response_time_ms_sum"]) / new_hit_count
                    
                    new_error_count = row_dict["error_count"] + data["error_count"]
                    new_malicious_count = row_dict["malicious_count"] + data["malicious_count"]
                    new_suspicious_count = row_dict["suspicious_count"] + data["suspicious_count"]

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
                            content_encoding = ?
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
                            data["content_encoding"] or row_dict["content_encoding"],
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
                            suspicious_count, has_https, has_versioning, content_encoding
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        ),
                    )
            # Commit all changes in one atomic transaction
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


def create_protected_app(name: str, domain: str, upstream_host: str, upstream_port: int, protocol: str = "http", is_active: int = 1, rate_limit_rps: int = 50, burst_tolerance: int = 100):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO protected_apps (name, domain, upstream_host, upstream_port, protocol, is_active, rate_limit_rps, burst_tolerance)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (name, domain.strip().lower(), upstream_host.strip(), upstream_port, protocol.strip().lower(), is_active, rate_limit_rps, burst_tolerance))
            conn.commit()
            new_id = cursor.lastrowid
            return get_protected_app_by_id(new_id)
    except Exception as e:
        logger.error(f"Error creating protected app: {e}")
        return None


def update_protected_app(app_id: int, name: str, domain: str, upstream_host: str, upstream_port: int, protocol: str = "http", is_active: int = 1, rate_limit_rps: int = 50, burst_tolerance: int = 100):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE protected_apps
                SET name = ?, domain = ?, upstream_host = ?, upstream_port = ?, protocol = ?, is_active = ?, rate_limit_rps = ?, burst_tolerance = ?
                WHERE id = ?
            """, (name, domain.strip().lower(), upstream_host.strip(), upstream_port, protocol.strip().lower(), is_active, rate_limit_rps, burst_tolerance, app_id))
            conn.commit()
            return get_protected_app_by_id(app_id)
    except Exception as e:
        logger.error(f"Error updating protected app: {e}")
        return None


def delete_protected_app(app_id: int):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM protected_apps WHERE id = ?", (app_id,))
            conn.commit()
            return True
    except Exception as e:
        logger.error(f"Error deleting protected app {app_id}: {e}")
        return False
