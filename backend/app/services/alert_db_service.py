"""
CyberSentinel WAF - Alert Database Service
Handles all database operations for the alerting system
"""
import sqlite3
import json
import hashlib
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Tuple
from pathlib import Path
import logging

from app.services import clickhouse_service

logger = logging.getLogger(__name__)

# Database path
DB_DIR = Path(__file__).parent.parent / "data"
DB_DIR.mkdir(parents=True, exist_ok=True)
ALERTS_DB_PATH = DB_DIR / "alerts.db"


class AlertDatabaseService:
    """Service for managing alert system database operations"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or str(ALERTS_DB_PATH)
        self._init_database()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection with JSON support"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _migrate_alert_channels_syslog_type(self, cursor: sqlite3.Cursor) -> None:
        """
        Widens alert_channels.channel_type's CHECK constraint to allow
        'syslog' (P1-12), for databases created before that channel type
        existed. `CREATE TABLE IF NOT EXISTS` above is a no-op against an
        already-existing table, so an existing install's table still has
        the old CHECK(...'pagerduty')) baked in — SQLite has no ALTER TABLE
        for modifying a CHECK constraint in place, so this is the standard
        rebuild-and-copy migration: rename, recreate with the wider
        constraint, copy every row across, drop the old table. Idempotent
        — checks sqlite_master's stored SQL text for 'syslog' first, so
        this is a no-op on every run after the first (or on a fresh
        install, which already has the wide constraint from CREATE TABLE).
        """
        cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='alert_channels'")
        row = cursor.fetchone()
        existing_sql = row[0] if row else ""
        if not existing_sql or "syslog" in existing_sql:
            return

        logger.info("Migrating alert_channels.channel_type CHECK constraint to allow 'syslog'.")
        cursor.execute("ALTER TABLE alert_channels RENAME TO alert_channels_old")
        cursor.execute("""
            CREATE TABLE alert_channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                channel_type TEXT NOT NULL CHECK(channel_type IN ('email', 'slack', 'webhook', 'pagerduty', 'syslog')),
                config TEXT NOT NULL,
                enabled BOOLEAN DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            INSERT INTO alert_channels (id, name, channel_type, config, enabled, created_at, updated_at)
            SELECT id, name, channel_type, config, enabled, created_at, updated_at FROM alert_channels_old
        """)
        cursor.execute("DROP TABLE alert_channels_old")

    def _init_database(self):
        """Initialize database schema if not exists"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            # Create alert_channels table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alert_channels (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    channel_type TEXT NOT NULL CHECK(channel_type IN ('email', 'slack', 'webhook', 'pagerduty', 'syslog')),
                    config TEXT NOT NULL,
                    enabled BOOLEAN DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            self._migrate_alert_channels_syslog_type(cursor)

            # Create alert_rules table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alert_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    event_type TEXT NOT NULL CHECK(event_type IN (
                        'attack_detected', 'high_threat_score', 'ddos_detected',
                        'rate_limit_exceeded', 'ml_anomaly', 'geo_violation',
                        'system_error', 'health_check_failed', 'config_changed'
                    )),
                    severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
                    conditions TEXT NOT NULL,
                    channels TEXT NOT NULL,
                    throttle_minutes INTEGER DEFAULT 5,
                    enabled BOOLEAN DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create alert_history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alert_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id INTEGER NOT NULL,
                    rule_name TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    channels_notified TEXT NOT NULL,
                    event_data TEXT NOT NULL,
                    message TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('sent', 'failed', 'throttled', 'acknowledged')),
                    error_message TEXT,
                    acknowledged_by TEXT,
                    acknowledged_at DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE
                )
            """)
            
            # Create alert_aggregations table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alert_aggregations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id INTEGER NOT NULL,
                    event_signature TEXT NOT NULL,
                    first_occurrence DATETIME NOT NULL,
                    last_occurrence DATETIME NOT NULL,
                    occurrence_count INTEGER DEFAULT 1,
                    last_notified_at DATETIME,
                    FOREIGN KEY (rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE
                )
            """)
            
            # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_history_rule ON alert_history(rule_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_history_created ON alert_history(created_at DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_history_severity ON alert_history(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_agg_rule_sig ON alert_aggregations(rule_id, event_signature)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_agg_last_notified ON alert_aggregations(last_notified_at)")
            # Seed default notification channel if empty
            cursor.execute("SELECT COUNT(*) FROM alert_channels")
            if cursor.fetchone()[0] == 0:
                default_config = json.dumps({"url": "http://localhost:8000/alerts/trigger", "method": "POST"})
                cursor.execute("""
                    INSERT INTO alert_channels (name, channel_type, config, enabled)
                    VALUES ('Default Log webhook', 'webhook', ?, 1)
                """, (default_config,))
                
            # Seed default alert rules if empty
            cursor.execute("SELECT COUNT(*) FROM alert_rules")
            if cursor.fetchone()[0] == 0:
                # Rule 1: Critical ML Threat
                cursor.execute("""
                    INSERT INTO alert_rules (name, description, event_type, severity, conditions, channels, throttle_minutes, enabled)
                    VALUES ('Critical ML Threat', 'Triggers when combined ML threat score exceeds 80', 'high_threat_score', 'critical', '{"threat_score_gt": 80}', '[1]', 5, 1)
                """)
                # Rule 2: High WAF Attack Rule
                cursor.execute("""
                    INSERT INTO alert_rules (name, description, event_type, severity, conditions, channels, throttle_minutes, enabled)
                    VALUES ('High WAF Attack Rule', 'Triggers when ModSecurity CRS score is high', 'attack_detected', 'high', '{"crs_score_gt": 4}', '[1]', 5, 1)
                """)
                # Rule 3: ML Novelty Anomaly
                cursor.execute("""
                    INSERT INTO alert_rules (name, description, event_type, severity, conditions, channels, throttle_minutes, enabled)
                    VALUES ('ML Novelty Anomaly', 'Triggers when Isolation Forest anomaly matches conditions', 'ml_anomaly', 'high', '{"isolation_score_gt": 0.5}', '[1]', 5, 1)
                """)

            conn.commit()
            logger.info("Alert database initialized and seeded successfully")
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to initialize alert database: {e}")
            raise
        finally:
            conn.close()
    
    # ========================================================================
    # Alert Channel Operations
    # ========================================================================
    
    def create_channel(self, name: str, channel_type: str, config: Dict[str, Any], enabled: bool = True) -> int:
        """Create a new alert channel"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO alert_channels (name, channel_type, config, enabled)
                VALUES (?, ?, ?, ?)
            """, (name, channel_type, json.dumps(config), enabled))
            
            conn.commit()
            channel_id = cursor.lastrowid
            logger.info(f"Created alert channel: {name} (ID: {channel_id})")
            return channel_id
        except sqlite3.IntegrityError:
            raise ValueError(f"Channel with name '{name}' already exists")
        finally:
            conn.close()
    
    def get_channel(self, channel_id: int) -> Optional[Dict[str, Any]]:
        """Get channel by ID"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT * FROM alert_channels WHERE id = ?", (channel_id,))
            row = cursor.fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()
    
    def get_channels(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        """Get all alert channels"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            query = "SELECT * FROM alert_channels"
            if enabled_only:
                query += " WHERE enabled = 1"
            query += " ORDER BY created_at DESC"
            
            cursor.execute(query)
            return [self._row_to_dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()
    
    def update_channel(self, channel_id: int, **kwargs) -> bool:
        """Update alert channel"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            # Build dynamic update query
            updates = []
            values = []
            
            for key, value in kwargs.items():
                if key in ['name', 'channel_type', 'enabled']:
                    updates.append(f"{key} = ?")
                    values.append(value)
                elif key == 'config':
                    updates.append("config = ?")
                    values.append(json.dumps(value))
            
            if not updates:
                return False
            
            updates.append("updated_at = CURRENT_TIMESTAMP")
            values.append(channel_id)
            
            query = f"UPDATE alert_channels SET {', '.join(updates)} WHERE id = ?"
            cursor.execute(query, values)
            conn.commit()
            
            return cursor.rowcount > 0
        finally:
            conn.close()
    
    def delete_channel(self, channel_id: int) -> bool:
        """Delete alert channel"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("DELETE FROM alert_channels WHERE id = ?", (channel_id,))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()
    
    # ========================================================================
    # Alert Rule Operations
    # ========================================================================
    
    def create_rule(self, name: str, event_type: str, severity: str, 
                   conditions: Dict[str, Any], channels: List[int],
                   description: str = None, throttle_minutes: int = 5,
                   enabled: bool = True) -> int:
        """Create a new alert rule"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO alert_rules 
                (name, description, event_type, severity, conditions, channels, throttle_minutes, enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (name, description, event_type, severity, 
                  json.dumps(conditions), json.dumps(channels), throttle_minutes, enabled))
            
            conn.commit()
            rule_id = cursor.lastrowid
            logger.info(f"Created alert rule: {name} (ID: {rule_id})")
            return rule_id
        except sqlite3.IntegrityError:
            raise ValueError(f"Rule with name '{name}' already exists")
        finally:
            conn.close()
    
    def get_rule(self, rule_id: int) -> Optional[Dict[str, Any]]:
        """Get rule by ID"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT * FROM alert_rules WHERE id = ?", (rule_id,))
            row = cursor.fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()
    
    def get_rules(self, enabled_only: bool = False, event_type: str = None) -> List[Dict[str, Any]]:
        """Get all alert rules with optional filtering"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            query = "SELECT * FROM alert_rules WHERE 1=1"
            params = []
            
            if enabled_only:
                query += " AND enabled = 1"
            if event_type:
                query += " AND event_type = ?"
                params.append(event_type)
            
            query += " ORDER BY created_at DESC"
            
            cursor.execute(query, params)
            return [self._row_to_dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()
    
    def update_rule(self, rule_id: int, **kwargs) -> bool:
        """Update alert rule"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            updates = []
            values = []
            
            for key, value in kwargs.items():
                if key in ['name', 'description', 'event_type', 'severity', 'throttle_minutes', 'enabled']:
                    updates.append(f"{key} = ?")
                    values.append(value)
                elif key in ['conditions', 'channels']:
                    updates.append(f"{key} = ?")
                    values.append(json.dumps(value))
            
            if not updates:
                return False
            
            updates.append("updated_at = CURRENT_TIMESTAMP")
            values.append(rule_id)
            
            query = f"UPDATE alert_rules SET {', '.join(updates)} WHERE id = ?"
            cursor.execute(query, values)
            conn.commit()
            
            return cursor.rowcount > 0
        finally:
            conn.close()
    
    def delete_rule(self, rule_id: int) -> bool:
        """Delete alert rule"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()
    
    # ========================================================================
    # Alert History Operations
    # ========================================================================
    
    def create_alert_history(self, rule_id: int, rule_name: str, event_type: str,
                            severity: str, channels_notified: List[str],
                            event_data: Dict[str, Any], message: str,
                            status: str, error_message: str = None) -> int:
        """Create alert history entry"""
        new_id = 0
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO alert_history 
                (rule_id, rule_name, event_type, severity, channels_notified, 
                 event_data, message, status, error_message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (rule_id, rule_name, event_type, severity, 
                  json.dumps(channels_notified), json.dumps(event_data),
                  message, status, error_message))
            
            conn.commit()
            new_id = cursor.lastrowid
        except Exception as e:
            logger.error(f"Error creating alert history in SQLite: {e}")
        finally:
            conn.close()

        if clickhouse_service.is_available() and new_id > 0:
            record = {
                "id": new_id,
                "rule_id": rule_id,
                "rule_name": rule_name,
                "event_type": event_type,
                "severity": severity,
                "channels_notified": json.dumps(channels_notified),
                "event_data": json.dumps(event_data),
                "message": message,
                "status": status,
                "error_message": error_message or "",
                "acknowledged_by": "",
                "acknowledged_at": None,
            }
            clickhouse_service.insert_alert_history(record)
            
        return new_id
    
    def get_alert_history(self, limit: int = 100, offset: int = 0,
                          event_type: str = None, severity: str = None, status: str = None,
                          start_date: datetime = None, end_date: datetime = None) -> List[Dict[str, Any]]:
        """Get alert history with filtering and pagination"""
        if clickhouse_service.is_available():
            res = clickhouse_service.query_alert_history(
                limit=limit, offset=offset, event_type=event_type, severity=severity, status=status,
                start_date=start_date, end_date=end_date
            )
            if res:
                for d in res:
                    try:
                        d["channels_notified"] = json.loads(d["channels_notified"])
                    except Exception:
                        pass
                    try:
                        d["event_data"] = json.loads(d["event_data"])
                    except Exception:
                        pass
                return res

        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            query = "SELECT * FROM alert_history WHERE 1=1"
            params = []
            
            if event_type:
                query += " AND event_type = ?"
                params.append(event_type)
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            if status:
                query += " AND status = ?"
                params.append(status)
            if start_date:
                query += " AND created_at >= ?"
                params.append(start_date.isoformat())
            if end_date:
                query += " AND created_at <= ?"
                params.append(end_date.isoformat())
            
            # Get paginated results
            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            results = [self._row_to_dict(row) for row in cursor.fetchall()]
            
            return results
        finally:
            conn.close()
    
    def acknowledge_alert(self, alert_id: int, acknowledged_by: str) -> bool:
        """Mark alert as acknowledged"""
        ch_ok = False
        if clickhouse_service.is_available():
            ch_ok = clickhouse_service.acknowledge_alert(alert_id, acknowledged_by)

        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                UPDATE alert_history 
                SET status = 'acknowledged', acknowledged_by = ?, acknowledged_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (acknowledged_by, alert_id))
            
            conn.commit()
            return cursor.rowcount > 0 or ch_ok
        finally:
            conn.close()
    
    # ========================================================================
    # Alert Aggregation Operations
    # ========================================================================
    
    def should_throttle_alert(self, rule_id: int, event_signature: str, throttle_minutes: int) -> bool:
        """Check if alert should be throttled based on recent notifications"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            threshold = datetime.now() - timedelta(minutes=throttle_minutes)
            
            cursor.execute("""
                SELECT last_notified_at FROM alert_aggregations
                WHERE rule_id = ? AND event_signature = ? AND last_notified_at > ?
            """, (rule_id, event_signature, threshold.isoformat()))
            
            return cursor.fetchone() is not None
        finally:
            conn.close()
    
    def update_aggregation(self, rule_id: int, event_signature: str, notified: bool = False):
        """Update or create alert aggregation entry"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            now = datetime.now().isoformat()
            
            # Check if aggregation exists
            cursor.execute("""
                SELECT id, occurrence_count FROM alert_aggregations
                WHERE rule_id = ? AND event_signature = ?
            """, (rule_id, event_signature))
            
            row = cursor.fetchone()
            
            if row:
                # Update existing
                agg_id, count = row
                update_query = """
                    UPDATE alert_aggregations 
                    SET last_occurrence = ?, occurrence_count = ?
                """
                params = [now, count + 1]
                
                if notified:
                    update_query += ", last_notified_at = ?"
                    params.append(now)
                
                update_query += " WHERE id = ?"
                params.append(agg_id)
                
                cursor.execute(update_query, params)
            else:
                # Create new
                cursor.execute("""
                    INSERT INTO alert_aggregations 
                    (rule_id, event_signature, first_occurrence, last_occurrence, occurrence_count, last_notified_at)
                    VALUES (?, ?, ?, ?, 1, ?)
                """, (rule_id, event_signature, now, now, now if notified else None))
            
            conn.commit()
        finally:
            conn.close()
    
    def cleanup_old_aggregations(self, days: int = 7):
        """Remove old aggregation entries"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            threshold = (datetime.now() - timedelta(days=days)).isoformat()
            cursor.execute("""
                DELETE FROM alert_aggregations 
                WHERE last_occurrence < ?
            """, (threshold,))
            
            deleted = cursor.rowcount
            conn.commit()
            logger.info(f"Cleaned up {deleted} old alert aggregations")
            return deleted
        finally:
            conn.close()
    
    # ========================================================================
    # Statistics Operations
    # ========================================================================
    
    def get_alert_stats(self, days: int = 30) -> Dict[str, Any]:
        """Get alert statistics"""
        if clickhouse_service.is_available():
            stats = clickhouse_service.get_alert_stats(days)
            if stats:
                stats["period_days"] = days
                for d in stats.get("recent_alerts", []):
                    try:
                        d["channels_notified"] = json.loads(d["channels_notified"])
                    except Exception:
                        pass
                    try:
                        d["event_data"] = json.loads(d["event_data"])
                    except Exception:
                        pass
                return stats

        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            start_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            # Total alerts
            cursor.execute("SELECT COUNT(*) FROM alert_history WHERE created_at >= ?", (start_date,))
            total_alerts = cursor.fetchone()[0]
            
            # By severity
            cursor.execute("""
                SELECT severity, COUNT(*) as count 
                FROM alert_history 
                WHERE created_at >= ?
                GROUP BY severity
            """, (start_date,))
            alerts_by_severity = {row[0]: row[1] for row in cursor.fetchall()}
            
            # By status
            cursor.execute("""
                SELECT status, COUNT(*) as count 
                FROM alert_history 
                WHERE created_at >= ?
                GROUP BY status
            """, (start_date,))
            alerts_by_status = {row[0]: row[1] for row in cursor.fetchall()}
            
            # By event type
            cursor.execute("""
                SELECT event_type, COUNT(*) as count 
                FROM alert_history 
                WHERE created_at >= ?
                GROUP BY event_type
                ORDER BY count DESC
            """, (start_date,))
            alerts_by_event_type = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Most triggered rules
            cursor.execute("""
                SELECT rule_name, COUNT(*) as count 
                FROM alert_history 
                WHERE created_at >= ?
                GROUP BY rule_name
                ORDER BY count DESC
                LIMIT 10
            """, (start_date,))
            most_triggered_rules = [{"rule_name": row[0], "count": row[1]} for row in cursor.fetchall()]
            
            # Recent alerts
            cursor.execute("SELECT * FROM alert_history ORDER BY id DESC LIMIT 5")
            recent_alerts = [self._row_to_dict(r) for r in cursor.fetchall()]
            
            # Avg alerts per day
            avg_alerts_per_day = round(float(total_alerts) / max(days, 1), 2)
            
            # Alert rate trend (first half of period vs second half)
            mid_date = (datetime.now() - timedelta(days=days / 2.0)).isoformat()
            cursor.execute("SELECT COUNT(*) FROM alert_history WHERE created_at >= ? AND created_at < ?", (start_date, mid_date))
            first_half = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM alert_history WHERE created_at >= ?", (mid_date,))
            second_half = cursor.fetchone()[0]
            
            if second_half > first_half:
                alert_rate_trend = "increasing"
            elif second_half < first_half:
                alert_rate_trend = "decreasing"
            else:
                alert_rate_trend = "stable"
                
            return {
                "total_alerts": total_alerts,
                "alerts_by_severity": alerts_by_severity,
                "alerts_by_status": alerts_by_status,
                "alerts_by_event_type": alerts_by_event_type,
                "most_triggered_rules": most_triggered_rules,
                "recent_alerts": recent_alerts,
                "avg_alerts_per_day": avg_alerts_per_day,
                "alert_rate_trend": alert_rate_trend,
                "period_days": days
            }
        finally:
            conn.close()
    
    # ========================================================================
    # Utility Methods
    # ========================================================================
    
    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Convert SQLite row to dictionary with JSON parsing"""
        if not row:
            return None
        
        result = dict(row)
        
        # Parse JSON fields
        for field in ['config', 'conditions', 'channels', 'channels_notified', 'event_data']:
            if field in result and result[field]:
                try:
                    result[field] = json.loads(result[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        
        return result
    
    @staticmethod
    def generate_event_signature(event_data: Dict[str, Any]) -> str:
        """Generate signature hash for event deduplication"""
        # Use key fields to create signature
        sig_fields = {
            'event_type': event_data.get('event_type'),
            'remote_addr': event_data.get('remote_addr'),
            'uri': event_data.get('uri'),
            'method': event_data.get('method')
        }
        
        sig_string = json.dumps(sig_fields, sort_keys=True)
        return hashlib.md5(sig_string.encode()).hexdigest()


# Singleton instance
_alert_db = None

def get_alert_db() -> AlertDatabaseService:
    """Get singleton alert database service instance"""
    global _alert_db
    if _alert_db is None:
        _alert_db = AlertDatabaseService()
    return _alert_db
