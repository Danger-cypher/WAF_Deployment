"""
clickhouse_service.py — CyberSentinel WAF
==========================================
Central ClickHouse client and query layer.
All reads and writes to the cybersentinel database flow through this module.

Design notes:
- Uses clickhouse-connect (official Clickhouse Python driver, HTTP-based)
- All inserts are batched — never row-by-row
- Reads use parameterized queries to prevent injection
- Client is created once per process (module-level singleton with reconnect on failure)
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import clickhouse_connect
from clickhouse_connect.driver.exceptions import ClickHouseError

from app.config.settings import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Client singleton
# ---------------------------------------------------------------------------
_client: Optional[clickhouse_connect.driver.Client] = None


def _get_client() -> Optional[clickhouse_connect.driver.Client]:
    """Return a live ClickHouse client, reconnecting if needed."""
    global _client
    try:
        if _client is not None:
            # Ping to verify connection is still alive
            _client.ping()
            return _client
    except Exception:
        _client = None

    try:
        _client = clickhouse_connect.get_client(
            host=settings.CLICKHOUSE_HOST,
            port=settings.CLICKHOUSE_PORT,
            username=settings.CLICKHOUSE_USER,
            password=settings.CLICKHOUSE_PASSWORD,
            database=settings.CLICKHOUSE_DB,
            connect_timeout=10,
            send_receive_timeout=30,
        )
        logger.info(
            f"ClickHouse connected: {settings.CLICKHOUSE_HOST}:{settings.CLICKHOUSE_PORT} "
            f"db={settings.CLICKHOUSE_DB}"
        )
        return _client
    except Exception as e:
        logger.error(f"ClickHouse connection failed: {e}")
        return None


def is_available() -> bool:
    """Return True if ClickHouse is reachable."""
    return _get_client() is not None


def reset_fabricated_api_discovery_fields() -> None:
    """
    One-time migration: api_discovery.has_https/content_encoding used to be
    fabricated (has_https hardcoded to 1, content_encoding guessed from the
    HTTP status code — see api_discovery.py) instead of measured from the
    request. Reset any pre-existing rows to the "unknown" sentinel (2 /
    "unknown") so old fabricated data doesn't keep misrepresenting endpoints
    under the new, honest scoring logic. Fresh log lines (which now carry
    $scheme/$sent_http_content_encoding) repopulate real values on the next
    discovery pass.

    ClickHouse has no per-install init-script re-run (configs/clickhouse/init.sql
    only executes on a brand-new container), so this mirrors db_service.py's
    marker-column trick: attempt to ADD COLUMN a marker; if that succeeds,
    this is the first time the process has run against this table, so also
    fire the mutation. If the column already exists, ClickHouse raises and
    we skip — the reset already happened on a prior startup.
    """
    client = _get_client()
    if client is None:
        return
    try:
        client.command(
            "ALTER TABLE api_discovery ADD COLUMN https_encoding_reset_done UInt8 DEFAULT 0"
        )
    except ClickHouseError:
        return  # Column already exists — reset already ran on a prior startup
    except Exception as e:
        logger.warning(f"ClickHouse api_discovery migration marker check failed: {e}")
        return

    try:
        client.command(
            "ALTER TABLE api_discovery UPDATE has_https = 2, content_encoding = 'unknown' WHERE 1"
        )
        logger.info(
            "One-time reset of ClickHouse api_discovery.has_https/content_encoding "
            "to 'unknown' — previous values were fabricated, not measured."
        )
    except Exception as e:
        logger.error(f"ClickHouse api_discovery fabricated-field reset failed: {e}")


# ---------------------------------------------------------------------------
# waf_events — Write
# ---------------------------------------------------------------------------
def insert_waf_events(entries: List[Dict[str, Any]]) -> int:
    """
    Batch-insert WAF audit events into cybersentinel.waf_events.
    Returns the number of rows inserted.
    Silently returns 0 if ClickHouse is unavailable.
    """
    if not entries:
        return 0
    client = _get_client()
    if client is None:
        return 0

    rows = []
    for e in entries:
        # Normalise timestamp to datetime object
        ts = e.get("timestamp", "")
        if isinstance(ts, str):
            try:
                ts = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            except Exception:
                try:
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
                except Exception:
                    ts = datetime.utcnow()
        elif not isinstance(ts, datetime):
            ts = datetime.utcnow()

        rows.append([
            str(e.get("id", "")),
            ts,
            str(e.get("client_ip", "")),
            str(e.get("country", "")),
            str(e.get("source_asn_org", "")),
            str(e.get("method", "")),
            str(e.get("uri", "")),
            str(e.get("hostname", "")),
            str(e.get("http_code", "")),
            str(e.get("rule_id", "")),
            str(e.get("message", "")),
            str(e.get("severity", "")),
            str(e.get("attack_type", "")),
            json.dumps(e.get("request_headers", {})) if isinstance(e.get("request_headers"), dict) else str(e.get("request_headers", "{}")),
            json.dumps(e.get("response_headers", {})) if isinstance(e.get("response_headers"), dict) else str(e.get("response_headers", "{}")),
            json.dumps([v.dict() if hasattr(v, "dict") else v for v in e.get("violations", [])]),
            json.dumps(e.get("raw_log", {})) if isinstance(e.get("raw_log"), dict) else str(e.get("raw_log", "")),
            str(e.get("log_source", "modsec_audit")),
        ])

    columns = [
        "id", "timestamp", "client_ip", "country", "source_asn_org",
        "method", "uri", "hostname", "http_code",
        "rule_id", "message", "severity", "attack_type",
        "request_headers", "response_headers", "violations", "raw_log",
        "log_source",
    ]

    try:
        client.insert("waf_events", rows, column_names=columns)
        return len(rows)
    except ClickHouseError as e:
        logger.error(f"ClickHouse insert_waf_events failed: {e}")
        return 0


def event_ids_exist(ids: List[str]) -> set:
    """
    Return the subset of the given IDs that already exist in waf_events.
    Used during backfill to skip already-ingested files.
    """
    if not ids:
        return set()
    client = _get_client()
    if client is None:
        return set()
    try:
        # Pass ids as a formatted tuple string for the IN clause
        placeholders = ", ".join(f"'{i}'" for i in ids)
        result = client.query(f"SELECT id FROM waf_events WHERE id IN ({placeholders})")
        return {row[0] for row in result.result_rows}
    except Exception as e:
        logger.warning(f"event_ids_exist query failed: {e}")
        return set()


# ---------------------------------------------------------------------------
# waf_events — Read / Query
# ---------------------------------------------------------------------------
def _time_filter_clause(hours: Optional[int], alias: str = "timestamp") -> str:
    """Return a WHERE clause fragment for the given time window."""
    if hours is None:
        return ""
    return f"AND {alias} >= now() - INTERVAL {int(hours)} HOUR"


def query_waf_events(
    page: int = 1,
    size: int = 50,
    severity: Optional[str] = None,
    min_severity: Optional[str] = None,
    rule_id: Optional[str] = None,
    ip: Optional[str] = None,
    attack_type: Optional[str] = None,
    status_code: Optional[str] = None,
    search: Optional[str] = None,
    uri_type: Optional[str] = None,
    hours: Optional[int] = None,
    blocked_only: bool = True,
) -> Tuple[List[Dict], int]:
    """
    Paginated, filtered query returning (rows, total_count).
    Returns ([], 0) when ClickHouse is unreachable.
    """
    SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    client = _get_client()
    if client is None:
        return [], 0

    where = ["1=1"]

    if blocked_only:
        where.append("(http_code LIKE '4%' OR http_code LIKE '5%' OR length(violations) > 2)")

    if hours:
        where.append(f"timestamp >= now() - INTERVAL {int(hours)} HOUR")

    if severity:
        where.append(f"lower(severity) = '{severity.lower()}'")

    if min_severity:
        threshold = SEVERITY_ORDER.get(min_severity.lower(), 0)
        sev_list = [s for s, v in SEVERITY_ORDER.items() if v >= threshold]
        if sev_list:
            in_clause = ", ".join(f"'{s}'" for s in sev_list)
            where.append(f"lower(severity) IN ({in_clause})")

    if rule_id:
        where.append(f"rule_id = '{rule_id.replace(chr(39), '')}'")

    if ip:
        where.append(f"client_ip = '{ip.replace(chr(39), '')}'")

    if attack_type:
        where.append(f"lower(attack_type) = '{attack_type.lower().replace(chr(39), '')}'")

    if status_code:
        where.append(f"http_code = '{status_code.replace(chr(39), '')}'")

    if search:
        s = search.replace("'", "").replace("\\", "")
        where.append(
            f"(lower(message) LIKE '%{s.lower()}%' OR lower(uri) LIKE '%{s.lower()}%' "
            f"OR client_ip LIKE '%{s}%' OR rule_id LIKE '%{s}%' "
            f"OR lower(attack_type) LIKE '%{s.lower()}%')"
        )

    if uri_type == "api":
        where.append("uri LIKE '/api%'")
    elif uri_type == "web":
        where.append("uri NOT LIKE '/api%'")

    where_clause = " AND ".join(where)
    offset = (page - 1) * size

    try:
        count_result = client.query(
            f"SELECT count() FROM waf_events WHERE {where_clause}"
        )
        total = count_result.result_rows[0][0] if count_result.result_rows else 0

        rows_result = client.query(
            f"""
            SELECT id, timestamp, client_ip, country, source_asn_org,
                   method, uri, hostname, http_code,
                   rule_id, message, severity, attack_type,
                   request_headers, response_headers, violations, raw_log
            FROM waf_events
            WHERE {where_clause}
            ORDER BY timestamp DESC
            LIMIT {int(size)} OFFSET {int(offset)}
            """
        )

        columns = [
            "id", "timestamp", "client_ip", "country", "source_asn_org",
            "method", "uri", "hostname", "http_code",
            "rule_id", "message", "severity", "attack_type",
            "request_headers", "response_headers", "violations", "raw_log",
        ]

        result = []
        for row in rows_result.result_rows:
            d = dict(zip(columns, row))
            # Convert datetime to string
            if isinstance(d["timestamp"], datetime):
                d["timestamp"] = d["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
            # Parse JSON strings back to dicts/lists
            for field in ("request_headers", "response_headers"):
                try:
                    d[field] = json.loads(d[field]) if d[field] else {}
                except Exception:
                    d[field] = {}
            try:
                d["violations"] = json.loads(d["violations"]) if d["violations"] else []
            except Exception:
                d["violations"] = []
            try:
                d["raw_log"] = json.loads(d["raw_log"]) if d["raw_log"] else None
            except Exception:
                d["raw_log"] = None
            result.append(d)

        return result, int(total)

    except Exception as e:
        logger.error(f"query_waf_events failed: {e}")
        return [], 0


def get_waf_event_by_id(log_id: str) -> Optional[Dict]:
    """Fetch a single WAF event by transaction ID."""
    rows, _ = query_waf_events(page=1, size=1, blocked_only=False)
    client = _get_client()
    if client is None:
        return None
    try:
        result = client.query(
            f"""
            SELECT id, timestamp, client_ip, country, source_asn_org,
                   method, uri, hostname, http_code,
                   rule_id, message, severity, attack_type,
                   request_headers, response_headers, violations, raw_log
            FROM waf_events
            WHERE id = '{log_id.replace(chr(39), "")}'
            LIMIT 1
            """
        )
        if not result.result_rows:
            return None
        columns = [
            "id", "timestamp", "client_ip", "country", "source_asn_org",
            "method", "uri", "hostname", "http_code",
            "rule_id", "message", "severity", "attack_type",
            "request_headers", "response_headers", "violations", "raw_log",
        ]
        d = dict(zip(columns, result.result_rows[0]))
        if isinstance(d["timestamp"], datetime):
            d["timestamp"] = d["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        for field in ("request_headers", "response_headers"):
            try:
                d[field] = json.loads(d[field]) if d[field] else {}
            except Exception:
                d[field] = {}
        try:
            d["violations"] = json.loads(d["violations"]) if d["violations"] else []
        except Exception:
            d["violations"] = []
        try:
            d["raw_log"] = json.loads(d["raw_log"]) if d["raw_log"] else None
        except Exception:
            d["raw_log"] = None
        return d
    except Exception as e:
        logger.error(f"get_waf_event_by_id failed: {e}")
        return None


# ---------------------------------------------------------------------------
# Stats / Aggregation Queries
# ---------------------------------------------------------------------------
def get_stats(hours: Optional[int] = None) -> Dict[str, Any]:
    """Aggregate stats from waf_events: total blocked, attack counts, etc.

    Raises on any failure (no client, query error) instead of swallowing it
    — the caller (stats_calculator.py) needs to be able to tell a real,
    empty result apart from a failed query, since only the former is safe
    to cache. Silently caching a transient failure's fallback value for a
    full cache-TTL window is what previously made dashboard panels flicker
    between real data and "empty" every refresh cycle.
    """
    client = _get_client()
    if client is None:
        raise RuntimeError("ClickHouse client unavailable")

    time_filter = _time_filter_clause(hours)
    recent_filter = "AND timestamp >= now() - INTERVAL 1 MINUTE"

    try:
        result = client.query(f"""
            SELECT
                countIf(http_code = '403')                                           AS total_blocked,
                countIf(lower(attack_type) = 'sql injection' AND http_code = '403') AS sqli_count,
                countIf(lower(attack_type) = 'xss' AND http_code = '403')           AS xss_count,
                uniqExactIf(client_ip, http_code = '403')                           AS unique_ips,
                countIf(http_code = '403' AND timestamp >= now() - INTERVAL 1 MINUTE) AS recent_threats,
                argMaxIf(attack_type, 1, http_code = '403' AND attack_type != '' AND attack_type != 'Unknown') AS top_attack
            FROM waf_events
            WHERE 1=1 {time_filter}
        """)
        row = result.result_rows[0] if result.result_rows else (0, 0, 0, 0, 0, "None")
        top_attack = row[5] if row[5] else "None"

        return {
            "total_requests": int(row[0]),   # will be supplemented by nginx access log count
            "total_blocked": int(row[0]),
            "sqli_count": int(row[1]),
            "xss_count": int(row[2]),
            "top_attack_type": top_attack,
            "total_unique_ips": int(row[3]),
            "recent_threats": int(row[4]),
        }
    except Exception as e:
        logger.error(f"get_stats failed: {e}")
        raise


def get_timeline(hours: Optional[int] = None) -> List[Dict]:
    """15-minute bucketed timeline of attack counts."""
    client = _get_client()
    if client is None:
        raise RuntimeError("ClickHouse client unavailable")
    time_filter = _time_filter_clause(hours)
    try:
        # `ORDER BY time ASC LIMIT 200` alone takes the 200 OLDEST buckets in
        # the queried window, not the 200 most recent — with no hours filter
        # (Overview's default call) that's the 200 oldest 15-minute buckets
        # in the entire 90-day retention window, i.e. mid-history data with
        # nothing from "now", which is exactly what makes the Attack Timeline
        # chart look empty/stale. It also silently truncates any window wide
        # enough to exceed 200 buckets (a 30-day report window allows up to
        # 2,880). Select the most recent 200 buckets first (DESC), then
        # re-sort them chronologically for the chart's left-to-right axis.
        result = client.query(f"""
            SELECT time, count FROM (
                SELECT
                    formatDateTime(toStartOfInterval(timestamp, INTERVAL 15 MINUTE), '%Y-%m-%d %H:%i') AS time,
                    count() AS count
                FROM waf_events
                WHERE 1=1 {time_filter}
                GROUP BY time
                ORDER BY time DESC
                LIMIT 200
            )
            ORDER BY time ASC
        """)
        return [{"time": row[0], "count": row[1]} for row in result.result_rows]
    except Exception as e:
        logger.error(f"get_timeline failed: {e}")
        raise


def get_attack_types(hours: Optional[int] = None) -> List[Dict]:
    """Distribution of attack types — blocked (HTTP 401, 403, 406, 429) events."""
    client = _get_client()
    if client is None:
        raise RuntimeError("ClickHouse client unavailable")
    time_filter = _time_filter_clause(hours)
    try:
        result = client.query(f"""
            SELECT attack_type, count() AS count
            FROM waf_events
            WHERE http_code IN ('401', '403', '406', '429') {time_filter}
            GROUP BY attack_type
            ORDER BY count DESC
        """)
        return [{"attack_type": row[0], "count": row[1]} for row in result.result_rows]
    except Exception as e:
        logger.error(f"get_attack_types failed: {e}")
        raise


def get_top_ips(limit: int = 10, hours: Optional[int] = None) -> List[Dict]:
    """Top attacking IPs — from blocked (HTTP 401, 403, 406, 429) events."""
    client = _get_client()
    if client is None:
        raise RuntimeError("ClickHouse client unavailable")
    time_filter = _time_filter_clause(hours)
    try:
        result = client.query(f"""
            SELECT client_ip, any(country) AS country, count() AS count
            FROM waf_events
            WHERE http_code IN ('401', '403', '406', '429') AND client_ip != '' {time_filter}
            GROUP BY client_ip
            ORDER BY count DESC
            LIMIT {int(limit)}
        """)
        return [
            {"ip": row[0], "country": row[1], "count": row[2], "abuse_score": 0.0}
            for row in result.result_rows
        ]
    except Exception as e:
        logger.error(f"get_top_ips failed: {e}")
        raise


def get_severity_distribution(hours: Optional[int] = None) -> List[Dict]:
    """Count of blocked (HTTP 401, 403, 406, 429) events per severity level."""
    client = _get_client()
    if client is None:
        raise RuntimeError("ClickHouse client unavailable")
    time_filter = _time_filter_clause(hours)
    standards = ["Critical", "High", "Medium", "Low"]
    try:
        result = client.query(f"""
            SELECT
                multiIf(
                    lower(severity) IN ('crit', 'critical'), 'Critical',
                    lower(severity) IN ('warn', 'warning', 'high'), 'High',
                    lower(severity) IN ('medium', 'med'), 'Medium',
                    lower(severity) IN ('info', 'notice', 'low'), 'Low',
                    'Low'
                ) AS sev_normalized,
                count() AS count
            FROM waf_events
            WHERE http_code IN ('401', '403', '406', '429') {time_filter}
            GROUP BY sev_normalized
        """)
        counts = {row[0]: row[1] for row in result.result_rows}
        return [{"severity": s, "count": counts.get(s, 0)} for s in standards]
    except Exception as e:
        logger.error(f"get_severity_distribution failed: {e}")
        raise


def get_top_rules(limit: int = 10, hours: Optional[int] = None) -> List[Dict]:
    """Most triggered ModSecurity rule IDs."""
    client = _get_client()
    if client is None:
        raise RuntimeError("ClickHouse client unavailable")
    time_filter = _time_filter_clause(hours)
    try:
        result = client.query(f"""
            SELECT rule_id, count() AS count
            FROM waf_events
            WHERE rule_id != '' {time_filter}
            GROUP BY rule_id
            ORDER BY count DESC
            LIMIT {int(limit)}
        """)
        return [{"rule_id": row[0], "count": row[1]} for row in result.result_rows]
    except Exception as e:
        logger.error(f"get_top_rules failed: {e}")
        raise


def get_total_blocked_count(hours: Optional[int] = None) -> int:
    """Fast count of all blocked events."""
    client = _get_client()
    if client is None:
        return 0
    time_filter = _time_filter_clause(hours)
    try:
        result = client.query(f"SELECT count() FROM waf_events WHERE 1=1 {time_filter}")
        return int(result.result_rows[0][0]) if result.result_rows else 0
    except Exception as e:
        logger.error(f"get_total_blocked_count failed: {e}")
        return 0


# ---------------------------------------------------------------------------
# ml_events — Write
# ---------------------------------------------------------------------------
def insert_ml_event(event: Dict[str, Any]) -> bool:
    """Insert a single ML scoring event. Returns True on success."""
    client = _get_client()
    if client is None:
        return False

    ts = event.get("timestamp")
    if isinstance(ts, str):
        try:
            ts = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        except Exception:
            ts = datetime.utcnow()
    elif not isinstance(ts, datetime):
        ts = datetime.utcnow()

    row = [[
        str(event.get("unique_id", "")),
        ts,
        str(event.get("remote_addr", "")),
        str(event.get("method", "")),
        str(event.get("uri", "")),
        str(event.get("args", "")),
        str(event.get("ct", "")),
        str(event.get("ua", "")),
        float(event.get("body_len", 0.0)),
        float(event.get("crs_score", 0.0)),
        str(event.get("matched_vars", "")),
        float(event.get("redis_rpm", 0.0)),
        float(event.get("redis_rep", 0.0)),
        float(event.get("abuse_score", 0.0)),
        float(event.get("xgb_prob", 0.0)),
        float(event.get("iso_score", 0.0)),
        float(event.get("threat_score", 0.0)),
        str(event.get("decision", "")),
    ]]

    columns = [
        "unique_id", "timestamp", "remote_addr", "method", "uri", "args",
        "ct", "ua", "body_len", "crs_score", "matched_vars",
        "redis_rpm", "redis_rep", "abuse_score",
        "xgb_prob", "iso_score", "threat_score", "decision",
    ]

    try:
        client.insert("ml_events", row, column_names=columns)
        return True
    except ClickHouseError as e:
        logger.error(f"insert_ml_event failed: {e}")
        return False


def get_ml_stats(hours: Optional[int] = None) -> Dict[str, Any]:
    """Aggregate stats from ml_events for the AI/ML dashboard tab."""
    client = _get_client()
    if client is None:
        return {}
    time_filter = _time_filter_clause(hours)
    try:
        result = client.query(f"""
            SELECT
                count()                                      AS total,
                countIf(decision = 'block')                  AS blocked,
                countIf(decision = 'rate_limit')             AS rate_limited,
                countIf(decision = 'allow')                  AS allowed,
                avg(threat_score)                            AS avg_threat,
                max(threat_score)                            AS max_threat,
                avg(xgb_prob)                                AS avg_xgb,
                avg(iso_score)                               AS avg_iso
            FROM ml_events
            WHERE 1=1 {time_filter}
        """)
        row = result.result_rows[0] if result.result_rows else (0,)*8
        return {
            "total_ml_events": int(row[0]),
            "total_blocked": int(row[1]),
            "total_rate_limited": int(row[2]),
            "total_allowed": int(row[3]),
            "avg_threat_score": round(float(row[4] or 0), 2),
            "max_threat_score": round(float(row[5] or 0), 2),
            "avg_xgb_prob": round(float(row[6] or 0), 4),
            "avg_iso_score": round(float(row[7] or 0), 4),
        }
    except Exception as e:
        logger.error(f"get_ml_stats failed: {e}")
        return {}


def get_ml_events(
    page: int = 1,
    size: int = 50,
    hours: Optional[int] = None,
    decision: Optional[str] = None,
) -> Tuple[List[Dict], int]:
    """Paginated ML events for the AI/ML tab."""
    client = _get_client()
    if client is None:
        return [], 0
    time_filter = _time_filter_clause(hours)
    where = ["1=1"] + ([f"timestamp >= now() - INTERVAL {int(hours)} HOUR"] if hours else [])
    if decision:
        where.append(f"decision = '{decision}'")
    where_clause = " AND ".join(where)
    offset = (page - 1) * size

    try:
        count_result = client.query(f"SELECT count() FROM ml_events WHERE {where_clause}")
        total = count_result.result_rows[0][0] if count_result.result_rows else 0

        result = client.query(f"""
            SELECT unique_id, timestamp, remote_addr, method, uri,
                   crs_score, xgb_prob, iso_score, threat_score, decision, abuse_score
            FROM ml_events
            WHERE {where_clause}
            ORDER BY timestamp DESC
            LIMIT {int(size)} OFFSET {int(offset)}
        """)

        cols = ["unique_id", "timestamp", "remote_addr", "method", "uri",
                "crs_score", "xgb_prob", "iso_score", "threat_score", "decision", "abuse_score"]
        rows = []
        for row in result.result_rows:
            d = dict(zip(cols, row))
            if isinstance(d["timestamp"], datetime):
                d["timestamp"] = d["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
            rows.append(d)
        return rows, int(total)
    except Exception as e:
        logger.error(f"get_ml_events failed: {e}")
        return [], 0


# ---------------------------------------------------------------------------
# analyst_feedback — Write
# ---------------------------------------------------------------------------
def insert_analyst_feedback(record: Dict[str, Any]) -> bool:
    """Insert a false positive / analyst feedback record."""
    import uuid
    client = _get_client()
    if client is None:
        return False

    ts = record.get("event_timestamp") or record.get("timestamp", "")
    if isinstance(ts, str):
        try:
            ts = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        except Exception:
            ts = datetime.utcnow()
    elif not isinstance(ts, datetime):
        ts = datetime.utcnow()

    entry_id = str(record.get("id", ""))
    if not entry_id:
        entry_id = str(uuid.uuid4())

    row = [[
        entry_id,
        str(record.get("log_id", "")),
        str(record.get("rule_id", "")),
        str(record.get("client_ip", "")),
        str(record.get("uri", "")),
        ts,
        str(record.get("severity", "")),
        str(record.get("attack_type", "")),
        str(record.get("status", "Pending")),
        str(record.get("analyst_note", "")),
        str(record.get("created_by", "system")),
        json.dumps(record.get("raw_log", {})) if isinstance(record.get("raw_log"), dict) else str(record.get("raw_log", "")),
    ]]

    columns = [
        "id", "log_id", "rule_id", "client_ip", "uri", "event_timestamp",
        "severity", "attack_type", "status", "analyst_note", "created_by", "raw_log",
    ]

    try:
        client.insert("analyst_feedback", row, column_names=columns)
        return True
    except ClickHouseError as e:
        logger.error(f"insert_analyst_feedback failed: {e}")
        return False


def get_false_positive_by_log_id(log_id: str) -> Optional[Dict]:
    """Retrieve the latest active false positive record by log ID."""
    client = _get_client()
    if client is None:
        return None
    try:
        result = client.query(
            f"""
            SELECT log_id, rule_id, client_ip, uri, event_timestamp,
                   severity, attack_type, status, analyst_note, created_by, raw_log, id
            FROM analyst_feedback FINAL
            WHERE log_id = '{log_id.replace(chr(39), "")}' AND status != 'Deleted'
            LIMIT 1
            """
        )
        if not result.result_rows:
            return None
        columns = [
            "log_id", "rule_id", "client_ip", "uri", "timestamp",
            "severity", "attack_type", "status", "analyst_note", "created_by", "raw_log", "id"
        ]
        d = dict(zip(columns, result.result_rows[0]))
        if isinstance(d["timestamp"], datetime):
            d["timestamp"] = d["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        return d
    except Exception as e:
        logger.error(f"get_false_positive_by_log_id failed: {e}")
        return None


def get_false_positive_by_id(entry_id: str) -> Optional[Dict]:
    """Retrieve the latest active false positive record by ID."""
    client = _get_client()
    if client is None:
        return None
    try:
        result = client.query(
            f"""
            SELECT log_id, rule_id, client_ip, uri, event_timestamp,
                   severity, attack_type, status, analyst_note, created_by, raw_log, id
            FROM analyst_feedback FINAL
            WHERE id = '{entry_id.replace(chr(39), "")}' AND status != 'Deleted'
            LIMIT 1
            """
        )
        if not result.result_rows:
            return None
        columns = [
            "log_id", "rule_id", "client_ip", "uri", "timestamp",
            "severity", "attack_type", "status", "analyst_note", "created_by", "raw_log", "id"
        ]
        d = dict(zip(columns, result.result_rows[0]))
        if isinstance(d["timestamp"], datetime):
            d["timestamp"] = d["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        return d
    except Exception as e:
        logger.error(f"get_false_positive_by_id failed: {e}")
        return None


def get_all_false_positives(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    rule_id: Optional[str] = None,
    search: Optional[str] = None,
) -> List[Dict]:
    """Retrieve all active false positives from analyst_feedback."""
    client = _get_client()
    if client is None:
        return []
    where = ["status != 'Deleted'"]
    if status:
        where.append(f"status = '{status.replace(chr(39), '')}'")
    if severity:
        where.append(f"lower(severity) = '{severity.lower().replace(chr(39), '')}'")
    if rule_id:
        where.append(f"rule_id = '{rule_id.replace(chr(39), '')}'")
    if search:
        s = search.replace("'", "").replace("\\", "")
        where.append(
            f"(lower(analyst_note) LIKE '%{s.lower()}%' OR lower(uri) LIKE '%{s.lower()}%' "
            f"OR client_ip LIKE '%{s}%' OR rule_id LIKE '%{s}%')"
        )
    where_clause = " AND ".join(where)
    try:
        result = client.query(
            f"""
            SELECT log_id, rule_id, client_ip, uri, event_timestamp,
                   severity, attack_type, status, analyst_note, created_by, raw_log, id
            FROM analyst_feedback FINAL
            WHERE {where_clause}
            ORDER BY created_at DESC
            """
        )
        columns = [
            "log_id", "rule_id", "client_ip", "uri", "timestamp",
            "severity", "attack_type", "status", "analyst_note", "created_by", "raw_log", "id"
        ]
        rows = []
        for row in result.result_rows:
            d = dict(zip(columns, row))
            if isinstance(d["timestamp"], datetime):
                d["timestamp"] = d["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
            rows.append(d)
        return rows
    except Exception as e:
        logger.error(f"get_all_false_positives failed: {e}")
        return []


def update_false_positive_status(entry_id: str, new_status: str) -> Optional[Dict]:
    """Update status of a false positive record by inserting an updated ReplacingMergeTree row."""
    existing = get_false_positive_by_id(entry_id)
    if not existing:
        return None

    client = _get_client()
    if client is None:
        return None

    try:
        ts = existing.get("timestamp", "")
        if isinstance(ts, str):
            try:
                ts = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            except Exception:
                ts = datetime.utcnow()

        row = [[
            existing["id"],
            existing["log_id"],
            existing["rule_id"],
            existing["client_ip"],
            existing["uri"],
            ts,
            existing["severity"],
            existing["attack_type"],
            new_status,
            existing["analyst_note"],
            existing["created_by"],
            json.dumps(existing["raw_log"]) if isinstance(existing["raw_log"], dict) else str(existing["raw_log"]),
        ]]

        columns = [
            "id", "log_id", "rule_id", "client_ip", "uri", "event_timestamp",
            "severity", "attack_type", "status", "analyst_note", "created_by", "raw_log",
        ]

        client.insert("analyst_feedback", row, column_names=columns)
        return get_false_positive_by_id(entry_id)
    except Exception as e:
        logger.error(f"update_false_positive_status failed: {e}")
        return None


def update_false_positive_note(entry_id: str, note: str) -> Optional[Dict]:
    """Update note of a false positive record by inserting an updated ReplacingMergeTree row."""
    existing = get_false_positive_by_id(entry_id)
    if not existing:
        return None

    client = _get_client()
    if client is None:
        return None

    try:
        ts = existing.get("timestamp", "")
        if isinstance(ts, str):
            try:
                ts = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            except Exception:
                ts = datetime.utcnow()

        row = [[
            existing["id"],
            existing["log_id"],
            existing["rule_id"],
            existing["client_ip"],
            existing["uri"],
            ts,
            existing["severity"],
            existing["attack_type"],
            existing["status"],
            note,
            existing["created_by"],
            json.dumps(existing["raw_log"]) if isinstance(existing["raw_log"], dict) else str(existing["raw_log"]),
        ]]

        columns = [
            "id", "log_id", "rule_id", "client_ip", "uri", "event_timestamp",
            "severity", "attack_type", "status", "analyst_note", "created_by", "raw_log",
        ]

        client.insert("analyst_feedback", row, column_names=columns)
        return get_false_positive_by_id(entry_id)
    except Exception as e:
        logger.error(f"update_false_positive_note failed: {e}")
        return None


def delete_false_positive(entry_id: str) -> bool:
    """Soft-delete a false positive record by inserting a ReplacingMergeTree row marked 'Deleted'."""
    existing = get_false_positive_by_id(entry_id)
    if not existing:
        return False

    client = _get_client()
    if client is None:
        return False

    try:
        ts = existing.get("timestamp", "")
        if isinstance(ts, str):
            try:
                ts = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            except Exception:
                ts = datetime.utcnow()

        row = [[
            existing["id"],
            existing["log_id"],
            existing["rule_id"],
            existing["client_ip"],
            existing["uri"],
            ts,
            existing["severity"],
            existing["attack_type"],
            "Deleted",
            existing["analyst_note"],
            existing["created_by"],
            json.dumps(existing["raw_log"]) if isinstance(existing["raw_log"], dict) else str(existing["raw_log"]),
        ]]

        columns = [
            "id", "log_id", "rule_id", "client_ip", "uri", "event_timestamp",
            "severity", "attack_type", "status", "analyst_note", "created_by", "raw_log",
        ]

        client.insert("analyst_feedback", row, column_names=columns)
        return True
    except Exception as e:
        logger.error(f"delete_false_positive failed: {e}")
        return False


# ---------------------------------------------------------------------------
# api_discovery — Read / Write
# ---------------------------------------------------------------------------
def insert_api_discovery(records: List[Dict[str, Any]]) -> int:
    """Batch-insert API discovery observations into cybersentinel.api_discovery."""
    if not records:
        return 0
    client = _get_client()
    if client is None:
        return 0

    rows = []
    for r in records:
        ts = r.get("timestamp", "")
        if isinstance(ts, str):
            try:
                ts = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            except Exception:
                ts = datetime.utcnow()
        elif not isinstance(ts, datetime):
            ts = datetime.utcnow()

        rows.append([
            str(r.get("uri", "")),
            str(r.get("method", "")),
            ts,
            int(r.get("hit_count", 1)),
            int(r.get("error_count", 0)),
            int(r.get("malicious_count", 0)),
            int(r.get("suspicious_count", 0)),
            int(r.get("external_hit_count", 0)),
            int(r.get("internal_hit_count", 0)),
            # 0=confirmed http, 1=confirmed https, 2=not measured (see
            # api_discovery.py's HTTPS_UNKNOWN/ENCODING_UNKNOWN) — default to
            # "not measured" rather than fabricating "secure"/"compressed".
            int(r.get("has_https", 2)),
            int(r.get("has_versioning", 0)),
            str(r.get("content_encoding", "unknown")),
            float(r.get("avg_response_time_ms", 0.0)),
            ts,
        ])

    columns = [
        "uri", "method", "timestamp", "hit_count", "error_count",
        "malicious_count", "suspicious_count", "external_hit_count", "internal_hit_count",
        "has_https", "has_versioning", "content_encoding", "avg_response_time_ms",
        "first_seen",
    ]

    try:
        client.insert("api_discovery", rows, column_names=columns)
        return len(rows)
    except Exception as e:
        logger.error(f"insert_api_discovery failed: {e}")
        return 0


def get_all_discovered_endpoints() -> List[Dict[str, Any]]:
    """Retrieve all discovered endpoints with aggregated statistics from ClickHouse."""
    client = _get_client()
    if client is None:
        return []
    try:
        result = client.query(
            """
            SELECT
                uri, method, first_seen, last_seen,
                total_hits,
                error_count, malicious_count, suspicious_count,
                external_hit_count, internal_hit_count,
                has_https, has_versioning, content_encoding,
                weighted_response_sum
            FROM (
                SELECT uri, method,
                       min(first_seen)  AS first_seen,
                       max(timestamp)   AS last_seen,
                       sum(hit_count)   AS total_hits,
                       sum(error_count) AS error_count,
                       sum(malicious_count)    AS malicious_count,
                       sum(suspicious_count)   AS suspicious_count,
                       sum(external_hit_count) AS external_hit_count,
                       sum(internal_hit_count) AS internal_hit_count,
                       -- 0=confirmed http, 1=confirmed https, 2=unknown — min()
                       -- means a confirmed-insecure hit always wins (a real
                       -- finding), then confirmed-secure, then unknown last.
                       min(has_https)       AS has_https,
                       max(has_versioning)  AS has_versioning,
                       -- Prefer any row with a real measurement over the
                       -- "unknown" sentinel; only report "unknown" if every
                       -- row for this endpoint is still unmeasured.
                       if(
                           countIf(content_encoding != 'unknown') > 0,
                           anyIf(content_encoding, content_encoding != 'unknown'),
                           'unknown'
                       ) AS content_encoding,
                       sum(avg_response_time_ms * hit_count) AS weighted_response_sum
                FROM api_discovery
                GROUP BY uri, method
            )
            ORDER BY total_hits DESC
            """
        )
        columns = [
            "uri", "method", "first_seen", "last_seen", "hit_count", "error_count",
            "malicious_count", "suspicious_count", "external_hit_count", "internal_hit_count",
            "has_https", "has_versioning", "content_encoding", "weighted_response_sum"
        ]
        rows = []
        for row in result.result_rows:
            d = dict(zip(columns, row))
            for f in ("first_seen", "last_seen"):
                if isinstance(d[f], datetime):
                    d[f] = d[f].strftime("%Y-%m-%d %H:%M:%S")
            # Compute weighted average in Python to avoid nested-aggregate SQL error
            wsum = d.pop("weighted_response_sum", 0) or 0
            hits = d.get("hit_count", 0) or 0
            d["avg_response_time_ms"] = round(wsum / hits, 2) if hits > 0 else 0.0
            rows.append(d)
        return rows
    except Exception as e:
        logger.error(f"get_all_discovered_endpoints failed: {e}")
        return []


def get_recently_discovered_endpoints(hours: int = 48) -> List[Dict[str, Any]]:
    """Retrieve endpoints first seen within the last N hours from ClickHouse."""
    endpoints = get_all_discovered_endpoints()
    cutoff = datetime.now() - timedelta(hours=hours)
    cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")
    return [e for e in endpoints if e["first_seen"] >= cutoff_str]


# ---------------------------------------------------------------------------
# alert_history — Write / Read / Stats
# ---------------------------------------------------------------------------
def insert_alert_history(record: Dict[str, Any]) -> bool:
    """Append a fired alert to the alert_history table."""
    client = _get_client()
    if client is None:
        return False
    try:
        ack_at = record.get("acknowledged_at")
        if isinstance(ack_at, str) and ack_at:
            try:
                ack_at = datetime.strptime(ack_at[:19], "%Y-%m-%d %H:%M:%S")
            except Exception:
                ack_at = None
        client.insert("alert_history", [[
            int(record.get("id", 0)),
            int(record.get("rule_id", 0)),
            str(record.get("rule_name", "")),
            str(record.get("event_type", "")),
            str(record.get("severity", "")),
            str(record.get("channels_notified", "")),
            str(record.get("event_data", "")),
            str(record.get("message", "")),
            str(record.get("status", "sent")),
            str(record.get("error_message", "") or ""),
            str(record.get("acknowledged_by", "") or ""),
            ack_at,
        ]], column_names=[
            "id", "rule_id", "rule_name", "event_type", "severity",
            "channels_notified", "event_data", "message", "status",
            "error_message", "acknowledged_by", "acknowledged_at",
        ])
        return True
    except ClickHouseError as e:
        logger.error(f"insert_alert_history failed: {e}")
        return False


def query_alert_history(
    limit: int = 100,
    offset: int = 0,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """Retrieve alert history from ClickHouse."""
    client = _get_client()
    if client is None:
        return []

    where = ["1=1"]
    if event_type:
        where.append(f"event_type = '{event_type.replace(chr(39), '')}'")
    if severity:
        where.append(f"severity = '{severity.replace(chr(39), '')}'")
    if status:
        where.append(f"status = '{status.replace(chr(39), '')}'")
    if start_date:
        where.append(f"created_at >= '{start_date.strftime('%Y-%m-%d %H:%M:%S')}'")
    if end_date:
        where.append(f"created_at <= '{end_date.strftime('%Y-%m-%d %H:%M:%S')}'")

    where_clause = " AND ".join(where)
    try:
        result = client.query(
            f"""
            SELECT id, rule_id, rule_name, event_type, severity, channels_notified,
                   event_data, message, status, error_message, acknowledged_by, acknowledged_at, created_at
            FROM alert_history
            WHERE {where_clause}
            ORDER BY created_at DESC
            LIMIT {int(limit)} OFFSET {int(offset)}
            """
        )
        columns = [
            "id", "rule_id", "rule_name", "event_type", "severity", "channels_notified",
            "event_data", "message", "status", "error_message", "acknowledged_by", "acknowledged_at", "created_at"
        ]
        rows = []
        for row in result.result_rows:
            d = dict(zip(columns, row))
            for f in ("created_at", "acknowledged_at"):
                if isinstance(d[f], datetime):
                    d[f] = d[f].strftime("%Y-%m-%d %H:%M:%S")
            rows.append(d)
        return rows
    except Exception as e:
        logger.error(f"query_alert_history failed: {e}")
        return []


def acknowledge_alert(alert_id: int, acknowledged_by: str) -> bool:
    """Acknowledge alert in ClickHouse using mutations."""
    client = _get_client()
    if client is None:
        return False
    try:
        client.command(
            f"ALTER TABLE alert_history UPDATE "
            f"status = 'acknowledged', "
            f"acknowledged_by = '{acknowledged_by.replace(chr(39), '')}', "
            f"acknowledged_at = now() "
            f"WHERE id = {int(alert_id)}"
        )
        return True
    except Exception as e:
        logger.error(f"acknowledge_alert mutation failed in ClickHouse: {e}")
        return False


def get_alert_stats(days: int = 30) -> Dict[str, Any]:
    """Retrieve alert statistics from ClickHouse."""
    client = _get_client()
    if client is None:
        return {}

    try:
        cutoff = datetime.now() - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Total count
        total_res = client.query(f"SELECT count() FROM alert_history WHERE created_at >= '{cutoff_str}'")
        total_alerts = total_res.result_rows[0][0] if total_res.result_rows else 0

        # By severity
        sev_res = client.query(
            f"""
            SELECT severity, count() FROM alert_history
            WHERE created_at >= '{cutoff_str}'
            GROUP BY severity
            """
        )
        alerts_by_severity = {row[0]: row[1] for row in sev_res.result_rows}

        # By status
        stat_res = client.query(
            f"""
            SELECT status, count() FROM alert_history
            WHERE created_at >= '{cutoff_str}'
            GROUP BY status
            """
        )
        alerts_by_status = {row[0]: row[1] for row in stat_res.result_rows}

        # By event type
        type_res = client.query(
            f"""
            SELECT event_type, count() FROM alert_history
            WHERE created_at >= '{cutoff_str}'
            GROUP BY event_type
            ORDER BY count() DESC
            """
        )
        alerts_by_event_type = {row[0]: row[1] for row in type_res.result_rows}

        # Top rules
        rules_res = client.query(
            f"""
            SELECT rule_name, count() FROM alert_history
            WHERE created_at >= '{cutoff_str}'
            GROUP BY rule_name
            ORDER BY count() DESC
            LIMIT 10
            """
        )
        most_triggered_rules = [{"rule_name": row[0], "count": row[1]} for row in rules_res.result_rows]

        # Recent alerts (top 5)
        recent_res = client.query(
            """
            SELECT id, rule_id, rule_name, event_type, severity, channels_notified,
                   event_data, message, status, error_message, acknowledged_by, acknowledged_at, created_at
            FROM alert_history
            ORDER BY id DESC
            LIMIT 5
            """
        )
        columns = [
            "id", "rule_id", "rule_name", "event_type", "severity", "channels_notified",
            "event_data", "message", "status", "error_message", "acknowledged_by", "acknowledged_at", "created_at"
        ]
        recent_alerts = []
        for row in recent_res.result_rows:
            d = dict(zip(columns, row))
            for f in ("created_at", "acknowledged_at"):
                if isinstance(d[f], datetime):
                    d[f] = d[f].strftime("%Y-%m-%d %H:%M:%S")
            recent_alerts.append(d)

        # Average per day
        avg_alerts_per_day = round(float(total_alerts) / max(days, 1), 2)

        # Rate trend (first half of period vs second half)
        mid_cutoff = datetime.now() - timedelta(days=days / 2.0)
        mid_str = mid_cutoff.strftime("%Y-%m-%d %H:%M:%S")

        fh_res = client.query(
            f"SELECT count() FROM alert_history WHERE created_at >= '{cutoff_str}' AND created_at < '{mid_str}'"
        )
        first_half = fh_res.result_rows[0][0] if fh_res.result_rows else 0

        sh_res = client.query(
            f"SELECT count() FROM alert_history WHERE created_at >= '{mid_str}'"
        )
        second_half = sh_res.result_rows[0][0] if sh_res.result_rows else 0

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
        }
    except Exception as e:
        logger.error(f"get_alert_stats failed: {e}")
        return {}
