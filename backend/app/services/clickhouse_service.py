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
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import clickhouse_connect
from clickhouse_connect.driver.exceptions import ClickHouseError

from app.config.settings import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Canonical "this WAF actively blocked the request" status codes.
# 401 = require-auth (nginx_manager._generate_app_auth_conf), 403 = CRS /
# positive-security extension check / exclusions, 405/415 = positive-security
# method/content-type allowlists, 429/444 = bot & DDoS rate-limiting
# (nginx_manager: 444 for "Silent Drop", 429 otherwise). 406 has no current
# generator but is kept for backward compatibility with already-ingested rows.
# Was previously duplicated ad hoc per-query as ('401','403','406','429'),
# silently missing 405/415/444 everywhere and used inconsistently (get_stats
# checked bare '403' only) — kept here as one shared tuple so every query
# stays in sync as enforcement features are added.
# ---------------------------------------------------------------------------
BLOCKED_HTTP_CODES = ("401", "403", "405", "406", "415", "429", "444")
_BLOCKED_HTTP_CODES_SQL = "(" + ", ".join(f"'{c}'" for c in BLOCKED_HTTP_CODES) + ")"

# ---------------------------------------------------------------------------
# Client pool — one client per thread
# ---------------------------------------------------------------------------
# clickhouse-connect's HttpClient auto-generates a server-side session_id per
# client instance (autogenerate_session_id defaults to True), and ClickHouse
# serializes queries within a session. A single client shared across every
# request — the previous module-level singleton — meant any two concurrent
# queries against it collided with "Attempt to execute concurrent queries
# within the same session", e.g. the dashboard Overview page firing 6 stats
# queries in parallel (each dispatched via asyncio.to_thread onto a
# different worker thread, but all sharing one session_id).
#
# Route handlers call every query/insert function here via asyncio.to_thread,
# so each concurrent request already lands on its own worker thread from the
# executor's thread pool; background tasks (log ingestion, retention) call
# these functions synchronously on the single event-loop thread, where
# blocking I/O serializes them anyway. Keying the client by thread — rather
# than one global client — gives each thread its own session, which is safe
# for genuine concurrency and is naturally bounded by the thread pool's
# worker count (in effect a connection pool), with no change needed at any
# of the 30 call sites in this module.
_thread_local = threading.local()


def _get_client() -> Optional[clickhouse_connect.driver.Client]:
    """Return a live ClickHouse client for the current thread, reconnecting if needed."""
    client = getattr(_thread_local, "client", None)
    try:
        if client is not None:
            # Ping to verify connection is still alive
            client.ping()
            return client
    except Exception:
        client = None
        _thread_local.client = None

    try:
        client = clickhouse_connect.get_client(
            host=settings.CLICKHOUSE_HOST,
            port=settings.CLICKHOUSE_PORT,
            username=settings.CLICKHOUSE_USER,
            password=settings.CLICKHOUSE_PASSWORD,
            database=settings.CLICKHOUSE_DB,
            connect_timeout=10,
            send_receive_timeout=30,
        )
        _thread_local.client = client
        logger.info(
            f"ClickHouse connected (thread={threading.current_thread().name}): "
            f"{settings.CLICKHOUSE_HOST}:{settings.CLICKHOUSE_PORT} db={settings.CLICKHOUSE_DB}"
        )
        return client
    except Exception as e:
        logger.error(f"ClickHouse connection failed: {e}")
        return None


def is_available() -> bool:
    """Return True if ClickHouse is reachable."""
    return _get_client() is not None


def ensure_api_discovery_param_names_column() -> None:
    """Idempotent schema migration: adds api_discovery.param_names
    (Array(String)) for installs whose table predates the sensitive-
    parameter-visibility feature. Pure schema addition — ADD COLUMN IF
    NOT EXISTS is naturally safe to run on every startup, no marker
    column needed (unlike reset_fabricated_api_discovery_fields below,
    which also runs a one-time data UPDATE)."""
    client = _get_client()
    if client is None:
        return
    try:
        client.command(
            "ALTER TABLE api_discovery ADD COLUMN IF NOT EXISTS param_names Array(String) DEFAULT []"
        )
    except Exception as e:
        logger.warning(f"ClickHouse api_discovery.param_names migration check failed: {e}")


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
        # ids are ModSecurity's own unique_id values, sourced from audit log
        # filenames during backfill — not attacker-reachable through any API
        # route today, but parameterized anyway rather than relying on that.
        result = client.query(
            "SELECT id FROM waf_events WHERE id IN %(ids)s",
            parameters={"ids": tuple(ids)},
        )
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


def _build_waf_events_where_clause(
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
) -> Tuple[str, Dict[str, Any]]:
    """
    Shared WHERE-clause builder for waf_events queries — used by both
    query_waf_events() (raw rows) and query_waf_events_grouped() (Events
    page's collapsed-by-IP+rule view) so the two can never drift on what
    counts as a match for the same filter inputs.

    Returns (sql_fragment, parameters). Callers MUST pass
    `parameters=parameters` to every client.query() call built from this
    fragment (including when it's empty — clickhouse-connect no-ops on an
    empty/falsy parameters dict, so this is always safe). All user-controlled
    values go through %(name)s placeholders — clickhouse-connect's
    finalize_query() does real value escaping (backslash/quote-escaping the
    whole value, not just stripping quotes) — rather than being interpolated
    into the SQL text directly, which is what let the severity/decision
    SQLi bugs happen (see git history: two call sites here were missing
    even the old ad-hoc quote-stripping other call sites had).

    Every LIKE-pattern wildcard (including the static '4%'/'5%'/'/api%'
    ones below) is passed as a parameter VALUE too, not left as literal '%'
    text in the template — clickhouse-connect's parameter substitution is a
    single Python `%`-format pass over the WHOLE query string, so any bare
    '%' left in the template (outside a %(name)s token) would raise
    ValueError the moment this fragment is combined with a non-empty
    parameters dict elsewhere in the query.
    """
    SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    where = ["1=1"]
    params: Dict[str, Any] = {}

    if blocked_only:
        where.append("(http_code LIKE %(blocked_4xx)s OR http_code LIKE %(blocked_5xx)s OR length(violations) > 2)")
        params["blocked_4xx"] = "4%"
        params["blocked_5xx"] = "5%"

    if hours:
        where.append(f"timestamp >= now() - INTERVAL {int(hours)} HOUR")

    if severity:
        where.append("lower(severity) = %(severity)s")
        params["severity"] = severity.lower()

    if min_severity:
        threshold = SEVERITY_ORDER.get(min_severity.lower(), 0)
        sev_list = [s for s, v in SEVERITY_ORDER.items() if v >= threshold]
        if sev_list:
            # sev_list values are always drawn from SEVERITY_ORDER's fixed
            # internal keys, never user input directly — safe to inline.
            in_clause = ", ".join(f"'{s}'" for s in sev_list)
            where.append(f"lower(severity) IN ({in_clause})")

    if rule_id:
        where.append("rule_id = %(rule_id)s")
        params["rule_id"] = rule_id

    if ip:
        where.append("client_ip = %(client_ip)s")
        params["client_ip"] = ip

    if attack_type:
        where.append("lower(attack_type) = %(attack_type)s")
        params["attack_type"] = attack_type.lower()

    if status_code:
        where.append("http_code = %(status_code)s")
        params["status_code"] = status_code

    if search:
        where.append(
            "(lower(message) LIKE %(search_lower)s OR lower(uri) LIKE %(search_lower)s "
            "OR client_ip LIKE %(search_raw)s OR rule_id LIKE %(search_raw)s "
            "OR lower(attack_type) LIKE %(search_lower)s)"
        )
        params["search_lower"] = f"%{search.lower()}%"
        params["search_raw"] = f"%{search}%"

    if uri_type == "api":
        where.append("uri LIKE %(uri_prefix)s")
        params["uri_prefix"] = "/api%"
    elif uri_type == "web":
        where.append("uri NOT LIKE %(uri_prefix)s")
        params["uri_prefix"] = "/api%"

    return " AND ".join(where), params


def get_rule_canary_report(rule_id: str, hours: int = 168) -> Dict[str, int]:
    """
    Historical-impact measurement for a rule flagged canary (rule_manager.
    mark_rule_canary) — answers "would disabling this rule actually open a
    hole?" using real past traffic instead of a live experiment.

    waf_events.violations is a String column holding a JSON-serialized list
    (see configs/clickhouse/init.sql — NOT a native ClickHouse Array), and
    the top-level `rule_id` column is only ONE selected "primary" rule per
    request (see modsec_parser.py), not every rule that matched — so this
    must search inside the violations JSON itself via JSONExtractArrayRaw/
    JSONExtractString rather than filtering on the indexed rule_id column,
    or it would silently undercount requests where this rule matched
    alongside another one.

    sole_match_count: this rule was the ONLY violation on the request —
    disabling it would let these through unblocked.
    co_matched_count: at least one other rule also matched — still blocked
    even if this one were disabled.
    """
    client = _get_client()
    if client is None:
        return {"total_matches": 0, "sole_match_count": 0, "co_matched_count": 0}

    matched_expr = (
        "arrayExists(x -> JSONExtractString(x, 'rule_id') = %(rule_id)s, "
        "JSONExtractArrayRaw(violations))"
    )
    count_expr = "length(JSONExtractArrayRaw(violations))"

    try:
        result = client.query(
            f"""
            SELECT
                countIf({matched_expr}) AS total_matches,
                countIf({matched_expr} AND {count_expr} = 1) AS sole_match_count,
                countIf({matched_expr} AND {count_expr} > 1) AS co_matched_count
            FROM waf_events
            WHERE timestamp >= now() - INTERVAL {int(hours)} HOUR
            """,
            parameters={"rule_id": rule_id},
        )
        row = result.result_rows[0] if result.result_rows else (0, 0, 0)
        return {
            "total_matches": int(row[0]),
            "sole_match_count": int(row[1]),
            "co_matched_count": int(row[2]),
        }
    except Exception as e:
        logger.error(f"get_rule_canary_report failed for rule {rule_id}: {e}")
        return {"total_matches": 0, "sole_match_count": 0, "co_matched_count": 0}


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
    client = _get_client()
    if client is None:
        return [], 0

    where_clause, where_params = _build_waf_events_where_clause(
        severity=severity, min_severity=min_severity, rule_id=rule_id, ip=ip,
        attack_type=attack_type, status_code=status_code, search=search,
        uri_type=uri_type, hours=hours, blocked_only=blocked_only,
    )
    offset = (page - 1) * size

    try:
        count_result = client.query(
            f"SELECT count() FROM waf_events WHERE {where_clause}",
            parameters=where_params,
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
            """,
            parameters=where_params,
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


def query_waf_events_grouped(
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
    Same filters as query_waf_events(), but collapses matching events into
    one row per (client_ip, rule_id) — the Events page's "Grouped" view, for
    surfacing e.g. "this IP hit this rule 47 times" instead of 47 identical-
    looking rows. `total` here is the count of distinct groups, not events.

    Each group's severity/attack_type/message/sample_uri/country come from
    that group's most recent event (argMax(..., timestamp)), so a group
    reflects its latest occurrence rather than an arbitrary member.
    """
    client = _get_client()
    if client is None:
        return [], 0

    where_clause, where_params = _build_waf_events_where_clause(
        severity=severity, min_severity=min_severity, rule_id=rule_id, ip=ip,
        attack_type=attack_type, status_code=status_code, search=search,
        uri_type=uri_type, hours=hours, blocked_only=blocked_only,
    )
    offset = (page - 1) * size

    try:
        count_result = client.query(
            f"""
            SELECT count() FROM (
                SELECT 1 FROM waf_events WHERE {where_clause}
                GROUP BY client_ip, rule_id
            )
            """,
            parameters=where_params,
        )
        total = count_result.result_rows[0][0] if count_result.result_rows else 0

        rows_result = client.query(
            f"""
            SELECT client_ip, rule_id,
                   count() AS event_count,
                   min(timestamp) AS first_seen,
                   max(timestamp) AS last_seen,
                   -- Aliased to *_latest, not the bare column name: aliasing
                   -- an aggregate as e.g. "severity" collides with the raw
                   -- `severity` column referenced in the WHERE clause above
                   -- and ClickHouse's analyzer substitutes the alias back
                   -- into WHERE, throwing ILLEGAL_AGGREGATION on any filtered
                   -- query (silently swallowed into an empty result by the
                   -- except-clause below — confirmed directly against a live
                   -- instance). The Python-side `columns` list below maps
                   -- these positionally, so the SQL alias names themselves
                   -- are otherwise cosmetic.
                   argMax(severity, timestamp) AS severity_latest,
                   argMax(attack_type, timestamp) AS attack_type_latest,
                   argMax(message, timestamp) AS message_latest,
                   argMax(uri, timestamp) AS sample_uri,
                   argMax(country, timestamp) AS country_latest
            FROM waf_events
            WHERE {where_clause}
            GROUP BY client_ip, rule_id
            ORDER BY last_seen DESC
            LIMIT {int(size)} OFFSET {int(offset)}
            """,
            parameters=where_params,
        )

        columns = [
            "client_ip", "rule_id", "event_count", "first_seen", "last_seen",
            "severity", "attack_type", "message", "sample_uri", "country",
        ]

        result = []
        for row in rows_result.result_rows:
            d = dict(zip(columns, row))
            for field in ("first_seen", "last_seen"):
                if isinstance(d[field], datetime):
                    d[field] = d[field].strftime("%Y-%m-%d %H:%M:%S")
            result.append(d)

        return result, int(total)

    except Exception as e:
        logger.error(f"query_waf_events_grouped failed: {e}")
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
            WHERE id = %(log_id)s
            LIMIT 1
            """,
            parameters={"log_id": log_id},
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


# waf_events (ModSecurity's own transaction ID) and ml_events (nginx's
# $request_id) are independent ID spaces — nothing in this stack threads
# one into the other (same limitation ml-waf/crs_audit_enrichment.py
# already documents and works around for its own, offline, SQLite-side
# join). This is the ClickHouse-side equivalent: both tables' timestamp
# columns are the same type (DateTime('Asia/Kolkata')), confirmed via
# DESCRIBE TABLE, so no timezone conversion is needed here — just a
# bounded window on (client_ip, uri, timestamp). Fuzzy by necessity, not
# a guaranteed match: two near-simultaneous requests from the same IP to
# the same URI could rarely mismatch, same accepted tradeoff as the
# offline job.
EXPLAIN_MATCH_WINDOW_SECONDS = 3


def find_ml_event_near(client_ip: str, uri: str, timestamp: str, window_seconds: int = EXPLAIN_MATCH_WINDOW_SECONDS) -> Optional[Dict]:
    """Best-effort lookup of the ml_events row (if any) for the same
    request a waf_events row describes — see the module comment above for
    why this can't be an exact join. Returns None if ml scoring never ran
    for this request (e.g. it was blocked natively by ModSecurity before
    reaching the content-phase /predict call — see ml_decide.lua) or no
    match falls inside the window."""
    client = _get_client()
    if client is None:
        return None
    try:
        result = client.query(
            """
            SELECT unique_id, timestamp, crs_score, matched_vars, xgb_prob,
                   iso_score, threat_score, decision, redis_rep, abuse_score
            FROM ml_events
            WHERE remote_addr = %(client_ip)s
              AND uri = %(uri)s
              AND timestamp BETWEEN %(ts)s - INTERVAL %(window)s SECOND
                                AND %(ts)s + INTERVAL %(window)s SECOND
            ORDER BY abs(dateDiff('second', timestamp, %(ts)s)) ASC
            LIMIT 1
            """,
            parameters={"client_ip": client_ip, "uri": uri, "ts": timestamp, "window": window_seconds},
        )
        if not result.result_rows:
            return None
        columns = ["unique_id", "timestamp", "crs_score", "matched_vars", "xgb_prob",
                   "iso_score", "threat_score", "decision", "redis_rep", "abuse_score"]
        d = dict(zip(columns, result.result_rows[0]))
        if isinstance(d["timestamp"], datetime):
            d["timestamp"] = d["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        return d
    except Exception as e:
        logger.error(f"find_ml_event_near failed: {e}")
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
                countIf(http_code IN {_BLOCKED_HTTP_CODES_SQL})                                           AS total_blocked,
                countIf(lower(attack_type) = 'sql injection' AND http_code = '403') AS sqli_count,
                countIf(lower(attack_type) = 'xss' AND http_code = '403')           AS xss_count,
                uniqExactIf(client_ip, http_code IN {_BLOCKED_HTTP_CODES_SQL})                           AS unique_ips,
                countIf(http_code IN {_BLOCKED_HTTP_CODES_SQL} AND timestamp >= now() - INTERVAL 1 MINUTE) AS recent_threats,
                argMaxIf(attack_type, 1, http_code IN {_BLOCKED_HTTP_CODES_SQL} AND attack_type != '' AND attack_type != 'Unknown') AS top_attack
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
            WHERE http_code IN {_BLOCKED_HTTP_CODES_SQL} {time_filter}
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
            WHERE http_code IN {_BLOCKED_HTTP_CODES_SQL} AND client_ip != '' {time_filter}
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


def get_repeat_offender_ips(threshold: int, hours: int) -> List[str]:
    """Self-learned IP reputation (P1-7): IPs with at least `threshold`
    blocked (401/403/406/429) requests in the last `hours` — the
    server-side HAVING equivalent of get_top_ips above, used by
    auto_reputation_service's scheduled job rather than a dashboard
    display, so it returns just the qualifying IP list, not a ranked
    top-N with country/count for humans to read."""
    client = _get_client()
    if client is None:
        raise RuntimeError("ClickHouse client unavailable")
    try:
        result = client.query(
            f"""
            SELECT client_ip
            FROM waf_events
            WHERE http_code IN {_BLOCKED_HTTP_CODES_SQL}
              AND client_ip != ''
              AND timestamp >= now() - INTERVAL %(hours)s HOUR
            GROUP BY client_ip
            HAVING count() >= %(threshold)s
            """,
            parameters={"hours": hours, "threshold": threshold},
        )
        return [row[0] for row in result.result_rows]
    except Exception as e:
        logger.error(f"get_repeat_offender_ips failed: {e}")
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
            WHERE http_code IN {_BLOCKED_HTTP_CODES_SQL} {time_filter}
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
    params: Dict[str, Any] = {}
    if decision:
        where.append("decision = %(decision)s")
        params["decision"] = decision
    where_clause = " AND ".join(where)
    offset = (page - 1) * size

    try:
        count_result = client.query(
            f"SELECT count() FROM ml_events WHERE {where_clause}",
            parameters=params,
        )
        total = count_result.result_rows[0][0] if count_result.result_rows else 0

        result = client.query(
            f"""
            SELECT unique_id, timestamp, remote_addr, method, uri,
                   crs_score, xgb_prob, iso_score, threat_score, decision, abuse_score
            FROM ml_events
            WHERE {where_clause}
            ORDER BY timestamp DESC
            LIMIT {int(size)} OFFSET {int(offset)}
            """,
            parameters=params,
        )

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
            WHERE log_id = %(log_id)s AND status != 'Deleted'
            LIMIT 1
            """,
            parameters={"log_id": log_id},
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
            WHERE id = %(entry_id)s AND status != 'Deleted'
            LIMIT 1
            """,
            parameters={"entry_id": entry_id},
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
    params: Dict[str, Any] = {}
    if status:
        where.append("status = %(status)s")
        params["status"] = status
    if severity:
        where.append("lower(severity) = %(severity)s")
        params["severity"] = severity.lower()
    if rule_id:
        where.append("rule_id = %(rule_id)s")
        params["rule_id"] = rule_id
    if search:
        where.append(
            "(lower(analyst_note) LIKE %(search_lower)s OR lower(uri) LIKE %(search_lower)s "
            "OR client_ip LIKE %(search_raw)s OR rule_id LIKE %(search_raw)s)"
        )
        params["search_lower"] = f"%{search.lower()}%"
        params["search_raw"] = f"%{search}%"
    where_clause = " AND ".join(where)
    try:
        result = client.query(
            f"""
            SELECT log_id, rule_id, client_ip, uri, event_timestamp,
                   severity, attack_type, status, analyst_note, created_by, raw_log, id
            FROM analyst_feedback FINAL
            WHERE {where_clause}
            ORDER BY created_at DESC
            """,
            parameters=params,
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
            [str(p) for p in (r.get("param_names") or [])],
            ts,
        ])

    columns = [
        "uri", "method", "timestamp", "hit_count", "error_count",
        "malicious_count", "suspicious_count", "external_hit_count", "internal_hit_count",
        "has_https", "has_versioning", "content_encoding", "avg_response_time_ms",
        "param_names", "first_seen",
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
                weighted_response_sum, p95_response_time_ms, p99_response_time_ms,
                param_names
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
                       sum(avg_response_time_ms * hit_count) AS weighted_response_sum,
                       -- Approximation, not a true per-request percentile: each
                       -- api_discovery row is already an average over one
                       -- ~10s discovery-cycle batch (see api_discovery.py),
                       -- not a single request. This is the 95th/99th
                       -- percentile of those per-batch averages — i.e. "how
                       -- bad do this endpoint's worst time windows get",
                       -- which still distinguishes a consistently-slow
                       -- endpoint from one with one-off outliers, without
                       -- needing per-request storage.
                       quantile(0.95)(avg_response_time_ms) AS p95_response_time_ms,
                       quantile(0.99)(avg_response_time_ms) AS p99_response_time_ms,
                       -- Union of every param name seen across all batches
                       -- for this endpoint — each row only carries what one
                       -- ~10s batch observed.
                       arrayDistinct(arrayFlatten(groupArray(param_names))) AS param_names
                FROM api_discovery
                GROUP BY uri, method
            )
            ORDER BY total_hits DESC
            """
        )
        columns = [
            "uri", "method", "first_seen", "last_seen", "hit_count", "error_count",
            "malicious_count", "suspicious_count", "external_hit_count", "internal_hit_count",
            "has_https", "has_versioning", "content_encoding", "weighted_response_sum",
            "p95_response_time_ms", "p99_response_time_ms", "param_names",
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
            d["p95_response_time_ms"] = round(d.get("p95_response_time_ms") or 0.0, 2)
            d["p99_response_time_ms"] = round(d.get("p99_response_time_ms") or 0.0, 2)
            d["param_names"] = sorted(d.get("param_names") or [])
            rows.append(d)
        return rows
    except Exception as e:
        logger.error(f"get_all_discovered_endpoints failed: {e}")
        return []


def get_endpoint_threat_counts(hours: Optional[int] = None) -> Dict[Tuple[str, str], Dict[str, int]]:
    """
    Real ModSecurity detection counts per (uri, method), keyed the same way
    api_discovery.py aggregates endpoints (query string stripped).

    API Protection's endpoint score previously derived malicious/suspicious
    counts purely from nginx access-log status codes plus a 6-keyword
    substring blocklist (".. etc/passwd select union <script> alert(") —
    disconnected from the ModSecurity engine actually protecting the site.
    This gives the score real signal instead: malicious_count is confirmed
    WAF blocks (same http_code set used everywhere else in this file for
    "blocked"); suspicious_count is ModSecurity-flagged Medium/Low severity
    hits that were NOT blocked (e.g. detection-only paranoia rules).
    """
    client = _get_client()
    if client is None:
        return {}
    time_filter = _time_filter_clause(hours)
    try:
        result = client.query(f"""
            SELECT
                splitByChar('?', uri)[1] AS clean_uri,
                method,
                countIf(http_code IN {_BLOCKED_HTTP_CODES_SQL}) AS malicious_count,
                countIf(
                    lower(severity) IN ('medium', 'med', 'low', 'info', 'notice')
                    AND http_code NOT IN {_BLOCKED_HTTP_CODES_SQL}
                ) AS suspicious_count
            FROM waf_events
            WHERE uri != '' AND method != '' {time_filter}
            GROUP BY clean_uri, method
        """)
        return {
            (row[0], row[1]): {"malicious_count": row[2], "suspicious_count": row[3]}
            for row in result.result_rows
        }
    except Exception as e:
        logger.error(f"get_endpoint_threat_counts failed: {e}")
        return {}


def get_recently_discovered_endpoints(hours: int = 48) -> List[Dict[str, Any]]:
    """Retrieve endpoints first seen within the last N hours from ClickHouse."""
    endpoints = get_all_discovered_endpoints()
    # first_seen/last_seen are true UTC strings (api_discovery.py's
    # parse_nginx_timestamp converts using the log line's own offset) — the
    # cutoff must be built the same way. Using naive datetime.now() here
    # would silently use this process's local system tz (this deployment
    # runs every container on host-local IST via a bind-mounted
    # /etc/localtime), producing a cutoff off by that offset relative to
    # the UTC data it's compared against.
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")
    return [e for e in endpoints if e["first_seen"] >= cutoff_str]


def get_stale_discovered_endpoints(days: int = 30) -> List[Dict[str, Any]]:
    """Retrieve endpoints not seen in at least `days` days — shadow/zombie
    API candidates. Inverse of get_recently_discovered_endpoints."""
    endpoints = get_all_discovered_endpoints()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")
    return [e for e in endpoints if e["last_seen"] < cutoff_str]


def get_known_endpoint_keys() -> set:
    """Distinct (uri, method) pairs currently in api_discovery. Used by the
    reconcile-from-SQLite admin action to know which endpoints NOT to
    duplicate — see db_service.reconcile_clickhouse_from_sqlite for why
    this matters (SQLite is written continuously regardless of ClickHouse's
    availability, so its running totals for an already-known endpoint
    already overlap with what ClickHouse has; only entirely-missing
    endpoints are safe to backfill without double-counting)."""
    client = _get_client()
    if client is None:
        return set()
    try:
        result = client.query("SELECT DISTINCT uri, method FROM api_discovery")
        return {(row[0], row[1]) for row in result.result_rows}
    except Exception as e:
        logger.error(f"get_known_endpoint_keys failed: {e}")
        return set()


def backfill_api_discovery_rows(rows: List[Dict[str, Any]]) -> int:
    """
    Insert historical endpoint rows directly, preserving each row's true
    first_seen/last_seen — unlike insert_api_discovery(), which is built
    for normal per-cycle discovery and always collapses first_seen to the
    same value as the fresh timestamp (correct there, since a real
    first-ever-seen row IS "now"; wrong here, where these rows can be
    weeks old). Only ever called by the reconcile admin action.
    """
    if not rows:
        return 0
    client = _get_client()
    if client is None:
        return 0

    def _parse_ts(v):
        if isinstance(v, datetime):
            return v
        try:
            return datetime.strptime(v, "%Y-%m-%d %H:%M:%S")
        except Exception:
            return datetime.utcnow()

    ch_rows = []
    for r in rows:
        first_seen = _parse_ts(r.get("first_seen"))
        last_seen = _parse_ts(r.get("last_seen"))
        ch_rows.append([
            str(r.get("uri", "")),
            str(r.get("method", "")),
            last_seen,  # timestamp column -> becomes max(timestamp)=last_seen on read
            int(r.get("hit_count", 0)),
            int(r.get("error_count", 0)),
            int(r.get("malicious_count", 0)),
            int(r.get("suspicious_count", 0)),
            int(r.get("external_hit_count", 0)),
            int(r.get("internal_hit_count", 0)),
            int(r.get("has_https", 2)),
            int(r.get("has_versioning", 0)),
            str(r.get("content_encoding", "unknown")),
            float(r.get("avg_response_time_ms", 0.0)),
            [str(p) for p in (r.get("param_names") or [])],
            first_seen,  # first_seen column -> preserves the true historical date
        ])

    columns = [
        "uri", "method", "timestamp", "hit_count", "error_count",
        "malicious_count", "suspicious_count", "external_hit_count", "internal_hit_count",
        "has_https", "has_versioning", "content_encoding", "avg_response_time_ms",
        "param_names", "first_seen",
    ]
    try:
        client.insert("api_discovery", ch_rows, column_names=columns)
        return len(ch_rows)
    except Exception as e:
        logger.error(f"backfill_api_discovery_rows failed: {e}")
        return 0


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
    params: Dict[str, Any] = {}
    if event_type:
        where.append("event_type = %(event_type)s")
        params["event_type"] = event_type
    if severity:
        where.append("severity = %(severity)s")
        params["severity"] = severity
    if status:
        where.append("status = %(status)s")
        params["status"] = status
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
            """,
            parameters=params,
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
            "ALTER TABLE alert_history UPDATE "
            "status = 'acknowledged', "
            "acknowledged_by = %(acknowledged_by)s, "
            "acknowledged_at = now() "
            f"WHERE id = {int(alert_id)}",
            parameters={"acknowledged_by": acknowledged_by},
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


# ---------------------------------------------------------------------------
# audit_log — Write (system configuration change history)
# ---------------------------------------------------------------------------
def insert_audit_log(
    entity_type: str,
    entity_id: str,
    action: str,
    username: str,
    details: Optional[Dict[str, Any]] = None,
    ip_address: str = "",
) -> bool:
    """
    Append a system-configuration-change record to audit_log (365-day TTL —
    see init.sql). This function didn't exist despite the table and its
    schema already being defined and despite 4 call sites in db_service.py
    (exclusion create/toggle-status/update-note/delete) already calling it —
    every one of those SQLite writes (already committed by the point this
    is reached) was throwing AttributeError and getting swallowed by the
    caller's outer try/except, silently returning failure to the route
    layer despite the underlying data having actually been written.
    """
    client = _get_client()
    if client is None:
        return False
    try:
        details_str = json.dumps(details) if isinstance(details, dict) else str(details or "")
        client.insert("audit_log", [[
            str(entity_type),
            str(entity_id),
            str(action),
            str(username),
            details_str,
            str(ip_address or ""),
        ]], column_names=[
            "entity_type", "entity_id", "action", "username", "details", "ip_address",
        ])
        return True
    except Exception as e:
        logger.error(f"insert_audit_log failed: {e}")
        return False


def get_audit_log(
    entity_type: Optional[str] = None,
    page: int = 1,
    size: int = 50,
    hours: Optional[int] = None,
) -> Tuple[List[Dict], int]:
    """
    Paginated, filtered read of audit_log — (rows, total_count). Returns
    ([], 0) when ClickHouse is unreachable, matching query_waf_events()'s
    convention (a dashboard panel reading this should degrade to empty
    rather than 500).
    """
    client = _get_client()
    if client is None:
        return [], 0

    where = ["1=1"]
    params: Dict[str, Any] = {}
    if entity_type:
        where.append("entity_type = %(entity_type)s")
        params["entity_type"] = entity_type
    if hours:
        where.append(f"timestamp >= now() - INTERVAL {int(hours)} HOUR")
    where_clause = " AND ".join(where)
    offset = (page - 1) * size

    try:
        count_result = client.query(
            f"SELECT count() FROM audit_log WHERE {where_clause}",
            parameters=params,
        )
        total = count_result.result_rows[0][0] if count_result.result_rows else 0

        rows_result = client.query(
            f"""
            SELECT id, timestamp, entity_type, entity_id, action, username, details, ip_address
            FROM audit_log
            WHERE {where_clause}
            ORDER BY timestamp DESC
            LIMIT {int(size)} OFFSET {int(offset)}
            """,
            parameters=params,
        )

        columns = ["id", "timestamp", "entity_type", "entity_id", "action", "username", "details", "ip_address"]
        result = []
        for row in rows_result.result_rows:
            d = dict(zip(columns, row))
            if isinstance(d["timestamp"], datetime):
                d["timestamp"] = d["timestamp"].isoformat()
            result.append(d)

        return result, total
    except Exception as e:
        logger.error(f"get_audit_log failed: {e}")
        return [], 0
