"""
Backfills the real, fully-computed OWASP CRS anomaly score into ml_events
rows whose live-path crs_score is unreliable.

Why this exists: ngx_http_modsecurity_module is loaded dynamically
(`load_module`), while OpenResty's Lua engine is compiled into the core
binary — nginx runs statically-linked modules' access-phase handlers before
dynamically-loaded ones, so `access_by_lua_file` (ml_check.lua) reads
$modsecurity_anomaly_score before ModSecurity has finished scoring that
request. ModSecurity's own native blocking is unaffected by this (it doesn't
depend on the Lua read), but the score ml_check.lua captures for ML
training is stale/empty. See project notes on the CRS->ML bridge for the
full diagnosis; fixing the live ordering is a separate, riskier change to
the request hot path — this script fixes the training-data consequence of
it without touching that path at all.

ModSecurity's own audit log (SecAuditLogFormat JSON, one file per
transaction) always contains the real, fully-accumulated score, computed
independently by ModSecurity itself. This script parses those files,
recomputes each transaction's total anomaly score from its matched rules'
severities (using CRS's standard severity->points mapping, since a
transaction that never crossed the block threshold has no explicit "Total
Score" message to read directly), and backfills matching ml_events rows.

Correlation problem: ModSecurity's own transaction unique_id (audit log) and
nginx's $request_id (ml_events.unique_id) are two independent ID spaces —
nothing in this stack currently threads one into the other. Matching is
done on (remote_addr, uri, timestamp within a small window) instead. This is
a fuzzy join, not a guaranteed one; see MATCH_WINDOW_SECONDS.
"""
from __future__ import annotations

import os
import sys
import json
import sqlite3
import logging
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

AUDIT_LOG_DIR = os.environ.get(
    "MODSEC_AUDIT_LOG_DIR",
    os.path.abspath(os.path.join(BASE_DIR, "..", "logs", "modsecurity", "audit")),
)
DB_PATH = os.environ.get(
    "ML_DB_PATH",
    os.path.abspath(os.path.join(BASE_DIR, "..", "backend", "app", "data", "ml_events.db")),
)
WATERMARK_PATH = os.environ.get(
    "CRS_ENRICHMENT_WATERMARK_PATH",
    os.path.join(BASE_DIR, "logs", "crs_enrichment_watermark.txt"),
)

# ModSecurity's internal syslog-style severity scale, mapped to CRS's
# standard anomaly-score point values (crs-setup.conf defaults: critical=5,
# error=4, warning=3, notice=2). Verified directly against a real audit log
# entry: rule 920350 (severity 4) + four XSS rules (severity 2 each) summed
# to exactly the "Total Score: 23" ModSecurity itself reported
# (3 + 4*5 == 23).
SEVERITY_TO_POINTS = {
    "2": 5,  # CRITICAL
    "3": 4,  # ERROR
    "4": 3,  # WARNING
    "5": 2,  # NOTICE
}

# The scoring-evaluation rules themselves (949xxx) are meta — they report
# the running total, they are not attack signals to add points for.
SCORING_RULE_PREFIX = "949"

# How close two independently-generated timestamps (nginx's request time vs
# ModSecurity's transaction time_stamp) must be to treat them as the same
# request. Both are logged at second resolution by their respective
# systems, so a couple of seconds of slack absorbs normal clock/processing
# skew without being wide enough to routinely collide two different
# requests from the same IP to the same URI.
MATCH_WINDOW_SECONDS = 3


def _compute_real_score(messages: list) -> tuple[float, list[str]]:
    score = 0.0
    rule_ids: list[str] = []
    for msg in messages:
        details = msg.get("details") or {}
        rule_id = str(details.get("ruleId") or "")
        if not rule_id or rule_id.startswith(SCORING_RULE_PREFIX):
            continue
        points = SEVERITY_TO_POINTS.get(str(details.get("severity") or ""))
        if points:
            score += points
            rule_ids.append(rule_id)
    return score, rule_ids


def _parse_audit_file(path: str) -> dict | None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Skipping unreadable audit file %s: %s", path, exc)
        return None

    txn = data.get("transaction") or {}
    request = txn.get("request") or {}
    response = txn.get("response") or {}
    time_stamp = txn.get("time_stamp")
    if not time_stamp:
        return None

    try:
        # ModSecurity logs this in the container's local time (IST here,
        # inherited from the host via the /etc/localtime bind mount), while
        # ml_events.timestamp is written as UTC (ml_server.py uses
        # datetime.now(pytz.UTC)) — convert so both sides compare in UTC.
        local_dt = datetime.strptime(time_stamp, "%a %b %d %H:%M:%S %Y")
        utc_dt = local_dt - timedelta(hours=5, minutes=30)
    except ValueError:
        logger.warning("Unparseable time_stamp %r in %s", time_stamp, path)
        return None

    real_score, rule_ids = _compute_real_score(txn.get("messages") or [])

    return {
        "remote_addr": txn.get("client_ip", ""),
        "uri": request.get("uri", ""),
        "method": request.get("method", ""),
        "timestamp_utc": utc_dt,
        "http_code": response.get("http_code"),
        "real_crs_score": real_score,
        "matched_rule_ids": rule_ids,
    }


def _iter_audit_files(since_dir: str | None):
    """Yields audit file paths in chronological order (day dir, then minute
    dir, then file — all three are zero-padded/lexically sortable by
    construction), optionally skipping everything at or before a watermark
    directory to make repeated runs incremental."""
    if not os.path.isdir(AUDIT_LOG_DIR):
        logger.error("Audit log directory not found: %s", AUDIT_LOG_DIR)
        return
    for day in sorted(os.listdir(AUDIT_LOG_DIR)):
        day_path = os.path.join(AUDIT_LOG_DIR, day)
        if not os.path.isdir(day_path):
            continue
        for minute in sorted(os.listdir(day_path)):
            minute_path = os.path.join(day_path, minute)
            if not os.path.isdir(minute_path):
                continue
            minute_key = f"{day}/{minute}"
            if since_dir and minute_key <= since_dir:
                continue
            for fname in sorted(os.listdir(minute_path)):
                fpath = os.path.join(minute_path, fname)
                if os.path.isfile(fpath):
                    yield minute_key, fpath


def _ensure_column(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    try:
        cur.execute("SELECT crs_score_verified FROM ml_events LIMIT 1;")
    except sqlite3.OperationalError:
        # Kept separate from the live-path crs_score column rather than
        # overwriting it, so the original (broken) value stays available
        # for debugging and this backfill is trivially distinguishable /
        # reversible. NULL means "not yet enriched", not "verified zero".
        cur.execute("ALTER TABLE ml_events ADD COLUMN crs_score_verified REAL DEFAULT NULL;")
        conn.commit()


def _match_and_update(conn: sqlite3.Connection, txn: dict) -> bool:
    lo = (txn["timestamp_utc"] - timedelta(seconds=MATCH_WINDOW_SECONDS)).strftime("%Y-%m-%d %H:%M:%S")
    hi = (txn["timestamp_utc"] + timedelta(seconds=MATCH_WINDOW_SECONDS)).strftime("%Y-%m-%d %H:%M:%S")
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id FROM ml_events
        WHERE remote_addr = ?
          AND uri = ?
          AND timestamp BETWEEN ? AND ?
          AND crs_score_verified IS NULL
        ORDER BY ABS(strftime('%s', timestamp) - strftime('%s', ?)) ASC
        LIMIT 1
        """,
        (txn["remote_addr"], txn["uri"], lo, hi, txn["timestamp_utc"].strftime("%Y-%m-%d %H:%M:%S")),
    )
    row = cur.fetchone()
    if row is None:
        return False
    cur.execute(
        "UPDATE ml_events SET crs_score_verified = ? WHERE id = ?",
        (txn["real_crs_score"], row[0]),
    )
    return True


def run(limit: int | None = None) -> dict:
    if not os.path.exists(DB_PATH):
        logger.error("ml_events.db not found at %s", DB_PATH)
        return {"processed": 0, "matched": 0}

    watermark = None
    if os.path.exists(WATERMARK_PATH):
        with open(WATERMARK_PATH, "r", encoding="utf-8") as f:
            watermark = f.read().strip() or None

    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    _ensure_column(conn)

    processed = 0
    matched = 0
    last_minute_key = watermark

    for minute_key, fpath in _iter_audit_files(watermark):
        txn = _parse_audit_file(fpath)
        last_minute_key = minute_key
        if txn is None:
            continue
        processed += 1
        if _match_and_update(conn, txn):
            matched += 1
        if processed % 500 == 0:
            conn.commit()
            logger.info("...%d audit files processed, %d matched so far", processed, matched)
        if limit and processed >= limit:
            break

    conn.commit()
    conn.close()

    if last_minute_key and last_minute_key != watermark:
        os.makedirs(os.path.dirname(WATERMARK_PATH), exist_ok=True)
        with open(WATERMARK_PATH, "w", encoding="utf-8") as f:
            f.write(last_minute_key)

    logger.info("Done. Audit transactions processed: %d, ml_events rows enriched: %d", processed, matched)
    return {"processed": processed, "matched": matched}


if __name__ == "__main__":
    limit_arg = int(sys.argv[1]) if len(sys.argv) > 1 else None
    run(limit=limit_arg)
