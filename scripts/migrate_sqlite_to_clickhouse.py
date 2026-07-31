#!/usr/bin/env python3
"""
migrate_sqlite_to_clickhouse.py — CyberSentinel WAF
======================================================
One-time migration script that copies existing SQLite data into ClickHouse.

Migrates:
  1. ml_events.db       → cybersentinel.ml_events
  2. false_positives.db → cybersentinel.analyst_feedback
  3. alerts.db          → cybersentinel.alert_history
  4. false_positives.db → exclusion_audit_history → cybersentinel.audit_log

Run AFTER ClickHouse is healthy (after docker compose up):

    docker exec waf-backend python3 /app/scripts/migrate_sqlite_to_clickhouse.py

Or from the host (if clickhouse-connect is installed locally):

    python3 scripts/migrate_sqlite_to_clickhouse.py \
        --ch-host localhost --ch-port 8123 \
        --ch-user wafuser --ch-password <PASSWORD> \
        --ch-db cybersentinel

Flags:
    --dry-run    Print row counts without inserting anything
    --skip-ml    Skip ml_events migration (takes longest)
"""

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

# ── Resolve paths ──────────────────────────────────────────────────────────
SCRIPT_DIR   = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent

# Detect container vs host project layout
if (PROJECT_ROOT / "app").exists() and not (PROJECT_ROOT / "backend").exists():
    BACKEND_DATA = PROJECT_ROOT / "app" / "data"
    BACKEND_CFG  = PROJECT_ROOT / "app" / "config"
else:
    BACKEND_DATA = PROJECT_ROOT / "backend" / "app" / "data"
    BACKEND_CFG  = PROJECT_ROOT / "backend" / "app" / "config"

FP_DB_PATH      = BACKEND_CFG / "false_positives.db"
ML_DB_PATH      = BACKEND_DATA / "ml_events.db"
ALERTS_DB_PATH  = BACKEND_DATA / "alerts.db"

CHUNK_SIZE = 1000   # rows per ClickHouse INSERT


def parse_args():
    p = argparse.ArgumentParser(description="Migrate SQLite WAF data to ClickHouse")
    p.add_argument("--ch-host",     default=os.environ.get("CLICKHOUSE_HOST", "localhost"))
    p.add_argument("--ch-port",     type=int, default=int(os.environ.get("CLICKHOUSE_PORT", "8123")))
    p.add_argument("--ch-user",     default=os.environ.get("CLICKHOUSE_USER", "wafuser"))
    p.add_argument("--ch-password", default=os.environ.get("CLICKHOUSE_PASSWORD", ""))
    p.add_argument("--ch-db",       default=os.environ.get("CLICKHOUSE_DB", "cybersentinel"))
    p.add_argument("--dry-run",     action="store_true", help="Count rows only, do not insert")
    p.add_argument("--skip-ml",     action="store_true", help="Skip ml_events migration")
    return p.parse_args()


def get_ch_client(args):
    try:
        import clickhouse_connect
        client = clickhouse_connect.get_client(
            host=args.ch_host,
            port=args.ch_port,
            username=args.ch_user,
            password=args.ch_password,
            database=args.ch_db,
            connect_timeout=15,
        )
        client.ping()
        print(f"✓ Connected to ClickHouse at {args.ch_host}:{args.ch_port} db={args.ch_db}")
        return client
    except Exception as e:
        print(f"✗ Could not connect to ClickHouse: {e}", file=sys.stderr)
        sys.exit(1)


def sqlite_rows(db_path: Path, query: str):
    if not db_path.exists():
        print(f"  ⚠  SQLite file not found: {db_path} — skipping")
        return []
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(query).fetchall()
    conn.close()
    return rows


def parse_ts(val, fallback=None):
    if not val:
        return fallback or datetime.utcnow()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(str(val)[:19], fmt)
        except Exception:
            pass
    return fallback or datetime.utcnow()


def insert_chunks(client, table: str, columns: list, rows: list, dry_run: bool, label: str):
    total = len(rows)
    if dry_run:
        print(f"  [dry-run] Would insert {total} rows into {table}")
        return
    inserted = 0
    for i in range(0, total, CHUNK_SIZE):
        chunk = rows[i:i + CHUNK_SIZE]
        client.insert(table, chunk, column_names=columns)
        inserted += len(chunk)
        print(f"  {label}: {inserted}/{total} rows inserted …", end="\r")
    print(f"  {label}: ✓ {inserted} rows inserted into {table}     ")


# ── Migration 1: ml_events ─────────────────────────────────────────────────
def migrate_ml_events(client, dry_run: bool):
    print("\n[1/3] Migrating ml_events.db → cybersentinel.ml_events")
    raw = sqlite_rows(ML_DB_PATH, "SELECT * FROM ml_events ORDER BY timestamp")
    if not raw:
        print("  No rows found.")
        return

    rows = []
    for r in raw:
        ts = parse_ts(r["timestamp"])
        rows.append([
            str(r["unique_id"] or ""),
            ts,
            str(r["remote_addr"] or ""),
            str(r["method"] or ""),
            str(r["uri"] or ""),
            str(r["args"] or ""),
            str(r["ct"] or ""),
            str(r["ua"] or ""),
            float(r["body_len"] or 0.0),
            float(r["crs_score"] or 0.0),
            str(r["matched_vars"] or ""),
            float(r["redis_rpm"] or 0.0),
            float(r["redis_rep"] or 0.0),
            float(r["abuse_score"] or 0.0),
            float(r["xgb_prob"] or 0.0),
            float(r["iso_score"] or 0.0),
            float(r["threat_score"] or 0.0),
            str(r["decision"] or ""),
        ])

    columns = [
        "unique_id", "timestamp", "remote_addr", "method", "uri", "args",
        "ct", "ua", "body_len", "crs_score", "matched_vars",
        "redis_rpm", "redis_rep", "abuse_score",
        "xgb_prob", "iso_score", "threat_score", "decision",
    ]
    insert_chunks(client, "ml_events", columns, rows, dry_run, "ml_events")


# ── Migration 2: false_positives → analyst_feedback ───────────────────────
def migrate_false_positives(client, dry_run: bool):
    print("\n[2/3] Migrating false_positives.db → cybersentinel.analyst_feedback")
    raw = sqlite_rows(
        FP_DB_PATH,
        "SELECT * FROM false_positives ORDER BY id"
    )
    if not raw:
        print("  No rows found.")
        return

    rows = []
    for r in raw:
        ts = parse_ts(r["timestamp"])
        raw_log_str = ""
        try:
            rlog = json.loads(r["raw_log"]) if r["raw_log"] else {}
            raw_log_str = json.dumps(rlog)
        except Exception:
            raw_log_str = str(r["raw_log"] or "")
        rows.append([
            str(r["log_id"] or ""),
            str(r["rule_id"] or ""),
            str(r["client_ip"] or ""),
            str(r["uri"] or ""),
            ts,
            str(r["severity"] or ""),
            str(r["attack_type"] or ""),
            str(r["status"] or "Pending"),
            str(r["analyst_note"] or ""),
            str(r["created_by"] or "system"),
            raw_log_str,
        ])

    columns = [
        "log_id", "rule_id", "client_ip", "uri", "event_timestamp",
        "severity", "attack_type", "status", "analyst_note", "created_by", "raw_log",
    ]
    insert_chunks(client, "analyst_feedback", columns, rows, dry_run, "analyst_feedback")


# ── Migration 3: alert_history ─────────────────────────────────────────────
def migrate_alert_history(client, dry_run: bool):
    print("\n[3/3] Migrating alerts.db → cybersentinel.alert_history")
    raw = sqlite_rows(
        ALERTS_DB_PATH,
        "SELECT * FROM alert_history ORDER BY created_at"
    )
    if not raw:
        print("  No rows found.")
        return

    rows = []
    for r in raw:
        ack_at = parse_ts(r["acknowledged_at"]) if r["acknowledged_at"] else None
        rows.append([
            int(r["id"] or 0),
            int(r["rule_id"] or 0),
            str(r["rule_name"] or ""),
            str(r["event_type"] or ""),
            str(r["severity"] or ""),
            str(r["channels_notified"] or ""),
            str(r["event_data"] or ""),
            str(r["message"] or ""),
            str(r["status"] or "sent"),
            str(r["error_message"] or ""),
            str(r["acknowledged_by"] or ""),
            ack_at,
        ])

    columns = [
        "id", "rule_id", "rule_name", "event_type", "severity",
        "channels_notified", "event_data", "message", "status",
        "error_message", "acknowledged_by", "acknowledged_at",
    ]
    insert_chunks(client, "alert_history", columns, rows, dry_run, "alert_history")


# ── Main ───────────────────────────────────────────────────────────────────
def main():
    args = parse_args()
    client = get_ch_client(args)

    if not args.skip_ml:
        migrate_ml_events(client, args.dry_run)
    else:
        print("\n[1/3] Skipping ml_events migration (--skip-ml)")

    migrate_false_positives(client, args.dry_run)
    migrate_alert_history(client, args.dry_run)

    print("\n✓ Migration complete.")
    if args.dry_run:
        print("  (Dry-run mode: no data was written to ClickHouse)")


if __name__ == "__main__":
    main()
