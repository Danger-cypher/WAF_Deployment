"""
inject_audit_attacks.py — CyberSentinel ML Training Data Enrichment
====================================================================
Parses the ModSecurity per-request audit log directory
(individual JSON files, one per transaction) and injects
confirmed blocked requests (HTTP 403) as labelled attack
samples into ml_events.db.

Run ONCE before retraining to fix the class imbalance problem.
Then run: sudo /opt/ModSecurity/WAF_GUI/ml-waf/retrain.sh

Usage:
    python3 /opt/ModSecurity/WAF_GUI/ml-waf/inject_audit_attacks.py
"""
import os
import json
import sqlite3
import logging
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get(
    "ML_DB_PATH",
    os.path.abspath(os.path.join(BASE_DIR, "..", "backend", "app", "data", "ml_events.db"))
)
AUDIT_DIR = "/var/log/modsecurity/audit/"

# CRS rule severity → anomaly score contribution
SEVERITY_SCORE_MAP = {
    "2": 5,   # CRITICAL
    "3": 4,   # ERROR
    "4": 3,   # WARNING
    "5": 2,   # NOTICE
}

def estimate_crs_score(messages: list) -> float:
    """Sum severity scores across all matched rule messages."""
    total = 0.0
    for m in messages:
        sev = str(m.get("details", {}).get("severity", "5"))
        total += SEVERITY_SCORE_MAP.get(sev, 1)
    return total


def parse_audit_file(filepath: str):
    """
    Parse a single ModSecurity audit log file (one JSON transaction per file).
    Returns a feature dict if the request was blocked (HTTP 403/400), else None.
    """
    try:
        with open(filepath, "r", errors="replace") as f:
            doc = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None

    tx        = doc.get("transaction", {})
    response  = tx.get("response", {})
    http_code = str(response.get("http_code", ""))

    # Only ingest confirmed hard-blocked requests
    if http_code not in ("403", "400"):
        return None

    req      = tx.get("request", {})
    messages = tx.get("messages", [])
    headers  = req.get("headers", {})

    crs_score = estimate_crs_score(messages)
    matched_vars = "; ".join(
        m.get("details", {}).get("match", "")[:120]
        for m in messages
    )[:500]

    body_raw = req.get("body", "") or ""

    return {
        "unique_id":    tx.get("unique_id", ""),
        "crs_score":    crs_score,
        "matched_vars": matched_vars,
        "uri":          req.get("uri", "")[:500],
        "args":         str(req.get("arguments", ""))[:500],
        "method":       req.get("method", ""),
        "body_len":     float(len(str(body_raw))),
        "ct":           headers.get("Content-Type", "")[:200],
        "ua":           headers.get("User-Agent", "")[:300],
        "remote_addr":  tx.get("client_ip", ""),
        "decision":     "block",
        "threat_score": 1.0,
        "xgb_prob":     1.0,
        "iso_score":    -0.5,
        "redis_rpm":    0.0,
        "redis_rep":    5.0,
        "abuse_score":  0.0,
    }


def get_existing_unique_ids(conn: sqlite3.Connection) -> set:
    cursor = conn.cursor()
    cursor.execute("SELECT unique_id FROM ml_events WHERE decision = 'block'")
    return {row[0] for row in cursor.fetchall() if row[0]}


def inject_entries(conn: sqlite3.Connection, entries: list) -> int:
    cursor = conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    inserted = 0
    for e in entries:
        cursor.execute("""
            INSERT INTO ml_events
            (unique_id, crs_score, matched_vars, uri, args, method, body_len,
             ct, ua, remote_addr, redis_rpm, redis_rep, xgb_prob, iso_score,
             threat_score, decision, abuse_score)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            e["unique_id"],    e["crs_score"],    e["matched_vars"],
            e["uri"],          e["args"],          e["method"],
            e["body_len"],     e["ct"],            e["ua"],
            e["remote_addr"],  e["redis_rpm"],     e["redis_rep"],
            e["xgb_prob"],     e["iso_score"],     e["threat_score"],
            e["decision"],     e["abuse_score"],
        ))
        inserted += 1
    conn.commit()
    return inserted


def main():
    logger.info("=" * 60)
    logger.info("  CyberSentinel — ML Attack Sample Injector")
    logger.info("=" * 60)

    if not os.path.exists(DB_PATH):
        logger.error(f"ml_events.db not found at {DB_PATH}. Is the backend running?")
        return

    conn = sqlite3.connect(DB_PATH, timeout=30)
    existing_ids = get_existing_unique_ids(conn)
    logger.info(f"Existing blocked samples in DB: {len(existing_ids)}")

    audit_path = Path(AUDIT_DIR)
    all_files  = [f for f in audit_path.rglob("*") if f.is_file()]
    logger.info(f"Audit log files found: {len(all_files)}")

    parsed_attacks = []
    skipped_allow  = 0
    skipped_dupes  = 0

    for filepath in all_files:
        entry = parse_audit_file(str(filepath))
        if entry is None:
            skipped_allow += 1
            continue
        uid = entry.get("unique_id", "")
        if uid and uid in existing_ids:
            skipped_dupes += 1
            continue
        parsed_attacks.append(entry)
        if uid:
            existing_ids.add(uid)

    logger.info(f"New blocked attack samples found: {len(parsed_attacks)}")
    logger.info(f"Skipped (allowed/logged): {skipped_allow}")
    logger.info(f"Skipped (duplicates): {skipped_dupes}")

    if not parsed_attacks:
        logger.warning("No new attack samples to inject.")
        conn.close()
        return

    inserted = inject_entries(conn, parsed_attacks)
    conn.close()

    logger.info(f"✅ Injected {inserted} attack samples into ml_events.db")
    logger.info("Next step — rebuild models:")
    logger.info("  sudo docker exec waf-ml python3 /app/train_xgb.py")
    logger.info("  sudo docker exec waf-ml python3 /app/train_iso.py")
    logger.info("  sudo docker compose restart ml-engine")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
