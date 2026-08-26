from __future__ import annotations

import os
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOCAL_EVENTS_PATH = os.path.join(BASE_DIR, "logs/events.jsonl")

# Analyst-reviewed rows (admin_label set via POST /ml/events/{id}/label) are
# ground truth; everything else is the WAF's own self-generated label. An
# attacker who crafts traffic to stay just under the block threshold gets
# labeled "benign" with no human ever looking at it — down-weighting
# unreviewed rows bounds how much a single such campaign can shift the
# decision boundary at the next retrain, without needing new review UI.
REVIEWED_WEIGHT = 1.0
SELF_LABELED_WEIGHT = 0.5

# Bounds a different, narrower poisoning vector than the weighting above:
# an attacker can't earn a human review, but CAN replay the same
# crafted-to-look-benign request thousands of times, hoping sheer
# repetition shifts the decision boundary even at 0.5x weight each. Caps
# how many times an identical (unreviewed) request signature counts toward
# training — legitimate repeat traffic (health checks, polling) collapses
# to a handful of samples instead of thousands, and a would-be flood loses
# its main lever entirely rather than merely being discounted. Scoped to
# the benign side only: the analogous "flood the attack side" doesn't
# dilute detection the same way — more labeled examples of one attack
# pattern make a classifier more sensitive to it, not less.
MAX_DUPLICATE_UNREVIEWED_SAMPLES = 20


def _cap_duplicate_unreviewed_rows(rows: list) -> list:
    seen_counts = {}
    capped = []
    dropped = 0
    for row in rows:
        if row.get("admin_label"):
            # A human already vouched for this exact row — exempt from the
            # cap regardless of how many identical unreviewed rows exist.
            capped.append(row)
            continue
        signature = (row.get("uri", ""), row.get("method", ""), row.get("args", ""))
        seen_counts[signature] = seen_counts.get(signature, 0) + 1
        if seen_counts[signature] <= MAX_DUPLICATE_UNREVIEWED_SAMPLES:
            capped.append(row)
        else:
            dropped += 1
    if dropped:
        logger.info(
            f"Capped {dropped} duplicate unreviewed benign samples "
            f"(signature repeated beyond {MAX_DUPLICATE_UNREVIEWED_SAMPLES}x) before training."
        )
    return capped


def connect_opensearch():
    """Connects to local OpenSearch service, if the optional opensearchpy
    dependency is installed. It is NOT in requirements.txt — this is a
    best-effort fallback behind the primary SQLite path below, so its
    absence must not break import of this module."""
    try:
        from opensearchpy import OpenSearch
    except ImportError:
        return None
    try:
        return OpenSearch(
            hosts=[{'host': 'localhost', 'port': 9200}],
            http_compress=True,
            timeout=2.0
        )
    except Exception as e:
        logger.warning(f"Failed to initialize OpenSearch client: {e}")
        return None

def fetch_events_from_opensearch(client, query: dict, size: int = 10000) -> list:
    """Fetches search query hits from OpenSearch index 'ml-waf-events'."""
    try:
        if not client.indices.exists(index="ml-waf-events"):
            logger.warning("Index 'ml-waf-events' does not exist in OpenSearch.")
            return []

        response = client.search(
            index="ml-waf-events",
            body={"query": query},
            size=size
        )
        hits = response['hits']['hits']
        return [hit['_source'] for hit in hits]
    except Exception as e:
        logger.error(f"OpenSearch query search failed: {e}")
        return []

def get_training_datasets() -> tuple[list, list]:
    """
    Fetches historical telemetry events to construct clean training arrays.
    Returns:
      benign_logs: List of dictionaries of benign/logged requests.
      attack_logs: List of dictionaries of blocked/malicious requests.
    """
    # 0. Try to fetch from SQLite first (primary data source)
    import sqlite3
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DB_PATH = os.environ.get(
        "ML_DB_PATH",
        os.path.abspath(os.path.join(BASE_DIR, "..", "backend", "app", "data", "ml_events.db"))
    )
    if os.path.exists(DB_PATH):
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM ml_events WHERE decision IN ('allow', 'log')")
            benign_logs = [dict(r) for r in cursor.fetchall()]

            # Blocks an analyst has confirmed were NOT actually malicious
            # belong in the benign set, not the attack set — otherwise a
            # corrected false positive keeps poisoning every future retrain.
            cursor.execute(
                "SELECT * FROM ml_events WHERE decision = 'block' AND admin_label = 'false_positive'"
            )
            benign_logs += [dict(r) for r in cursor.fetchall()]

            cursor.execute(
                "SELECT * FROM ml_events WHERE decision = 'block' "
                "AND (admin_label IS NULL OR admin_label != 'false_positive')"
            )
            attack_logs = [dict(r) for r in cursor.fetchall()]

            benign_logs = _cap_duplicate_unreviewed_rows(benign_logs)

            for row in benign_logs + attack_logs:
                row["_training_weight"] = REVIEWED_WEIGHT if row.get("admin_label") else SELF_LABELED_WEIGHT
                # crs_score from the live request path can be stale (see
                # crs_audit_enrichment.py's module docstring for why) —
                # crs_score_verified, backfilled from ModSecurity's own
                # audit log, is the real value when present.
                if row.get("crs_score_verified") is not None:
                    row["crs_score"] = row["crs_score_verified"]

            conn.close()
            logger.info(f"SQLite DB ETL complete. Extracted {len(benign_logs)} benign and {len(attack_logs)} attack samples.")
            if benign_logs or attack_logs:
                return benign_logs, attack_logs
        except Exception as e:
            logger.warning(f"Failed to query SQLite DB for training datasets: {e}")

    # 1. Try to fetch from OpenSearch (fallback)
    client = connect_opensearch()
    if client:
        # Match decision values: 'allow' or 'log' for benign
        benign_query = {
            "bool": {
                "should": [
                    {"match": {"decision": "allow"}},
                    {"match": {"decision": "log"}}
                ]
            }
        }
        # Match decision value: 'block' for attack
        attack_query = {
            "match": {"decision": "block"}
        }
        
        logger.info("Querying benign events from OpenSearch...")
        benign_logs = fetch_events_from_opensearch(client, benign_query)
        logger.info("Querying attack events from OpenSearch...")
        attack_logs = fetch_events_from_opensearch(client, attack_query)
        
        if benign_logs or attack_logs:
            logger.info(f"OpenSearch ETL complete. Extracted {len(benign_logs)} benign and {len(attack_logs)} attack samples.")
            return benign_logs, attack_logs
            
    # 2. Fall back to local JSONL logs if OpenSearch is down or empty
    logger.info(f"OpenSearch data not available. Falling back to local log parser: {LOCAL_EVENTS_PATH}")
    benign_logs = []
    attack_logs = []
    
    if os.path.exists(LOCAL_EVENTS_PATH):
        try:
            with open(LOCAL_EVENTS_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        decision = event.get("decision")
                        if decision in ["allow", "log"]:
                            benign_logs.append(event)
                        elif decision == "block":
                            attack_logs.append(event)
                    except json.JSONDecodeError:
                        continue
            logger.info(f"Local logs ETL complete. Loaded {len(benign_logs)} benign and {len(attack_logs)} attack samples.")
        except Exception as e:
            logger.error(f"Failed to read local events file: {e}")
            
    return benign_logs, attack_logs
