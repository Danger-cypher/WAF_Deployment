import os
import json
import logging
from opensearchpy import OpenSearch, OpenSearchException

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOCAL_EVENTS_PATH = os.path.join(BASE_DIR, "logs/events.jsonl")

def connect_opensearch() -> OpenSearch:
    """Connects to local OpenSearch service."""
    try:
        return OpenSearch(
            hosts=[{'host': 'localhost', 'port': 9200}],
            http_compress=True,
            timeout=2.0
        )
    except Exception as e:
        logger.warning(f"Failed to initialize OpenSearch client: {e}")
        return None

def fetch_events_from_opensearch(client: OpenSearch, query: dict, size: int = 10000) -> list:
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
    except OpenSearchException as e:
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
            
            cursor.execute("SELECT * FROM ml_events WHERE decision = 'block'")
            attack_logs = [dict(r) for r in cursor.fetchall()]
            
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
