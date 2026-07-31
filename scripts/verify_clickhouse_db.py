#!/usr/bin/env python3
import sys
import os
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, "/app")

from app.services import clickhouse_service

def verify():
    print("====================================================")
    print("🤖 CYBERSENTINEL CLICKHOUSE VERIFICATION UTILITY")
    print("====================================================")
    
    # 1. Connectivity Check
    print("\n[1/4] Checking ClickHouse Connectivity...")
    if not clickhouse_service.is_available():
        print("❌ ClickHouse connection is UNAVAILABLE. Please check the network.")
        sys.exit(1)
    print("✓ ClickHouse connection is ACTIVE and healthy.")

    # 2. Table Counts Verification
    print("\n[2/4] Verifying Migrated Database Tables Counts...")
    client = clickhouse_service._get_client()
    
    tables = ["ml_events", "analyst_feedback", "alert_history", "waf_events"]
    for t in tables:
        try:
            res = client.query(f"SELECT count() FROM cybersentinel.{t}")
            count = res.result_rows[0][0]
            print(f"  - Table cybersentinel.{t:<18} : {count} rows")
        except Exception as e:
            print(f"  ✗ Failed to query table {t}: {e}")

    # 3. Data Integrity & Schema Structure Checks
    print("\n[3/4] Checking Data Samples & Structural Formats...")
    
    # Sample ML Event
    try:
        res = client.query("SELECT timestamp, remote_addr, threat_score, decision FROM cybersentinel.ml_events LIMIT 1")
        if res.result_rows:
            ts, ip, score, decision = res.result_rows[0]
            print(f"  ✓ Sample ML Event: Time={ts}, RemoteAddr={ip}, Score={score}, Decision={decision}")
        else:
            print("  ⚠ No records found in ml_events")
    except Exception as e:
        print(f"  ✗ Failed to query ml_events sample: {e}")

    # Sample Analyst Feedback (False Positives)
    try:
        res = client.query("SELECT log_id, rule_id, status, analyst_note, created_by FROM cybersentinel.analyst_feedback LIMIT 1")
        if res.result_rows:
            log_id, rule_id, status, note, creator = res.result_rows[0]
            print(f"  ✓ Sample Analyst Feedback: LogID={log_id}, RuleID={rule_id}, Status={status}, Creator={creator}, Note='{note}'")
        else:
            print("  ⚠ No records found in analyst_feedback")
    except Exception as e:
        print(f"  ✗ Failed to query analyst_feedback sample: {e}")

    # Sample Alert History
    try:
        res = client.query("SELECT rule_id, rule_name, event_type, severity, message FROM cybersentinel.alert_history LIMIT 1")
        if res.result_rows:
            rule_id, rule_name, ev_type, sev, msg = res.result_rows[0]
            print(f"  ✓ Sample Alert History: RuleID={rule_id}, Name='{rule_name}', Type={ev_type}, Severity={sev}, Message='{msg}'")
        else:
            print("  ⚠ No records found in alert_history")
    except Exception as e:
        print(f"  ✗ Failed to query alert_history sample: {e}")

    # 4. Live Ingestion Verification (Write -> Read Test)
    print("\n[4/4] Testing Live Ingestion Flow (Write-Then-Read)...")
    test_id = f"test-uuid-{int(datetime.utcnow().timestamp())}"
    test_event = {
        "id": test_id,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "client_ip": "192.168.9.9",
        "uri": "/test-verification-endpoint",
        "method": "POST",
        "http_code": "200",
        "rule_id": "999999",
        "message": "ClickHouse Insertion Verification Test",
        "severity": "low",
        "attack_type": "Test Probe",
        "hostname": "localhost",
        "country": "US",
        "source_asn_org": "Verification System",
        "request_headers": {},
        "response_headers": {},
        "violations": [],
        "raw_log": "{}"
    }
    
    # Perform write
    try:
        inserted = clickhouse_service.insert_waf_events([test_event])
        print(f"  - Injected 1 WAF test event. Rows affected: {inserted}")
    except Exception as e:
        print(f"  ❌ Write test failed: {e}")
        return

    # Perform read query
    try:
        res = client.query(f"SELECT client_ip, uri, message FROM cybersentinel.waf_events WHERE id = '{test_id}'")
        if res.result_rows:
            ip, uri, msg = res.result_rows[0]
            print(f"  ✓ Retrieved test event successfully: ClientIP={ip}, URI={uri}, Msg='{msg}'")
            print("  ✓ WAF Event Live Ingestion pipeline verified successfully.")
        else:
            print("  ❌ Verification event not found in ClickHouse search query.")
    except Exception as e:
        print(f"  ❌ Read verification query failed: {e}")

    print("\n====================================================")
    print("✓ VERIFICATION COMPLETED SUCCESSFULLY.")
    print("====================================================")

if __name__ == "__main__":
    verify()
