import os
import sqlite3
from fastapi import APIRouter, Query, Depends
from typing import Optional
from app.services.auth import require_any_role, require_admin, TokenData

router = APIRouter()

DB_PATH = os.environ.get(
    "ML_DB_PATH",
    os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "data",
            "ml_events.db"
        )
    )
)


def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.row_factory = sqlite3.Row
    return conn


@router.get("/ml/stats")
async def get_ml_stats(current_user: TokenData = Depends(require_any_role)):
    if not os.path.exists(DB_PATH):
        return {
            "total_evaluations": 0,
            "decision_breakdown": {"allow": 0, "block": 0, "rate_limit": 0, "log": 0},
            "avg_threat_score": 0.0,
            "top_anomalous_uris": [],
            "top_anomalous_ips": [],
        }

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Total and avg threat score
        cursor.execute("SELECT COUNT(*), AVG(threat_score) FROM ml_events")
        row = cursor.fetchone()
        total = row[0] or 0
        avg_score = row[1] or 0.0

        # Decision breakdown
        cursor.execute("SELECT decision, COUNT(*) FROM ml_events GROUP BY decision")
        decisions = {r[0]: r[1] for r in cursor.fetchall()}

        # Top anomalous URIs (highest avg threat score or count)
        cursor.execute("""
            SELECT uri, COUNT(*) as count, AVG(threat_score) as avg_score 
            FROM ml_events 
            GROUP BY uri 
            ORDER BY avg_score DESC, count DESC 
            LIMIT 5
        """)
        top_uris = [dict(r) for r in cursor.fetchall()]

        # Top anomalous IPs
        cursor.execute("""
            SELECT remote_addr as ip, COUNT(*) as count, AVG(threat_score) as avg_score 
            FROM ml_events 
            GROUP BY remote_addr 
            ORDER BY avg_score DESC, count DESC 
            LIMIT 5
        """)
        top_ips = [dict(r) for r in cursor.fetchall()]

        conn.close()

        # Fill in missing decision types
        for d_type in ["allow", "block", "rate_limit", "log"]:
            if d_type not in decisions:
                decisions[d_type] = 0

        return {
            "total_evaluations": total,
            "decision_breakdown": decisions,
            "avg_threat_score": round(avg_score, 4),
            "top_anomalous_uris": top_uris,
            "top_anomalous_ips": top_ips,
        }
    except Exception as e:
        return {"error": str(e)}


@router.get("/ml/logs")
async def get_ml_logs(
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=100),
    decision: Optional[str] = None,
    ip: Optional[str] = None,
    uri: Optional[str] = None,
    search: Optional[str] = None,
    current_user: TokenData = Depends(require_any_role),
):
    if not os.path.exists(DB_PATH):
        return {"data": [], "total": 0, "page": page, "size": size}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        query = "SELECT * FROM ml_events WHERE 1=1"
        params = []

        if decision:
            query += " AND decision = ?"
            params.append(decision)
        if ip:
            query += " AND remote_addr = ?"
            params.append(ip)
        if uri:
            query += " AND uri LIKE ?"
            params.append(f"%{uri}%")
        if search:
            query += " AND (uri LIKE ? OR remote_addr LIKE ? OR matched_vars LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

        # Get count
        count_query = f"SELECT COUNT(*) FROM ({query})"  # nosec B608
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]

        # Get data with pagination
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        offset = (page - 1) * size
        params.extend([size, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        data = []
        for r in rows:
            d = dict(r)
            data.append(d)

        conn.close()
        return {"data": data, "total": total, "page": page, "size": size}
    except Exception as e:
        return {"error": str(e), "data": [], "total": 0, "page": page, "size": size}


@router.get("/ml/timeline")
async def get_ml_timeline(current_user: TokenData = Depends(require_any_role)):
    if not os.path.exists(DB_PATH):
        return {"data": []}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Group by 15 minute intervals in UTC, limit to last 100 buckets
        cursor.execute("""
            SELECT 
                strftime('%Y-%m-%d %H:', timestamp) || 
                printf('%02d:00', (cast(strftime('%M', timestamp) as integer) / 15) * 15) as time_bucket,
                AVG(threat_score) as avg_score,
                COUNT(*) as count
            FROM ml_events
            GROUP BY time_bucket
            ORDER BY time_bucket ASC
            LIMIT 100
        """)
        rows = cursor.fetchall()
        data = [dict(r) for r in rows]
        conn.close()
        return {"data": data}
    except Exception as e:
        return {"error": str(e), "data": []}

from pydantic import BaseModel

class RollbackPayload(BaseModel):
    timestamp: str

@router.get("/ml/model-info")
async def get_ml_model_info(current_user: TokenData = Depends(require_any_role)):
    import requests
    ml_api = os.environ.get("ML_API", "http://waf-ml:9000")
    try:
        res = requests.get(f"{ml_api}/health", timeout=5)
        if res.status_code == 200:
            return res.json()
        return {"status": "error", "message": f"ML service returned HTTP {res.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.post("/ml/retrain")
async def trigger_ml_retrain(current_user: TokenData = Depends(require_admin)):
    import requests
    ml_api = os.environ.get("ML_API", "http://waf-ml:9000")
    try:
        res = requests.post(f"{ml_api}/retrain", timeout=5)
        if res.status_code == 200:
            return res.json()
        return {"status": "error", "message": f"ML service returned HTTP {res.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.get("/ml/retrain/status")
async def get_ml_retrain_status(current_user: TokenData = Depends(require_any_role)):
    import requests
    ml_api = os.environ.get("ML_API", "http://waf-ml:9000")
    try:
        res = requests.get(f"{ml_api}/retrain/status", timeout=5)
        if res.status_code == 200:
            return res.json()
        return {"status": "error", "message": f"ML service returned HTTP {res.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.get("/ml/backups")
async def get_ml_backups(current_user: TokenData = Depends(require_any_role)):
    import requests
    ml_api = os.environ.get("ML_API", "http://waf-ml:9000")
    try:
        res = requests.get(f"{ml_api}/models/backups", timeout=5)
        if res.status_code == 200:
            return res.json()
        return {"status": "error", "message": f"ML service returned HTTP {res.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.post("/ml/rollback")
async def rollback_ml_model(payload: RollbackPayload, current_user: TokenData = Depends(require_admin)):
    import requests
    ml_api = os.environ.get("ML_API", "http://waf-ml:9000")
    try:
        res = requests.post(f"{ml_api}/models/rollback", json=payload.model_dump(), timeout=5)
        if res.status_code == 200:
            return res.json()
        return {"status": "error", "message": f"ML service returned HTTP {res.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.get("/ml/feature-importance")
async def get_ml_feature_importance(current_user: TokenData = Depends(require_any_role)):
    import requests
    ml_api = os.environ.get("ML_API", "http://waf-ml:9000")
    try:
        res = requests.get(f"{ml_api}/models/feature-importance", timeout=5)
        if res.status_code == 200:
            return res.json()
        return {"status": "error", "message": f"ML service returned HTTP {res.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
