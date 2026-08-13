import os
import sqlite3
from fastapi import APIRouter, Query, Depends, HTTPException, status
from pydantic import BaseModel
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
        # Returning {"error": ...} with a 200 status leaves the frontend
        # silently rendering "0 evaluations" for what's actually a DB
        # failure — indistinguishable from "no ML events yet." A real
        # failure must fail visibly.
        raise HTTPException(status_code=500, detail=f"Failed to load ML stats: {e}")


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
        # A 200 with "total": 0 here is indistinguishable from "no matching
        # ML events" — a real DB error must surface as one.
        raise HTTPException(status_code=500, detail=f"Failed to load ML logs: {e}")


class MlEventLabelPayload(BaseModel):
    label: str  # "false_positive" | "true_positive" | null to clear


@router.post("/ml/events/{event_id}/label")
async def label_ml_event(
    event_id: int,
    payload: MlEventLabelPayload,
    current_user: TokenData = Depends(require_any_role),
):
    """Analyst feedback on an ML decision. Feeds drift_monitor's
    xgb_fp_rate signal, which is otherwise always 0 (nothing else writes
    admin_label) and can never trigger a drift-based retrain."""
    if payload.label not in ("false_positive", "true_positive"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="label must be 'false_positive' or 'true_positive'.",
        )
    if not os.path.exists(DB_PATH):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found.")

    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "UPDATE ml_events SET admin_label = ? WHERE id = ?", (payload.label, event_id)
        )
        conn.commit()
        if cursor.rowcount == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found.")
    finally:
        conn.close()
    return {"message": "Event labeled successfully.", "label": payload.label}


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
        raise HTTPException(status_code=500, detail=f"Failed to load ML timeline: {e}")

from pydantic import BaseModel
import asyncio
import requests

class RollbackPayload(BaseModel):
    timestamp: str


async def _ml_api_request(method: str, path: str, **kwargs) -> dict:
    """
    Proxies a request to the ML sidecar. requests.get/post() is a blocking
    call — run directly inside these async routes it would stall the whole
    FastAPI event loop (every other logged-in user's request, not just this
    one) for up to the 5s timeout whenever the ML container is slow or down.
    asyncio.to_thread offloads it to a worker thread instead.

    Sends the same shared secret used for the reverse direction (waf-ml ->
    backend, see app/routes/alerts.py's verify_internal_key) — waf-ml's
    administrative endpoints (retrain/rollback/reload/model-internals) now
    require it too, since they previously had no auth of their own beyond
    Docker network topology.
    """
    ml_api = os.environ.get("ML_API", "http://waf-ml:9000")
    headers = kwargs.pop("headers", {}) or {}
    internal_key = os.environ.get("INTERNAL_ALERT_TRIGGER_KEY")
    if internal_key:
        headers["X-Internal-Key"] = internal_key
    try:
        res = await asyncio.to_thread(
            requests.request, method, f"{ml_api}{path}", timeout=5, headers=headers, **kwargs
        )
        if res.status_code == 200:
            return res.json()
        return {"status": "error", "message": f"ML service returned HTTP {res.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.get("/ml/model-info")
async def get_ml_model_info(current_user: TokenData = Depends(require_any_role)):
    return await _ml_api_request("GET", "/health")

@router.post("/ml/retrain")
async def trigger_ml_retrain(current_user: TokenData = Depends(require_admin)):
    return await _ml_api_request("POST", "/retrain")

@router.get("/ml/retrain/status")
async def get_ml_retrain_status(current_user: TokenData = Depends(require_any_role)):
    return await _ml_api_request("GET", "/retrain/status")

@router.get("/ml/backups")
async def get_ml_backups(current_user: TokenData = Depends(require_any_role)):
    return await _ml_api_request("GET", "/models/backups")

@router.post("/ml/rollback")
async def rollback_ml_model(payload: RollbackPayload, current_user: TokenData = Depends(require_admin)):
    return await _ml_api_request("POST", "/models/rollback", json=payload.model_dump())

@router.get("/ml/drift-history")
async def get_ml_drift_history(current_user: TokenData = Depends(require_any_role)):
    return await _ml_api_request("GET", "/drift/history")

@router.get("/ml/feature-importance")
async def get_ml_feature_importance(current_user: TokenData = Depends(require_any_role)):
    return await _ml_api_request("GET", "/models/feature-importance")
