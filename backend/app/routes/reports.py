"""
CyberSentinel WAF - Executive & Compliance Report Routes
Endpoints for unified multi-vector report compilation, scheduled dispatching, and delivery audit.
"""
from fastapi import APIRouter, Depends, Query, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import io

from app.services.auth import require_any_role, require_admin, TokenData
from app.services import report_service

router = APIRouter()


class SchedulePayload(BaseModel):
    id: Optional[int] = None
    name: str = Field(..., min_length=2, max_length=120)
    template: str = Field(default="executive", pattern="^(executive|threat|compliance|api_security)$")
    frequency: str = Field(default="weekly", pattern="^(daily|weekly|monthly)$")
    time_utc: str = Field(default="08:00", pattern="^([01][0-9]|2[0-3]):[0-5][0-9]$")
    day_of_week: int = Field(default=1, ge=1, le=7)
    day_of_month: int = Field(default=1, ge=1, le=31)
    recipients_email: Optional[str] = Field(default="")
    webhook_url: Optional[str] = Field(default="")
    is_active: bool = Field(default=True)


class DispatchNowPayload(BaseModel):
    template: str = Field(default="executive", pattern="^(executive|threat|compliance|api_security)$")
    timeframe: str = Field(default="24h", pattern="^(24h|7d|30d)$")
    recipients_email: Optional[str] = Field(default="")
    webhook_url: Optional[str] = Field(default="")


@router.get("/reports/executive-summary")
def get_executive_summary_report(
    hours: int = Query(24, ge=1, le=720),
    timeframe: str = Query("24h"),
    current_user: TokenData = Depends(require_any_role)
):
    """Compiles unified multi-vector executive security report."""
    try:
        return report_service.compile_executive_report(hours=hours, timeframe_label=timeframe)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate executive report: {e}"
        )


@router.get("/reports/export/csv")
def export_report_csv(
    hours: int = Query(24, ge=1, le=720),
    timeframe: str = Query("24h"),
    current_user: TokenData = Depends(require_any_role)
):
    """Exports compiled report as a plain text CSV."""
    try:
        data = report_service.compile_executive_report(hours=hours, timeframe_label=timeframe)
        csv_text = report_service.generate_csv_report(data)
        return StreamingResponse(
            io.StringIO(csv_text),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=waf_report_{timeframe}.csv"}
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to export CSV: {e}"
        )


@router.get("/reports/schedules")
def get_schedules(current_user: TokenData = Depends(require_any_role)):
    """Retrieves all active and configured automated report schedules."""
    return {"data": report_service.get_report_schedules()}


@router.post("/reports/schedules")
def save_schedule(payload: SchedulePayload, current_user: TokenData = Depends(require_admin)):
    """Creates or updates a scheduled report automation configuration."""
    schedule_id = report_service.create_or_update_report_schedule(payload.model_dump())
    return {"status": "success", "id": schedule_id, "message": "Report schedule saved."}


@router.delete("/reports/schedules/{schedule_id}")
def delete_schedule(schedule_id: int, current_user: TokenData = Depends(require_admin)):
    """Deletes an automated report schedule."""
    ok = report_service.delete_report_schedule(schedule_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Report schedule not found.")
    return {"status": "success", "message": "Report schedule deleted."}


@router.get("/reports/history")
def get_report_history(
    limit: int = Query(50, ge=1, le=200),
    current_user: TokenData = Depends(require_any_role)
):
    """Retrieves past delivery execution records for dispatched reports."""
    return {"data": report_service.get_delivery_history(limit=limit)}


@router.post("/reports/dispatch-now")
def dispatch_report_now(
    payload: DispatchNowPayload,
    current_user: TokenData = Depends(require_admin)
):
    """Immediately compiles and dispatches a test or on-demand security report."""
    hours = 24 if payload.timeframe == "24h" else 168 if payload.timeframe == "7d" else 720
    report_data = report_service.compile_executive_report(hours=hours, timeframe_label=payload.timeframe)
    report_data["template"] = payload.template

    emails = [e.strip() for e in (payload.recipients_email or "").split(",") if e.strip()]
    webhook = payload.webhook_url.strip() if payload.webhook_url else None

    if not emails and not webhook:
        raise HTTPException(
            status_code=400,
            detail="Must provide at least one recipient email address or webhook URL."
        )

    ok, message = report_service.dispatch_report(
        report_data=report_data,
        emails=emails,
        webhook_url=webhook,
        schedule_name=f"Manual On-Demand ({current_user.username})"
    )

    if not ok:
        raise HTTPException(status_code=502, detail=message)
    return {"status": "success", "message": message}
