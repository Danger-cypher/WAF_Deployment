"""
Security Audit Logging Endpoint
Provides endpoints to view and analyze security audit logs.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timezone

from app.utils.security import security_audit_logger, SecurityAuditLogger

router = APIRouter()

class SecurityEvent(BaseModel):
    timestamp: str
    level: str
    event_type: str
    client_ip: Optional[str] = None
    username: Optional[str] = None
    success: Optional[bool] = None
    attempts: Optional[int] = None
    block_duration_seconds: Optional[int] = None
    field: Optional[str] = None
    value: Optional[str] = None
    violation_type: Optional[str] = None
    action_taken: Optional[str] = None
    details: Optional[str] = None


class EventsResponse(BaseModel):
    total: int
    page: int
    page_size: int
    total_pages: int
    events: List[SecurityEvent]


class AuthEventsResponse(BaseModel):
    total: int
    events: List[SecurityEvent]


@router.get("/events", response_model=EventsResponse)
async def get_security_events(
    request: Request,
    event_type: Optional[str] = None,
    hours: int = 24,
    limit: int = 100,
    page: int = 1,
    page_size: int = 50
):
    """
    Get recent security audit events with pagination.
    
    - **event_type**: Filter by event type (AUTH_ATTEMPT, RATE_LIMIT_TRIGGER, etc.)
    - **hours**: Time window in hours (default: 24)
    - **limit**: Maximum number of events to return (default: 100)
    - **page**: Page number for pagination
    - **page_size**: Number of events per page
    """
    if page < 1:
        page = 1
    if page_size < 1 or page_size > 1000:
        page_size = 50
    
    all_events = security_audit_logger.get_recent_events(
        event_type=event_type,
        hours=hours,
        limit=limit
    )
    
    # Sort by timestamp (newest first)
    all_events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    
    # Pagination
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    paginated_events = all_events[start_idx:end_idx]
    
    return {
        "total": len(all_events),
        "page": page,
        "page_size": page_size,
        "total_pages": (len(all_events) + page_size - 1) // page_size,
        "events": paginated_events
    }


@router.get("/events/auth", response_model=AuthEventsResponse)
async def get_auth_events(
    request: Request,
    hours: int = 24,
    success: Optional[bool] = None
):
    """
    Get authentication-related security events.
    
    - **hours**: Time window in hours (default: 24)
    - **success**: Filter by success/failure (optional)
    """
    all_events = security_audit_logger.get_recent_events(
        event_type="AUTH_ATTEMPT",
        hours=hours
    )
    
    if success is not None:
        all_events = [
            e for e in all_events 
            if e.get("success") == success
        ]
    
    # Sort by timestamp (newest first)
    all_events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    
    return {
        "total": len(all_events),
        "events": all_events
    }


@router.get("/events/rate-limits", response_model=AuthEventsResponse)
async def get_rate_limit_events(
    request: Request,
    hours: int = 24
):
    """
    Get rate limit trigger events.
    
    - **hours**: Time window in hours (default: 24)
    """
    all_events = security_audit_logger.get_recent_events(
        event_type="RATE_LIMIT_TRIGGER",
        hours=hours
    )
    
    # Sort by timestamp (newest first)
    all_events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    
    return {
        "total": len(all_events),
        "events": all_events
    }


@router.get("/events/input-validation", response_model=AuthEventsResponse)
async def get_input_validation_events(
    request: Request,
    hours: int = 24,
    violation_type: Optional[str] = None
):
    """
    Get input validation failure events.
    
    - **hours**: Time window in hours (default: 24)
    - **violation_type**: Filter by violation type (XSS, SQL_INJECTION, etc.)
    """
    all_events = security_audit_logger.get_recent_events(
        event_type="INPUT_VALIDATION_FAILURE",
        hours=hours
    )
    
    if violation_type:
        all_events = [
            e for e in all_events 
            if e.get("violation_type") == violation_type
        ]
    
    # Sort by timestamp (newest first)
    all_events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    
    return {
        "total": len(all_events),
        "events": all_events
    }


@router.get("/statistics")
async def get_security_statistics(
    request: Request,
    hours: int = 24
):
    """
    Get security statistics summary for the specified time window.
    
    - **hours**: Time window in hours (default: 24)
    """
    all_events = security_audit_logger.get_recent_events(hours=hours)
    
    # Count events by type
    stats = {
        "total_events": len(all_events),
        "by_type": {},
        "by_hour": {},
        "unique_ips": set(),
    }
    
    for event in all_events:
        event_type = event.get("event_type", "UNKNOWN")
        
        # Count by type
        stats["by_type"][event_type] = stats["by_type"].get(event_type, 0) + 1
        
        # Extract hour for time-based stats
        timestamp = event.get("timestamp", "")
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                hour_key = dt.strftime("%Y-%m-%d %H:00")
                stats["by_hour"][hour_key] = stats["by_hour"].get(hour_key, 0) + 1
            except ValueError:
                pass
        
        # Collect unique IPs
        client_ip = event.get("client_ip")
        if client_ip:
            stats["unique_ips"].add(client_ip)
    
    # Convert set to list for JSON serialization
    stats["unique_ips"] = list(stats["unique_ips"])
    
    # Sort by hour
    stats["by_hour"] = dict(sorted(stats["by_hour"].items()))
    
    return stats


@router.get("/ip/{ip_address}")
async def get_ip_security_profile(
    ip_address: str,
    request: Request,
    hours: int = 24
):
    """
    Get all security events for a specific IP address.
    
    - **ip_address**: The IP address to look up
    - **hours**: Time window in hours (default: 24)
    """
    all_events = security_audit_logger.get_recent_events(hours=hours)
    
    # Filter by IP
    ip_events = [
        event for event in all_events 
        if event.get("client_ip") == ip_address
    ]
    
    # Sort by timestamp (newest first)
    ip_events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    
    # Calculate summary
    summary = {
        "total_events": len(ip_events),
        "auth_attempts": sum(1 for e in ip_events if e.get("event_type") == "AUTH_ATTEMPT"),
        "rate_limit_triggers": sum(1 for e in ip_events if e.get("event_type") == "RATE_LIMIT_TRIGGER"),
        "input_validation_failures": sum(1 for e in ip_events if e.get("event_type") == "INPUT_VALIDATION_FAILURE"),
    }
    
    return {
        "ip_address": ip_address,
        "summary": summary,
        "events": ip_events[:100]  # Limit to 100 events
    }
