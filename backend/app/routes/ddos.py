import logging
import asyncio
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from typing import Dict, Any, List, Optional

from app.services.ddos_analytics import get_ddos_analytics
from app.services.stats_calculator import get_bot_traffic_breakdown, get_top_bot_identities
from app.services.auth import require_admin, TokenData

logger = logging.getLogger(__name__)
router = APIRouter()


class ChallengeVerifyRequest(BaseModel):
    token: str
    provider: str = "native"  # "turnstile" | "hcaptcha" | "native"


@router.get("/ddos/analytics", response_model=Dict[str, Any])
async def ddos_analytics(
    hours: int = Query(24, ge=1, le=168, description="Time window in hours (default 24, max 1 week)"),
    current_user: TokenData = Depends(require_admin),
):
    """
    Returns the latest DDoS/Bot mitigation traffic graph, top blocked IPs,
    and a per-mechanism breakdown, over a real time window (not a raw log
    line count — see ddos_analytics.get_ddos_analytics's docstring).
    """
    try:
        return await asyncio.to_thread(get_ddos_analytics, hours)
    except Exception as e:
        # Returning a fake "0 total_blocks" 200 here is the worst possible
        # failure mode: if this breaks (e.g. ClickHouse unreachable) during
        # an actual DDoS event, the dashboard confidently reports "0 blocks"
        # at the exact moment an admin most needs accurate data.
        logger.error(f"Error fetching DDoS analytics: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to load DDoS analytics: {e}")


@router.get("/ddos/bot-traffic", response_model=List[Dict[str, Any]])
async def ddos_bot_traffic(
    hours: Optional[int] = Query(None, description="Timeframe in hours"),
    current_user: TokenData = Depends(require_admin)
):
    """
    Traffic volume by bot/human category (User-Agent based), each with its
    own blocked count — the DDoS & Bot Shield page's traffic-composition
    view (P1 item 5 of the WAAP console teardown roadmap).
    """
    return await asyncio.to_thread(get_bot_traffic_breakdown, hours)


@router.get("/ddos/bot-identities", response_model=List[Dict[str, Any]])
async def ddos_bot_identities(
    hours: Optional[int] = Query(None, description="Timeframe in hours"),
    limit: int = Query(10, ge=1, le=50),
    current_user: TokenData = Depends(require_admin)
):
    """
    The specific User-Agent strings behind the non-human traffic categories.
    """
    return await asyncio.to_thread(get_top_bot_identities, hours, limit)


@router.post("/ddos/challenge/verify")
async def verify_challenge(request: Request, payload: ChallengeVerifyRequest):
    """
    Public challenge verification endpoint for Turnstile / hCaptcha / native JS challenge.
    When verified, records IP pass in Redis (1h TTL) so the client can proceed.
    """
    client_ip = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or (request.client.host if request.client else "127.0.0.1")
    )
    from app.services.nginx_manager import get_redis_client
    from app.services.settings_manager import settings_manager

    r = get_redis_client()
    if r is None:
        raise HTTPException(status_code=503, detail="Redis unavailable")

    provider = (payload.provider or "native").lower()
    ddos_settings = settings_manager.get_ddos_bot_mitigation()

    if provider == "turnstile":
        secret_key = ddos_settings.get("turnstile_secret_key", "")
        if not secret_key:
            secret_key = r.get("waf:challenge:turnstile_secret_key") or ""
        if secret_key:
            import urllib.request
            import urllib.parse
            import json as _json
            try:
                verify_data = urllib.parse.urlencode({
                    "secret": secret_key,
                    "response": payload.token,
                    "remoteip": client_ip,
                }).encode("utf-8")
                req = urllib.request.Request(
                    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                    data=verify_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = _json.loads(resp.read().decode("utf-8"))
                    if not data.get("success", False):
                        logger.warning(f"Turnstile verification failed for {client_ip}: {data}")
                        raise HTTPException(status_code=400, detail="Challenge verification failed")
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Error calling Cloudflare Turnstile verify API: {e}")
                raise HTTPException(status_code=502, detail="Upstream verification service error")

    elif provider == "hcaptcha":
        secret_key = ddos_settings.get("hcaptcha_secret_key", "")
        if not secret_key:
            secret_key = r.get("waf:challenge:hcaptcha_secret_key") or ""
        if secret_key:
            import urllib.request
            import urllib.parse
            import json as _json
            try:
                verify_data = urllib.parse.urlencode({
                    "secret": secret_key,
                    "response": payload.token,
                    "remoteip": client_ip,
                }).encode("utf-8")
                req = urllib.request.Request(
                    "https://api.hcaptcha.com/siteverify",
                    data=verify_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = _json.loads(resp.read().decode("utf-8"))
                    if not data.get("success", False):
                        logger.warning(f"hCaptcha verification failed for {client_ip}: {data}")
                        raise HTTPException(status_code=400, detail="Challenge verification failed")
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Error calling hCaptcha verify API: {e}")
                raise HTTPException(status_code=502, detail="Upstream verification service error")

    # Mark client as passed in Redis for 1 hour (3600 seconds)
    r.setex(f"waf:challenge_passed:{client_ip}", 3600, "1")
    return {"success": True, "message": "Verification successful"}
