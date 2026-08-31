import logging
import asyncio
from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Dict, Any, List, Optional

from app.services.ddos_analytics import get_ddos_analytics
from app.services.stats_calculator import get_bot_traffic_breakdown, get_top_bot_identities
from app.services.auth import require_admin, TokenData

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/ddos/analytics", response_model=Dict[str, Any])
async def ddos_analytics(current_user: TokenData = Depends(require_admin)):
    """
    Returns the latest DDoS/Bot mitigation traffic graph and top blocked IPs.
    """
    try:
        return await asyncio.to_thread(get_ddos_analytics)
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
