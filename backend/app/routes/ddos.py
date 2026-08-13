import logging
import asyncio
from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any

from app.services.ddos_analytics import get_ddos_analytics
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
