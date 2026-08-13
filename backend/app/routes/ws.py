"""
CyberSentinel WAF - Real-time WebSocket Stream
Pushes live log entries and alert notifications to connected dashboards.

Registered on its own router (no CSRF dependency) because the CSRF double
submit check is designed around HTTP Request objects, not the WebSocket
handshake — applying it here previously made the endpoint unusable.
"""
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.config.settings import settings
from app.services.auth import decode_token
from app.websocket.connection_manager import manager

logger = logging.getLogger(__name__)
router = APIRouter()


def _origin_allowed(origin: str) -> bool:
    """
    Defense-in-depth check for the WS handshake's Origin header. The cookie
    itself is samesite="strict" so a modern browser won't attach it
    cross-site anyway — this exists as a second, independent layer for
    older/non-compliant clients rather than relying on the cookie alone.
    """
    if not origin:
        return False
    return origin.rstrip("/") in {o.rstrip("/") for o in settings.BACKEND_CORS_ORIGINS}


@router.websocket("/logs/stream")
async def websocket_endpoint(websocket: WebSocket):
    """Authenticated WebSocket stream of live log/alert events.

    Auth mirrors the HTTP session: the same HttpOnly JWT cookie set at
    login is read from the WebSocket handshake (browsers attach cookies
    to the WS upgrade request automatically for same-origin connections).
    """
    origin = websocket.headers.get("origin", "")
    token = websocket.cookies.get("waf_session_v3")
    if not _origin_allowed(origin) or decode_token(token) is None:
        # Accept-then-close (rather than closing pre-accept) is the more
        # reliably-supported rejection pattern across ASGI servers/proxies.
        await websocket.accept()
        await websocket.close(code=1008)  # policy violation
        return

    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
