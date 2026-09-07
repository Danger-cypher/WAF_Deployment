import json
import logging
from typing import List
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(
            f"WebSocket connected. Total clients: {len(self.active_connections)}"
        )

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(
            f"WebSocket disconnected. Total clients: {len(self.active_connections)}"
        )

    async def _broadcast(self, envelope: dict):
        if not self.active_connections:
            return

        message = json.dumps(envelope)
        for connection in list(self.active_connections):
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error(f"Error sending to websocket: {e}")
                self.disconnect(connection)

    async def broadcast_log(self, log_dict: dict):
        await self._broadcast({"type": "log", "data": log_dict})

    async def broadcast_alert(self, alert_dict: dict):
        await self._broadcast({"type": "alert", "data": alert_dict})


manager = ConnectionManager()

# The file-watcher that used to live in this module (NewLogHandler /
# start_log_watcher — a second watchdog.Observer duplicating what
# log_ingestor.py's own file watcher already does on the same audit
# directory) was removed 2026-09-04. It was imported in main.py but its
# start function was never actually called, which meant broadcast_log()
# above had exactly zero real callers: the Threat Globe and Overview
# pages' live feeds (both filter for `msg.type === 'log'` on this
# websocket) silently never received anything, and "attack_detected" —
# the event type behind the default-seeded "High WAF Attack Rule" — was
# triggered from nowhere else in the codebase, so that alert never fired
# either. Both are now driven from log_ingestor.py's _flush_loop
# (_broadcast_and_alert), which already sees every ingested entry
# regardless of source — see that function's docstring for the full
# explanation. This module now only holds the connection registry and
# broadcast primitives that _flush_loop and routes/ws.py both call into.
