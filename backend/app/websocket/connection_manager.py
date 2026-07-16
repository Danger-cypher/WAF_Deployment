import asyncio
import json
import logging
from typing import List
from fastapi import WebSocket
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os

from app.config.settings import settings
from app.parsers.modsec_parser import parse_modsec_audit_json
from app.services.log_reader import parsed_entries

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

    async def broadcast_log(self, log_dict: dict):
        if not self.active_connections:
            return

        message = json.dumps(log_dict)
        for connection in list(self.active_connections):
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error(f"Error sending to websocket: {e}")
                self.disconnect(connection)


manager = ConnectionManager()


class NewLogHandler(FileSystemEventHandler):
    def __init__(self, loop: asyncio.AbstractEventLoop):
        self.loop = loop
        super().__init__()

    def process_file(self, file_path: str):
        # We only process if it's new
        if file_path in parsed_entries:
            return

        # Security: Prevent path traversal
        abs_file_path = os.path.abspath(file_path)
        abs_log_dir = os.path.abspath(settings.LOG_DIR)
        if not abs_file_path.startswith(os.path.join(abs_log_dir, "")):
            return

        entry = parse_modsec_audit_json(file_path, settings.LOG_DIR)
        if entry:
            parsed_entries[file_path] = entry

            # Broadcast the new log to websocket clients
            asyncio.run_coroutine_threadsafe(
                manager.broadcast_log(entry.model_dump()), self.loop
            )

            # Trigger real-time alert rule evaluation
            from app.services.alert_manager import alert_manager
            asyncio.run_coroutine_threadsafe(
                alert_manager.trigger_event("attack_detected", entry.model_dump()), self.loop
            )

    def on_created(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)


def start_log_watcher(loop: asyncio.AbstractEventLoop) -> Observer:
    """
    Start watchdog observer to watch for new ModSecurity logs.
    """
    if not os.path.exists(settings.LOG_DIR):
        logger.warning(
            f"Log directory {settings.LOG_DIR} does not exist. Watcher not started."
        )
        return None

    event_handler = NewLogHandler(loop)
    observer = Observer()
    observer.schedule(event_handler, settings.LOG_DIR, recursive=True)
    observer.start()
    logger.info(f"Started watching log directory: {settings.LOG_DIR}")
    return observer
