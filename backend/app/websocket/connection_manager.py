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


class NewLogHandler(FileSystemEventHandler):
    def __init__(self, loop: asyncio.AbstractEventLoop):
        self.loop = loop
        super().__init__()

    @staticmethod
    def _log_future_exception(future, label: str):
        """
        run_coroutine_threadsafe() returns a concurrent.futures.Future whose
        exception is otherwise silently discarded if nothing ever calls
        .result()/.exception() on it — meaning a bug in broadcast_log or
        trigger_event (a bad rule condition, a DB error, ...) could make
        real-time alerting or the live log feed quietly stop working with
        zero log line, zero crash, and no signal to anyone that it broke.
        """
        try:
            future.result()
        except Exception as e:
            logger.error(f"Unhandled error in {label}: {e}", exc_info=True)

    def process_file(self, file_path: str):
        try:
            self._process_file_unsafe(file_path)
        except Exception as e:
            # Watchdog's observer thread has no try/except of its own around
            # event handler calls — an uncaught exception here would kill the
            # entire watcher thread silently (log ingestion + real-time alerts
            # stop for good, with the process otherwise still running normally).
            logger.error(f"Error processing log file {file_path}: {e}", exc_info=True)

    def _process_file_unsafe(self, file_path: str):
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
            broadcast_future = asyncio.run_coroutine_threadsafe(
                manager.broadcast_log(entry.model_dump()), self.loop
            )
            broadcast_future.add_done_callback(
                lambda f: self._log_future_exception(f, "broadcast_log")
            )

            # Trigger real-time alert rule evaluation
            from app.services.alert_manager import alert_manager
            alert_future = asyncio.run_coroutine_threadsafe(
                alert_manager.trigger_event("attack_detected", entry.model_dump()), self.loop
            )
            alert_future.add_done_callback(
                lambda f: self._log_future_exception(f, "alert_manager.trigger_event")
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
